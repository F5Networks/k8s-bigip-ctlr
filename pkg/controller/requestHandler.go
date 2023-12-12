package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"time"
)

func (req *RequestHandler) startAgent() {
	log.Debug("starting requestHandler")
	// requestHandler runs as a separate go routine
	// blocks on reqChan to get new/updated configuration to be posted to BIG-IP
	go req.requestHandler()

	// retryWorker runs as a separate go routine
	// blocks on retryChan ; retries failed declarations and polls for accepted tenant statuses
	go req.retryWorker()
}

func (req *RequestHandler) stopAgent() {
	log.Debug("stopping requestHandler")
	if req.reqChan != nil {
		close(req.reqChan)
	}
	if req.PostManager.postChan != nil {
		close(req.PostManager.postChan)
	}
}

func NewAgent(params AgentParams, bigiplabel string, bigIpAddress string) *RequestHandler {
	DEFAULT_PARTITION = params.Partition
	DEFAULT_GTM_PARTITION = params.Partition + "_gtm"
	postMgr := NewPostManager(params)

	agent := &RequestHandler{
		PostManager:  postMgr,
		reqChan:      make(chan ResourceConfigRequest, 1),
		userAgent:    params.UserAgent,
		bigipLabel:   bigiplabel,
		bigIpAddress: bigIpAddress,
	}
	agent.startAgent()
	return agent
}

func (req *RequestHandler) EnqueueRequestConfig(rsConfig ResourceConfigRequest) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above

	select {
	case req.reqChan <- rsConfig:
	case <-time.After(3 * time.Millisecond):
	}
}

// RequestHandler blocks on reqChan
// whenever it gets unblocked, it creates an as3, l3 declaration for respective bigip and puts on post channel for postmanger to handle
func (req *RequestHandler) requestHandler() {
	for rsConfig := range req.reqChan {
		// For the very first post after starting controller, need not wait to post
		if !req.PostManager.AS3PostManager.firstPost && req.PostManager.AS3PostManager.AS3Config.PostDelayAS3 != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", req.PostManager.AS3PostManager.AS3Config.PostDelayAS3)
			_ = <-time.After(time.Duration(req.PostManager.AS3PostManager.AS3Config.PostDelayAS3) * time.Second)
		}

		// Fetch the latest config from channel
		select {
		case rsConfig = <-req.reqChan:
		case <-time.After(1 * time.Microsecond):
		}
		//create AS3 declaration for bigip pair and put in post channel
		req.createDeclarationForBIGIP(rsConfig)
	}
}

func (req *RequestHandler) createDeclarationForBIGIP(rsConfig ResourceConfigRequest) {
	//for each bigip config create AS3, L3 declaration

	req.declUpdate.Lock()
	currentConfig, err := req.PostManager.GetAS3DeclarationFromBigIP()
	if err != nil {
		log.Errorf("[AS3] Could not fetch the latest AS3 declaration from BIG-IP")
	}
	if req.PostManager.HAMode {
		// Delete the tenant which is monitored by CIS and current request does not contain it, if it's the first post or
		// if it's secondary CIS and primary CIS is down and statusChanged is true
		if req.PostManager.AS3PostManager.firstPost ||
			(req.PostManager.PrimaryClusterHealthProbeParams.EndPoint != "" && !req.PostManager.PrimaryClusterHealthProbeParams.statusRunning &&
				req.PostManager.PrimaryClusterHealthProbeParams.statusChanged) {
			removeDeletedTenantsForBigIP(&rsConfig.bigIpResourceConfig, req.PostManager.defaultPartition, currentConfig, req.PostManager.defaultPartition)
			req.PostManager.AS3PostManager.firstPost = false
		}
	}

	for tenantName, partitionConfig := range rsConfig.bigIpResourceConfig.ltmConfig {
		// TODO partitionConfig priority can be overridden by another request if requesthandler is unable to process the prioritized request in time
		partitionConfig.PriorityMutex.RLock()
		if *(partitionConfig.Priority) > 0 {
			req.PostManager.tenantPriorityMap[tenantName] = *(partitionConfig.Priority)
		}
		partitionConfig.PriorityMutex.RUnlock()
	}

	decl := req.createTenantDeclaration(rsConfig.bigIpResourceConfig, req.PostManager.defaultPartition, req.PostManager.cachedTenantDeclMap)
	if req.PostManager.HAMode {
		// if endPoint is not empty means, cis is running in secondary mode
		// check if the primary cis is up and running
		if req.PostManager.PrimaryClusterHealthProbeParams.EndPointType != "" {
			if req.PostManager.PrimaryClusterHealthProbeParams.statusRunning {
				req.declUpdate.Unlock()
				return
			} else {
				if req.PostManager.PrimaryClusterHealthProbeParams.statusChanged {
					req.PostManager.PrimaryClusterHealthProbeParams.paramLock.Lock()
					req.PostManager.PrimaryClusterHealthProbeParams.statusChanged = false
					req.PostManager.PrimaryClusterHealthProbeParams.paramLock.Unlock()
				}
			}
		}
	}

	var updatedTenants []string
	// initializing the priority tenants
	var priorityTenants []string
	/*
		For every incoming post request, create a new tenantResponseMap.
		tenantResponseMap will be updated with responses during postConfig.
		It holds the updatedTenants in the current iteration's as keys.
		This is needed to update response code in cases (202/404) when httpResponse body does not contain the tenant details.
	*/
	req.PostManager.tenantResponseMap = make(map[string]tenantResponse)

	for tenant := range req.PostManager.incomingTenantDeclMap {
		// CIS with AS3 doesnt allow write to Common partition.So objects in common partition
		// should not be updated or deleted by CIS. So removing from tenant map
		if tenant != "Common" {
			if _, ok := req.PostManager.tenantPriorityMap[tenant]; ok {
				priorityTenants = append(priorityTenants, tenant)
			} else {
				updatedTenants = append(updatedTenants, tenant)
			}
			req.PostManager.tenantResponseMap[tenant] = tenantResponse{}
		}
	}
	req.declUpdate.Unlock()
	// TODO: need to handle bigip target address depending on AS3 API either single or two step as part of postManager
	// Update the priority tenants first
	if len(priorityTenants) > 0 {
		req.enqueueCfgForPost(decl.(as3Declaration), rsConfig, priorityTenants, rsConfig.bigipConfig.BigIpAddress)
	}
	// Updating the remaining tenants
	req.enqueueCfgForPost(decl.(as3Declaration), rsConfig, updatedTenants, rsConfig.bigipConfig.BigIpAddress)

}

// Enqueue AS3 declaration to post chanel
func (req *RequestHandler) enqueueCfgForPost(decl as3Declaration, rsConfig ResourceConfigRequest, tenants []string, bigipTargetAddress string) {
	as3cfg := as3Config{
		data:               string(decl),
		as3APIURL:          req.PostManager.getAS3APIURL(tenants),
		id:                 rsConfig.reqId,
		bigipTargetAddress: bigipTargetAddress,
	}
	//TODO: Implement as part of L3 Manager
	l3cfg := l3Config{}
	cfg := agentConfig{as3Config: as3cfg, l3Config: l3cfg}
	select {
	case req.PostManager.postChan <- cfg:
		log.Debugf("Declaration written to post chan")
	case <-time.After(3 * time.Second):
	}
}

// retryWorker blocks on retryChan
// whenever it gets unblocked, retries failed declarations and polls for accepted tenant statuses
func (req *RequestHandler) retryWorker() {

	/*
		retryWorker runs as a goroutine. It is idle until an arrives at retryChan.
		retryTenantDeclMal holds all information about tenant adc configuration and response codes.

		Once retryChan is signalled, retryWorker posts tenant declarations and/or polls for accepted tenants' statuses continuously until it succeeds
		Locks are used to block retries if an incoming request arrives at agentWorker.

		For each iteration, retryWorker tries to acquire requesthandler.declUpdate lock.
		During an ongoing agentWorker's activity, retryWorker tries to wait until requesthandler.declUpdate lock is acquired
		Similarly, during an ongoing retry, agentWorker waits for graceful termination of ongoing iteration - i.e., until requesthandler.declUpdate is unlocked

	*/

	for range req.PostManager.retryChan {

		for len(req.PostManager.retryTenantDeclMap) != 0 {

			if req.PostManager.HAMode {
				// if endPoint is not empty -> cis is running in secondary mode
				// check if the primary cis is up and running
				if req.PostManager.PrimaryClusterHealthProbeParams.EndPointType != "" {
					if req.PostManager.PrimaryClusterHealthProbeParams.statusRunning {
						req.PostManager.retryTenantDeclMap = make(map[string]*tenantParams)
						// dont post the declaration
						continue
					}
				}
			}

			req.declUpdate.Lock()

			// If we had a delay in acquiring lock, re-check if we have any tenants to be retried
			if len(req.PostManager.retryTenantDeclMap) == 0 {
				req.declUpdate.Unlock()
				break
			}

			log.Debugf("[AS3] Posting failed tenants configuration in %v seconds", timeoutMedium)

			//If there are any 201 tenants, poll for its status
			req.PostManager.pollTenantStatus()

			//If there are any failed tenants, retry posting them
			req.PostManager.retryFailedTenant(req.userAgent)

			req.PostManager.notifyRscStatusHandler(0, false)

			req.declUpdate.Unlock()
		}
	}
}
