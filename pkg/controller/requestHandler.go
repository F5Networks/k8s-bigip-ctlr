package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
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
	req.PostManager.closePostChan()
}

func NewAgent(params AgentParams, bigIPLabel string, bigIpAddress string, respChan chan resourceStatusMeta,
	config v1.AS3Config) *RequestHandler {
	DEFAULT_PARTITION = params.Partition
	DEFAULT_GTM_PARTITION = params.Partition + "_gtm"
	postMgr := NewPostManager(params, respChan, config)

	agent := &RequestHandler{
		PostManager:  postMgr,
		reqChan:      make(chan ResourceConfigRequest, 1),
		userAgent:    params.UserAgent,
		bigipLabel:   bigIPLabel,
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
		if !req.PostManager.getFirstPost() && req.PostManager.getPostDelay() != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", req.PostManager.getPostDelay())
			_ = <-time.After(time.Duration(req.PostManager.getPostDelay()) * time.Second)
		}

		// Fetch the latest config from channel
		select {
		case rsConfig = <-req.reqChan:
			log.Infof("%v[AS3] Processing request", getRequestPrefix(rsConfig.reqId))
		case <-time.After(1 * time.Microsecond):
		}
		//create AS3 declaration for bigip pair and put in post channel
		req.createDeclarationForBIGIP(rsConfig)
	}
}

func (req *RequestHandler) createDeclarationForBIGIP(rsConfig ResourceConfigRequest) {
	//for each bigip config create AS3, L3 declaration

	req.declUpdate.Lock()
	currentConfig, err := req.PostManager.GetDeclarationFromBigIP()
	if err != nil {
		log.Errorf("[AS3] Could not fetch the latest AS3 declaration from BIG-IP")
	}
	if req.HAMode {
		// Delete the tenant which is monitored by CIS and current request does not contain it, if it's the first post or
		// if it's secondary CIS and primary CIS is down and statusChanged is true
		if req.PostManager.getFirstPost() ||
			(req.PrimaryClusterHealthProbeParams.EndPoint != "" && !req.PrimaryClusterHealthProbeParams.statusRunning &&
				req.PrimaryClusterHealthProbeParams.statusChanged) {
			removeDeletedTenantsForBigIP(&rsConfig.bigIpResourceConfig, req.defaultPartition, currentConfig, req.defaultPartition)
			req.PostManager.setFirstPost(false)
		}
	}

	for tenantName, partitionConfig := range rsConfig.bigIpResourceConfig.ltmConfig {
		// TODO partitionConfig priority can be overridden by another request if requesthandler is unable to process the prioritized request in time
		partitionConfig.PriorityMutex.RLock()
		if *(partitionConfig.Priority) > 0 {
			req.PostManager.setTenantPriorityMap(tenantName, *(partitionConfig.Priority))
		}
		partitionConfig.PriorityMutex.RUnlock()
	}

	decl := req.PostManager.createTenantDeclaration(rsConfig.bigIpResourceConfig, req.defaultPartition, req.PrimaryClusterHealthProbeParams)
	if req.HAMode {
		// if endPoint is not empty means, cis is running in secondary mode
		// check if the primary cis is up and running
		if req.PrimaryClusterHealthProbeParams.EndPointType != "" {
			if req.PrimaryClusterHealthProbeParams.statusRunning {
				req.declUpdate.Unlock()
				return
			} else {
				if req.PrimaryClusterHealthProbeParams.statusChanged {
					req.PrimaryClusterHealthProbeParams.paramLock.Lock()
					req.PrimaryClusterHealthProbeParams.statusChanged = false
					req.PrimaryClusterHealthProbeParams.paramLock.Unlock()
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
	req.PostManager.initTenantResponseMap()

	for _, tenant := range req.PostManager.getIncomingTenantDeclTenants() {
		// CIS with AS3 doesnt allow write to Common partition.So objects in common partition
		// should not be updated or deleted by CIS. So removing from tenant map
		if tenant != "Common" {
			if req.PostManager.tenantPriorityHasTenant(tenant) {
				priorityTenants = append(priorityTenants, tenant)
			} else {
				updatedTenants = append(updatedTenants, tenant)
			}
			req.PostManager.setTenantResponseMap(tenant, tenantResponse{})
		}
	}
	req.declUpdate.Unlock()
	// TODO: need to handle bigip target address depending on AS3 API either single or two step as part of postManager
	// Update the priority tenants first
	if len(priorityTenants) > 0 {
		req.enqueueCfgForPost(decl, rsConfig, priorityTenants, rsConfig.bigipConfig.BigIpAddress)
	}
	// Updating the remaining tenants
	req.enqueueCfgForPost(decl, rsConfig, updatedTenants, rsConfig.bigipConfig.BigIpAddress)

}

// Enqueue AS3 declaration to post chanel
func (req *RequestHandler) enqueueCfgForPost(decl interface{}, rsConfig ResourceConfigRequest, tenants []string, bigipTargetAddress string) {
	cfg := req.PostManager.getConfigForPost(decl, rsConfig, tenants, bigipTargetAddress)
	select {
	case req.PostManager.getPostChan() <- cfg:
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

	for range req.PostManager.getRetryChan() {

		for len(req.PostManager.getRetryTenantDeclMap()) != 0 {

			if req.HAMode {
				// if endPoint is not empty -> cis is running in secondary mode
				// check if the primary cis is up and running
				if req.PrimaryClusterHealthProbeParams.EndPointType != "" {
					if req.PrimaryClusterHealthProbeParams.statusRunning {
						req.PostManager.initRetryTenantDeclMap()
						// dont post the declaration
						continue
					}
				}
			}

			req.declUpdate.Lock()

			// If we had a delay in acquiring lock, re-check if we have any tenants to be retried
			if len(req.PostManager.getRetryTenantDeclMap()) == 0 {
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
