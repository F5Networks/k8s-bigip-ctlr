package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"reflect"
	"time"
)

func NewGTMPostManager(params AgentParams) *GTMPostManager {
	gtmMgr := NewPostManager(params, true)
	gtmPostMgr := &GTMPostManager{
		PostManager: gtmMgr,
		Partition:   DEFAULT_GTM_PARTITION,
	}
	return gtmPostMgr
}

// retryGTMWorker blocks on retryChan
// whenever it gets unblocked, retries failed declarations and polls for accepted tenant statuses
func (agent *Agent) gtmWorker() {

	for rsConfig := range agent.GTMPostManager.PostManager.postChan {
		// For the very first post after starting controller, need not wait to post
		if !agent.GTMPostManager.firstPost && agent.GTMPostManager.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3][GTM] Delaying post to BIG-IP for %v seconds ", agent.GTMPostManager.AS3PostDelay)
			_ = <-time.After(time.Duration(agent.GTMPostManager.AS3PostDelay) * time.Second)
		}

		// If there are no retries going on in parallel, acquiring lock will be straight forward.
		// Otherwise, we will wait for other workers to complete its current iteration
		agent.declUpdate.Lock()

		// Fetch the latest config from channel
		select {
		case rsConfig = <-agent.GTMPostManager.PostManager.postChan:
			log.Infof("%v[AS3] Processing request", getRequestPrefix(rsConfig.reqId))
		case <-time.After(1 * time.Microsecond):
		}
		adc := as3ADC{}
		agent.GTMPostManager.incomingTenantDeclMap = make(map[string]as3Tenant)
		log.Infof("%v[AS3] creating a new AS3 manifest", getRequestPrefix(rsConfig.reqId))
		for tenant, cfg := range agent.createAS3GTMConfigADC(rsConfig, adc) {
			if !reflect.DeepEqual(cfg, agent.GTMPostManager.cachedTenantDeclMap[tenant]) {
				agent.GTMPostManager.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
			} else {
				// cachedTenantDeclMap always holds the current configuration on BigIP(lets say A)
				// When an invalid configuration(B) is reverted (to initial A) (i.e., config state A -> B -> A),
				// delete entry from retryTenantDeclMap if any
				delete(agent.GTMPostManager.retryTenantDeclMap, tenant)
			}
		}

		if len(agent.GTMPostManager.incomingTenantDeclMap) == 0 {
			log.Infof("%v[AS3] No tenants found in request", getRequestPrefix(rsConfig.reqId))
			agent.declUpdate.Unlock()
			continue
		}

		agent.GTMPostManager.tenantResponseMap = make(map[string]tenantResponse)

		for tenant := range agent.GTMPostManager.incomingTenantDeclMap {
			// CIS with AS3 doesn't allow to write to Common partition.So objects in common partition
			// should not be updated or deleted by CIS. So removing from tenant map
			if tenant != "Common" {
				agent.GTMPostManager.tenantResponseMap[tenant] = tenantResponse{}
			}
		}

		cfg := agentConfig{
			data:      string(agent.createAS3Declaration(agent.GTMPostManager.incomingTenantDeclMap, agent.userAgent)),
			as3APIURL: agent.GTMPostManager.getAS3APIURL([]string{agent.GTMPostManager.Partition}),
			id:        0,
		}

		agent.GTMPostManager.publishConfig(cfg)

		agent.GTMPostManager.updateTenantResponseMap(true)

		if len(agent.GTMPostManager.retryTenantDeclMap) > 0 {
			// Activate retry
			select {
			case agent.GTMPostManager.retryChan <- struct{}{}:
			case <-agent.GTMPostManager.retryChan:
				agent.GTMPostManager.retryChan <- struct{}{}
			}
		}

		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		agent.GTMPostManager.pollTenantStatus()

		// release the lock
		agent.declUpdate.Unlock()

	}
}

func (gtmPostManager *GTMPostManager) PostGTMConfig(rsConfig ResourceConfigRequest) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above
	select {
	case gtmPostManager.PostManager.postChan <- rsConfig:
	case <-gtmPostManager.PostManager.postChan:
		gtmPostManager.PostManager.postChan <- rsConfig
	}

}

func (agent *Agent) retryGTMWorker() {

	/*
		retryGTMWorker runs as a goroutine. It is idle until an arrives at GTM retryChan.
		retryTenantDeclMal holds all information about tenant adc configuration and response codes.

		Once GTM retryChan is signalled, retryGTMWorker posts tenant declarations and/or polls for accepted tenants' statuses continuously until it succeeds
		Locks are used to block retries if an incoming request arrives at agentWorker.

		For each iteration, retryGTMWorker tries to acquire agent.declUpdate lock.
		During an ongoing agentWorker's activity, retryGTMWorker tries to wait until agent.declUpdate lock is acquired
		Similarly, during an ongoing retry, agentWorker waits for graceful termination of ongoing iteration - i.e., until agent.declUpdate is unlocked

	*/

	for range agent.GTMPostManager.retryChan {

		for len(agent.GTMPostManager.retryTenantDeclMap) != 0 {

			agent.declUpdate.Lock()

			// If we had a delay in acquiring lock, re-check if we have any tenants to be retried
			if len(agent.GTMPostManager.retryTenantDeclMap) == 0 {
				agent.declUpdate.Unlock()
				break
			}

			log.Debugf("[AS3][GTM] Posting failed tenants configuration in %v seconds", timeoutMedium)

			//If there are any 201 tenants, poll for its status
			agent.GTMPostManager.pollTenantStatus()

			//If there are any failed tenants, retry posting them
			agent.GTMPostManager.retryFailedTenant(agent.userAgent)

			agent.declUpdate.Unlock()
		}
	}
}

func isGTMOnSeparateServer(params AgentParams) bool {
	var isGTMOnSeparateServer bool
	if !params.CCCLGTMAgent && len(params.GTMParams.BIGIPURL) != 0 && len(params.GTMParams.BIGIPUsername) != 0 && len(params.GTMParams.BIGIPPassword) != 0 {
		// Check if GTM parameter is different then LTM parameter
		if params.PostParams.BIGIPURL != params.GTMParams.BIGIPURL || params.PostParams.BIGIPUsername != params.GTMParams.BIGIPUsername || params.PostParams.BIGIPPassword != params.GTMParams.BIGIPPassword {
			isGTMOnSeparateServer = true
		}
	}
	return isGTMOnSeparateServer
}
