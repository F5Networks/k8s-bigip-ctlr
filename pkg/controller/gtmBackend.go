package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
)

func NewGTMPostManager(params AgentParams) *GTMPostManager {
	gtmMgr := NewPostManager(params, true)
	gtmPostMgr := &GTMPostManager{
		PostManager: gtmMgr,
		Partition:   DEFAULT_GTM_PARTITION,
	}
	return gtmPostMgr
}

func (gtmPostManager *GTMPostManager) PostGTMConfig(rsConfig agentConfig) {
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
	if len(params.GTMParams.CMURL) != 0 && len(params.GTMParams.CMUsername) != 0 && len(params.GTMParams.CMPassword) != 0 {
		// Check if GTM parameter is different then LTM parameter
		if params.PostParams.CMURL != params.GTMParams.CMURL || params.PostParams.CMUsername != params.GTMParams.CMUsername || params.PostParams.CMPassword != params.GTMParams.CMPassword {
			isGTMOnSeparateServer = true
		}
	}
	return isGTMOnSeparateServer
}
