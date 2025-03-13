package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"reflect"
	"time"
)

func NewGTMPostManager(params AgentParams) *GTMPostManager {
	gtmMgr := NewPostManager(params, GTMBigIP)
	gtmPostMgr := &GTMPostManager{
		PostManager: gtmMgr,
		Partition:   DEFAULT_GTM_PARTITION,
	}
	return gtmPostMgr
}

// write a function which checks if the GTM is on a separate server under the agentworker object
func (aw *AgentWorker) isGTMOnSeparateServer() bool {
	if !aw.ccclGTMAgent && len(aw.GTM.PostManager.PostParams.BIGIPURL) != 0 &&
		len(aw.GTM.PostManager.PostParams.BIGIPUsername) != 0 &&
		len(aw.GTM.PostManager.PostParams.BIGIPPassword) != 0 {
		// Check if GTM parameter is different than LTM parameter
		if aw.LTM.PostManager.PostParams.BIGIPURL != aw.GTM.PostManager.PostParams.BIGIPURL ||
			aw.LTM.PostManager.PostParams.BIGIPUsername != aw.GTM.PostManager.PostParams.BIGIPUsername ||
			aw.LTM.PostManager.PostParams.BIGIPPassword != aw.GTM.PostManager.PostParams.BIGIPPassword {
			return true
		}
	}
	return false
}

// retryGTMWorker blocks on retryChan
// whenever it gets unblocked, retries failed declarations and polls for accepted tenant statuses
func (aw *AgentWorker) gtmWorker() {

	for rsConfigData := range aw.GTM.PostManager.postChan {
		// For the very first post after starting controller, need not wait to post
		if !aw.GTM.PostManager.firstPost && aw.GTM.PostManager.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3][GTM] Delaying post to BIG-IP for %v seconds ", aw.GTM.PostManager.AS3PostDelay)
			_ = <-time.After(time.Duration(aw.GTM.PostManager.AS3PostDelay) * time.Second)
		}

		// If there are no retries going on in parallel, acquiring lock will be straight forward.
		// Otherwise, we will wait for other workers to complete its current iteration
		aw.declUpdate.Lock()

		// Fetch the latest config from channel
		rsConfig := ResourceConfigRequest{}
		select {
		case rsConfigData = <-aw.GTM.PostManager.postChan:
			rsConfig, err := aw.GTM.APIHandler.getResourceConfigRequest(rsConfigData)
			if err != nil {
				log.Errorf("Error getting resource config request: %v", err)
				continue
			}
			log.Infof("%v[AS3] Processing request", getRequestPrefix(rsConfig.reqId))
		case <-time.After(1 * time.Microsecond):
		}
		adc := as3ADC{}
		aw.GTM.PostManager.incomingTenantDeclMap = make(map[string]as3Tenant)
		log.Infof("%v[AS3] creating a new AS3 manifest", getRequestPrefix(rsConfig.reqId))
		for tenant, cfg := range aw.Agent.createGTMConfigADC(rsConfig, adc) {
			if !reflect.DeepEqual(cfg, aw.GTM.PostManager.cachedTenantDeclMap[tenant]) {
				aw.GTM.PostManager.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
			} else {
				// cachedTenantDeclMap always holds the current configuration on BigIP(lets say A)
				// When an invalid configuration(B) is reverted (to initial A) (i.e., config state A -> B -> A),
				// delete entry from retryTenantDeclMap if any
				delete(aw.GTM.PostManager.retryTenantDeclMap, tenant)
			}
		}

		if len(aw.GTM.PostManager.incomingTenantDeclMap) == 0 {
			log.Infof("%v[AS3] No tenants found in request", getRequestPrefix(rsConfig.reqId))
			aw.declUpdate.Unlock()
			continue
		}

		aw.GTM.PostManager.tenantResponseMap = make(map[string]tenantResponse)

		for tenant := range aw.GTM.PostManager.incomingTenantDeclMap {
			// CIS with AS3 doesn't allow to write to Common partition.So objects in common partition
			// should not be updated or deleted by CIS. So removing from tenant map
			if tenant != "Common" {
				aw.GTM.PostManager.tenantResponseMap[tenant] = tenantResponse{}
			}
		}

		cfg := agentConfig{
			data:      string(aw.GTM.APIHandler.createAPIDeclaration(aw.GTM.PostManager.incomingTenantDeclMap, aw.userAgent)),
			as3APIURL: aw.GTM.APIHandler.getAPIURL([]string{aw.GTM.Partition}),
			id:        0,
		}

		aw.GTM.publishConfig(cfg)

		aw.GTM.PostManager.updateTenantResponseMap(true)

		if len(aw.GTM.PostManager.retryTenantDeclMap) > 0 {
			// Activate retry
			select {
			case aw.GTM.PostManager.retryChan <- struct{}{}:
			case <-aw.GTM.PostManager.retryChan:
				aw.GTM.PostManager.retryChan <- struct{}{}
			}
		}

		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		aw.GTM.pollTenantStatus(true)

		// release the lock
		aw.declUpdate.Unlock()

	}
}

//func (agent *Agent) retryGTMWorker() {
//
//	/*
//		retryGTMWorker runs as a goroutine. It is idle until an arrives at GTM retryChan.
//		retryTenantDeclMal holds all information about tenant adc configuration and response codes.
//
//		Once GTM retryChan is signalled, retryGTMWorker posts tenant declarations and/or polls for accepted tenants' statuses continuously until it succeeds
//		Locks are used to block retries if an incoming request arrives at agentWorker.
//
//		For each iteration, retryGTMWorker tries to acquire agent.declUpdate lock.
//		During an ongoing agentWorker's activity, retryGTMWorker tries to wait until agent.declUpdate lock is acquired
//		Similarly, during an ongoing retry, agentWorker waits for graceful termination of ongoing iteration - i.e., until agent.declUpdate is unlocked
//
//	*/
//
//	for range agent.GTMPostManager.retryChan {
//
//		for len(agent.GTMPostManager.retryTenantDeclMap) != 0 {
//			// Ignoring timeouts for custom errors
//			log.Debugf("[AS3][GTM] Posting failed tenants configuration in %v seconds", timeoutMedium)
//			<-time.After(timeoutMedium)
//
//			agent.declUpdate.Lock()
//
//			// If we had a delay in acquiring lock, re-check if we have any tenants to be retried
//			if len(agent.GTMPostManager.retryTenantDeclMap) == 0 {
//				agent.declUpdate.Unlock()
//				break
//			}
//
//			//If there are any 201 tenants, poll for its statusma
//			agent.GTMPostManager.pollTenantStatus(false)
//
//			//If there are any failed tenants, retry posting them
//			agent.GTMPostManager.retryFailedTenant(agent.userAgent)
//
//			agent.declUpdate.Unlock()
//		}
//	}
//}

func isGTMOnSeparateServer(params AgentParams) bool {
	var isGTMOnSeparateServer bool
	if !params.CCCLGTMAgent && len(params.GTMParams.BIGIPURL) != 0 && len(params.GTMParams.BIGIPUsername) != 0 && len(params.GTMParams.BIGIPPassword) != 0 {
		// Check if GTM parameter is different then LTM parameter
		if params.PrimaryParams.BIGIPURL != params.GTMParams.BIGIPURL || params.PrimaryParams.BIGIPUsername != params.GTMParams.BIGIPUsername || params.PrimaryParams.BIGIPPassword != params.GTMParams.BIGIPPassword {
			isGTMOnSeparateServer = true
		}
	}
	return isGTMOnSeparateServer
}
