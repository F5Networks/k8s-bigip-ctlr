package controller

import (
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

// whenever it gets unblocked, retries failed declarations and polls for accepted tenant statuses
func (agent *Agent) gtmWorker() {

	for agentConfig := range agent.GTM.PostManager.postChan {
		// For the very first post after starting controller, need not wait to post
		if !agent.GTM.PostManager.firstPost && agent.GTM.PostManager.PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[%v]%v Delaying post to BIG-IP for %v seconds ", agent.getAPIType(), agent.GTM.postManagerPrefix, agent.GTM.PostManager.PostDelay)
			_ = <-time.After(time.Duration(agent.GTM.PostManager.PostDelay) * time.Second)
		}

		if len(agentConfig.incomingTenantDeclMap) == 0 {
			log.Infof("%v[%v]%v No tenants found in request", agent.getAPIType(), getRequestPrefix(agentConfig.reqMeta.id), agent.GTM.postManagerPrefix)
			continue
		}
		// this post manager lock prevents that tenant cache map is not read by other components
		// while this post manager is processing this request
		agent.GTM.PostManager.declUpdate.Lock()
		agent.GTM.postConfig(agentConfig)
		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		agent.GTM.APIHandler.pollTenantStatus(agentConfig)

		// update the tenant cache
		agent.GTM.APIHandler.getApiHandler().updateTenantCache(agentConfig)
		// unlock the PostManager lock after updating tenant cache
		agent.GTM.PostManager.declUpdate.Unlock()
		// notify resourceStatusUpdate response handler on successful tenant update
		agent.GTM.respChan <- agentConfig
	}
}

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
