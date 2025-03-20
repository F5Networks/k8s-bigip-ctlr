package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
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

	for agentConfig := range aw.GTM.PostManager.postChan {
		// For the very first post after starting controller, need not wait to post
		if !aw.GTM.PostManager.firstPost && aw.GTM.PostManager.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3]%v Delaying post to BIG-IP for %v seconds ", aw.postManagerPrefix, aw.GTM.PostManager.AS3PostDelay)
			_ = <-time.After(time.Duration(aw.GTM.PostManager.AS3PostDelay) * time.Second)
		}

		if len(agentConfig.incomingTenantDeclMap) == 0 {
			log.Infof("%v[AS3]%v No tenants found in request", getRequestPrefix(agentConfig.id), aw.postManagerPrefix)
			continue
		}

		aw.GTM.publishConfig(&agentConfig)
		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		aw.GTM.APIHandler.pollTenantStatus(&agentConfig)

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
