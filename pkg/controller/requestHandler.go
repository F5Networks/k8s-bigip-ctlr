package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"time"
)

func NewRequestHandler(agentParams AgentParams) *RequestHandler {
	reqHandler := &RequestHandler{
		reqChan:      make(chan ResourceConfigRequest, 1),
		userAgent:    agentParams.UserAgent,
		AgentWorkers: NewAgentWorkersMap(agentParams),
	}
	return reqHandler
}

func (req *RequestHandler) startRequestHandler() {
	log.Debug("Starting requestHandler")
	// requestHandler runs as a separate go routine
	// blocks on reqChan to get new/updated configuration to be posted to BIG-IP
	go req.requestHandler()
}

// - PostManager: Manages HTTP POST operations to BIG-IP, handles tenant responses and retries
// - AS3Handler: Handles AS3 declarations and configurations for BIG-IP
// - APIHandler: Interface for different API types (AS3, etc)
// - RequestHandler: Processes and routes configuration requests to appropriate agents
// - BigIpConfig: Contains BIG-IP connection details like address, label and partition
// - Agent: Manages BIG-IP configurations and events
// - AgentWorker: Wraps Agent with additional worker functionality

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

func (req *RequestHandler) requestHandler() {
	for rsConfig := range req.reqChan {
		worker := req.AgentWorkers[PrimaryBigIP]

		// Post GTM config if enabled for either mode
		if worker.ccclGTMAgent || worker.isGTMOnSeparateServer() {
			worker.PostGTMConfig(rsConfig)
		}

		// Post LTM config based on HA mode
		if req.HAMode {
			req.AgentWorkers[PrimaryBigIP].PostLTMConfig(rsConfig)
			req.AgentWorkers[SecondaryBigIP].PostLTMConfig(rsConfig)
		} else {
			worker.PostLTMConfig(rsConfig)
		}
	}
}
