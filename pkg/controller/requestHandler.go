package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
	"os"
	"strings"
	"time"
)

var OsExit = os.Exit

func (ctlr *Controller) NewRequestHandler(agentParams AgentParams) *RequestHandler {
	reqHandler := &RequestHandler{
		reqChan:                         make(chan ResourceConfigRequest, 1),
		userAgent:                       agentParams.UserAgent,
		respChan:                        ctlr.respChan,
		agentParams:                     agentParams,
		PrimaryClusterHealthProbeParams: ctlr.multiClusterHandler.PrimaryClusterHealthProbeParams,
	}
	if (agentParams.PrimaryParams != PostParams{}) {
		reqHandler.PrimaryBigIPWorker = reqHandler.NewAgentWorker(PrimaryBigIP)
		reqHandler.CcclHandler(reqHandler.PrimaryBigIPWorker)
		go reqHandler.PrimaryBigIPWorker.agentWorker()
	}
	if (agentParams.SecondaryParams != PostParams{}) {
		reqHandler.SecondaryBigIPWorker = reqHandler.NewAgentWorker(SecondaryBigIP)
		reqHandler.CcclHandler(reqHandler.SecondaryBigIPWorker)
		go reqHandler.SecondaryBigIPWorker.agentWorker()
	}
	if isGTMOnSeparateServer(agentParams) && !agentParams.CCCLGTMAgent {
		reqHandler.GTMBigIPWorker = reqHandler.NewAgentWorker(GTMBigIP)
		go reqHandler.GTMBigIPWorker.gtmWorker()
	}
	return reqHandler
}

// - PostManager: Manages HTTP POST operations to BIG-IP, handles tenant responses and retries
// - AS3Handler: Handles AS3 declarations and configurations for BIG-IP
// - APIHandler: Interface for different API types (AS3, etc)
// - RequestHandler: Processes and routes configuration requests to appropriate agents
// - BigIpConfig: Contains BIG-IP connection details like address, label and partition
// - Agent: Manages BIG-IP configurations and events
// - AgentWorker: Wraps Agent with additional worker functionality

func (reqHandler *RequestHandler) EnqueueRequestConfig(rsConfig ResourceConfigRequest) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above

	select {
	case reqHandler.reqChan <- rsConfig:
	case <-time.After(3 * time.Millisecond):
	}
}

func (reqHandler *RequestHandler) requestHandler() {
	log.Debug("Starting requestHandler")
	for rsConfig := range reqHandler.reqChan {

		// If CIS is running in non multi-cluster mode or the Primary CIS status is changed
		if reqHandler.PrimaryClusterHealthProbeParams.EndPoint == "" || (reqHandler.PrimaryClusterHealthProbeParams.EndPoint != "" && reqHandler.PrimaryClusterHealthProbeParams.statusChanged) {
			// Post LTM config based on HA mode
			if reqHandler.HAMode {
				reqHandler.PrimaryBigIPWorker.PostConfig(rsConfig)
				reqHandler.SecondaryBigIPWorker.PostConfig(rsConfig)
			} else {
				reqHandler.PrimaryBigIPWorker.PostConfig(rsConfig)
			}
			// post to the GTM server if it's on a separate server
			if reqHandler.GTMBigIPWorker != nil {
				reqHandler.GTMBigIPWorker.PostConfig(rsConfig)
			}
		} else {
			// Log only when it's primary/standalone CIS or when it's secondary CIS and primary CIS is down
			if !reqHandler.PrimaryClusterHealthProbeParams.statusRunning {
				log.Debugf("[RequestHandler] No change in configuration")
			}
		}
	}
}

func (reqHandler *RequestHandler) CcclHandler(agent *Agent) {
	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
	}
	agent.ConfigWriter = configWriter
	agent.Partition = reqHandler.agentParams.Partition
	agent.EventChan = make(chan interface{})
	agent.userAgent = reqHandler.agentParams.UserAgent
	agent.HttpAddress = reqHandler.agentParams.HttpAddress
	agent.disableARP = reqHandler.agentParams.DisableARP

	// If running in VXLAN mode, extract the partition name from the tunnel
	// to be used in configuring a net instance of CCCL for that partition
	var vxlanPartition string
	if len(reqHandler.agentParams.VXLANName) > 0 {
		cleanPath := strings.TrimLeft(reqHandler.agentParams.VXLANName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos == -1 {
			// No partition
			vxlanPartition = "Common"
		} else {
			// Partition and name
			vxlanPartition = cleanPath[:slashPos]
		}
	}
	if reqHandler.agentParams.StaticRoutingMode == true {
		vxlanPartition = reqHandler.agentParams.Partition
		if reqHandler.agentParams.SharedStaticRoutes == true {
			vxlanPartition = "Common"
		}
	}
	gs := globalSection{
		LogLevel:          reqHandler.agentParams.LogLevel,
		VerifyInterval:    reqHandler.agentParams.VerifyInterval,
		VXLANPartition:    vxlanPartition,
		DisableLTM:        true,
		GTM:               reqHandler.agentParams.CCCLGTMAgent,
		DisableARP:        reqHandler.agentParams.DisableARP,
		StaticRoutingMode: reqHandler.agentParams.StaticRoutingMode,
		MultiClusterMode:  reqHandler.agentParams.MultiClusterMode,
	}

	// If AS3DEBUG is set, set log level to DEBUG
	if gs.LogLevel == "AS3DEBUG" {
		gs.LogLevel = "DEBUG"
	}

	bs := bigIPSection{
		BigIPUsername:   agent.APIHandler.LTM.PostManager.BIGIPUsername,
		BigIPPassword:   agent.APIHandler.LTM.PostManager.BIGIPPassword,
		BigIPURL:        agent.APIHandler.LTM.PostManager.BIGIPURL,
		BigIPPartitions: []string{reqHandler.agentParams.Partition},
	}

	var gtm gtmBigIPSection
	if len(reqHandler.agentParams.GTMParams.BIGIPURL) == 0 || len(reqHandler.agentParams.GTMParams.BIGIPUsername) == 0 || len(reqHandler.agentParams.GTMParams.BIGIPPassword) == 0 {
		// gs.GTM = false
		gtm = gtmBigIPSection{
			GtmBigIPUsername: agent.APIHandler.LTM.PostManager.BIGIPUsername,
			GtmBigIPPassword: agent.APIHandler.LTM.PostManager.BIGIPPassword,
			GtmBigIPURL:      agent.APIHandler.LTM.PostManager.BIGIPURL,
		}
		log.Warning("Creating GTM with default bigip credentials as GTM BIGIP Url or GTM BIGIP Username or GTM BIGIP Password is missing on CIS args.")
	} else {
		gtm = gtmBigIPSection{
			GtmBigIPUsername: reqHandler.agentParams.GTMParams.BIGIPUsername,
			GtmBigIPPassword: reqHandler.agentParams.GTMParams.BIGIPPassword,
			GtmBigIPURL:      reqHandler.agentParams.GTMParams.BIGIPURL,
		}
	}
	//For IPV6 net config is not required. f5-sdk doesnt support ipv6
	if !(reqHandler.agentParams.EnableIPV6) {
		agent.startPythonDriver(
			gs,
			bs,
			gtm,
			reqHandler.agentParams.PythonBaseDir,
		)
	} else {
		// we only enable metrics as pythondriver is not initialized for ipv6
		go agent.enableMetrics()
	}
}

func (reqHandler *RequestHandler) NewAgentWorker(kind string) *Agent {
	var err error
	var agent *Agent
	switch kind {
	case GTMBigIP:
		agent = reqHandler.NewAgent(GTMBigIP)
		err = agent.GTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			agent.Stop()
			OsExit(1)
		}
	case SecondaryBigIP:
		agent = reqHandler.NewAgent(SecondaryBigIP)
		err = agent.LTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			agent.Stop()
			OsExit(1)
		}
	case PrimaryBigIP:
		agent = reqHandler.NewAgent(PrimaryBigIP)
		err = agent.LTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			agent.Stop()
			OsExit(1)
		}
	default:
		log.Errorf("Invalid Agent kind: %s", kind)
		OsExit(1)
	}
	return agent
}

func (reqHandler *RequestHandler) NewAgent(kind string) *Agent {
	agent := &Agent{
		APIHandler:   &APIHandler{},
		ccclGTMAgent: reqHandler.agentParams.CCCLGTMAgent,
		stopChan:     make(chan struct{}),
	}
	switch kind {
	case GTMBigIP:
		DEFAULT_GTM_PARTITION = reqHandler.agentParams.Partition + "_gtm"
		agent.APIHandler.GTM = NewGTMAPIHandler(reqHandler.agentParams, reqHandler.respChan)
	default:
		DEFAULT_PARTITION = reqHandler.agentParams.Partition
		agent.APIHandler.LTM = NewLTMAPIHandler(reqHandler.agentParams, kind, reqHandler.respChan)
	}
	return agent
}
