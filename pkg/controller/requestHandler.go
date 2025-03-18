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
		reqChan:     make(chan ResourceConfigRequest, 1),
		userAgent:   agentParams.UserAgent,
		respChan:    ctlr.respChan,
		agentParams: agentParams,
	}
	if (agentParams.PrimaryParams != PostParams{}) {
		reqHandler.PrimaryBigIPWorker = reqHandler.NewAgentWorker(PrimaryBigIP, nil)
	}
	if (agentParams.SecondaryParams != PostParams{}) {
		reqHandler.SecondaryBigIPWorker = reqHandler.NewAgentWorker(SecondaryBigIP, nil)
		go reqHandler.SecondaryBigIPWorker.agentWorker()
	}
	if isGTMOnSeparateServer(agentParams) && !agentParams.CCCLGTMAgent {
		reqHandler.GTMBigIPWorker = reqHandler.NewAgentWorker(GTMBigIP, nil)
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
	log.Debug("Starting requestHandler")
	for rsConfig := range req.reqChan {

		if req.GTMBigIPWorker != nil {
			req.GTMBigIPWorker.PostConfig(rsConfig)
		}

		// Post LTM config based on HA mode
		if req.HAMode {
			req.SecondaryBigIPWorker.PostConfig(rsConfig)
			req.SecondaryBigIPWorker.PostConfig(rsConfig)
		} else {
			req.PrimaryBigIPWorker.PostConfig(rsConfig)
		}
	}
}

func (req *RequestHandler) NewAgentWorker(kind string, appServicesChecker func() error) *AgentWorker {
	aw := &AgentWorker{
		stopChan: make(chan struct{}),
	}
	var err error
	switch kind {
	case GTMBigIP:
		aw.Agent = req.NewAgent(GTMBigIP)
		if appServicesChecker == nil {
			err = aw.GTM.IsBigIPAppServicesAvailable()
		} else {
			err = appServicesChecker()
		}
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			OsExit(1)
		}
	case SecondaryBigIP:
		aw.Agent = req.NewAgent(SecondaryBigIP)
		if appServicesChecker == nil {
			err = aw.LTM.IsBigIPAppServicesAvailable()
		} else {
			err = appServicesChecker()
		}
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			OsExit(1)
		}
	case PrimaryBigIP:
		aw.Agent = req.NewAgent(PrimaryBigIP)
		if appServicesChecker == nil {
			err = aw.LTM.IsBigIPAppServicesAvailable()
		} else {
			err = appServicesChecker()
		}
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			OsExit(1)
		}
		go aw.agentWorker()
	default:
		log.Errorf("Invalid Agent kind: %s", kind)
		OsExit(1)
	}
	return aw
}

// Stop stops the AgentWorker.
func (aw *AgentWorker) Stop() {
	close(aw.StopChan)
}

func (req *RequestHandler) NewAgent(kind string) *Agent {
	agent := &Agent{
		APIHandler:   &APIHandler{},
		ccclGTMAgent: req.agentParams.CCCLGTMAgent,
	}
	switch kind {
	case GTMBigIP:
		DEFAULT_GTM_PARTITION = req.agentParams.Partition + "_gtm"
		agent.APIHandler.GTM = NewGTMAPIHandler(req.agentParams, req.respChan)
	default:
		DEFAULT_PARTITION = req.agentParams.Partition
		agent.APIHandler.LTM = NewLTMAPIHandler(req.agentParams, kind, req.respChan)
		agent.Partition = req.agentParams.Partition
		configWriter, err := writer.NewConfigWriter()
		if nil != err {
			log.Fatalf("Failed creating ConfigWriter tool: %v", err)
		}
		agent.ConfigWriter = configWriter
		agent.EventChan = make(chan interface{})
		agent.userAgent = req.agentParams.UserAgent
		agent.HttpAddress = req.agentParams.HttpAddress
		agent.disableARP = req.agentParams.DisableARP

		// If running in VXLAN mode, extract the partition name from the tunnel
		// to be used in configuring a net instance of CCCL for that partition
		var vxlanPartition string
		if len(req.agentParams.VXLANName) > 0 {
			cleanPath := strings.TrimLeft(req.agentParams.VXLANName, "/")
			slashPos := strings.Index(cleanPath, "/")
			if slashPos == -1 {
				// No partition
				vxlanPartition = "Common"
			} else {
				// Partition and name
				vxlanPartition = cleanPath[:slashPos]
			}
		}
		if req.agentParams.StaticRoutingMode == true {
			vxlanPartition = req.agentParams.Partition
			if req.agentParams.SharedStaticRoutes == true {
				vxlanPartition = "Common"
			}
		}
		gs := globalSection{
			LogLevel:          req.agentParams.LogLevel,
			VerifyInterval:    req.agentParams.VerifyInterval,
			VXLANPartition:    vxlanPartition,
			DisableLTM:        true,
			GTM:               req.agentParams.CCCLGTMAgent,
			DisableARP:        req.agentParams.DisableARP,
			StaticRoutingMode: req.agentParams.StaticRoutingMode,
			MultiClusterMode:  req.agentParams.MultiClusterMode,
		}

		// If AS3DEBUG is set, set log level to DEBUG
		if gs.LogLevel == "AS3DEBUG" {
			gs.LogLevel = "DEBUG"
		}

		bs := bigIPSection{
			BigIPUsername:   agent.APIHandler.LTM.PostManager.BIGIPUsername,
			BigIPPassword:   agent.APIHandler.LTM.PostManager.BIGIPPassword,
			BigIPURL:        agent.APIHandler.LTM.PostManager.BIGIPURL,
			BigIPPartitions: []string{req.agentParams.Partition},
		}

		var gtm gtmBigIPSection
		if len(req.agentParams.GTMParams.BIGIPURL) == 0 || len(req.agentParams.GTMParams.BIGIPUsername) == 0 || len(req.agentParams.GTMParams.BIGIPPassword) == 0 {
			// gs.GTM = false
			gtm = gtmBigIPSection{
				GtmBigIPUsername: agent.APIHandler.LTM.PostManager.BIGIPUsername,
				GtmBigIPPassword: agent.APIHandler.LTM.PostManager.BIGIPPassword,
				GtmBigIPURL:      agent.APIHandler.LTM.PostManager.BIGIPURL,
			}
			log.Warning("Creating GTM with default bigip credentials as GTM BIGIP Url or GTM BIGIP Username or GTM BIGIP Password is missing on CIS args.")
		} else {
			gtm = gtmBigIPSection{
				GtmBigIPUsername: req.agentParams.GTMParams.BIGIPUsername,
				GtmBigIPPassword: req.agentParams.GTMParams.BIGIPPassword,
				GtmBigIPURL:      req.agentParams.GTMParams.BIGIPURL,
			}
		}
		//For IPV6 net config is not required. f5-sdk doesnt support ipv6
		if !(req.agentParams.EnableIPV6) {
			agent.startPythonDriver(
				gs,
				bs,
				gtm,
				req.agentParams.PythonBaseDir,
			)
		} else {
			// we only enable metrics as pythondriver is not initialized for ipv6
			go agent.enableMetrics()
		}
	}
	return agent
}
