package controller

import (
	"os"
	"strings"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
)

var OsExit = os.Exit

func (ctlr *Controller) NewRequestHandler(agentParams AgentParams, baseAPIHandler *BaseAPIHandler) *RequestHandler {
	var refreshTokenInterval time.Duration
	if agentParams.RefreshTokenInterval != 0 {
		refreshTokenInterval = time.Duration(agentParams.RefreshTokenInterval) * time.Hour
	} else {
		refreshTokenInterval = 10 * time.Hour
	}
	reqHandler := &RequestHandler{
		reqChan:                         make(chan ResourceConfigRequest, 1),
		respChan:                        ctlr.respChan,
		agentParams:                     agentParams,
		PrimaryClusterHealthProbeParams: ctlr.multiClusterHandler.PrimaryClusterHealthProbeParams,
	}
	gtmOnSeparateBigIPServer := isGTMOnSeparateServer(agentParams)
	if (agentParams.PrimaryParams != PostParams{}) {
		reqHandler.PrimaryBigIPWorker = reqHandler.NewAgentWorker(PrimaryBigIP, gtmOnSeparateBigIPServer, baseAPIHandler)
		reqHandler.CcclHandler(reqHandler.PrimaryBigIPWorker)
		// start the token manager
		go reqHandler.PrimaryBigIPWorker.getPostManager().TokenManagerInterface.Start(make(chan struct{}), refreshTokenInterval)
		// start the worker
		go reqHandler.PrimaryBigIPWorker.agentWorker()
	}
	if (agentParams.SecondaryParams != PostParams{}) {
		reqHandler.SecondaryBigIPWorker = reqHandler.NewAgentWorker(SecondaryBigIP, gtmOnSeparateBigIPServer, baseAPIHandler)
		reqHandler.CcclHandler(reqHandler.SecondaryBigIPWorker)
		// start the token manager
		go reqHandler.SecondaryBigIPWorker.getPostManager().TokenManagerInterface.Start(make(chan struct{}), refreshTokenInterval)
		// start the worker
		go reqHandler.SecondaryBigIPWorker.agentWorker()
	}
	// Run the GTM Agent only in case of separate server and not in cccl mode
	if gtmOnSeparateBigIPServer && !agentParams.CCCLGTMAgent {
		reqHandler.GTMBigIPWorker = reqHandler.NewAgentWorker(GTMBigIP, gtmOnSeparateBigIPServer, baseAPIHandler)
		// start the token manager
		go reqHandler.GTMBigIPWorker.getPostManager().TokenManagerInterface.Start(make(chan struct{}), refreshTokenInterval)
		// start the worker
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
	select {
	case reqHandler.reqChan <- rsConfig:
		// Sent successfully
	default:
	// Channel full: remove the old value, then send new one
	case <-reqHandler.reqChan:
		reqHandler.reqChan <- rsConfig
	}
}

func (reqHandler *RequestHandler) requestHandler() {
	log.Debug("Starting requestHandler")
	for rsConfig := range reqHandler.reqChan {

		// If CIS is running in non multi-cluster mode or the Primary CIS status is changed
		if reqHandler.PrimaryClusterHealthProbeParams.EndPoint == "" || (reqHandler.PrimaryClusterHealthProbeParams.EndPoint != "" && reqHandler.PrimaryClusterHealthProbeParams.statusChanged) {
			// Post LTM config based on HA mode
			if reqHandler.HAMode && reqHandler.SecondaryBigIPWorker != nil {
				log.Debugf("%s%s enqueuing request", getRequestPrefix(rsConfig.reqMeta.id), primaryPostmanagerPrefix)
				reqHandler.PrimaryBigIPWorker.PostConfig(rsConfig)
				log.Debugf("%s%s enqueuing request", getRequestPrefix(rsConfig.reqMeta.id), secondaryPostmanagerPrefix)
				reqHandler.SecondaryBigIPWorker.PostConfig(rsConfig)
			} else {
				log.Debugf("%s%s enqueuing request", getRequestPrefix(rsConfig.reqMeta.id), defaultPostmanagerPrefix)
				reqHandler.PrimaryBigIPWorker.PostConfig(rsConfig)
			}
			// post to the GTM server if it's on a separate server
			if reqHandler.GTMBigIPWorker != nil {
				log.Debugf("%s%s enqueuing request", getRequestPrefix(rsConfig.reqMeta.id), gtmPostmanagerPrefix)
				reqHandler.GTMBigIPWorker.PostConfig(rsConfig)
			}
		} else {
			// Log only when it's primary/standalone CIS or when it's secondary CIS and primary CIS is down
			if !reqHandler.PrimaryClusterHealthProbeParams.statusRunning {
				log.Debugf("%s No change in request", getRequestPrefix(rsConfig.reqMeta.id))
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

	var gtmBigIPUsername, gtmBigIPPassword string
	bs := bigIPSection{
		BigIPURL:        agent.APIHandler.LTM.PostManager.BIGIPURL,
		BigIPPartitions: []string{reqHandler.agentParams.Partition},
	}

	var gtm gtmBigIPSection
	if reqHandler.agentParams.CCCLGTMAgent {
		if len(reqHandler.agentParams.GTMParams.BIGIPURL) == 0 || len(reqHandler.agentParams.GTMParams.BIGIPUsername) == 0 || len(reqHandler.agentParams.GTMParams.BIGIPPassword) == 0 {
			// gs.GTM = false
			gtm = gtmBigIPSection{
				GtmBigIPURL: agent.APIHandler.LTM.PostManager.BIGIPURL,
			}
			gtmBigIPUsername = agent.APIHandler.LTM.PostManager.BIGIPUsername
			gtmBigIPPassword = agent.APIHandler.LTM.PostManager.BIGIPPassword
			log.Warning("Creating GTM with default bigip credentials as GTM BIGIP Url or GTM BIGIP Username or GTM BIGIP Password is missing on CIS args.")
		} else {
			gtm = gtmBigIPSection{

				GtmBigIPURL: reqHandler.agentParams.GTMParams.BIGIPURL,
			}
			gtmBigIPUsername = reqHandler.agentParams.GTMParams.BIGIPUsername
			gtmBigIPPassword = reqHandler.agentParams.GTMParams.BIGIPPassword
		}
	}
	//For IPV6 net config is not required. f5-sdk doesnt support ipv6
	if !(reqHandler.agentParams.EnableIPV6) {
		agent.startPythonDriver(
			gs,
			bs,
			gtm,
			agent.APIHandler.LTM.PostManager.BIGIPUsername,
			agent.APIHandler.LTM.PostManager.BIGIPPassword,
			gtmBigIPUsername,
			gtmBigIPPassword,
			reqHandler.agentParams.PythonBaseDir,
		)
	} else {
		// we only enable metrics as pythondriver is not initialized for ipv6
		go agent.enableMetrics()
	}
}

func (reqHandler *RequestHandler) NewAgentWorker(kind string, gtmOnSeparateBigIpServer bool, baseAPIHandler *BaseAPIHandler) *Agent {
	var err error
	var agent *Agent
	switch kind {
	case GTMBigIP:
		agent = reqHandler.NewAgent(GTMBigIP, baseAPIHandler)
		err = agent.GTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			agent.Stop()
			OsExit(1)
		}
	case SecondaryBigIP:
		agent = reqHandler.NewAgent(SecondaryBigIP, baseAPIHandler)
		err = agent.LTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			agent.Stop()
			OsExit(1)
		}
	case PrimaryBigIP:
		agent = reqHandler.NewAgent(PrimaryBigIP, baseAPIHandler)
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
	// setting gtmOnSeparateServer helps avoid GTM declaration getting posted to BigIP handling LTM in scenarios where
	// LTM and GTM are handled by different BigIPs
	agent.gtmOnSeparateServer = gtmOnSeparateBigIpServer
	return agent
}

func (reqHandler *RequestHandler) NewAgent(kind string, baseAPIHandler *BaseAPIHandler) *Agent {
	agent := &Agent{
		APIHandler:   &APIHandler{},
		ccclGTMAgent: reqHandler.agentParams.CCCLGTMAgent,
		StopChan:     make(chan struct{}),
		userAgent:    reqHandler.agentParams.UserAgent,
	}
	switch kind {
	case GTMBigIP:
		DEFAULT_GTM_PARTITION = reqHandler.agentParams.Partition + "_gtm"
		agent.APIHandler.GTM = NewGTMAPIHandler(reqHandler.agentParams, baseAPIHandler, reqHandler.respChan)
	default:
		DEFAULT_PARTITION = reqHandler.agentParams.Partition
		DEFAULT_GTM_PARTITION = reqHandler.agentParams.Partition + "_gtm"
		agent.APIHandler.LTM = NewLTMAPIHandler(reqHandler.agentParams, kind, baseAPIHandler, reqHandler.respChan)
	}
	return agent
}
