/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controller

import (
	"fmt"
	"os"
	"strings"
	"time"

	rsc "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
)

// const (
//
//	as3SharedApplication = "Shared"
//	gtmPartition         = "Common"
//
// )
var DEFAULT_PARTITION string
var DEFAULT_GTM_PARTITION string

func NewAgentWorker(params AgentParams, kind string) *AgentWorker {
	aw := &AgentWorker{
		stopChan: make(chan struct{}),
	}
	var err error
	switch kind {
	case GTMBigIP:
		aw.Agent = NewAgent(params, GTMBigIP)
		err = aw.GTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			os.Exit(1)
		}
		go aw.gtmWorker()
	case SecondaryBigIP:
		aw.Agent = NewAgent(params, SecondaryBigIP)
		err = aw.LTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			os.Exit(1)
		}
		go aw.agentWorker()
	case PrimaryBigIP:
		aw.Agent = NewAgent(params, PrimaryBigIP)
		err = aw.LTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			os.Exit(1)
		}
		go aw.agentWorker()
	default:
		log.Errorf("Invalid Agent kind: %s", kind)
		os.Exit(1)
	}
	return aw
}

func NewAgentWorkersMap(params AgentParams) map[string]*AgentWorker {
	// Create workers based on configured BIG-IPs
	workers := make(map[string]*AgentWorker)
	if (params.PrimaryParams != PostParams{}) {
		workers[PrimaryBigIP] = NewAgentWorker(params, PrimaryBigIP)
	}
	if (params.SecondaryParams != PostParams{}) {
		workers[SecondaryBigIP] = NewAgentWorker(params, SecondaryBigIP)
	}
	if isGTMOnSeparateServer(params) && !params.CCCLGTMAgent {
		workers[GTMBigIP] = NewAgentWorker(params, GTMBigIP)
	}
	return workers
}

// Stop stops the AgentWorker.
func (aw *AgentWorker) Stop() {
	close(aw.StopChan)
}

func (ps *PostToChannelStrategy) Post(agentConfig agentPostConfig) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above
	select {
	case ps.postChan <- agentConfig:
	case <-ps.postChan:
		ps.postChan <- agentConfig
	}

}

func (ps *PostToFileStrategy) Post(config ResourceConfigRequest) {

	dnsConfig := make(map[string]interface{})
	wideIPs := WideIPs{}

	for _, gtmPartitionConfig := range config.gtmConfig {
		for _, v := range gtmPartitionConfig.WideIPs {
			wideIPs.WideIPs = append(wideIPs.WideIPs, v)
		}
	}
	deletedTenants := []string{}
	activeTenants := []string{}
	for tenant, partitionConfig := range config.ltmConfig {
		if len(partitionConfig.ResourceMap) == 0 {
			deletedTenants = append(deletedTenants, tenant)
		} else {
			activeTenants = append(activeTenants, tenant)
		}
	}
	dnsConfig["deletedTenants"] = deletedTenants
	dnsConfig["activeTenants"] = activeTenants
	wideIpConfig := make(map[string]interface{})
	wideIpConfig["Common"] = wideIPs
	dnsConfig["config"] = wideIpConfig
	doneCh, errCh, err := ps.ConfigWriter.SendSection("gtm", dnsConfig)

	if nil != err {
		log.Warningf("Failed to write gtm config section: %v", err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("Wrote gtm config section: %v", config.gtmConfig)
		case e := <-errCh:
			log.Warningf("Failed to write gtm config section: %v", e)
		case <-time.After(time.Second):
			log.Warningf("Did not receive write response in 1s")
		}
	}
}

// function to the post the config to the respective bigip
func (aw *AgentWorker) PostConfig(config Configurable) {
	switch v := config.(type) {
	case agentPostConfig:
		fmt.Println("Posting As3Config:", v.data)
		aw.PostStrategy.Post(v)
	case ResourceConfigRequest:
		fmt.Printf("Posting ResourceConfigRequest: %+v\n", v)
		var agentConfig agentPostConfig
		if aw.postManagerPrefix != gtmPostmanagerPrefix {
			// Convert ResourceConfigRequest to as3Config
			agentConfig = aw.LTM.APIHandler.createAPIConfig(v)
			agentConfig.as3APIURL = aw.LTM.APIHandler.getAPIURL([]string{})
			// add gtm config to the cccl worker if ccclGTMAgent is true
			if aw.ccclGTMAgent {
				aw.PostGTMConfig(v)
			}
		} else {
			agentConfig = aw.GTM.APIHandler.createAPIConfig(v)
			agentConfig.as3APIURL = aw.GTM.APIHandler.getAPIURL([]string{})
		}
		aw.PostStrategy.Post(agentConfig)
	default:
		fmt.Println("Unknown config type, cannot post to channel")
	}
}

func NewAgent(params AgentParams, kind string) *Agent {
	agent := &Agent{
		APIHandler:   &APIHandler{},
		ccclGTMAgent: params.CCCLGTMAgent,
		respChan:     make(chan *agentPostConfig),
	}
	switch kind {
	case GTMBigIP:
		DEFAULT_GTM_PARTITION = params.Partition + "_gtm"
		agent.APIHandler.GTM = NewGTMAPIHandler(params)
	default:
		DEFAULT_PARTITION = params.Partition
		agent.APIHandler.LTM = NewLTMAPIHandler(params, kind)
		agent.Partition = params.Partition
		configWriter, err := writer.NewConfigWriter()
		if nil != err {
			log.Fatalf("Failed creating ConfigWriter tool: %v", err)
		}
		agent.ConfigWriter = configWriter
		agent.EventChan = make(chan interface{})
		agent.userAgent = params.UserAgent
		agent.HttpAddress = params.HttpAddress
		agent.disableARP = params.DisableARP

		// If running in VXLAN mode, extract the partition name from the tunnel
		// to be used in configuring a net instance of CCCL for that partition
		var vxlanPartition string
		if len(params.VXLANName) > 0 {
			cleanPath := strings.TrimLeft(params.VXLANName, "/")
			slashPos := strings.Index(cleanPath, "/")
			if slashPos == -1 {
				// No partition
				vxlanPartition = "Common"
			} else {
				// Partition and name
				vxlanPartition = cleanPath[:slashPos]
			}
		}
		if params.StaticRoutingMode == true {
			vxlanPartition = params.Partition
			if params.SharedStaticRoutes == true {
				vxlanPartition = "Common"
			}
		}
		gs := globalSection{
			LogLevel:          params.LogLevel,
			VerifyInterval:    params.VerifyInterval,
			VXLANPartition:    vxlanPartition,
			DisableLTM:        true,
			GTM:               params.CCCLGTMAgent,
			DisableARP:        params.DisableARP,
			StaticRoutingMode: params.StaticRoutingMode,
			MultiClusterMode:  params.MultiClusterMode,
		}

		// If AS3DEBUG is set, set log level to DEBUG
		if gs.LogLevel == "AS3DEBUG" {
			gs.LogLevel = "DEBUG"
		}

		bs := bigIPSection{
			BigIPUsername:   agent.APIHandler.LTM.PostManager.BIGIPUsername,
			BigIPPassword:   agent.APIHandler.LTM.PostManager.BIGIPPassword,
			BigIPURL:        agent.APIHandler.LTM.PostManager.BIGIPURL,
			BigIPPartitions: []string{params.Partition},
		}

		var gtm gtmBigIPSection
		if len(params.GTMParams.BIGIPURL) == 0 || len(params.GTMParams.BIGIPUsername) == 0 || len(params.GTMParams.BIGIPPassword) == 0 {
			// gs.GTM = false
			gtm = gtmBigIPSection{
				GtmBigIPUsername: agent.APIHandler.LTM.PostManager.BIGIPUsername,
				GtmBigIPPassword: agent.APIHandler.LTM.PostManager.BIGIPPassword,
				GtmBigIPURL:      agent.APIHandler.LTM.PostManager.BIGIPURL,
			}
			log.Warning("Creating GTM with default bigip credentials as GTM BIGIP Url or GTM BIGIP Username or GTM BIGIP Password is missing on CIS args.")
		} else {
			gtm = gtmBigIPSection{
				GtmBigIPUsername: params.GTMParams.BIGIPUsername,
				GtmBigIPPassword: params.GTMParams.BIGIPPassword,
				GtmBigIPURL:      params.GTMParams.BIGIPURL,
			}
		}
		//For IPV6 net config is not required. f5-sdk doesnt support ipv6
		if !(params.EnableIPV6) {
			agent.startPythonDriver(
				gs,
				bs,
				gtm,
				params.PythonBaseDir,
			)
		} else {
			// we only enable metrics as pythondriver is not initialized for ipv6
			go agent.enableMetrics()
		}
	}
	return agent
}

func (agent *Agent) Stop() {
	agent.ConfigWriter.Stop()
	if !(agent.EnableIPV6) {
		agent.stopPythonDriver()
	}
}

// whenever it gets unblocked, it creates an as3 declaration for modified tenants and posts the request
func (aw *AgentWorker) agentWorker() {
	for agentConfig := range aw.LTM.PostManager.postChan {
		// For the very first post after starting controller, need not wait to post
		if !aw.LTM.PostManager.firstPost && aw.LTM.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", aw.LTM.AS3PostDelay)
			_ = <-time.After(time.Duration(aw.LTM.AS3PostDelay) * time.Second)
		}

		// Fetch the latest config from channel
		select {
		case agentConfig = <-aw.LTM.PostManager.postChan:

			log.Infof("%v[AS3] Processing request", getRequestPrefix(agentConfig.id))

		case <-time.After(1 * time.Microsecond):
		}

		log.Infof("%v[AS3] creating a new AS3 manifest", getRequestPrefix(agentConfig.id))

		if len(agentConfig.incomingTenantDeclMap) == 0 {
			log.Infof("%v[AS3] No tenants found in request", getRequestPrefix(agentConfig.id))
			// notify resourceStatusUpdate response handler for resourcestatus update
			aw.notifyRscStatusHandler(agentConfig.id, false)
			continue
		}

		if aw.HAMode {
			// if endPoint is not empty means, cis is running in secondary mode
			// check if the primary cis is up and running
			if aw.LTM.PrimaryClusterHealthProbeParams.EndPointType != "" {
				if aw.LTM.PrimaryClusterHealthProbeParams.statusRunning {
					// dont post the declaration
					continue
				} else {
					if aw.LTM.PrimaryClusterHealthProbeParams.statusChanged {
						aw.LTM.PrimaryClusterHealthProbeParams.paramLock.Lock()
						aw.LTM.PrimaryClusterHealthProbeParams.statusChanged = false
						aw.LTM.PrimaryClusterHealthProbeParams.paramLock.Unlock()
					}
				}
			}
		}
		aw.LTM.publishConfig(&agentConfig)
		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		aw.LTM.APIHandler.pollTenantStatus(&agentConfig)
	}
}

func (agent *Agent) notifyRscStatusHandler(id int, overwriteCfg bool) {
	rscUpdateMeta := resourceStatusMeta{
		id,
		make(map[string]tenantResponse),
	}

	agentPostConfig := agentPostConfig{
		reqStatusMeta: rscUpdateMeta,
	}

	//for tenant := range agent.LTM.retryTenantDeclMap {
	//	rscUpdateMeta.failedTenants[tenant] = agent.retryTenantDeclMap[tenant].tenantResponse
	//}
	// If triggerred from retry block, process the previous successful request completely
	if !overwriteCfg {
		agent.respChan <- &agentPostConfig
	} else {
		// Always push latest id to channel
		// Case1: Put latest id into the channel
		// Case2: If channel is blocked because of earlier id, pop out earlier id and push latest id
		// Either Case1 or Case2 executes, which ensures the above
		select {
		case agent.respChan <- &agentPostConfig:
		case <-agent.respChan:
			agent.respChan <- &agentPostConfig
		}
	}
}

func (agent *Agent) updateARPsForPoolMembers(rsConfig ResourceConfigRequest) {
	allPoolMembers := rsConfig.ltmConfig.GetAllPoolMembers()

	// Convert allPoolMembers to rsc.Members so that vxlan Manger accepts
	var allPoolMems []rsc.Member

	for _, poolMem := range allPoolMembers {
		if rsConfig.poolMemberType != Auto ||
			(rsConfig.poolMemberType == Auto && poolMem.MemberType != NodePort) {
			allPoolMems = append(
				allPoolMems,
				rsc.Member(poolMem),
			)
		}
	}
	if agent.EventChan != nil {
		select {
		case agent.EventChan <- allPoolMems:
			log.Debugf("Controller wrote endpoints to VxlanMgr")
		case <-time.After(3 * time.Second):
		}
	}
}

func (agent *Agent) PostGTMConfig(config ResourceConfigRequest) {

	dnsConfig := make(map[string]interface{})
	wideIPs := WideIPs{}

	for _, gtmPartitionConfig := range config.gtmConfig {
		for _, v := range gtmPartitionConfig.WideIPs {
			wideIPs.WideIPs = append(wideIPs.WideIPs, v)
		}
	}
	deletedTenants := []string{}
	activeTenants := []string{}
	for tenant, partitionConfig := range config.ltmConfig {
		if len(partitionConfig.ResourceMap) == 0 {
			deletedTenants = append(deletedTenants, tenant)
		} else {
			activeTenants = append(activeTenants, tenant)
		}
	}
	dnsConfig["deletedTenants"] = deletedTenants
	dnsConfig["activeTenants"] = activeTenants
	wideIpConfig := make(map[string]interface{})
	wideIpConfig["Common"] = wideIPs
	dnsConfig["config"] = wideIpConfig
	doneCh, errCh, err := agent.ConfigWriter.SendSection("gtm", dnsConfig)

	if nil != err {
		log.Warningf("Failed to write gtm config section: %v", err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("Wrote gtm config section: %v", config.gtmConfig)
		case e := <-errCh:
			log.Warningf("Failed to write gtm config section: %v", e)
		case <-time.After(time.Second):
			log.Warningf("Did not receive write response in 1s")
		}
	}
}

// addPersistenceMethod adds persistence methods in the service declaration
func (svc *as3Service) addPersistenceMethod(persistenceProfile string) {
	if len(persistenceProfile) == 0 {
		return
	}
	switch persistenceProfile {
	case "none":
		svc.PersistenceMethods = &[]as3MultiTypeParam{}
	case "cookie", "destination-address", "hash", "msrdp", "sip-info", "source-address", "tls-session-id", "universal":
		svc.PersistenceMethods = &[]as3MultiTypeParam{as3MultiTypeParam(persistenceProfile)}
	default:
		svc.PersistenceMethods = &[]as3MultiTypeParam{
			as3MultiTypeParam(
				as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", persistenceProfile),
				},
			),
		}
	}
}
