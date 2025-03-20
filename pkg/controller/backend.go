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
	"strconv"
	"strings"
	"time"

	rsc "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

var DEFAULT_PARTITION string
var DEFAULT_GTM_PARTITION string

func (aw AgentWorker) Post(agentConfig *agentPostConfig) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above
	select {
	case aw.postChan <- agentConfig:
	case <-aw.postChan:
		aw.postChan <- agentConfig
	}

}

// function to the post the config to the respective bigip
func (aw *AgentWorker) PostConfig(rsConfigRequest ResourceConfigRequest) {
	log.Debugf("%v Posting ResourceConfigRequest: %+v\n", aw.postManagerPrefix, rsConfigRequest)
	var agentConfig agentPostConfig
	if aw.postManagerPrefix != gtmPostmanagerPrefix {
		// Convert ResourceConfigRequest to as3Config
		agentConfig = aw.LTM.APIHandler.createAPIConfig(rsConfigRequest)
		agentConfig.as3APIURL = aw.LTM.APIHandler.getAPIURL([]string{})
		if aw.postManagerPrefix == secondaryPostmanagerPrefix {
			agentConfig.agentKind = SecondaryBigIP
		} else {
			agentConfig.agentKind = PrimaryBigIP
		}
		// add gtm config to the cccl worker if ccclGTMAgent is true
		if aw.ccclGTMAgent {
			aw.PostGTMConfigWithCccl(rsConfigRequest)
		}
	} else {
		agentConfig = aw.GTM.APIHandler.createAPIConfig(rsConfigRequest)
		agentConfig.as3APIURL = aw.GTM.APIHandler.getAPIURL([]string{})
		agentConfig.agentKind = GTMBigIP
	}
	aw.Post(&agentConfig)
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
			// notify resourceStatusUpdate response handler on successful tenant update
			aw.respChan <- agentConfig
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
		aw.LTM.publishConfig(agentConfig)
		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		aw.LTM.APIHandler.pollTenantStatus(agentConfig)
		// notify resourceStatusUpdate response handler on successful tenant update
		aw.respChan <- agentConfig
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

func (agent *Agent) PostGTMConfigWithCccl(config ResourceConfigRequest) {

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

// Extract virtual address and port from host URL
func extractVirtualAddressAndPort(str string) (string, int) {

	destination := strings.Split(str, "/")
	ipPort := strings.Split(destination[len(destination)-1], ":")
	if len(ipPort) != 2 {
		ipPort = strings.Split(destination[len(destination)-1], ".")
	}
	// verify that ip address and port exists else log error.
	if len(ipPort) == 2 {
		port, _ := strconv.Atoi(ipPort[1])
		return ipPort[0], port
	} else {
		log.Error("Invalid Virtual Server Destination IP address/Port.")
		return "", 0
	}

}
