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
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/writer"
	"os"
	"reflect"
	"strings"
	"time"
)

var DEFAULT_PARTITION string
var DEFAULT_GTM_PARTITION string

// RequestHandler blocks on reqChan
// whenever it gets unblocked, it creates an as3, l3 declaration for respective bigip and puts on post channel for postmanger to handle
func (agent *Agent) requestHandler() {
	for rsConfig := range agent.reqChan {
		// For the very first post after starting controller, need not wait to post
		if !agent.firstPost && agent.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", agent.AS3PostDelay)
			_ = <-time.After(time.Duration(agent.AS3PostDelay) * time.Second)
		}

		// Fetch the latest config from channel
		select {
		case rsConfig = <-agent.reqChan:
		case <-time.After(1 * time.Microsecond):
		}
		for bigip, bigipconfig := range rsConfig.bigIpConfigs {
			//create AS3 declaration for each bigip and put in post channel
			go agent.createAS3DeclarationForBIGIP(bigip, bigipconfig, rsConfig)
		}
	}
}

func (agent *Agent) createAS3DeclarationForBIGIP(bigip BigIP, bigipconfig BigIpConfig, rsConfig ResourceConfigRequest) {
	//for each bigip config create AS3, L3 declaration
	targetIPs := []string{bigip.bigIPddress}
	if bigip.haBigIPddress != "" {
		targetIPs = append(targetIPs, bigip.haBigIPddress)
	}
	for _, bigIPAddress := range targetIPs {
		// If there are no retries going on in parallel, acquiring lock will be straight forward.
		// Otherwise, we will wait for other workers to complete its current iteration
		// This lock is required because both requestHandler and retryWorker read and update
		// tenantResponseMap and retryTenantDeclMap to avoid concurrent read write of maps
		agent.declUpdate.Lock()
		decl := agent.createTenantAS3Declaration(bigipconfig, bigIPAddress)
		//check tenantDeclMap for bigip label
		if len(agent.incomingBIGIPTenantDeclMap) == 0 {
			//No need to put in post channel
			agent.declUpdate.Unlock()
			return
		}
		if agent.HAMode {
			// if endPoint is not empty means, cis is running in secondary mode
			// check if the primary cis is up and running
			if agent.PrimaryClusterHealthProbeParams.EndPointType != "" {
				if agent.PrimaryClusterHealthProbeParams.statusRunning {
					// dont need to post the declaration
					agent.declUpdate.Unlock()
					return

				} else {
					if agent.PrimaryClusterHealthProbeParams.statusChanged {
						agent.PrimaryClusterHealthProbeParams.paramLock.Lock()
						agent.PrimaryClusterHealthProbeParams.statusChanged = false
						agent.PrimaryClusterHealthProbeParams.paramLock.Unlock()
					}
				}
			}
		}

		var updatedTenants []string
		// initializing the priority tenants
		var priorityTenants []string
		/*
			For every incoming post request, create a new tenantResponseMap.
			tenantResponseMap will be updated with responses during postConfig.
			It holds the updatedTenants in the current iteration's as keys.
			This is needed to update response code in cases (202/404) when httpResponse body does not contain the tenant details.
		*/
		agent.tenantResponseMap = make(map[string]map[string]tenantResponse)

		for tenant := range agent.incomingBIGIPTenantDeclMap[bigIPAddress] {
			// CIS with AS3 doesnt allow write to Common partition.So objects in common partition
			// should not be updated or deleted by CIS. So removing from tenant map
			if tenant != "Common" {
				if _, ok := agent.tenantPriorityMap[tenant]; ok {
					priorityTenants = append(priorityTenants, tenant)
				} else {
					updatedTenants = append(updatedTenants, tenant)
				}
				agent.tenantResponseMap[bigip.bigIPLabel][tenant] = tenantResponse{}
			}
		}
		// TODO: need to handle bigip target address depending on AS3 API either single or two step as part of postManager
		// Update the priority tenants first
		if len(priorityTenants) > 0 {
			agent.enqueueCfgForPost(decl, rsConfig, priorityTenants, bigIPAddress)
		}
		// Updating the remaining tenants
		agent.enqueueCfgForPost(decl, rsConfig, updatedTenants, bigIPAddress)

		agent.declUpdate.Unlock()
	}
}

func NewAgent(params AgentParams) *Agent {
	DEFAULT_PARTITION = params.Partition
	DEFAULT_GTM_PARTITION = params.Partition + "_gtm"
	postMgr := NewPostManager(params, false)
	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
	}
	agent := &Agent{
		PostManager:  postMgr,
		Partition:    params.Partition,
		ConfigWriter: configWriter,
		EventChan:    make(chan interface{}),
		respChan:     make(chan resourceStatusMeta, 1),
		reqChan:      make(chan ResourceConfigRequest, 1),
		userAgent:    params.UserAgent,
		HttpAddress:  params.HttpAddress,
		ccclGTMAgent: params.CCCLGTMAgent,
		disableARP:   params.DisableARP,
	}

	// requestHandler runs as a separate go routine
	// blocks on reqChan to get new/updated configuration to be posted to BIG-IP
	go agent.requestHandler()

	// retryWorker runs as a separate go routine
	// blocks on retryChan ; retries failed declarations and polls for accepted tenant statuses
	go agent.retryWorker()

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
		BigIPUsername:   params.PostParams.BIGIPUsername,
		BigIPPassword:   params.PostParams.BIGIPPassword,
		BigIPURL:        params.PostParams.BIGIPURL,
		BigIPPartitions: []string{params.Partition},
	}

	var gtm gtmBigIPSection
	if len(params.GTMParams.BIGIPURL) == 0 || len(params.GTMParams.BIGIPUsername) == 0 || len(params.GTMParams.BIGIPPassword) == 0 {
		// gs.GTM = false
		gtm = gtmBigIPSection{
			GtmBigIPUsername: params.PostParams.BIGIPUsername,
			GtmBigIPPassword: params.PostParams.BIGIPPassword,
			GtmBigIPURL:      params.PostParams.BIGIPURL,
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
	// Set the AS3 version for the LTM Postmanager
	err = agent.IsBigIPAppServicesAvailable()
	if err != nil {
		log.Errorf("%v", err)
		agent.Stop()
		os.Exit(1)
	}
	// Set the AS3 version on the GTM Postmanager
	if agent.GTMPostManager != nil {
		err = agent.GTMPostManager.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			agent.Stop()
			os.Exit(1)
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

func (agent *Agent) enqueueRequestConfig(rsConfig ResourceConfigRequest) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above

	select {
	case agent.reqChan <- rsConfig:
	case <-agent.reqChan:
		agent.reqChan <- rsConfig

	}
}

// removeDeletedTenantsForBigIP will check the tenant exists on bigip or not
// if tenant exists and rsConfig does not have tenant, update the tenant with empty PartitionConfig
func (agent *Agent) removeDeletedTenantsForBigIP(rsConfig *BigIpConfig, cisLabel string) {
	//Fetching the latest BIGIP Configuration and identify if any tenant needs to be deleted
	as3Config, err := agent.PostManager.GetAS3DeclarationFromBigIP()
	if err != nil {
		log.Errorf("[AS3] Could not fetch the latest AS3 declaration from BIG-IP")
	}
	for k, v := range as3Config {
		if decl, ok := v.(map[string]interface{}); ok {
			if label, found := decl["label"]; found && label == cisLabel && k != agent.Partition+"_gtm" {
				if _, ok := rsConfig.ltmConfig[k]; !ok {
					// adding an empty tenant to delete the tenant from BIGIP
					priority := 1
					rsConfig.ltmConfig[k] = &PartitionConfig{Priority: &priority}
				}
			}
		}
	}
}

// Enqueue AS3 declaration to post chanel
func (agent *Agent) enqueueCfgForPost(decl as3Declaration, rsConfig ResourceConfigRequest, tenants []string, bigipTargetAddress string) {
	as3cfg := as3Config{
		data:               string(decl),
		as3APIURL:          agent.getAS3APIURL(tenants),
		id:                 rsConfig.reqId,
		bigipTargetAddress: bigipTargetAddress,
	}
	//TODO: Implement as part of L3 Manager
	l3cfg := l3Config{}
	cfg := agentConfig{as3Config: as3cfg, l3Config: l3cfg}
	select {
	case agent.postChan <- cfg:
		log.Debugf("Declaration written to post chan")
	case <-time.After(3 * time.Second):
	}
}

func (agent *Agent) notifyRscStatusHandler(id int, overwriteCfg bool) {

	rscUpdateMeta := resourceStatusMeta{
		id,
		make(map[string]struct{}),
	}
	for tenant := range agent.retryTenantDeclMap {
		rscUpdateMeta.failedTenants[tenant] = struct{}{}
	}
	// If triggerred from retry block, process the previous successful request completely
	if !overwriteCfg {
		agent.respChan <- rscUpdateMeta
	} else {
		// Always push latest id to channel
		// Case1: Put latest id into the channel
		// Case2: If channel is blocked because of earlier id, pop out earlier id and push latest id
		// Either Case1 or Case2 executes, which ensures the above
		select {
		case agent.respChan <- rscUpdateMeta:
		case <-agent.respChan:
			agent.respChan <- rscUpdateMeta
		}
	}
}

// retryWorker blocks on retryChan
// whenever it gets unblocked, retries failed declarations and polls for accepted tenant statuses
func (agent *Agent) retryWorker() {

	/*
		retryWorker runs as a goroutine. It is idle until an arrives at retryChan.
		retryTenantDeclMal holds all information about tenant adc configuration and response codes.

		Once retryChan is signalled, retryWorker posts tenant declarations and/or polls for accepted tenants' statuses continuously until it succeeds
		Locks are used to block retries if an incoming request arrives at agentWorker.

		For each iteration, retryWorker tries to acquire agent.declUpdate lock.
		During an ongoing agentWorker's activity, retryWorker tries to wait until agent.declUpdate lock is acquired
		Similarly, during an ongoing retry, agentWorker waits for graceful termination of ongoing iteration - i.e., until agent.declUpdate is unlocked

	*/

	for range agent.retryChan {

		for len(agent.retryTenantDeclMap) != 0 {

			if agent.HAMode {
				// if endPoint is not empty -> cis is running in secondary mode
				// check if the primary cis is up and running
				if agent.PrimaryClusterHealthProbeParams.EndPointType != "" {
					if agent.PrimaryClusterHealthProbeParams.statusRunning {
						agent.retryTenantDeclMap = make(map[string]map[string]*tenantParams)
						// dont post the declaration
						continue
					}
				}
			}

			agent.declUpdate.Lock()

			// If we had a delay in acquiring lock, re-check if we have any tenants to be retried
			if len(agent.retryTenantDeclMap) == 0 {
				agent.declUpdate.Unlock()
				break
			}

			log.Debugf("[AS3] Posting failed tenants configuration in %v seconds", timeoutMedium)

			//If there are any 201 tenants, poll for its status
			agent.pollTenantStatus()

			//If there are any failed tenants, retry posting them
			agent.retryFailedTenant(agent.userAgent)

			agent.notifyRscStatusHandler(0, false)

			agent.declUpdate.Unlock()
		}
	}
}

// Creates AS3 adc only for tenants with updated configuration
func (agent *Agent) createTenantAS3Declaration(config BigIpConfig, bigipIP string) as3Declaration {
	// Re-initialise incomingTenantDeclMap map and tenantPriorityMap for each new config request
	agent.incomingBIGIPTenantDeclMap = make(map[string]map[string]as3Tenant)
	agent.tenantPriorityMap = make(map[string]int)
	for tenant, cfg := range agent.createAS3BIGIPConfig(config, bigipIP) {
		if !reflect.DeepEqual(cfg, agent.cachedBIGIPTenantDeclMap[bigipIP][tenant]) ||
			(agent.PrimaryClusterHealthProbeParams.EndPoint != "" && agent.PrimaryClusterHealthProbeParams.statusChanged) {
			agent.incomingBIGIPTenantDeclMap[bigipIP][tenant] = cfg.(as3Tenant)
		} else {
			// cachedTenantDeclMap always holds the current configuration on BigIP(lets say A)
			// When an invalid configuration(B) is reverted (to initial A) (i.e., config state A -> B -> A),
			// delete entry from retryTenantDeclMap if any
			delete(agent.retryTenantDeclMap, tenant)
			// Log only when it's primary/standalone CIS or when it's secondary CIS and primary CIS is down
			if agent.PrimaryClusterHealthProbeParams.EndPoint == "" || !agent.PrimaryClusterHealthProbeParams.statusRunning {
				log.Debugf("[AS3] No change in %v tenant configuration", tenant)
			}
		}
	}

	return agent.createAS3Declaration(agent.incomingBIGIPTenantDeclMap[bigipIP], agent.userAgent)
}

func (agent *Agent) createAS3BIGIPConfig(config BigIpConfig, bigipLabel string) as3ADC {
	adc := agent.createAS3LTMConfigADC(config, bigipLabel)
	return adc
}

func (agent *Agent) createAS3LTMConfigADC(config BigIpConfig, bigipLabel string) as3ADC {
	adc := as3ADC{}
	cisLabel := agent.Partition

	if agent.HAMode {
		// Delete the tenant which is monitored by CIS and current request does not contain it, if it's the first post or
		// if it's secondary CIS and primary CIS is down and statusChanged is true
		if agent.firstPost ||
			(agent.PrimaryClusterHealthProbeParams.EndPoint != "" && !agent.PrimaryClusterHealthProbeParams.statusRunning &&
				agent.PrimaryClusterHealthProbeParams.statusChanged) {
			agent.removeDeletedTenantsForBigIP(&config, cisLabel)
			agent.firstPost = false
		}
	}

	for tenant := range agent.cachedBIGIPTenantDeclMap[bigipLabel] {
		if _, ok := config.ltmConfig[tenant]; !ok && !agent.isGTMTenant(tenant) {
			// Remove partition
			adc[tenant] = getDeletedTenantDeclaration(agent.Partition, tenant, cisLabel)
		}
	}
	for tenantName, partitionConfig := range config.ltmConfig {
		// TODO partitionConfig priority can be overridden by another request if agent is unable to process the prioritized request in time
		partitionConfig.PriorityMutex.RLock()
		if *(partitionConfig.Priority) > 0 {
			agent.tenantPriorityMap[tenantName] = *(partitionConfig.Priority)
		}
		partitionConfig.PriorityMutex.RUnlock()
		if len(partitionConfig.ResourceMap) == 0 {
			// Remove partition
			adc[tenantName] = getDeletedTenantDeclaration(agent.Partition, tenantName, cisLabel)
			continue
		}
		// Create Shared as3Application object
		sharedApp := as3Application{}
		sharedApp["class"] = "Application"
		sharedApp["template"] = "shared"

		// Process rscfg to create AS3 Resources
		processResourcesForAS3(partitionConfig.ResourceMap, sharedApp, config.shareNodes, tenantName)

		// Process CustomProfiles
		processCustomProfilesForAS3(partitionConfig.ResourceMap, sharedApp, agent.bigIPAS3Version)

		// Process Profiles
		processProfilesForAS3(partitionConfig.ResourceMap, sharedApp)

		processIRulesForAS3(partitionConfig.ResourceMap, sharedApp)

		processDataGroupForAS3(partitionConfig.ResourceMap, sharedApp)

		// Create AS3 Tenant
		tenantDecl := as3Tenant{
			"class":              "Tenant",
			"defaultRouteDomain": config.defaultRouteDomain,
			as3SharedApplication: sharedApp,
			"label":              cisLabel,
		}
		adc[tenantName] = tenantDecl
	}
	return adc
}
