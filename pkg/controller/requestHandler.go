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
	"reflect"
	"time"
)

// RequestHandler blocks on reqChan
// whenever it gets unblocked, it creates an as3, l3 declaration for respective bigip and puts on post channel for postmanger to handle
func (agent *Agent) requestHandler() {
	for rsConfig := range agent.reqChan {
		// For the very first post after starting controller, need not wait to post
		if !agent.firstPost && agent.AS3Config.PostDelayAS3 != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", agent.AS3Config.PostDelayAS3)
			_ = <-time.After(time.Duration(agent.AS3Config.PostDelayAS3) * time.Second)
		}

		// Fetch the latest config from channel
		select {
		case rsConfig = <-agent.reqChan:
		case <-time.After(1 * time.Microsecond):
		}
		//create AS3 declaration for bigip pair and put in post channel
		go agent.createAS3DeclarationForBIGIP(rsConfig)
	}
}

func (agent *Agent) createAS3DeclarationForBIGIP(rsConfig ResourceConfigRequest) {
	//for each bigip config create AS3, L3 declaration
	targetIPs := []string{rsConfig.bigipConfig.BigIpAddress}
	if rsConfig.bigipConfig.HaBigIpAddress != "" {
		targetIPs = append(targetIPs, rsConfig.bigipConfig.HaBigIpAddress)
	}
	agent.declUpdate.Lock()
	decl := agent.createTenantAS3Declaration(rsConfig.bigIpResourceConfig)
	if agent.HAMode {
		// if endPoint is not empty means, cis is running in secondary mode
		// check if the primary cis is up and running
		if agent.PrimaryClusterHealthProbeParams.EndPointType != "" {
			if agent.PrimaryClusterHealthProbeParams.statusRunning {
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
	agent.tenantResponseMap = make(map[string]tenantResponse)

	for tenant := range agent.incomingTenantDeclMap {
		// CIS with AS3 doesnt allow write to Common partition.So objects in common partition
		// should not be updated or deleted by CIS. So removing from tenant map
		if tenant != "Common" {
			if _, ok := agent.tenantPriorityMap[tenant]; ok {
				priorityTenants = append(priorityTenants, tenant)
			} else {
				updatedTenants = append(updatedTenants, tenant)
			}
			agent.tenantResponseMap[tenant] = tenantResponse{}
		}
	}
	agent.declUpdate.Unlock()
	for _, bigIPAddress := range targetIPs {
		// TODO: need to handle bigip target address depending on AS3 API either single or two step as part of postManager
		// Update the priority tenants first
		if len(priorityTenants) > 0 {
			agent.enqueueCfgForPost(decl, rsConfig, priorityTenants, bigIPAddress)
		}
		// Updating the remaining tenants
		agent.enqueueCfgForPost(decl, rsConfig, updatedTenants, bigIPAddress)

	}
}

func NewAgent(params AgentParams, bigiplabel string) *Agent {
	DEFAULT_PARTITION = params.Partition
	DEFAULT_GTM_PARTITION = params.Partition + "_gtm"
	postMgr := NewPostManager(params, false)
	agent := &Agent{
		PostManager: postMgr,
		Partition:   params.Partition,
		respChan:    make(chan resourceStatusMeta, 1),
		reqChan:     make(chan ResourceConfigRequest, 1),
		userAgent:   params.UserAgent,
		bigipLabel:  bigiplabel,
	}

	// requestHandler runs as a separate go routine
	// blocks on reqChan to get new/updated configuration to be posted to BIG-IP
	go agent.requestHandler()

	// retryWorker runs as a separate go routine
	// blocks on retryChan ; retries failed declarations and polls for accepted tenant statuses
	go agent.retryWorker()
	return agent
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
func (agent *Agent) removeDeletedTenantsForBigIP(rsConfig *BigIpResourceConfig, cisLabel string) {
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
						agent.retryTenantDeclMap = make(map[string]*tenantParams)
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
func (agent *Agent) createTenantAS3Declaration(config BigIpResourceConfig) as3Declaration {
	// Re-initialise incomingTenantDeclMap map and tenantPriorityMap for each new config request
	agent.incomingTenantDeclMap = make(map[string]as3Tenant)
	agent.tenantPriorityMap = make(map[string]int)
	for tenant, cfg := range agent.createAS3BIGIPConfig(config) {
		if !reflect.DeepEqual(cfg, agent.cachedTenantDeclMap[tenant]) ||
			(agent.PrimaryClusterHealthProbeParams.EndPoint != "" && agent.PrimaryClusterHealthProbeParams.statusChanged) {
			agent.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
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

	return agent.createAS3Declaration(agent.incomingTenantDeclMap, agent.userAgent)
}

func (agent *Agent) createAS3BIGIPConfig(config BigIpResourceConfig) as3ADC {
	adc := agent.createAS3LTMConfigADC(config)
	return adc
}

func (agent *Agent) createAS3LTMConfigADC(config BigIpResourceConfig) as3ADC {
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

	for tenant := range agent.cachedTenantDeclMap {
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
