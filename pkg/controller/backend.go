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
	"reflect"
	"strings"
	"time"

	rsc "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
)

var DEFAULT_PARTITION string
var DEFAULT_GTM_PARTITION string

func NewAgentWorker(params AgentParams) *AgentWorker {
	aw := &AgentWorker{
		Agent:    NewAgent(params),
		stopChan: make(chan struct{}),
	}

	err := aw.LTM.IsBigIPAppServicesAvailable()
	if err != nil {
		log.Errorf("%v", err)
		aw.Stop()
		os.Exit(1)
	}
	if aw.GTM.PostManager != nil {
		err = aw.GTM.IsBigIPAppServicesAvailable()
		if err != nil {
			log.Errorf("%v", err)
			aw.Stop()
			os.Exit(1)
		}
	}

	if isGTMOnSeparateServer(params) && !aw.ccclGTMAgent {
		go aw.gtmWorker()
	}

	go aw.agentWorker()

	return aw
}

func NewAgentWorkersMap(params AgentParams) map[string]*AgentWorker {
	// Create workers based on configured BIG-IPs
	workers := make(map[string]*AgentWorker)
	for _, bigIP := range []string{PrimaryBigIP, SecondaryBigIP} {
		if bigIP != "" {
			workers[bigIP] = NewAgentWorker(params)
		}
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

func (aw *AgentWorker) PostGTMConfig(rsConfig ResourceConfigRequest) {
	as3Config := agentPostConfig{
		data:      string(aw.createTenantDeclaration(rsConfig)),
		id:        rsConfig.reqId,
		as3APIURL: aw.LTM.APIHandler.getAPIURL([]string{}),
	}
	aw.PostStrategy.Post(as3Config)
}

// can you write a function which converts the agentPostConfig to ResourceConfigRequest

func (aw *AgentWorker) PostLTMConfig(config Configurable) {
	switch v := config.(type) {
	case agentPostConfig:
		fmt.Println("Posting As3Config:", v.data)
		aw.PostStrategy.Post(v)
	case ResourceConfigRequest:
		fmt.Printf("Posting ResourceConfigRequest: %+v\n", v)
		// Convert ResourceConfigRequest to as3Config
		as3Config := agentPostConfig{
			data:      string(aw.createTenantDeclaration(v)),
			id:        v.reqId,
			as3APIURL: aw.LTM.APIHandler.getAPIURL([]string{}),
		}
		aw.PostStrategy.Post(as3Config)
	default:
		fmt.Println("Unknown config type, cannot post to channel")
	}
}

func NewAgent(params AgentParams) *Agent {
	DEFAULT_PARTITION = params.Partition
	DEFAULT_GTM_PARTITION = params.Partition + "_gtm"
	apiHandler := NewAPIHandler(params)
	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
	}
	agent := &Agent{
		APIHandler:   apiHandler,
		Partition:    params.Partition,
		ConfigWriter: configWriter,
		EventChan:    make(chan interface{}),
		respChan:     make(chan resourceStatusMeta, 1),
		userAgent:    params.UserAgent,
		HttpAddress:  params.HttpAddress,
		ccclGTMAgent: params.CCCLGTMAgent,
		disableARP:   params.DisableARP,
	}

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
	rsConfig := ResourceConfigRequest{}
	for rsConfigData := range aw.LTM.PostManager.postChan {
		// For the very first post after starting controller, need not wait to post
		if !aw.LTM.PostManager.firstPost && aw.LTM.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", aw.LTM.AS3PostDelay)
			_ = <-time.After(time.Duration(aw.LTM.AS3PostDelay) * time.Second)
		}

		// If there are no retries going on in parallel, acquiring lock will be straight forward.
		// Otherwise, we will wait for other workers to complete its current iteration
		aw.declUpdate.Lock()

		// Fetch the latest config from channel
		select {
		case rsConfigData = <-aw.LTM.PostManager.postChan:

			//config := ResourceConfigRequest{
			//	ltmConfig:          ctlr.resources.getLTMConfigDeepCopy(),
			//	shareNodes:         ctlr.shareNodes,
			//	gtmConfig:          ctlr.resources.getGTMConfigCopy(),
			//	defaultRouteDomain: ctlr.defaultRouteDomain,
			//}
			rsConfig, err := aw.LTM.APIHandler.getResourceConfigRequest(rsConfigData)
			log.Infof("%v[AS3] Processing request", getRequestPrefix(rsConfig.reqId))
			// handle the err below
			if err != nil {
				log.Errorf("Error getting resource config request: %v", err)
				aw.declUpdate.Unlock()
				continue
			}

		case <-time.After(1 * time.Microsecond):
		}

		log.Infof("%v[AS3] creating a new AS3 manifest", getRequestPrefix(rsConfig.reqId))
		decl := aw.createTenantDeclaration(rsConfig)

		if len(aw.LTM.incomingTenantDeclMap) == 0 {
			log.Infof("%v[AS3] No tenants found in request", getRequestPrefix(rsConfig.reqId))
			// notify resourceStatusUpdate response handler for resourcestatus update
			aw.notifyRscStatusHandler(rsConfig.reqId, false)
			aw.declUpdate.Unlock()
			continue
		}

		if aw.HAMode {
			// if endPoint is not empty means, cis is running in secondary mode
			// check if the primary cis is up and running
			if aw.LTM.PrimaryClusterHealthProbeParams.EndPointType != "" {
				if aw.LTM.PrimaryClusterHealthProbeParams.statusRunning {
					// dont post the declaration
					aw.declUpdate.Unlock()
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

		var updatedTenants []string
		// initializing the priority tenants
		var priorityTenants []string
		/*
			For every incoming post request, create a new tenantResponseMap.
			tenantResponseMap will be updated with responses during postConfig.
			It holds the updatedTenants in the current iteration's as keys.
			This is needed to update response code in cases (202/404) when httpResponse body does not contain the tenant details.
		*/
		aw.LTM.tenantResponseMap = make(map[string]tenantResponse)

		for tenant := range aw.LTM.incomingTenantDeclMap {
			// CIS with AS3 doesnt allow write to Common partition.So objects in common partition
			// should not be updated or deleted by CIS. So removing from tenant map
			if tenant != "Common" {
				if _, ok := aw.LTM.tenantPriorityMap[tenant]; ok {
					priorityTenants = append(priorityTenants, tenant)
				} else {
					updatedTenants = append(updatedTenants, tenant)
				}
				aw.LTM.tenantResponseMap[tenant] = tenantResponse{}
			}
		}

		// Update the priority tenants first
		if len(priorityTenants) > 0 {
			aw.postTenantsDeclaration(decl, rsConfig.reqId, priorityTenants)
		}
		// Updating the remaining tenants
		if len(updatedTenants) > 0 {
			aw.postTenantsDeclaration(decl, rsConfig.reqId, updatedTenants)
		}

		aw.declUpdate.Unlock()
	}
}

// Post the tenants declaration
func (agent *Agent) postTenantsDeclaration(decl as3Declaration, reqId int, tenants []string) {
	cfg := agentConfig{
		data:      string(decl),
		as3APIURL: agent.LTM.APIHandler.getAPIURL(tenants),
		id:        reqId,
	}

	agent.LTM.publishConfig(cfg)

	// Don't update ARPs if disableARP is set to true
	//if !agent.disableARP {
	//	go agent.updateARPsForPoolMembers(rsConfig)
	//}

	agent.LTM.updateTenantResponseMap(true)

	//if len(agent.retryTenantDeclMap) > 0 {
	//	// Activate retry
	//	select {
	//	case agent.retryChan <- struct{}{}:
	//	case <-agent.retryChan:
	//		agent.retryChan <- struct{}{}
	//	}
	//}

	/*
		If there are any tenants with 201 response code,
		poll for its status continuously and block incoming requests
	*/
	agent.LTM.pollTenantStatus(true)

	// notify resourceStatusUpdate response handler on successful tenant update
	agent.notifyRscStatusHandler(cfg.id, true)
}

func (agent *Agent) notifyRscStatusHandler(id int, overwriteCfg bool) {

	rscUpdateMeta := resourceStatusMeta{
		id,
		make(map[string]tenantResponse),
	}
	//for tenant := range agent.LTM.retryTenantDeclMap {
	//	rscUpdateMeta.failedTenants[tenant] = agent.retryTenantDeclMap[tenant].tenantResponse
	//}
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

// retryWorker blocks on retryChan
// whenever it gets unblocked, retries failed declarations and polls for accepted tenant statuses
//func (agent *Agent) retryWorker() {
//
//	/*
//		retryWorker runs as a goroutine. It is idle until an arrives at retryChan.
//		retryTenantDeclMal holds all information about tenant adc configuration and response codes.
//
//		Once retryChan is signalled, retryWorker posts tenant declarations and/or polls for accepted tenants' statuses continuously until it succeeds
//		Locks are used to block retries if an incoming request arrives at agentWorker.
//
//		For each iteration, retryWorker tries to acquire agent.declUpdate lock.
//		During an ongoing agentWorker's activity, retryWorker tries to wait until agent.declUpdate lock is acquired
//		Similarly, during an ongoing retry, agentWorker waits for graceful termination of ongoing iteration - i.e., until agent.declUpdate is unlocked
//
//	*/
//
//	for range agent.retryChan {
//
//		for len(agent.retryTenantDeclMap) != 0 {
//			// Ignoring timeouts for custom errors
//			log.Debugf("[AS3] Posting failed tenants configuration in %v seconds", timeoutMedium)
//			<-time.After(timeoutMedium)
//			if agent.HAMode {
//				// if endPoint is not empty -> cis is running in secondary mode
//				// check if the primary cis is up and running
//				if agent.PrimaryClusterHealthProbeParams.EndPointType != "" {
//					if agent.PrimaryClusterHealthProbeParams.statusRunning {
//						agent.retryTenantDeclMap = make(map[string]*tenantParams)
//						// dont post the declaration
//						continue
//					}
//				}
//			}
//
//			agent.declUpdate.Lock()
//
//			// If we had a delay in acquiring lock, re-check if we have any tenants to be retried
//			if len(agent.retryTenantDeclMap) == 0 {
//				agent.declUpdate.Unlock()
//				break
//			}
//
//			//If there are any 201 tenants, poll for its status
//			agent.pollTenantStatus(false)
//
//			//If there are any failed tenants, retry posting them
//			agent.retryFailedTenant(agent.userAgent)
//
//			agent.notifyRscStatusHandler(0, false)
//
//			agent.declUpdate.Unlock()
//		}
//	}
//}

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

// Creates AS3 adc only for tenants with updated configuration
func (agent *Agent) createTenantDeclaration(config ResourceConfigRequest) as3Declaration {
	// Re-initialise incomingTenantDeclMap map and tenantPriorityMap for each new config request
	agent.LTM.incomingTenantDeclMap = make(map[string]as3Tenant)
	agent.LTM.tenantPriorityMap = make(map[string]int)
	for tenant, cfg := range agent.createLTMAndGTMConfigADC(config) {
		if !reflect.DeepEqual(cfg, agent.LTM.cachedTenantDeclMap[tenant]) ||
			(agent.LTM.PrimaryClusterHealthProbeParams.EndPoint != "" && agent.LTM.PrimaryClusterHealthProbeParams.statusChanged) {
			agent.LTM.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
		} else {
			// cachedTenantDeclMap always holds the current configuration on BigIP(lets say A)
			// When an invalid configuration(B) is reverted (to initial A) (i.e., config state A -> B -> A),
			// delete entry from retryTenantDeclMap if any
			delete(agent.LTM.retryTenantDeclMap, tenant)
			// Log only when it's primary/standalone CIS or when it's secondary CIS and primary CIS is down
			if agent.LTM.PrimaryClusterHealthProbeParams.EndPoint == "" || !agent.LTM.PrimaryClusterHealthProbeParams.statusRunning {
				log.Debugf("[AS3] No change in %v tenant configuration", tenant)
			}
		}
	}

	return agent.LTM.APIHandler.createAPIDeclaration(agent.LTM.incomingTenantDeclMap, agent.userAgent)
}

func (agent *Agent) createLTMAndGTMConfigADC(config ResourceConfigRequest) as3ADC {
	adc := agent.createLTMConfigADC(config)
	if !agent.ccclGTMAgent && agent.GTM.PostManager == nil {
		adc = agent.createGTMConfigADC(config, adc)
	}
	return adc
}

func (agent *Agent) createGTMConfigADC(config ResourceConfigRequest, adc as3ADC) as3ADC {
	if len(config.gtmConfig) == 0 {
		sharedApp := as3Application{}
		sharedApp["class"] = "Application"
		sharedApp["template"] = "shared"
		cisLabel := agent.Partition
		tenantDecl := as3Tenant{
			"class":              "Tenant",
			as3SharedApplication: sharedApp,
			"label":              cisLabel,
		}
		adc[DEFAULT_GTM_PARTITION] = tenantDecl

		return adc
	}

	for pn, gtmPartitionConfig := range config.gtmConfig {
		var tenantDecl as3Tenant
		var sharedApp as3Application

		if obj, ok := adc[pn]; ok {
			tenantDecl = obj.(as3Tenant)
			sharedApp = tenantDecl[as3SharedApplication].(as3Application)
		} else {
			sharedApp = as3Application{}
			sharedApp["class"] = "Application"
			sharedApp["template"] = "shared"

			tenantDecl = as3Tenant{
				"class":              "Tenant",
				as3SharedApplication: sharedApp,
			}
		}

		for domainName, wideIP := range gtmPartitionConfig.WideIPs {

			gslbDomain := as3GLSBDomain{
				Class:              "GSLB_Domain",
				DomainName:         wideIP.DomainName,
				RecordType:         wideIP.RecordType,
				LBMode:             wideIP.LBMethod,
				PersistenceEnabled: wideIP.PersistenceEnabled,
				PersistCidrIPv4:    wideIP.PersistCidrIPv4,
				PersistCidrIPv6:    wideIP.PersistCidrIPv6,
				TTLPersistence:     wideIP.TTLPersistence,
				Pools:              make([]as3GSLBDomainPool, 0, len(wideIP.Pools)),
			}
			if wideIP.ClientSubnetPreferred != nil {
				gslbDomain.ClientSubnetPreferred = wideIP.ClientSubnetPreferred
			}
			for _, pool := range wideIP.Pools {
				gslbPool := as3GSLBPool{
					Class:          "GSLB_Pool",
					RecordType:     pool.RecordType,
					LBMode:         pool.LBMethod,
					LBModeFallback: pool.LBModeFallBack,
					Members:        make([]as3GSLBPoolMemberA, 0, len(pool.Members)),
					Monitors:       make([]as3ResourcePointer, 0, len(pool.Monitors)),
				}

				for _, mem := range pool.Members {
					gslbPool.Members = append(gslbPool.Members, as3GSLBPoolMemberA{
						Enabled: true,
						Server: as3ResourcePointer{
							BigIP: pool.DataServer,
						},
						VirtualServer: mem,
					})
				}

				for _, mon := range pool.Monitors {
					gslbMon := as3GSLBMonitor{
						Class:    "GSLB_Monitor",
						Interval: mon.Interval,
						Type:     mon.Type,
						Send:     mon.Send,
						Receive:  mon.Recv,
						Timeout:  mon.Timeout,
					}

					gslbPool.Monitors = append(gslbPool.Monitors, as3ResourcePointer{
						Use: mon.Name,
					})

					sharedApp[mon.Name] = gslbMon
				}
				gslbDomain.Pools = append(gslbDomain.Pools, as3GSLBDomainPool{Use: pool.Name, Ratio: pool.Ratio})
				sharedApp[pool.Name] = gslbPool
			}

			sharedApp[strings.Replace(domainName, "*", "wildcard", -1)] = gslbDomain
		}
		adc[pn] = tenantDecl
	}

	return adc
}

func (agent *Agent) createLTMConfigADC(config ResourceConfigRequest) as3ADC {
	adc := as3ADC{}
	cisLabel := agent.Partition

	if agent.HAMode {
		// Delete the tenant which is monitored by CIS and current request does not contain it, if it's the first post or
		// if it's secondary CIS and primary CIS is down and statusChanged is true
		if agent.LTM.firstPost ||
			(agent.PrimaryClusterHealthProbeParams.EndPoint != "" && !agent.PrimaryClusterHealthProbeParams.statusRunning &&
				agent.PrimaryClusterHealthProbeParams.statusChanged) {
			agent.LTM.removeDeletedTenantsForBigIP(&config, cisLabel)
			agent.LTM.firstPost = false
		}
	}

	as3 := agent.LTM.APIHandler.getApiHandler()

	for tenant := range agent.LTM.cachedTenantDeclMap {
		if _, ok := config.ltmConfig[tenant]; !ok && !agent.isGTMTenant(tenant) {
			// Remove partition
			adc[tenant] = as3.getDeletedTenantDeclaration(agent.Partition, tenant, cisLabel, &config)
		}
	}
	for tenantName, partitionConfig := range config.ltmConfig {
		// TODO partitionConfig priority can be overridden by another request if agent is unable to process the prioritized request in time
		partitionConfig.PriorityMutex.RLock()
		if *(partitionConfig.Priority) > 0 {
			agent.LTM.tenantPriorityMap[tenantName] = *(partitionConfig.Priority)
		}
		partitionConfig.PriorityMutex.RUnlock()
		if len(partitionConfig.ResourceMap) == 0 {
			// Remove partition
			adc[tenantName] = as3.getDeletedTenantDeclaration(agent.Partition, tenantName, cisLabel, &config)
			continue
		}
		// Create Shared as3Application object
		sharedApp := as3Application{}
		sharedApp["class"] = "Application"
		sharedApp["template"] = "shared"

		// Process rscfg to create AS3 Resources
		as3 := agent.LTM.APIHandler.getApiHandler()

		as3.processResourcesForAS3(partitionConfig.ResourceMap, sharedApp, config.shareNodes, tenantName,
			config.poolMemberType)

		// Process CustomProfiles
		as3.processCustomProfilesForAS3(partitionConfig.ResourceMap, sharedApp)

		// Process Profiles
		as3.processProfilesForAS3(partitionConfig.ResourceMap, sharedApp)

		as3.processIRulesForAS3(partitionConfig.ResourceMap, sharedApp)

		as3.processDataGroupForAS3(partitionConfig.ResourceMap, sharedApp)

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

func (agent *Agent) isGTMTenant(partition string) bool {
	return partition == DEFAULT_GTM_PARTITION
}
