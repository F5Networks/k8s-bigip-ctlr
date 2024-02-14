package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"reflect"
	"time"
)

func (req *RequestHandler) startRequestHandler() {
	log.Debug("Starting requestHandler")
	// requestHandler runs as a separate go routine
	// blocks on reqChan to get new/updated configuration to be posted to BIG-IP
	go req.requestHandler()
}

func (req *RequestHandler) stopPostManager(key BigIpKey) {
	//stop post manager
	if pm, ok := req.PostManagers.PostManagerMap[key]; ok {
		//close the channels to stop the post channel
		close(pm.postChan)
		//remove bigiplabel from agentmap
		delete(req.PostManagers.PostManagerMap, key)
		// decrease the post manager Count
		prometheus.AgentCount.Dec()
	}
}

func (req *RequestHandler) startPostManager(config cisapiv1.BigIpConfig) {
	for _, bigIpKey := range getBigIpList(config) {
		//start agent
		req.PostManagers.Lock()
		if _, ok := req.PostManagers.PostManagerMap[bigIpKey]; !ok {
			pm := NewPostManager(req.PostParams, config.DefaultPartition)
			pm.respChan = req.respChan
			pm.tokenManager = req.CMTokenManager
			// update agent Map
			req.PostManagers.PostManagerMap[bigIpKey] = pm
			// increase the Agent Count
			prometheus.AgentCount.Inc()
		}
		req.PostManagers.Unlock()
	}
}

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

// RequestHandler blocks on reqChan
// whenever it gets unblocked, it creates an as3, l3 declaration for respective bigip and puts on post channel for postmanger to handle
func (req *RequestHandler) requestHandler() {
	for rsConfig := range req.reqChan {
		req.PostManagers.RLock()
		if pm, ok := req.PostManagers.PostManagerMap[rsConfig.bigIpKey]; ok {
			//create post config declaration for BigIp pair and put in post channel
			cfg := req.createDeclarationForBIGIP(rsConfig, pm)
			if !reflect.DeepEqual(cfg, agentConfig{}) {
				pm.postChan <- cfg
			}
		}
		req.PostManagers.RUnlock()
	}
}

func (req *RequestHandler) createDeclarationForBIGIP(rsConfig ResourceConfigRequest, pm *PostManager) agentConfig {
	var agentCfg agentConfig
	if req.HAMode {
		// if endPoint is not empty means, cis is running in secondary mode
		// check if the primary cis is up and running
		if req.PrimaryClusterHealthProbeParams.EndPointType != "" {
			if req.PrimaryClusterHealthProbeParams.statusRunning {
				return agentCfg
			} else {
				if req.PrimaryClusterHealthProbeParams.statusChanged {
					req.PrimaryClusterHealthProbeParams.paramLock.Lock()
					req.PrimaryClusterHealthProbeParams.statusChanged = false
					req.PrimaryClusterHealthProbeParams.paramLock.Unlock()
				}
			}
		}
		// Delete the tenant which is monitored by CIS and current request does not contain it, if it's the first post or
		// if it's secondary CIS and primary CIS is down and statusChanged is true
		if pm.AS3PostManager.firstPost ||
			(req.PrimaryClusterHealthProbeParams.EndPoint != "" && !req.PrimaryClusterHealthProbeParams.statusRunning &&
				req.PrimaryClusterHealthProbeParams.statusChanged) {
			currentConfig, err := pm.GetAS3DeclarationFromBigIP()
			if err != nil {
				log.Errorf("[AS3] Could not fetch the latest AS3 declaration from BIG-IP")
			}
			removeDeletedTenantsForBigIP(&rsConfig.bigIpResourceConfig, pm.defaultPartition, currentConfig, pm.defaultPartition)
			pm.AS3PostManager.firstPost = false
		}
	}
	//for each request config create AS3, L3 declaration
	// create the AS3 declaration for the bigip
	as3cfg := req.createAS3Config(rsConfig, pm)
	if len(rsConfig.bigIpResourceConfig.ltmConfig) == 0 {
		as3cfg.deleted = true
	}
	// TODO : Create the L3 declaration for the bigip
	agentCfg = agentConfig{
		id:        rsConfig.reqMeta.id,
		as3Config: as3cfg,
		l3Config:  l3Config{},
		BigIpKey:  rsConfig.bigIpKey,
		reqMeta:   rsConfig.reqMeta}
	return agentCfg
}
