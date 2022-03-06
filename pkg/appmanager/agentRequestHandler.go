package appmanager

import (
	cisAgent "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
)

// Method to deploy resources on configured agent
func (appMgr *Manager) deployResource() error {
	// Generate Agent Request

	// Prepare Custom Profiles Copy
	Profs := map[SecretKey]CustomProfile{}
	appMgr.customProfiles.Lock()
	for k, v := range appMgr.customProfiles.Profs {
		Profs[k] = v
	}
	appMgr.customProfiles.Unlock()

	// Initialize cfgMap context
	agentCfgMapLst := []*AgentCfgMap{}
	for _, cm := range appMgr.agentCfgMap {
		agentCfgMapLst = append(agentCfgMapLst, cm)
	}
	deployCfg := ResourceRequest{
		Resources: &AgentResources{
			RsMap:  appMgr.resources.RsMap,
			RsCfgs: appMgr.resources.GetAllResources(),
		},
		Profs:        Profs,
		IRulesStore:  appMgr.IRulesStore,
		IntDgMap:     appMgr.intDgMap,
		IntF5Res:     appMgr.intF5Res,
		AgentCfgmaps: agentCfgMapLst,
	}

	agentReq := MessageRequest{MsgType: cisAgent.MsgTypeSendDecl, ResourceRequest: deployCfg}
	// Handle resources to agent and deploy to BIG-IP
	appMgr.AgentCIS.Deploy(agentReq)
	go appMgr.TeemData.PostTeemsData()
	// Initialize cfgMap context if CfgMaps are removed
	for key, cm := range appMgr.agentCfgMap {
		if cm.Operation == OprTypeDelete {
			delete(appMgr.agentCfgMap, key)
		}
	}
	return nil
}
