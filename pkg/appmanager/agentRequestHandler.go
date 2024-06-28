package appmanager

import (
	cisAgent "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
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

	// Prepare copy of InternalDataGroupMap
	appMgr.intDgMutex.Lock()
	idgMap := make(InternalDataGroupMap)
	for nameRef, dgnMap := range appMgr.intDgMap {
		dataGroupNamespaceMap := make(map[string]*InternalDataGroup)
		for k, v := range dgnMap {
			dg := &InternalDataGroup{}
			idrgs := InternalDataGroupRecords{}
			for _, record := range v.Records {
				idrgs = append(idrgs, record)
			}
			dg.Records = idrgs
			dg.Name = v.Name
			dg.Partition = v.Partition
			dataGroupNamespaceMap[k] = dg
		}
		idgMap[nameRef] = dataGroupNamespaceMap
	}
	appMgr.intDgMutex.Unlock()

	// prepare copy of iRuleMap
	iRulesMap := make(IRulesMap)
	for key, value := range appMgr.irulesMap {
		iRule := IRule{}
		iRule.Name = value.Name
		iRule.Partition = value.Partition
		iRule.Code = value.Code
		iRulesMap[key] = &iRule
	}

	// Prepare copy of RsMap
	appMgr.resources.Lock()
	resourceConfigMap := make(ResourceConfigMap)
	partitions := make(map[string]struct{})
	for key, value := range appMgr.resources.RsMap {
		rsConfig := ResourceConfig{}
		rsConfig.CopyConfig(value)
		resourceConfigMap[key] = &rsConfig
		partitions[rsConfig.GetPartition()] = struct{}{}
	}
	appMgr.resources.Unlock()

	// Prepare InternalF5ResourcesGroup Copy
	intF5Res := InternalF5ResourcesGroup{}
	for k, v := range appMgr.intF5Res {
		intF5Res[k] = v
	}

	// Initialize cfgMap context
	agentCfgMapLst := []*AgentCfgMap{}
	for _, cm := range appMgr.agentCfgMap {
		agentCfgMapLst = append(agentCfgMapLst, cm)
	}

	deployCfg := ResourceRequest{
		Resources: &AgentResources{
			RsMap:      resourceConfigMap,
			Partitions: partitions,
		},
		Profs:        Profs,
		IrulesMap:    iRulesMap,
		IntDgMap:     idgMap,
		IntF5Res:     intF5Res,
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
