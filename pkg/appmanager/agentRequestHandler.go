package appmanager

import (
	cisAgent "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

// Method to deploy resources on configured agent
func (appMgr *Manager) deployResource() error {
	// Generate Agent Request
	deployCfg := ResourceRequest{Resources: &AgentResources{RsMap: appMgr.resources.RsMap,
		RsCfgs: appMgr.resources.GetAllResources()}, CustomProfiles: appMgr.customProfiles,
		IrulesMap: appMgr.irulesMap, IntDgMap: appMgr.intDgMap, IntF5Res: appMgr.intF5Res,
		AgentCfgmap: appMgr.agentCfgMap}
	agentReq := MessageRequest{MsgType: cisAgent.MsgTypeSendDecl, ResourceRequest: deployCfg}
	// Handle resources to agent and deploy to BIG-IP
	appMgr.AgentCIS.Deploy(agentReq)
	return nil
}

// Method to deploy ARP on L2-L3 agent
func (appMgr *Manager) deployARP(members map[Member]struct{}) error {
	log.Debugf("[CORE] Sending ARP entries")
	agentCIS := appMgr.getL2L3Agent()
	deployCfg := ResourceRequest{Resources: &AgentResources{RsMap: appMgr.resources.RsMap,
		RsCfgs: appMgr.resources.GetAllResources()}, PoolMembers: members}
	// Generate Agent Request
	agentReq := MessageRequest{MsgType: cisAgent.MsgTypeSendARP, ResourceRequest: deployCfg}
	// Handle resources to agent and deploy to BIG-IP
	agentCIS.Deploy(agentReq)
	return nil
}

// Method to deploy FDB on L2-L3 agent
func (appMgr *Manager) deployFDB() error {
	agentCIS := appMgr.getL2L3Agent()
	// Generate Agent Request
	deployCfg := ResourceRequest{Resources: &AgentResources{RsMap: appMgr.resources.RsMap,
		RsCfgs: appMgr.resources.GetAllResources()}}
	agentReq := MessageRequest{MsgType: cisAgent.MsgTypeSendFDB, ResourceRequest: deployCfg}
	// Handle resources to agent and deploy to BIG-IP
	agentCIS.Deploy(agentReq)
	return nil
}

// Method to get L2-L3 agent
func (appMgr *Manager) getL2L3Agent() cisAgent.CISAgentInterface {
	// This condition holds good for Agent AS3 for now,
	// However, agent CCCL doesn't use this method
	// This can be used and extended by future agents.
	if appMgr.AgentCIS != nil && appMgr.AgentCCCL != nil {
		return appMgr.AgentCCCL
	}
	return appMgr.AgentCIS
}
