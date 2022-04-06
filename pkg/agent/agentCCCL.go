package agent

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

type agentCCCL struct {
	*CCCLManager
}

func (ag *agentCCCL) Init(params interface{}) error {
	log.Infof("[CCCL] Initializing CCCL Agent")
	ccclParams := params.(*Params)
	ag.CCCLManager = NewCCCLManager(ccclParams)
	return nil
}

func (ag *agentCCCL) Deploy(req interface{}) error {
	log.Debugf("[CORE] Deploy entries")
	msgReq := req.(resource.MessageRequest)
	ag.ResourceRequest = msgReq.ResourceRequest
	switch msgReq.MsgType {
	case MsgTypeSendDecl:
		ag.OutputConfigLocked()
	}
	return nil
}

func (ag *agentCCCL) GetBigipRegKey() string {
	return ""
}

func (ag *agentCCCL) Clean(partition string) error {
	return nil
}

func (ag *agentCCCL) DeInit() error {
	log.Infof("[CCCL] DeInitializing CCCL Agent\n")
	ag.ConfigWriter().Stop()
	return nil
}

func (ag *agentCCCL) IsImplInAgent(rsrc string) bool {
	return false
}
