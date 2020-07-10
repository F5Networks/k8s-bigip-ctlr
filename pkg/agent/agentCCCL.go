package agent

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/cccl"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
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

//TODO: Remove this post CIS2.2
func (ag *agentCCCL) Remove(partition string) error {
	log.Infof("[CCCL] Removing Partition %v_AS3 \n", partition)
	ag.DeleteAS3Partition(partition + "_AS3")
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
