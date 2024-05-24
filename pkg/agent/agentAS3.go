package agent

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/as3"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

type agentAS3 struct {
	*AS3Manager
}

func (ag *agentAS3) Init(params interface{}) error {
	log.Info("[AS3] Initializing AS3 Agent")
	as3Params := params.(*Params)
	ag.AS3Manager = NewAS3Manager(as3Params)

	ag.ReqChan = make(chan resource.MessageRequest, 1)
	if ag.ReqChan != nil {
		go ag.ConfigDeployer()
	}

	if ag.PatchChan != nil {
		go ag.PatchDeployer()
	}

	err := ag.IsBigIPAppServicesAvailable()
	if err != nil {
		return err
	}
	return nil
}

func (ag *agentAS3) GetBigipRegKey() string {
	key, err := ag.PostManager.GetBigipRegKey()
	if err != nil {
		return ""
	}
	return key
}

func (ag *agentAS3) Deploy(req interface{}) error {
	msgReq := req.(resource.MessageRequest)
	select {
	case ag.ReqChan <- msgReq:
	case <-ag.ReqChan:
		ag.ReqChan <- msgReq
	}
	return nil
}

func (ag *agentAS3) PatchPoolMember(req interface{}) error {
	if ag.PatchChan != nil {
		ag.PatchChan <- req.(PatchRequest)
	}
	return nil
}

func (ag *agentAS3) Clean(partition string) error {
	log.Debugf("[AS3] Cleaning Partition %v \n", partition)
	ag.CleanAS3Tenant(partition)
	return nil
}

func (ag *agentAS3) DeInit() error {
	close(ag.RspChan)
	close(ag.ReqChan)
	return nil
}

func (ag *agentAS3) IsImplInAgent(rsrc string) bool {
	if resource.ResourceTypeCfgMap == rsrc {
		return true
	}
	return false
}
