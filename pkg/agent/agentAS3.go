package agent

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/as3"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
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

//TODO: Remove this post CIS2.2
func (ag *agentAS3) Remove(partition string) error {
	log.Debugf("[AS3] Removing Partition %v_AS3 \n", partition)
	ag.DeleteAS3Partition(partition + "_AS3")
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
