package agent

import (
	"fmt"
	as3 "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/as3"
)


type agentAS3 struct {
	as3Mgr *as3.AS3Manager
	Req    AgentRequest
}

func (ag *agentAS3) Init(params interface {}) (error) {
	as3Params := params.(as3.Params)
	ag.as3Mgr = as3.NewAS3Manager(&as3Params)
	err := ag.as3Mgr.FetchAS3Schema()
	if err != nil{
		return err
	}
	return nil
}

func (ag *agentAS3) Deploy(req AgentRequest)(error) {
        //rsCfg.rsType = ag.typeName
	fmt.Println("In Deploy AS3")
	return nil
}

func (ag *agentAS3) Remove(partition string) (error) {
	fmt.Printf("Removing AS3 Partition %v \n", partition)
	ag.as3Mgr.DeleteAS3Partition(partition)
	return nil
}

func (ag *agentAS3) DeInit() (error) {
	fmt.Printf("DeInit\n")
	return nil
}
