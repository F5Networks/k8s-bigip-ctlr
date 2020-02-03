package agent

import (
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/cccl"
)

type agentCCCL struct {
	typeName string
	ccclMgr *cccl.CCCLManager
}

func (ag *agentCCCL) Init(params interface{}) (error) {
	ag.typeName = " CCCL"
	ccclParams := params.(cccl.Params)
	ag.ccclMgr = cccl.NewCCCLManager(&ccclParams)
	return nil
}

func (ag *agentCCCL) Deploy(req AgentRequest)(error) {
        fmt.Println("In Deploy CCCL")
        return nil
}

func (ag *agentCCCL) Remove(partition string) (error) {
        fmt.Printf("Removing CCCL Partition %v \n", partition)
        return nil
}

func (ag *agentCCCL) DeInit() (error) {
	fmt.Printf("DeInit\n")
	ag.ccclMgr.NodePoller.Stop()
	ag.ccclMgr.ConfigWriter().Stop()
	return nil
}