package agent

import(
	"errors"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource")

const (
    msgTypeSendFDB      = "FDB"
    msgTypeSendARP      = "ARP"
    msgTypeSendL4L7Decl = "L4L7Decleration"
)

type endPoints struct{
    members      []Member
}

type AgentRequest struct {
	ReqID       uint
    MsgType     string
	Message     interface{}
}

type AgentResponse struct {
	ReqID       uint
	MsgType     string
	Message     interface{}
}

type AgentDeployConfigRequest struct {
	PoolMembers    map[string]endPoints
	resources      *Resources
	customProfiles *CustomProfileStore
	irulesMap      IRulesMap
	intDgMap       InternalDataGroupMap
	intF5Res       InternalF5ResourcesGroup
}

type AgentDeployConfigResponse struct {
    ReqID       uint
    MsgType     string
    AdmitStatus string
    AS3Members  map[string]string
}

type CISAgentInterface interface {
    Initializer
    Deployer
    //Patcher
    Remover
	DeInitializer
}

// Initializer is the interface that wraps basic Init method.
type Initializer interface {
   //Init(params *Params)(error)
	Init(interface{})(error)
}

// Deployer is the interface that wraps basic Deploy method
type Deployer interface {
   Deploy(req AgentRequest)(error)
}

// Remover is the interface that wraps basic Remove method
type Remover interface {
   Remove(partition string)(error)
}

// De-Initializer is the interface that wraps basic Init method.
type DeInitializer interface {
	//Init(params *Params)(error)
	DeInit()(error)
}

const (
	AS3Agent = "as3"
	CCCLAgent = "cccl"
	//BIGIQ
	//FAST
)

func CreateAgent(agentType string) (CISAgentInterface, error) {
	switch agentType {
	case AS3Agent:
		return new(agentAS3), nil
	case CCCLAgent:
		return new(agentCCCL), nil
	//case BIGIQ:
	//	return new(agentBIGIQ), nil
	//case FAST:
	//	return new(agentFAST), nil
	default:
		return nil, errors.New("Invalid Agent Type")
	}
}
