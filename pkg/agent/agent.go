package agent

import (
	"errors"
)

const (
	MsgTypeSendDecl = "L4L7Declaration"
)

type CISAgentInterface interface {
	Initializer
	Deployer
	DeInitializer
	Remover
	IsImplInAgent(string) bool
}

// Initializer is the interface which wraps basic Init method.
type Initializer interface {
	Init(interface{}) error
	GetBigipRegKey() string
}

// Deployer is the interface which wraps basic Deploy method
type Deployer interface {
	Deploy(req interface{}) error
}

// De-Initializer is the interface which wraps basic De-Init method.
type DeInitializer interface {
	DeInit() error
}

// Remover is the interface which wraps basic Remove method
type Remover interface {
	Clean(partition string) error
}

const (
	AS3Agent  = "as3"
	CCCLAgent = "cccl"
)

func CreateAgent(agentType string) (CISAgentInterface, error) {
	switch agentType {
	case AS3Agent:
		return new(agentAS3), nil
	case CCCLAgent:
		return new(agentCCCL), nil
	// Futuristic Agents
	//case BIGIQ:
	//	return new(agentBIGIQ), nil
	//case FAST:
	//	return new(agentFAST), nil
	default:
		return nil, errors.New("Invalid Agent Type")
	}
}
