package mockmanager

import (
	v1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	. "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager"
	"k8s.io/client-go/tools/cache"
)

type (
	MockStatusManager struct {
		StatusManager
	}
)

//coverage:ignore file

func NewMockStatusManager() *MockStatusManager {
	return &MockStatusManager{}
}

// Implement the StatusManager interface
func (sm *MockStatusManager) Start() {
}

func (sm *MockStatusManager) Stop() {

}

func (sm *MockStatusManager) AddRequest(kind, namespace, name string, exit bool, request interface{}) {

}

func (sm *MockStatusManager) GetDeployConfigCR(name, namespace string) *v1.DeployConfig {
	return nil
}

func (sm *MockStatusManager) updateDeployConfigStatus(req *StatusRequest) {

}

func (sm *MockStatusManager) AddDeployInformer(informer *cache.SharedIndexInformer, namespace string) {

}
