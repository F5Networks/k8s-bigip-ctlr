package statusmanager

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	v1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type (
	StatusManager struct {
		kubeCRClient         *versioned.Interface
		Status               chan *StatusRequest
		deployConfigResource DeployConfigResource
	}
	StatusRequest struct {
		Kind      string
		Name      string
		Namespace string
		Request   interface{}
		Exit      bool
	}
	DeployConfigResource struct {
		deployConfigInformer *cache.SharedIndexInformer
		name                 string
		namespace            string
		sync.RWMutex
	}
)

// Interface for StatusManager
type StatusManagerInterface interface {
	Start()
	Stop()
	AddRequest(kind, namespace, name string, exit bool, request interface{})
	GetDeployConfigCR(name, namespace string) *v1.DeployConfig
	updateDeployConfigStatus(req *StatusRequest)
	AddDeployInformer(informer *cache.SharedIndexInformer, namespace string)
}

const (
	DeployConfig       = "deployconfig"
	SingleCluster      = "single-cluster"
	MultiClusterPrefix = "multi-cluster-"
	Ok                 = "Ok"
	Accepted           = "Accepted"
)

func NewStatusManager(kubeCRClient *versioned.Interface, crNamespace, crName string) *StatusManager {
	return &StatusManager{
		kubeCRClient: kubeCRClient,
		Status:       make(chan *StatusRequest),
		deployConfigResource: DeployConfigResource{
			name:      crName,
			namespace: crNamespace,
		},
	}
}

// Start the StatusManager
func (sm *StatusManager) Start() {
	for req := range sm.Status {
		switch req.Kind {
		case DeployConfig:
			go sm.updateDeployConfigStatus(req)
		default:
			log.Errorf("Unknown request kind: %s", req.Kind)
		}
	}
}

// Stop the StatusManager
func (sm *StatusManager) Stop() {
	close(sm.Status)
}

func (sm *StatusManager) AddRequest(kind, namespace, name string, exit bool, request interface{}) {
	if kind == DeployConfig {
		sm.deployConfigResource.RLock()
		name = sm.deployConfigResource.name
		namespace = sm.deployConfigResource.namespace
		sm.deployConfigResource.RUnlock()
	}
	sm.Status <- &StatusRequest{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Request:   request,
		Exit:      exit,
	}
}

func (sm *StatusManager) GetDeployConfigCR(name, namespace string) *v1.DeployConfig {
	var configCR *v1.DeployConfig
	var obj interface{}
	var exist bool
	var err error

	if sm.deployConfigResource.deployConfigInformer != nil {
		obj, exist, err = (*sm.deployConfigResource.deployConfigInformer).GetIndexer().GetByKey(fmt.Sprintf("%s/%s", namespace, name))
	}
	if !exist || err != nil || obj == nil {
		// If informer fails to fetch config CR which may occur if cis just started which means informers may not have
		// synced properly then try to fetch using kubeClient
		// other reason could be at CIS start time we fetch the CR
		configCR, err = (*sm.kubeCRClient).CisV1().DeployConfigs(namespace).Get(context.TODO(), name, metaV1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get DeployConfig CR: %s/%s, ensure DeployConfig CR is created in CIS monitored namespace", namespace, name)
			return configCR
		}
	}
	// if informer has fetched the CR then use it
	if obj != nil {
		configCR, _ = obj.(*v1.DeployConfig)
	}
	return configCR
}

func (sm *StatusManager) updateDeployConfigStatus(req *StatusRequest) {
	// Lock the update hence no one can read it while updating
	sm.deployConfigResource.Lock()
	defer sm.deployConfigResource.Unlock()
	// Get DeployConfig CR
	configCR := sm.GetDeployConfigCR(req.Name, req.Namespace)
	if configCR == nil {
		log.Errorf("Failed to get DeployConfig CR: %s/%s", req.Namespace, req.Name)
		return
	}
	// if deploy config status is empty then initialize it
	if reflect.DeepEqual(configCR.Status, v1.DeployConfigStatus{}) {
		configCR.Status = v1.DeployConfigStatus{}
	}
	// variable to check if controller needs to exit
	var exit bool
	var exitErr error
	// Handle DeployConfig
	switch req.Request.(type) {
	case *v1.CMStatus:
		// Handle CMStatus
		log.Debugf("updating CMStatus in DeployConfig CR for request: %v", req.Request)
		configCR.Status.CMStatus = req.Request.(*v1.CMStatus)
		if req.Exit {
			exit = true
			exitErr = fmt.Errorf("%v", configCR.Status.CMStatus.Error)
		}
	case *v1.BigIPStatus:
		// Handle BigIPStatus
		log.Debugf("updating BigIPStatus in DeployConfig CR for request: %v", req.Request)
		bigIpStatus := *req.Request.(*v1.BigIPStatus)
		sm.updateBigIPStatus(configCR, &bigIpStatus)
	case *v1.NetworkConfigStatus:
		// Handle NetworkConfigStatus
		log.Debugf("updating NetworkConfigStatus in DeployConfig CR for request: %v", req.Request)
		configCR.Status.NetworkConfigStatus = req.Request.(*v1.NetworkConfigStatus)
		if req.Exit {
			exit = true
			exitErr = fmt.Errorf("%v", configCR.Status.NetworkConfigStatus.Error)
		}
	case *v1.ControllerStatus:
		// Handle ControllerStatus
		log.Debugf("updating ControllerStatus in DeployConfig CR for request: %v", req.Request)
		configCR.Status.ControllerStatus = req.Request.(*v1.ControllerStatus)
		if configCR.Status.ControllerStatus.Type == "" {
			configCR.Status.ControllerStatus.Type = SingleCluster
		} else {
			configCR.Status.ControllerStatus.Type = MultiClusterPrefix + configCR.Status.ControllerStatus.Type
		}
		if req.Exit {
			exit = true
			exitErr = fmt.Errorf("%v", configCR.Status.ControllerStatus.Error)
		}
	case *v1.HAStatus:
		// Handle HAStatus
		log.Debugf("updating HAStatus in DeployConfig CR for request: %v", req.Request)
		configCR.Status.HAStatus = *req.Request.(*[]v1.HAStatus)
		if req.Exit {
			exit = true
			exitErr = fmt.Errorf("%v", configCR.Status.HAStatus)
		}
	case *v1.K8SClusterStatus:
		// Handle K8SClusterStatus
		log.Debugf("updating K8SClusterStatus in DeployConfig CR for request: %v", req.Request)
		configCR.Status.K8SClusterStatus = *req.Request.(*[]v1.K8SClusterStatus)
		if req.Exit {
			exit = true
			exitErr = fmt.Errorf("%v", configCR.Status.K8SClusterStatus)
		}
	default:
		if req.Exit {
			exit = true
			exitErr = fmt.Errorf("unknown DeployConfig status request: %v", *req)
		}
		log.Errorf("Unknown DeployConfig status request: %v", *req)
	}
	_, err := (*sm.kubeCRClient).CisV1().DeployConfigs(configCR.Namespace).UpdateStatus(context.TODO(), configCR, metaV1.UpdateOptions{})
	if err != nil {
		log.Errorf("Failed to update DeployConfig status for request %v: %v", *req, err)
	}
	if exit {
		log.Fatalf("Controller failed: %v", exitErr)
	}
}

// func to update the bigip status
func (sm *StatusManager) updateBigIPStatus(configCR *v1.DeployConfig, bigipStatus *v1.BigIPStatus) {
	// for the first entry in the deploy config status
	if configCR.Status.BigIPStatus == nil {
		if bigipStatus.AS3Status != nil {
			if bigipStatus.AS3Status.Message == Ok || bigipStatus.AS3Status.Message == Accepted {
				bigipStatus.AS3Status.LastSuccessful = bigipStatus.AS3Status.LastSubmitted
			}
		}
		if bigipStatus.L3Status != nil {
			if bigipStatus.L3Status.Message == Ok || bigipStatus.L3Status.Message == Accepted {
				bigipStatus.L3Status.LastSuccessful = bigipStatus.L3Status.LastSubmitted
			}
		}
		configCR.Status.BigIPStatus = []v1.BigIPStatus{*bigipStatus}
		return
	}
	var found bool
	var index int
	var bigip v1.BigIPStatus
	for index, bigip = range configCR.Status.BigIPStatus {
		if bigip.BigIPAddress == bigipStatus.BigIPAddress {
			found = true
			break
		}
	}
	if !found {
		// for the second entry of a new bigip in the deploy config status
		if bigipStatus.AS3Status != nil {
			if bigipStatus.AS3Status.Message == Ok || bigipStatus.AS3Status.Message == Accepted {
				bigipStatus.AS3Status.LastSuccessful = bigipStatus.AS3Status.LastSubmitted
			}
		}
		if bigipStatus.L3Status != nil {
			if bigipStatus.L3Status.Message == Ok || bigipStatus.L3Status.Message == Accepted {
				bigipStatus.L3Status.LastSuccessful = bigipStatus.L3Status.LastSubmitted
			}
		}
		configCR.Status.BigIPStatus = append(configCR.Status.BigIPStatus, *bigipStatus)
		return
	} else {
		// Let's check if the bigip status needs to be deleted or not if bigip instance is removed from the deploy config
		if bigipStatus.L3Status == nil && bigipStatus.AS3Status == nil {
			configCR.Status.BigIPStatus = append(configCR.Status.BigIPStatus[:index], configCR.Status.BigIPStatus[index+1:]...)
			return
		}
		// Update the status of the existing bigip in the deploy config status
		if bigipStatus.L3Status == nil {
			if configCR.Status.BigIPStatus[index].AS3Status != nil {
				if bigipStatus.AS3Status.Message == Ok || bigipStatus.AS3Status.Message == Accepted {
					configCR.Status.BigIPStatus[index].AS3Status.Message = bigipStatus.AS3Status.Message
					configCR.Status.BigIPStatus[index].AS3Status.Error = ""
					configCR.Status.BigIPStatus[index].AS3Status.LastSubmitted = bigipStatus.AS3Status.LastSubmitted
					configCR.Status.BigIPStatus[index].AS3Status.LastSuccessful = bigipStatus.AS3Status.LastSubmitted
				} else {
					configCR.Status.BigIPStatus[index].AS3Status.Message = bigipStatus.AS3Status.Message
					configCR.Status.BigIPStatus[index].AS3Status.Error = bigipStatus.AS3Status.Error
					configCR.Status.BigIPStatus[index].AS3Status.LastSubmitted = bigipStatus.AS3Status.LastSubmitted
				}
			} else {
				configCR.Status.BigIPStatus[index].AS3Status = bigipStatus.AS3Status
			}
		}
		if bigipStatus.AS3Status == nil {
			if configCR.Status.BigIPStatus[index].L3Status != nil {
				if bigipStatus.L3Status.Message == Ok || bigipStatus.L3Status.Message == Accepted {
					configCR.Status.BigIPStatus[index].L3Status.Message = bigipStatus.L3Status.Message
					configCR.Status.BigIPStatus[index].L3Status.Error = ""
					configCR.Status.BigIPStatus[index].L3Status.LastSubmitted = bigipStatus.L3Status.LastSubmitted
					configCR.Status.BigIPStatus[index].L3Status.LastSuccessful = bigipStatus.L3Status.LastSubmitted
				} else {
					configCR.Status.BigIPStatus[index].L3Status.Message = bigipStatus.L3Status.Message
					configCR.Status.BigIPStatus[index].L3Status.Error = bigipStatus.L3Status.Error
					configCR.Status.BigIPStatus[index].L3Status.LastSubmitted = bigipStatus.L3Status.LastSubmitted
				}
			} else {
				configCR.Status.BigIPStatus[index].L3Status = bigipStatus.L3Status
			}
		}
	}
}

func (sm *StatusManager) AddDeployInformer(informer *cache.SharedIndexInformer, namespace string) {
	sm.deployConfigResource.Lock()
	defer sm.deployConfigResource.Unlock()
	if sm.deployConfigResource.deployConfigInformer == nil {
		if namespace == "" || namespace == sm.deployConfigResource.namespace {
			sm.deployConfigResource.deployConfigInformer = informer
		}
	}
}
