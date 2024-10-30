package clustermanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
)

type AdminState string

const (
	Disable AdminState = "disable"
	Enable  AdminState = "enable"
	Offline AdminState = "offline"
	NoPool  AdminState = "no-pool"
)

type (
	// MultiClusterConfig defines a structure for holding cluster configuration
	MultiClusterConfig struct {
		ClusterConfigs    map[string]ClusterConfig
		HAPairClusterName string
		LocalClusterName  string
	}

	ClusterConfig struct {
		KubeClient   kubernetes.Interface
		KubeCRClient versioned.Interface
		// Maintain a mapping of managed resources -> services and services -> resources
		//ManagedResources
		// Maintain a mapping of managed informers -> services and services -> informers
		//ManagedInformers
	}

	// MultiClusterConfig defines a structure for holding cluster configuration
	HAClusterConfig struct {
		ClusterConfigs map[string]ClusterConfig
	}

	//ManagedResources struct {
	//	managedResources map[string]ManagedResource
	//	sync.Mutex
	//}
	//
	//ManagedResource struct {
	//	Name             string
	//	Kind             string
	//	Service          string
	//	ServiceNamespace string
	//}
	//
	//ManagedInformers struct {
	//}
)
