package clustermanager

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	Disable cisapiv1.AdminState = "disable"
	Enable  cisapiv1.AdminState = "enable"
	Offline cisapiv1.AdminState = "offline"
)

type (
	// MultiClusterConfig defines a structure for holding cluster configuration
	MultiClusterConfig struct {
		ClusterConfigs    map[string]ClusterConfig
		HAPairClusterName string
		LocalClusterName  string
	}

	ClusterConfig struct {
		KubeClient kubernetes.Interface
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
