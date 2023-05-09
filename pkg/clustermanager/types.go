package clustermanager

import (
	"k8s.io/client-go/kubernetes"
)

type (
	// MultiClusterConfig defines a structure for holding cluster configuration
	MultiClusterConfig struct {
		ClusterConfigs   map[string]ClusterConfig
		HAPairCusterName string
	}

	ClusterConfig struct {
		HACIS      string
		KubeClient kubernetes.Interface
		// Maintain a mapping of managed resources -> services and services -> resources
		//ManagedResources
		// Maintain a mapping of managed informers -> services and services -> informers
		//ManagedInformers
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
