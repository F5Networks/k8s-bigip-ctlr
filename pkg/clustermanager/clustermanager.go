package clustermanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// NewMultiClusterConfig creates a new instance of MultiClusterConfig
func NewMultiClusterConfig() *MultiClusterConfig {
	return &MultiClusterConfig{
		ClusterConfigs: make(map[string]ClusterConfig),
	}
}

func CreateKubeClientFromKubeConfig(kubeConfig *[]byte) (kubernetes.Interface, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(*kubeConfig)
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return kubeClient, nil
}

func CreateKubeCRClientFromKubeConfig(kubeConfig *[]byte) (versioned.Interface, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(*kubeConfig)
	if err != nil {
		return nil, err
	}
	kubeCRClient, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return kubeCRClient, nil
}
