package clustermanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func CreateKubeClientFromKubeConfig(config *rest.Config) (kubernetes.Interface, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return kubeClient, nil
}

func CreateKubeCRClientFromKubeConfig(config *rest.Config) (versioned.Interface, error) {
	kubeCRClient, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return kubeCRClient, nil
}

func CreateKubeIPAMClientFromKubeConfig(config *rest.Config) (*extClient.Clientset, error) {
	kubeIPAMClient, err := extClient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return kubeIPAMClient, nil
}

func CreateRouteClientFromKubeconfig(config *rest.Config) (*routeclient.RouteV1Client, error) {
	rclient, err := routeclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return rclient, nil
}
