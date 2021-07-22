package ipammachinery

import (
	"github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/client/clientset/versioned"
	ipamFake "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/client/clientset/versioned/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func NewFakeIPAMClient(
	kubeCRClient versioned.Interface,
	kubeClient kubernetes.Interface,
	restClient rest.Interface,
) *IPAMClient {

	ipamCli := &IPAMClient{}

	ipamCli.kubeCRClient = kubeCRClient
	if kubeCRClient == nil {
		ipamCli.kubeCRClient = ipamFake.NewSimpleClientset()
	}

	ipamCli.kubeClient = kubeClient

	ipamCli.restClient = restClient

	return ipamCli
}
