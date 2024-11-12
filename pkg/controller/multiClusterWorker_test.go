package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("MultiClusterWorker", func() {
	var mockCtlr *mockController
	var svc *v1.Service
	var clusterName string
	var clusterName2 string
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		clusterName = "cluster-1"
		clusterName2 = "cluster-2"
		mockCtlr.multiClusterHandler.HAPairClusterName = "cluster-2"
		svc = test.NewService(
			"svc1",
			"1",
			"ns",
			v1.ServiceTypeClusterIP,
			[]v1.ServicePort{
				{
					Port: 80,
					Name: "port0",
				},
			},
		)
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(svc)}
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName2] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(svc)}
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName].InformerStore = initInformerStore()
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName2].InformerStore = initInformerStore()
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
	})
	It("Get service from HA cluster", func() {
		mockCtlr.discoveryMode = Active
		svcKey := MultiClusterServiceKey{
			serviceName: "svc1",
			namespace:   "ns",
			clusterName: clusterName,
		}
		err := mockCtlr.setupAndStartMultiClusterInformers(svcKey, false)
		Expect(err).To(BeNil())
		_, exists, err := mockCtlr.getSvcFromHACluster(svcKey.namespace, svcKey.serviceName)
		Expect(err).NotTo(BeNil())
		Expect(exists).To(BeFalse())
		svcKey2 := MultiClusterServiceKey{
			serviceName: "svc-1",
			namespace:   "ns",
			clusterName: clusterName2,
		}
		err2 := mockCtlr.setupAndStartMultiClusterInformers(svcKey2, false)
		Expect(err2).To(BeNil())
		port, err := mockCtlr.getSvcPortFromHACluster(svcKey.namespace, svcKey.serviceName, "port0", "")
		Expect(err).NotTo(BeNil())
		Expect(port).To(BeZero())
	})
})
