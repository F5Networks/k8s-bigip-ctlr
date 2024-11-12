package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("MultiClusterInformers", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		clusterName := "cluster-1"
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset()}
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName].InformerStore = initInformerStore()
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
	})
	It("Setup and start multi-cluster informers NodePortLocal", func() {
		mockCtlr.PoolMemberType = NodePortLocal
		svcKey := MultiClusterServiceKey{
			serviceName: "svc-1",
			namespace:   "ns",
			clusterName: "cluster-1",
		}
		err := mockCtlr.setupAndStartMultiClusterInformers(svcKey, false)
		Expect(err).To(BeNil())
		poolInf, found := mockCtlr.getNamespaceMultiClusterPoolInformer(svcKey.namespace, svcKey.clusterName)
		Expect(found).To(BeTrue())
		Expect(poolInf).ToNot(BeNil())
		mockCtlr.stopMultiClusterInformers(svcKey.clusterName, false)
		Expect(len(mockCtlr.multiClusterHandler.ClusterConfigs["cluster-1"].comInformers)).To(Equal(0))
	})
	It("Setup and start multi-cluster informers Cluster", func() {
		mockCtlr.PoolMemberType = Cluster
		svcKey := MultiClusterServiceKey{
			serviceName: "svc-1",
			namespace:   "ns",
			clusterName: "cluster-1",
		}
		err := mockCtlr.setupAndStartMultiClusterInformers(svcKey, false)
		Expect(err).To(BeNil())
	})
	It("Verifies creation and deletion of namespace informers for multiCluster Cluster in case of namespace label", func() {
		mockCtlr.PoolMemberType = Cluster
		ns := "test-new-ns"
		err := mockCtlr.updateMultiClusterInformers(ns, false)
		Expect(err).To(BeNil())
		Expect(len(mockCtlr.multiClusterHandler.ClusterConfigs)).NotTo(Equal(0))
		Expect(mockCtlr.multiClusterHandler.ClusterConfigs["cluster-1"].comInformers).To(HaveKey(ns))
	})
})
