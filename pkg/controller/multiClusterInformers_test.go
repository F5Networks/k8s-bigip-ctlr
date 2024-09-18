package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/clustermanager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("MultiClusterInformers", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		clusterName := "cluster-1"
		mockCtlr.multiClusterConfigs.ClusterConfigs[clusterName] = clustermanager.ClusterConfig{KubeClient: k8sfake.NewSimpleClientset()}
		mockCtlr.multiClusterPoolInformers = make(map[string]map[string]*MultiClusterPoolInformer)
		mockCtlr.multiClusterNodeInformers = make(map[string]*NodeInformer)
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
		Expect(len(mockCtlr.multiClusterPoolInformers)).To(Equal(0))
		Expect(len(mockCtlr.multiClusterNodeInformers)).To(Equal(0))
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
		Expect(len(mockCtlr.multiClusterPoolInformers)).NotTo(Equal(0))
		for clusterNameKey, _ := range mockCtlr.multiClusterPoolInformers {
			Expect(mockCtlr.multiClusterPoolInformers[clusterNameKey]).To(HaveKey(ns))
		}
	})
})
