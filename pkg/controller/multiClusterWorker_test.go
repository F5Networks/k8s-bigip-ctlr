package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
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
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		clusterName = "cluster-1"
		clusterName2 = "cluster-2"
		mockCtlr.multiClusterConfigs.HAPairClusterName = "cluster-2"
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
		mockCtlr.multiClusterConfigs.ClusterConfigs[clusterName] = clustermanager.ClusterConfig{KubeClient: k8sfake.NewSimpleClientset(svc)}
		mockCtlr.multiClusterConfigs.ClusterConfigs[clusterName2] = clustermanager.ClusterConfig{KubeClient: k8sfake.NewSimpleClientset(svc)}
		mockCtlr.multiClusterPoolInformers = make(map[string]map[string]*MultiClusterPoolInformer)
		mockCtlr.multiClusterNodeInformers = make(map[string]*NodeInformer)
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
	})
	It("Get service from HA cluster", func() {
		mockCtlr.haModeType = Active
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

var _ = Describe("Test Cluster config updated", func() {
	var (
		mockCtlr *mockController
	)

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.clusterRatio = make(map[string]*int)
		mockCtlr.clusterAdminState = make(map[string]cisapiv1.AdminState)
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
	})

	Context("getClusterConfigState", func() {
		It("should return the current cluster state with empty ratios and admin states", func() {
			state := mockCtlr.getClusterConfigState()
			Expect(state.clusterRatio).To(BeEmpty())
			Expect(state.clusterAdminState).To(BeEmpty())
		})

		It("should return the current cluster state with existing ratios and admin states", func() {
			ratio1 := 1
			mockCtlr.clusterRatio["cluster1"] = &ratio1
			mockCtlr.clusterAdminState["cluster1"] = "enabled"

			state := mockCtlr.getClusterConfigState()
			Expect(state.clusterRatio).To(HaveKeyWithValue("cluster1", 1))
			Expect(state.clusterAdminState).To(HaveKey("cluster1"))
		})
	})

	Context("isClusterConfigUpdated", func() {
		var oldState clusterConfigState

		BeforeEach(func() {
			oldState = clusterConfigState{
				clusterRatio:      make(map[string]int),
				clusterAdminState: make(map[string]cisapiv1.AdminState),
			}
		})

		It("should return false if there are no updates to the cluster ratio or admin state", func() {
			Expect(mockCtlr.isClusterConfigUpdated(oldState)).To(BeFalse())
		})

		It("should return true if the cluster ratio is updated", func() {
			ratio1 := 1
			mockCtlr.clusterRatio["cluster1"] = &ratio1
			Expect(mockCtlr.isClusterConfigUpdated(oldState)).To(BeTrue())
		})

		It("should return true if the cluster admin state is updated", func() {
			mockCtlr.clusterAdminState["cluster1"] = "enabled"
			Expect(mockCtlr.isClusterConfigUpdated(oldState)).To(BeTrue())
		})

		It("should return false if the cluster ratio and admin state are the same", func() {
			ratio1 := 1
			oldState.clusterRatio["cluster1"] = ratio1
			mockCtlr.clusterRatio["cluster1"] = &ratio1

			oldState.clusterAdminState["cluster1"] = "enabled"
			mockCtlr.clusterAdminState["cluster1"] = "enabled"

			Expect(mockCtlr.isClusterConfigUpdated(oldState)).To(BeFalse())
		})

		It("should return true if the cluster ratio is different", func() {
			ratio1 := 1
			ratio2 := 2
			oldState.clusterRatio["cluster1"] = ratio1
			mockCtlr.clusterRatio["cluster1"] = &ratio2
			Expect(mockCtlr.isClusterConfigUpdated(oldState)).To(BeTrue())
		})

		It("should return true if the cluster admin state is different", func() {
			oldState.clusterAdminState["cluster1"] = "enabled"
			mockCtlr.clusterAdminState["cluster1"] = "disable"
			Expect(mockCtlr.isClusterConfigUpdated(oldState)).To(BeTrue())
		})
	})
})
