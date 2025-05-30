package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var _ = Describe("MultiClusterInformers", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
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
		mockCtlr.stopMultiClusterPoolInformers(svcKey.clusterName, false)
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
	// New test case for dynamic informers with Calico CNI static routing
	It("Creates dynamic informers for Calico CNI with static routing enabled", func() {
		// Setup controller with Calico CNI and static routing
		mockCtlr.OrchestrationCNI = CALICO_K8S
		mockCtlr.StaticRoutingMode = true
		clusterName := "cluster-1"

		// Create a fake dynamic client
		scheme := runtime.NewScheme()
		dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme)

		// Setup mock for RBAC check
		// Create a fake client that returns allowed for RBAC check
		fakeClient := k8sfake.NewSimpleClientset()
		mockCtlr.multiClusterHandler.ClusterConfigs[clusterName].kubeClient = fakeClient

		// Mock the SelfSubjectAccessReview response
		fakeClient.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := &authv1.SelfSubjectAccessReview{
				Status: authv1.SubjectAccessReviewStatus{
					Allowed: true,
				},
			}
			return true, review, nil
		})

		// Create dynamic informers
		dynamicInformers := mockCtlr.newDynamicInformersForCluster(dynamicClient, clusterName)

		// Verify dynamic informers were created correctly
		Expect(dynamicInformers).NotTo(BeNil())
		Expect(dynamicInformers.clusterName).To(Equal(clusterName))
		Expect(dynamicInformers.stopCh).NotTo(BeNil())

		// Verify Calico BlockAffinity informer was created
		Expect(dynamicInformers.CalicoBlockAffinityInformer).NotTo(BeNil())

		// Verify the dynamic informers were stored in the cluster config
		Expect(mockCtlr.multiClusterHandler.ClusterConfigs[clusterName].InformerStore.dynamicInformers).To(Equal(dynamicInformers))

	})

	It("Does not create Calico informers when static routing is disabled", func() {
		// Setup controller with Calico CNI but static routing disabled
		mockCtlr.OrchestrationCNI = CALICO_K8S
		mockCtlr.StaticRoutingMode = false
		clusterName := "cluster-1"

		// Create a fake dynamic client
		scheme := runtime.NewScheme()
		dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme)

		// Create dynamic informers
		dynamicInformers := mockCtlr.newDynamicInformersForCluster(dynamicClient, clusterName)

		// Verify dynamic informers were created but without Calico informers
		Expect(dynamicInformers).NotTo(BeNil())
		Expect(dynamicInformers.CalicoBlockAffinityInformer).To(BeNil())
	})
})
