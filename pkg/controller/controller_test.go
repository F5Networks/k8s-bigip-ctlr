package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

var _ = Describe("OtherSDNType", func() {
	var mockCtlr *mockController
	var selectors map[string]string
	var pod *v1.Pod
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{InformerStore: initInformerStore(),
			namespaces: make(map[string]struct{})}
		mockCtlr.TeemData = &teem.TeemsData{SDNType: "other"}
		selectors = make(map[string]string)

	})
	It("Check the SDNType Cilium", func() {
		pod = test.NewPod("cilium-node1", "default", 8080, selectors)
		pod.Status.Phase = "Running"
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(pod)}
		mockCtlr.setOtherSDNType()
		Expect(mockCtlr.TeemData.SDNType).To(Equal("cilium"), "SDNType should be cilium")
	})
	It("Check the SDNType Calico", func() {
		pod = test.NewPod("calico-node1", "default", 8080, selectors)
		pod.Status.Phase = "Running"
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(pod)}
		mockCtlr.setOtherSDNType()
		Expect(mockCtlr.TeemData.SDNType).To(Equal("calico"), "SDNType should be calico")
	})
	It("Check the SDNType other", func() {
		pod = test.NewPod("node1", "default", 8080, selectors)
		pod.Status.Phase = "Running"
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(pod)}
		mockCtlr.setOtherSDNType()
		Expect(mockCtlr.TeemData.SDNType).To(Equal("other"), "SDNType should be other")
	})
	It("Create a new controller object", func() {
		mockWriter := &test.MockWriter{FailStyle: test.Success}
		mockRequestHandler := newMockRequestHandler(mockWriter)
		ctlrOpenShift := NewController(Params{
			Mode:           OpenShiftMode,
			PoolMemberType: Cluster,
			Config:         &rest.Config{},
			NamespaceLabel: "ctlr=cis",
			VXLANMode:      "multi-point",
			VXLANName:      "vxlan0",
		}, false,
			AgentParams{
				ApiType: AS3,
				PrimaryParams: PostParams{BIGIPURL: "http://127.0.0.1:8080",
					BIGIPPassword: "password",
					BIGIPUsername: "username"},
				Partition: "default",
			},
			mockRequestHandler)
		Expect(ctlrOpenShift.processedHostPath).NotTo(BeNil(), "processedHostPath object should not be nil")
		Expect(ctlrOpenShift.shareNodes).To(BeFalse(), "shareNodes should not be enable")
		Expect(ctlrOpenShift.vxlanMgr).To(BeNil(), "vxlanMgr should be created")
		DEFAULT_PARTITION = "test"
		ctlrK8s := NewController(Params{
			Mode:           CustomResourceMode,
			PoolMemberType: NodePort,
			Config:         &rest.Config{},
			IPAM:           true,
		}, false,
			AgentParams{
				PrimaryParams: PostParams{BIGIPURL: "http://127.0.0.1:8080"},
			},
			mockRequestHandler)
		Expect(ctlrK8s.processedHostPath).To(BeNil(), "processedHostPath object should be nil")
		Expect(ctlrK8s.shareNodes).To(BeTrue(), "shareNodes should be enable")
	})
	It("Validate the IPAM configuration", func() {
		mockWriter := &test.MockWriter{FailStyle: test.Success}
		mockRequestHandler := newMockRequestHandler(mockWriter)
		ctlr := NewController(Params{
			Config: &rest.Config{},
		}, false,
			AgentParams{
				PrimaryParams: PostParams{BIGIPURL: "http://127.0.0.1:8080"},
			},
			mockRequestHandler)
		ctlr.multiClusterHandler = NewClusterHandler("")
		ctlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{InformerStore: initInformerStore(),
			namespaces: make(map[string]struct{})}
		Expect(ctlr.validateIPAMConfig("kube-system")).To(BeFalse(), "ipam namespace should not be valid")
		ctlr.multiClusterHandler.ClusterConfigs[""].namespaces["kube-system"] = struct{}{}
		Expect(ctlr.validateIPAMConfig("kube-system")).To(BeTrue(), "ipam namespace should be valid")
		Expect(ctlr.validateIPAMConfig("default")).To(BeFalse(), "ipam namespace should not be valid")
		ctlr.multiClusterHandler.ClusterConfigs[""].namespaces[""] = struct{}{}
		Expect(ctlr.validateIPAMConfig("default")).To(BeTrue(), "ipam namespace should be valid")
	})
})
