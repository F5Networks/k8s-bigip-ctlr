package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo"
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
		mockCtlr.TeemData = &teem.TeemsData{SDNType: "other"}
		selectors = make(map[string]string)

	})
	It("Check the SDNType Cilium", func() {
		pod = test.NewPod("cilium-node1", "default", 8080, selectors)
		pod.Status.Phase = "Running"
		mockCtlr.kubeClient = k8sfake.NewSimpleClientset(pod)
		mockCtlr.setOtherSDNType()
		Expect(mockCtlr.TeemData.SDNType).To(Equal("cilium"), "SDNType should be cilium")
	})
	It("Check the SDNType Calico", func() {
		pod = test.NewPod("calico-node1", "default", 8080, selectors)
		pod.Status.Phase = "Running"
		mockCtlr.kubeClient = k8sfake.NewSimpleClientset(pod)
		mockCtlr.setOtherSDNType()
		Expect(mockCtlr.TeemData.SDNType).To(Equal("calico"), "SDNType should be calico")
	})
	It("Check the SDNType other", func() {
		pod = test.NewPod("node1", "default", 8080, selectors)
		pod.Status.Phase = "Running"
		mockCtlr.kubeClient = k8sfake.NewSimpleClientset(pod)
		mockCtlr.setOtherSDNType()
		Expect(mockCtlr.TeemData.SDNType).To(Equal("other"), "SDNType should be other")
	})
	It("Create a new controller object", func() {
		ctlrOpenShift := NewController(Params{
			Mode:           OpenShiftMode,
			PoolMemberType: Cluster,
			Config:         &rest.Config{},
			NamespaceLabel: "ctlr=cis",
			VXLANMode:      "multi-point",
			VXLANName:      "vxlan0",
			Agent:          newMockAgent(&test.MockWriter{FailStyle: test.Success}),
		}, false)
		Expect(ctlrOpenShift.processedHostPath).NotTo(BeNil(), "processedHostPath object should not be nil")
		Expect(ctlrOpenShift.shareNodes).To(BeFalse(), "shareNodes should not be enable")
		Expect(ctlrOpenShift.vxlanMgr).To(BeNil(), "vxlanMgr should be created")
		ctlrK8s := NewController(Params{
			Mode:           CustomResourceMode,
			PoolMemberType: NodePort,
			Config:         &rest.Config{},
			IPAM:           true,
		}, false)
		Expect(ctlrK8s.processedHostPath).To(BeNil(), "processedHostPath object should be nil")
		Expect(ctlrK8s.shareNodes).To(BeTrue(), "shareNodes should be enable")
	})
})
