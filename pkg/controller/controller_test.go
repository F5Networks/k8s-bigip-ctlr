package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
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
})
