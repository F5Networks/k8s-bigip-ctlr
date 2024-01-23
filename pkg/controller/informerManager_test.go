package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Informers Tests", func() {
	var mockCtlr *mockController
	namespace := "default"
	var configCR *cisapiv1.DeployConfig
	configCRName := "sampleConfigCR"
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.CISConfigCRKey = namespace + "/" + configCRName
		mockCtlr.resources = NewResourceStore()
		configCR = test.NewConfigCR(
			configCRName,
			namespace,
			cisapiv1.DeployConfigSpec{
				BaseConfig: cisapiv1.BaseConfig{
					NodeLabel:      "",
					RouteLabel:     "",
					NamespaceLabel: "",
				},
			},
		)
		mockCtlr.clientsets = &ClientSets{
			routeClientV1: fakeRouteClient.NewSimpleClientset().RouteV1(),
			kubeCRClient:  crdfake.NewSimpleClientset(configCR),
			kubeClient:    k8sfake.NewSimpleClientset(),
		}
		mockCtlr.managedResources = ManagedResources{
			ManageRoutes:          true,
			ManageCustomResources: true,
		}
	})

	Describe("Controller reset tests", func() {
		//It("Controller reset with namespaceLabel", func() {
		//	newconfigCR := test.NewConfigCR(
		//		configCRName,
		//		namespace,
		//		cisapiv1.DeployConfigSpec{
		//			BaseConfig: cisapiv1.BaseConfig{
		//				NodeLabel:      "new-node-label",
		//				RouteLabel:     "new-route-label",
		//				NamespaceLabel: "new-namespace-label",
		//			},
		//		},
		//	)
		//	mockCtlr.enqueueUpdatedConfigCR(configCR, newconfigCR)
		//	Expect(mockCtlr.resources.ltmConfig).ToNot(BeNil(), "Failed to reset controller")
		//	Expect(mockCtlr.resourceSelectorConfig.NodeLabel).To(Equal("new-node-label"), "Failed to reset controller")
		//	Expect(mockCtlr.resourceSelectorConfig.RouteLabel).To(Equal("new-route-label"), "Failed to reset controller")
		//	Expect(mockCtlr.resourceSelectorConfig.NamespaceLabel).To(Equal("new-namespace-label"), "Failed to reset controller")
		//
		//})
		It("Controller infromer setup for all namespaces", func() {
			mockCtlr.initController()
			Expect(mockCtlr.resourceSelectorConfig.NodeLabel).To(Equal(""), "Failed to initialize informers")
			Expect(mockCtlr.resourceSelectorConfig.RouteLabel).To(Equal(""), "Failed to initialize informers")
			Expect(mockCtlr.resourceSelectorConfig.NamespaceLabel).To(Equal(""), "Failed to initialize informers")
			Expect(mockCtlr.namespaces[""]).To(BeTrue(), "Failed to initialize informers")
			mockCtlr.setupInformers()
			comInf, _ := mockCtlr.getNamespacedCommonInformer("")
			Expect(comInf).ToNot(BeNil(), "Failed to setup informers")
			crInf, _ := mockCtlr.getNamespacedCRInformer("")
			Expect(crInf).ToNot(BeNil(), "Failed to setup informers")
			nodeInf := mockCtlr.getNodeInformer("")
			Expect(nodeInf).ToNot(BeNil(), "Failed to setup informers")
			newconfigCR := test.NewConfigCR(
				configCRName,
				namespace,
				cisapiv1.DeployConfigSpec{
					BaseConfig: cisapiv1.BaseConfig{
						NodeLabel:      "new-node-label",
						RouteLabel:     "new-route-label",
						NamespaceLabel: "",
					},
				},
			)
			mockCtlr.enqueueUpdatedConfigCR(configCR, newconfigCR)
			Expect(mockCtlr.resourceSelectorConfig.NodeLabel).To(Equal("new-node-label"), "Failed to reset controller")
			Expect(mockCtlr.resourceSelectorConfig.RouteLabel).To(Equal("new-route-label"), "Failed to reset controller")
			Expect(mockCtlr.resourceSelectorConfig.NamespaceLabel).To(Equal(""), "Failed to reset controller")
			mockCtlr.stopInformers()
		})
		It("Controller reset with nodeLabel", func() {
			mockCtlr.initController()
			mockCtlr.setupInformers()
			newconfigCR := test.NewConfigCR(
				configCRName,
				namespace,
				cisapiv1.DeployConfigSpec{
					BaseConfig: cisapiv1.BaseConfig{
						NodeLabel:      "new-node-label",
						RouteLabel:     "",
						NamespaceLabel: "",
					},
				},
			)
			mockCtlr.enqueueUpdatedConfigCR(configCR, newconfigCR)
			Expect(mockCtlr.resourceSelectorConfig.NodeLabel).To(Equal("new-node-label"), "Failed to reset controller")
			Expect(mockCtlr.resourceSelectorConfig.RouteLabel).To(Equal(""), "Failed to reset controller")
			Expect(mockCtlr.resourceSelectorConfig.NamespaceLabel).To(Equal(""), "Failed to reset controller")
			mockCtlr.stopInformers()
		})
	})
})
