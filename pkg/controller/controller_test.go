package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager/mockmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"time"
)

var _ = Describe("getPersistenceType", func() {
	Context("when the input key is empty", func() {
		It("should return an empty string", func() {
			Expect(getPersistenceType("")).To(Equal(""))
		})
	})

	Context("when the input key matches a supported persistence type", func() {
		It("should return 'uie' for 'uieSourceAddress'", func() {
			Expect(getPersistenceType("uieSourceAddress")).To(Equal("uie"))
		})

		It("should return 'hash' for 'hashSourceAddress'", func() {
			Expect(getPersistenceType("hashSourceAddress")).To(Equal("hash"))
		})
	})

	Context("when the input key does not match any supported persistence type", func() {
		It("should return an empty string", func() {
			Expect(getPersistenceType("unsupportedKey")).To(Equal(""))
		})
	})
})

var _ = Describe("New Controller", func() {
	var server *ghttp.Server
	var statusCode int
	var params Params
	var mockStatusManager *mockmanager.MockStatusManager
	namespace := "default"
	configCRName := "sampleConfigCR"
	BeforeEach(func() {
		// Mock the token server
		server = ghttp.NewServer()
		mockStatusManager = mockmanager.NewMockStatusManager()
		configCR := test.NewConfigCR(
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
		params = Params{
			CISConfigCRKey: namespace + "/" + configCRName,
			CMConfigDetails: &CMConfig{
				URL:      server.URL(),
				UserName: "admin",
				Password: "admin",
			},
			ClientSets: &ClientSets{
				RouteClientV1: fakeRouteClient.NewSimpleClientset().RouteV1(),
				KubeCRClient:  crdfake.NewSimpleClientset(configCR),
				KubeClient:    k8sfake.NewSimpleClientset(),
			},
		}
	})
	AfterEach(func() {
		// Stop the mock token server
		server.Close()
	})
	It("should create, start and stop the controller", func() {
		statusCode = 200
		responseLogin := tokenmanager.TokenResponse{
			AccessToken: "test.token",
		}
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/api/login"),
				ghttp.RespondWithJSONEncoded(statusCode, responseLogin),
			))
		responseVersion := map[string]interface{}{
			"version": "BIG-IP-Next-CentralManager-20.1.0-1",
		}
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", tokenmanager.CMVersionURL),
				ghttp.RespondWithJSONEncoded(statusCode, responseVersion),
			))
		ctlr := NewController(params, mockStatusManager)
		Expect(ctlr).ToNot(BeNil())
		time.Sleep(1 * time.Second)
		token := ctlr.CMTokenManager.GetToken()
		Expect(token).To(BeEquivalentTo("test.token"), "Token should be empty")
		Expect(ctlr.CMTokenManager.CMVersion).To(Equal("20.1.0"))
		Expect(ctlr.RequestHandler).ToNot(BeNil())
		Expect(ctlr.resourceQueue).ToNot(BeNil())
		Expect(ctlr.CISConfigCRKey).To(Equal(namespace + "/" + configCRName))
		Expect(ctlr.namespaces).ToNot(BeNil())
		Expect(ctlr.comInformers).ToNot(BeNil())
		// Let's try to start the controller
		stopChan := make(chan struct{})
		go ctlr.Start(stopChan)
		// Let's try to stop the controller
		stopChan <- struct{}{}
	})
})
