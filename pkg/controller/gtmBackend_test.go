package controller

import (
	"io"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Backend Tests", func() {

	Describe("GTM Worker test", func() {
		var agent *Agent
		var postConfig *agentPostConfig
		var mockBaseAPIHandler *BaseAPIHandler
		BeforeEach(func() {
			mockBaseAPIHandler = newMockBaseAPIHandler()
			agent = &Agent{}
			tenantDeclMap := make(map[string]as3Tenant)
			tenantDeclMap["test_gtm"] = as3Tenant{
				"class":              "Tenant",
				"defaultRouteDomain": 0,
				as3SharedApplication: "shared",
				"label":              "cis2.x",
			}
			postConfig = &agentPostConfig{
				reqMeta: requestMeta{
					id: 1,
				},
				as3APIURL:             "https://127.0.0.1/mgmt/shared/appsvcs/declare",
				data:                  `{"class": "AS3", "declaration": {"class": "ADC", "test": {"class": "Tenant", "testApp": {"class": "Application", "webcert":{"class": "Certificate", "certificate": "abc", "privateKey": "abc", "chainCA": "abc"}}}}}`,
				incomingTenantDeclMap: tenantDeclMap,
				tenantResponseMap:     make(map[string]tenantResponse),
			}
		})
		It("GTM worker", func() {
			client, _ := getMockHttpClient([]responseCtx{{
				tenant: "test_gtm",
				status: http.StatusOK,
				body:   io.NopCloser(strings.NewReader("{\"results\": [{\"code\": 200, \"message\": \"success\", \"tenant\": \"test_gtm\"}], \"declaration\": {\"class\": \"ADC\", \"test\": {\"class\": \"Tenant\", \"testApp\": {\"class\": \"Application\", \"webcert\":{\"class\": \"Certificate\", \"certificate\": \"abc\", \"privateKey\": \"abc\", \"chainCA\": \"abc\"}}}}}")),
			}}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			agent.APIHandler = &APIHandler{
				LTM: &LTMAPIHandler{
					BaseAPIHandler: mockBaseAPIHandler,
				},
				GTM: &GTMAPIHandler{
					BaseAPIHandler: mockBaseAPIHandler,
				},
			}
			go agent.gtmWorker()
			agent.GTM.PostManager.postChan <- postConfig
			response := <-agent.GTM.PostManager.respChan

			Expect(response).NotTo(BeNil(), "response should not be nil")
			Expect(response.tenantResponseMap["test_gtm"].agentResponseCode).To(Equal(http.StatusOK), "response code should be 200")

			close(agent.LTM.PostManager.postChan)
			close(agent.LTM.PostManager.respChan)
		})
	})

	Describe("Prepare AS3 GTM PostManager", func() {
		BeforeEach(func() {
			DEFAULT_GTM_PARTITION = "test_gtm"
		})
		It("Test GTM on different server", func() {
			var agentParams AgentParams
			agentParams.CCCLGTMAgent = true
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(false), "GTM is not on a separate server")
			agentParams.CCCLGTMAgent = false
			agentParams.PrimaryParams.BIGIPURL = "https://192.168.1.1"
			agentParams.PrimaryParams.BIGIPPassword = "admin"
			agentParams.PrimaryParams.BIGIPUsername = "admin"
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(false), "GTM is not on a separate server")
			agentParams.GTMParams.BIGIPURL = "https://192.168.1.1"
			agentParams.GTMParams.BIGIPPassword = "admin"
			agentParams.GTMParams.BIGIPUsername = "admin"
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(false), "GTM is not on a separate server")
			agentParams.GTMParams.BIGIPURL = "https://172.16.1.1"
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(true), "GTM is on a separate server")
		})
	})
})

var _ = Describe("normalizeURL", func() {
	It("returns empty string for empty or whitespace-only input", func() {
		Expect(normalizeURL("")).To(Equal(""))
		Expect(normalizeURL("   \t\n  ")).To(Equal(""))
	})

	It("lowercases scheme/host and removes trailing slash and path", func() {
		Expect(normalizeURL("HTTPS://EXAMPLE.COM/")).To(Equal("https://example.com"))
		Expect(normalizeURL("HTTPS://EXAMPLE.COM/Some/Path/")).To(Equal("https://example.com"))
	})

	It("removes :443 for https scheme", func() {
		Expect(normalizeURL("https://example.com:443")).To(Equal("https://example.com"))
		Expect(normalizeURL("HTTPS://EXAMPLE.COM:443/")).To(Equal("https://example.com"))
		// IPv6 host with default https port
		Expect(normalizeURL("https://[2001:db8::1]:443")).To(Equal("https://[2001:db8::1]"))
	})

	It("preserves non-default ports", func() {
		Expect(normalizeURL("http://example.com:80")).To(Equal("http://example.com:80"))
		Expect(normalizeURL("https://example.com:8443")).To(Equal("https://example.com:8443"))
	})

	It("returns lowercased, trimmed string for unparsable URLs", func() {
		// url.Parse fails for strings like "://FOO/"; function falls back to lowercase and trim trailing slash
		Expect(normalizeURL("://FOO/")).To(Equal("://foo"))
	})
})
