package controller

import (
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
)

var _ = Describe("AS3PostManager Tests", func() {
	var mockPM *mockPostManager
	BeforeEach(func() {
		mockPM = newMockPostManger()
		mockPM.PostManager.AS3PostManager.AS3Config = cisapiv1.AS3Config{DebugAS3: true,
			PostDelayAS3: 2}
	})

	It("Setup Client", func() {
		mockPM.setupBIGIPRESTClient()
	})

	Describe("Post Config and Handle Response", func() {
		var as3Cfg as3Config
		BeforeEach(func() {
			as3Cfg = as3Config{
				data:              `{"declaration": {"test": {"Shared": {"class": "application"}}}}`,
				as3APIURL:         mockPM.getAS3APIURL([]string{"test"}),
				id:                0,
				tenantResponseMap: make(map[string]tenantResponse),
			}
		})

		It("Handle First Post", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   "",
			}}, http.MethodPost)
			mockPM.AS3PostManager.firstPost = false
			mockPM.publishConfig(&as3Cfg)
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(BeEquivalentTo(http.StatusOK), "Posting Failed")
		})

		It("Handle HTTP StatusOK", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   "",
			}}, http.MethodPost)
			mockPM.publishConfig(&as3Cfg)
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(BeEquivalentTo(http.StatusOK), "Posting Failed")
		})

		It("Handle HTTP Status Accepted", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusOK,
					body:   "",
				},
				{
					tenant: tnt,
					status: http.StatusAccepted,
					body:   `{"id": "100", "code": 400}`,
				}}, http.MethodPost)
			mockPM.publishConfig(&as3Cfg)
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(BeEquivalentTo(http.StatusOK), "Posting Failed")
			mockPM.publishConfig(&as3Cfg)
		})

		It("Handle Expected HTTP Response Errors", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusServiceUnavailable,
					body:   "",
				},
				{
					tenant: tnt,
					status: http.StatusNotFound,
					body:   "",
				},
			}, http.MethodPost)
			mockPM.publishConfig(&as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(BeZero(), "Posting Failed")
			mockPM.publishConfig(&as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(BeZero(), "Posting Failed")
		})

		It("Handle Unexpected HTTP Response Errors", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusRequestTimeout,
					body:   "",
				},
				{
					tenant: tnt,
					status: http.StatusRequestTimeout,
					body:   fmt.Sprintf(`{"error": {{"code":%d}}`, http.StatusRequestTimeout),
				},
				{
					tenant: tnt,
					status: http.StatusAlreadyReported,
					body:   fmt.Sprintf(`{"code":%d}`, http.StatusAlreadyReported),
				},
			}, http.MethodPost)

			mockPM.publishConfig(&as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusRequestTimeout))

			mockPM.publishConfig(&as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusRequestTimeout))

			mockPM.publishConfig(&as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusAlreadyReported))
		})

		It("Handle Multiple HTTP Responses", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusMultiStatus,
				body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"success", "tenant": "%s"}],"declaration": {"%s": {"Shared": {"class": "application"}}}}`, http.StatusOK, tnt, tnt),
			},
			}, http.MethodPost)
			mockPM.publishConfig(&as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(Equal(1), "Posting Failed")
		})
	})

	Describe("BIGIP Queries", func() {
		It("Get Tenant Configuration Status", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusOK,
					body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"in progress", "tenant": "%s"}],"declaration": {"%s": {"Shared": {"class": "application"}}}}`, http.StatusOK, tnt, tnt),
				},
				{
					tenant: tnt,
					status: http.StatusOK,
					body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "%s"}],"declaration": {"%s": {"Shared": {"class": "application"}}}}`, http.StatusOK, tnt, tnt),
				},
				{
					tenant: tnt,
					status: http.StatusUnprocessableEntity,
					body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "%s"}]}`, http.StatusUnprocessableEntity, tnt),
				},
			}, http.MethodGet)
			as3Cfg := as3Config{
				id:                1,
				tenantResponseMap: make(map[string]tenantResponse),
			}
			mockPM.getTenantConfigStatus("100", &as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(BeZero(), "Posting Failed")
			mockPM.getTenantConfigStatus("100", &as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusOK))
			mockPM.getTenantConfigStatus("100", &as3Cfg)
			Expect(len(as3Cfg.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(as3Cfg.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusUnprocessableEntity))
		})
	})

	Describe("BIGIP AS3 Version", func() {
		It("Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusOK,
					body:   `{"version":"v1", "release":"r1", "schemaCurrent":"test"}`,
				},
			}, http.MethodGet)
			_, _, _, err := mockPM.GetBigipAS3Version()
			Expect(err).To(BeNil(), "Failed to get BIG-IP AS3 Version")
		})

		It("Validation1: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusNotFound,
					body:   fmt.Sprintf(`{"version":"v1", "release":"r1", "code":%d}`, http.StatusNotFound),
				},
			}, http.MethodGet)
			_, _, _, err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})

		It("Validation2: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusNotFound,
					body:   fmt.Sprintf(`{"code":%d}`, http.StatusNotFound),
				},
			}, http.MethodGet)
			_, _, _, err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})

		It("Validation2: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusNotFound,
					body:   `{`,
				},
			}, http.MethodGet)
			_, _, _, err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})
	})

	Describe("Get BIGIP Registration key", func() {
		It("Get Registration key successfully", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   `{"registrationKey": "sfiifhanji"}`,
			}}, http.MethodGet)
			key, err := mockPM.GetBigipRegKey()
			Expect(err).To(BeNil(), "Failed to fetch registration key")
			Expect(key).NotTo(BeEmpty(), "Fetched invalid registration key")
		})
		It("Handle Failures while Getting Registration key", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusNotFound,
					body:   fmt.Sprintf(`{"code":%d}`, http.StatusNotFound),
				},
				{
					tenant: tnt,
					status: http.StatusServiceUnavailable,
					body:   fmt.Sprintf(`{"code":%d}`, http.StatusServiceUnavailable),
				},
			}, http.MethodGet)

			key, err := mockPM.GetBigipRegKey()
			Expect(err).NotTo(BeNil(), "Failed to fetch registration key")
			Expect(key).To(BeEmpty(), "Fetched invalid registration key")

			key, err = mockPM.GetBigipRegKey()
			Expect(err).NotTo(BeNil(), "Failed to fetch registration key")
			Expect(key).To(BeEmpty(), "Fetched invalid registration key")
		})
		It("test as3 request logging", func() {
			as3config := "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/master/schema/3.38.0/as3-schema-3.38.0-4.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"}],\"redirect80\":false,\"pool\":\"/k8s/Shared/test_pool\"},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.38.0\"}}"
			mockPM.logAS3Request(as3config)
		})
	})

	Describe("Get BIGIP AS3 Declaration", func() {
		It("Get Declaration successfully", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   `{"declaration": {"test": {"Shared": {"class": "application"}}}}`,
			}}, http.MethodGet)
			dec, err := mockPM.GetAS3DeclarationFromBigIP()
			Expect(err).To(BeNil(), "Failed to fetch declaration")
			Expect(dec).NotTo(BeEmpty(), "Fetched invalid declaration")
		})
		It("Handle Failures while Getting Declaration", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusNotFound,
					body:   fmt.Sprintf(`{"code":%d}`, http.StatusNotFound),
				},
				{
					tenant: tnt,
					status: http.StatusServiceUnavailable,
					body:   fmt.Sprintf(`{"code":%d}`, http.StatusServiceUnavailable),
				},
			}, http.MethodGet)

			dec, err := mockPM.GetAS3DeclarationFromBigIP()
			Expect(err).NotTo(BeNil(), "Failed to fetch declaration")
			Expect(dec).To(BeEmpty(), "Fetched invalid declaration")
		})
	})
})
