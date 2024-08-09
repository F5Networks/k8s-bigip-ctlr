package as3

import (
	"bytes"
	"fmt"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"net/http"
)

type (
	mockPostManager struct {
		*PostManager
		Responses []int
		RespIndex int
	}

	responceCtx struct {
		tenant string
		status float64
		body   string
	}
)

func newMockPostManger() *mockPostManager {
	mockPM := &mockPostManager{
		PostManager: &PostManager{},
		Responses:   []int{},
		RespIndex:   0,
	}
	return mockPM
}

func (mockPM *mockPostManager) setResponses(responces []responceCtx, method string) {
	var body string

	responseMap := make(mockhc.ResponseConfigMap)
	responseMap[method] = &mockhc.ResponseConfig{}

	for _, resp := range responces {
		if resp.body == "" {
			if resp.status == http.StatusOK {
				body = fmt.Sprintf(`{"results":[{"code":%f,"message":"none", "tenant": "%s"}]}`,
					resp.status, resp.tenant)
			} else {
				body = fmt.Sprintf(`{"results":[{"code":%f,"message":"none", "tenant": "%s"}],"error":{"code":%f}}`,
					resp.status, resp.tenant, resp.status)
			}
		} else {
			body = resp.body
		}

		responseMap[method].Responses = append(responseMap[method].Responses, &http.Response{
			StatusCode: int(resp.status),
			Header:     http.Header{},
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(body))),
		})
	}

	client, _ := mockhc.NewMockHTTPClient(responseMap)
	mockPM.HttpClient = client
}

var _ = Describe("PostManager Tests", func() {
	var mockPM *mockPostManager
	BeforeEach(func() {
		mockPM = newMockPostManger()
		//mockPM.tenantResponseMap = make(map[string]tenantResponse)
		mockPM.LogAS3Response = true
		mockPM.AS3PostDelay = 2
	})

	It("Setup Client", func() {
		mockPM.setupBIGIPRESTClient()
	})

	Describe("Post Config and Handle Response", func() {
		//var agentCfg agentConfig
		BeforeEach(func() {
			mockPM.BIGIPURL = "bigip.com"
			mockPM.BIGIPUsername = "user"
			mockPM.BIGIPPassword = "pswd"
		})

		It("Handle HTTP Status OK, Accepted & Created", func() {
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
				},
				{
					tenant: tnt,
					status: http.StatusCreated,
					body:   `{"id": "100", "code": 400}`,
				}}, http.MethodPost)
			result, output := mockPM.postConfigRequests("", "")
			Expect(result).To(BeTrue(), "Posting Failed")
			Expect(output).To(Equal("statusOK"), "Posting Failed")
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
			result, output := mockPM.postConfigRequests("", "")
			Expect(result).To(BeFalse(), "Posting expected to fail but passed")
			Expect(output).To(Equal("statusServiceUnavailable"), "Posting expected to fail but passed")
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
			result, output := mockPM.postConfigRequests("", "")
			Expect(result).To(BeFalse(), "Posting expected to fail but passed")
			Expect(output).To(Equal("statusCommonResponse"), "Posting expected to fail but passed")
		})

		It("Handle HTTP Response Errors: StatusServiceUnavailable", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusServiceUnavailable,
					body:   "",
				},
			}, http.MethodPost)
			result, output := mockPM.postConfigRequests("", "")
			Expect(result).To(BeFalse(), "Posting expected to fail but passed")
			Expect(output).To(Equal("statusServiceUnavailable"), "Posting expected to fail but passed")
		})
		It("Handle HTTP Response Errors: StatusNotFound", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusNotFound,
					body:   "",
				},
			}, http.MethodPost)
			result, output := mockPM.postConfigRequests("", "")
			Expect(result).To(BeTrue(), "Posting expected to fail but passed")
			Expect(output).To(Equal("statusNotFound"), "Posting expected to fail but passed")
		})
		It("Handle HTTP Response Errors: StatusUnprocessableEntity", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusUnprocessableEntity,
					body:   "",
				},
			}, http.MethodPost)
			result, output := mockPM.postConfigRequests("", "")
			Expect(result).To(BeFalse(), "Posting expected to fail but passed")
			Expect(output).To(Equal("statusUnprocessableEntity"), "Posting expected to fail but passed")
		})
	})

	Describe("BIGIP AS3 Version", func() {
		BeforeEach(func() {
			mockPM.BIGIPURL = "bigip.com"
			mockPM.BIGIPUsername = "user"
			mockPM.BIGIPPassword = "pswd"
		})

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

		It("Validation3: Get BIG-IP AS3 Version", func() {
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
		It("function getTimeDurationForErrorResponse", func() {
			Expect(getTimeDurationForErrorResponse(responseStatusCommon)).To(Equal(timeoutMedium))
			Expect(getTimeDurationForErrorResponse(responseStatusUnprocessableEntity)).To(Equal(timeoutMedium))
			Expect(getTimeDurationForErrorResponse(responseStatusServiceUnavailable)).To(Equal(timeoutSmall))
			Expect(getTimeDurationForErrorResponse("")).To(Equal(timeoutNill))
		})
		It("test as3 request logging", func() {
			as3config := "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.38.0/as3-schema-3.38.0-4.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"}],\"redirect80\":false,\"pool\":\"/k8s/Shared/test_pool\"},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.38.0\"}}"
			mockPM.logAS3Request(as3config)
		})
	})
})
