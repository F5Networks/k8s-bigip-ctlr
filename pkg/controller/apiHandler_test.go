package controller

import (
	"io"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("API Handler tests", func() {
	Describe("Validate base api handler", func() {
		It("Verify base api handler", func() {
			baseAPIHandler := NewBaseAPIHandler(
				AgentParams{
					ApiType: AS3,
					PrimaryParams: PostParams{BIGIPURL: "http://127.0.0.1:8080",
						BIGIPPassword: "password",
						BIGIPUsername: "username"},
					Partition: "default",
				},
				PrimaryBigIP,
				make(chan *agentPostConfig, 1),
			)
			Expect(baseAPIHandler).NotTo(BeNil(), "Base api handler must not be nil")
			Expect(baseAPIHandler.PostManager).NotTo(BeNil(), "Post manager must not be nil")
			Expect(baseAPIHandler.PostManager.BIGIPURL).To(Equal("http://127.0.0.1:8080"), "BIGIPURL didn't matched with the agent params BIGIPURL")
		})
	})
	Describe("Post config tests with HTTP response handlers", func() {
		var mockBaseAPIHandler *BaseAPIHandler
		var postConfig *agentPostConfig
		var tenantResponseMap map[string]tenantResponse

		BeforeEach(func() {
			mockBaseAPIHandler = newMockBaseAPIHandler()
			tenantDeclMap := make(map[string]as3Tenant)
			tenantResponseMap = make(map[string]tenantResponse)
			tenantResponseMap["test"] = tenantResponse{}
			tenantResponseMap["test1"] = tenantResponse{}
			tenantDeclMap["test"] = as3Tenant{
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
				tenantResponseMap:     tenantResponseMap,
			}
		})
		It("Validate post config for OK response", func() {
			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusOK,
					body:   io.NopCloser(strings.NewReader("{\"results\": [{\"code\": 200, \"message\": \"success\", \"tenant\": \"test\"}], \"declaration\": {\"class\": \"ADC\", \"test\": {\"class\": \"Tenant\", \"testApp\": {\"class\": \"Application\", \"webcert\":{\"class\": \"Certificate\", \"certificate\": \"abc\", \"privateKey\": \"abc\", \"chainCA\": \"abc\"}}}}}")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "post config must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusOK), "Post configuration must have status code 200")
		})
		It("Validate post config for CREATED or ACCEPTED response", func() {
			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusCreated,
					body:   io.NopCloser(strings.NewReader("{\"id\": \"1234\"}")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.acceptedTaskId).To(Equal("1234"), "Post configuration must have accepted task id")
			// Expect(postConfig.tenantResponseMap).To(Equal(http.StatusCreated), "Post configuration must have status code 201")
		})
		It("Validate post config for MULTISTATUS", func() {

			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusMultiStatus,
					body:   io.NopCloser(strings.NewReader("{\"results\": [{\"code\": 200, \"message\": \"success\", \"tenant\": \"test\"}, {\"code\": 422, \"message\": \"resulted in failure\", \"tenant\": \"test1\"}], \"declaration\": {\"class\": \"ADC\", \"test\": {\"class\": \"Tenant\", \"testApp\": {\"class\": \"Application\", \"webcert\":{\"class\": \"Certificate\", \"certificate\": \"abc\", \"privateKey\": \"abc\", \"chainCA\": \"abc\"}}}, \"test1\": { \"class\": \"Tenant\", \"testApp\": {\"class\": \"Application\", \"webcert\":{\"class\": \"Certificate\", \"certificate\": \"abc\", \"privateKey\": \"abc\", \"chainCA\": \"abc\"}}}}}")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusOK), "Post configuration must have status code 200")
			Expect(postConfig.tenantResponseMap["test1"].agentResponseCode).To(Equal(422), "Post configuration must have status code 422")
		})
		It("Validate post config for UNAUTHORIZED response", func() {
			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusUnauthorized,
					body:   io.NopCloser(strings.NewReader("{\"code\": 401, \"message\": \"Unauthorized service\"}")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusUnauthorized), "Post configuration must have status code 401")
		})
		It("Validate post config for NOT FOUND response", func() {
			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusNotFound,
					body:   io.NopCloser(strings.NewReader("{\"error\": {\"code\": 404, \"message\": \"RPM is not installed on BIGIP\"}}")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusNotFound), "Post configuration must have status code 401")
		})
		It("Validate post config for SERVICE UNAVAILABLE response", func() {
			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusServiceUnavailable,
					body:   io.NopCloser(strings.NewReader("{\"error\": {\"code\": 503, \"message\": \"BIGIP is busy\"}}")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusServiceUnavailable), "Post configuration must have status code 503")
		})
		It("Validate post config for unknown response error cases", func() {
			client, _ := getMockHttpClient([]responseCtx{
				{
					tenant: "test",
					status: http.StatusUnprocessableEntity,
					body:   io.NopCloser(strings.NewReader("{\"results\": [{\"code\": 422, \"message\": \"Failure on post\", \"tenant\": \"test\"}]}")),
				},
				{
					tenant: "test",
					status: http.StatusForbidden,
					body:   io.NopCloser(strings.NewReader("{\"error\": {\"code\": 403, \"message\": \"Forbidden request\"}}")),
				},
				{
					tenant: "test",
					status: http.StatusBadRequest,
					body:   io.NopCloser(strings.NewReader("{\"code\": 400}")),
				},
				{
					tenant: "test",
					status: http.StatusBadRequest,
					body:   io.NopCloser(strings.NewReader("{\"code\": 400")),
				},
			}, http.MethodPost)
			mockBaseAPIHandler.httpClient = client
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusUnprocessableEntity), "Post configuration must have status code 503")
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusForbidden), "Post configuration must have status code 503")
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusBadRequest), "Post configuration must have status code 503")
			mockBaseAPIHandler.postConfig(postConfig)
			Expect(postConfig).NotTo(BeNil(), "Post configuration must not be nil")
			Expect(postConfig.tenantResponseMap["test"].agentResponseCode).To(Equal(http.StatusBadRequest), "Post configuration must have status code 503")
			Expect(postConfig.tenantResponseMap["test"].message).To(Equal("Big-IP Responded with error code: 400 -- verify the logs for detailed error"), "Post configuration must have status code 400")
		})
	})
	Describe("BIGIP utils functions", func() {
		var mockBaseAPIHandler *BaseAPIHandler

		BeforeEach(func() {
			mockBaseAPIHandler = newMockBaseAPIHandler()
		})

		It("Get BIGIP registration key", func() {
			mockBaseAPIHandler.httpClient, _ = getMockHttpClient([]responseCtx{
				{
					status: http.StatusOK,
					body:   io.NopCloser(strings.NewReader("{\"registrationKey\": \"abcd-efgh-ijkl-mnopqr\"}")),
				},
				{
					status: http.StatusNotFound,
					body:   io.NopCloser(strings.NewReader("{\"code\": 404}")),
				},
				{
					status: http.StatusUnauthorized,
					body:   io.NopCloser(strings.NewReader("{\"code\": 401, \"message\": \"Unauthorized service\"}")),
				},
				{
					status: http.StatusUnprocessableEntity,
					body:   io.NopCloser(strings.NewReader("{\"code\": 422, \"message\": \"Error while fetching key\"}")),
				},
			}, http.MethodGet)
			response, err := mockBaseAPIHandler.GetBigipRegKey()
			Expect(response).To(Equal("abcd-efgh-ijkl-mnopqr"), "BIGIP reg key did not match")
			Expect(err).To(BeNil(), "BIGIP reg key error must be nil")
			response, err = mockBaseAPIHandler.GetBigipRegKey()
			Expect(response).To(BeEmpty(), "BIGIP reg key expected to be empty")
			Expect(err.Error()).To(Equal("RPM is not installed on BIGIP, Error response from BIGIP with status code 404"))
			response, err = mockBaseAPIHandler.GetBigipRegKey()
			Expect(response).To(BeEmpty(), "BIGIP reg key expected to be empty")
			Expect(err.Error()).To(Equal("Internal Error"))
			response, err = mockBaseAPIHandler.GetBigipRegKey()
			Expect(response).To(BeEmpty(), "BIGIP reg key expected to be empty")
			Expect(err.Error()).To(Equal("error response from BIGIP with status code 422"))
		})
	})
})
