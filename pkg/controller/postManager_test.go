package controller

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
)

var _ = Describe("PostManager Tests", func() {
	var mockPM *mockPostManager
	BeforeEach(func() {
		mockPM = newMockPostManger()
		mockPM.tenantResponseMap = make(map[string]tenantResponse)
		mockPM.LogResponse = true
		mockPM.AS3PostDelay = 2
	})

	It("Setup Client", func() {
		mockPM.setupBIGIPRESTClient()
	})

	Describe("Post Config and Handle Response", func() {
		var agentCfg agentConfig
		BeforeEach(func() {
			mockPM.BIGIPURL = "bigip.com"
			mockPM.BIGIPUsername = "user"
			mockPM.BIGIPPassword = "pswd"
			agentCfg = agentConfig{
				data:      "{}",
				as3APIURL: mockPM.getAS3APIURL([]string{"test"}),
				id:        0,
			}
			mockPM.tenantResponseMap = make(map[string]tenantResponse)
		})

		It("Handle First Post", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   "",
			}}, http.MethodPost)
			mockPM.firstPost = false
			mockPM.publishConfig(agentCfg)
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(BeEquivalentTo(http.StatusOK), "Posting Failed")
		})

		It("Handle HTTP StatusOK", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   "",
			}}, http.MethodPost)
			mockPM.publishConfig(agentCfg)
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(BeEquivalentTo(http.StatusOK), "Posting Failed")
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
			mockPM.publishConfig(agentCfg)
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(BeEquivalentTo(http.StatusOK), "Posting Failed")
			mockPM.publishConfig(agentCfg)
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
			mockPM.publishConfig(agentCfg)
			Expect(len(mockPM.tenantResponseMap)).To(BeZero(), "Posting Failed")
			mockPM.publishConfig(agentCfg)
			Expect(len(mockPM.tenantResponseMap)).To(BeZero(), "Posting Failed")
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

			mockPM.publishConfig(agentCfg)
			Expect(len(mockPM.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusRequestTimeout))

			mockPM.publishConfig(agentCfg)
			Expect(len(mockPM.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusRequestTimeout))

			mockPM.publishConfig(agentCfg)
			Expect(len(mockPM.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusAlreadyReported))
		})

		It("Handle Multiple HTTP Responses", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusMultiStatus,
				body:   "",
			},
			}, http.MethodPost)
			mockPM.publishConfig(agentCfg)
			Expect(len(mockPM.tenantResponseMap)).To(Equal(1), "Posting Failed")
		})
	})

	Describe("BIGIP Queries", func() {
		It("Get Tenant Configuration Status", func() {
			tnt := "test"
			mockPM.setResponses([]responceCtx{
				{
					tenant: tnt,
					status: http.StatusOK,
					body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"in progress", "tenant": "%s"}]}`, http.StatusOK, tnt),
				},
				{
					tenant: tnt,
					status: http.StatusOK,
					body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "%s"}]}`, http.StatusOK, tnt),
				},
				{
					tenant: tnt,
					status: http.StatusUnprocessableEntity,
					body:   fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "%s"}]}`, http.StatusUnprocessableEntity, tnt),
				},
			}, http.MethodGet)
			mockPM.getTenantConfigStatus("100")
			Expect(len(mockPM.tenantResponseMap)).To(BeZero(), "Posting Failed")
			mockPM.getTenantConfigStatus("100")
			Expect(len(mockPM.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusOK))
			mockPM.getTenantConfigStatus("100")
			Expect(len(mockPM.tenantResponseMap)).To(Equal(1), "Posting Failed")
			Expect(mockPM.tenantResponseMap[tnt].agentResponseCode).To(Equal(http.StatusUnprocessableEntity))
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
	})
})
