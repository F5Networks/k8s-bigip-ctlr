package as3

import (
	"bytes"
	"fmt"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo"
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
		mockPM.LogResponse = true
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
	})
})
