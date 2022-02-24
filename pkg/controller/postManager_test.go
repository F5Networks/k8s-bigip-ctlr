package controller

import (
	"net/http"

	mockhc "github.com/f5devcentral/mockhttpclient"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PostManager Tests", func() {
	var mockPM *mockPostManager
	BeforeEach(func() {
		mockPM = newMockPostManger()
		mockPM.tenantResponseMap = make(map[string]tenantResponse)
		mockPM.LogResponse = true
		responseMap := make(mockhc.ResponseConfigMap)
		responseMap["POST"] = &mockhc.ResponseConfig{}
		client, _ := mockhc.NewMockHTTPClient(responseMap)
		mockPM.httpClient = client
	})

	It("Setup Client", func() {
		mockPM.setupBIGIPRESTClient()
	})
	//It("Write Config", func() {
	//	mockPM.BIGIPURL = "bigip.com"
	//	agentCfg := agentConfig{
	//		data:      "",
	//		as3APIURL: mockPM.getAS3APIURL([]string{"test"}),
	//		id:        0,
	//	}
	//	mockPM.retryTenantDeclMap["test"] = &tenantParams{agentConfig: agentCfg}
	//	mockPM.setResponses([]float64{http.StatusServiceUnavailable, http.StatusOK}, "", http.MethodPost)
	//	agentCfg.data = ""
	//	mockPM.Write(agentCfg, true)
	//	agentCfg.data = "{}"
	//	mockPM.Write(agentCfg, false)
	//})

	//Describe("Post Config and Handle Response", func() {
	//	BeforeEach(func() {
	//		mockPM.BIGIPURL = "bigip.com"
	//		mockPM.BIGIPUsername = "user"
	//		mockPM.BIGIPPassword = "pswd"
	//		agentCfg := agentConfig{
	//			data:      "{}",
	//			as3APIURL: mockPM.getAS3APIURL([]string{"test"}),
	//			id:        0,
	//		}
	//		mockPM.retryTenantDeclMap = map[string]*tenantParams{}
	//		mockPM.retryTenantDeclMap["test"] = &tenantParams{agentConfig: agentCfg}
	//		mockPM.Write(agentCfg, false)
	//	})
	//	It("Handle HTTP StatusOK", func() {
	//		mockPM.setResponses([]float64{http.StatusOK}, "", http.MethodPost)
	//		mockPM.postOnEventOrTimeout(0, &agentConfig{})
	//		Expect(mockPM.retryTenantDeclMap["test"].agentResponseCode).To(BeEquivalentTo(200), "Posting Failed")
	//	})
	//
	//	It("Handle HTTP StatusServiceUnavailable", func() {
	//		mockPM.setResponses([]float64{http.StatusServiceUnavailable, http.StatusOK}, "", http.MethodPost)
	//		mockPM.postOnEventOrTimeout(0, &agentConfig{})
	//		Expect(mockPM.retryTenantDeclMap["test"].agentResponseCode).To(BeEquivalentTo(200), "Posting Failed")
	//	})
	//
	//	It("Handle HTTP StatusNotFound", func() {
	//		mockPM.setResponses([]float64{http.StatusNotFound}, "", http.MethodPost)
	//		mockPM.postOnEventOrTimeout(0, &agentConfig{})
	//		Expect(mockPM.retryTenantDeclMap["test"].agentResponseCode).To(BeEquivalentTo(404), "Posting Failed")
	//	})
	//
	//	It("Handle HTTP StatusTimeout", func() {
	//		mockPM.setResponses([]float64{http.StatusRequestTimeout, http.StatusOK}, "", http.MethodPost)
	//		mockPM.postOnEventOrTimeout(0, &agentConfig{})
	//		Expect(mockPM.retryTenantDeclMap["test"].agentResponseCode).To(BeEquivalentTo(200), "Posting Failed")
	//	})
	//})

	Describe("BIGIP AS3 Version", func() {
		BeforeEach(func() {
			mockPM.BIGIPURL = "bigip.com"
			mockPM.BIGIPUsername = "user"
			mockPM.BIGIPPassword = "pswd"
		})

		It("Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]float64{http.StatusOK}, `{"version":"v1", "release":"r1"}`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).To(BeNil(), "Failed to get BIG-IP AS3 Version")
		})

		It("Validation1: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]float64{http.StatusNotFound}, `{"version":"v1", "release":"r1", "code":400}`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})

		It("Validation2: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]float64{http.StatusNotFound}, `{"code":404}`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})

		It("Validation2: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]float64{http.StatusNotFound}, `{`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})
	})
})
