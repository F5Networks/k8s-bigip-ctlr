package crmanager

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
)

var _ = Describe("PostManager Tests", func() {
	var mockPM *mockPostManager
	BeforeEach(func() {
		mockPM = newMockPostManger()
		mockPM.LogResponse = true
	})

	It("Setup Client", func() {
		mockPM.setupBIGIPRESTClient()
	})
	It("Write Config", func() {
		mockPM.BIGIPURL = "bigip.com"
		agentCfg := agentConfig{
			data: "",
			as3APIURL: mockPM.getAS3APIURL([]string{"test"}),
			id:        0,
		}
		agentCfg.data = ""
		mockPM.Write(agentCfg)
		agentCfg.data = "{}"
		mockPM.Write(agentCfg)
	})

	Describe("Post Config and Handle Response", func() {
		BeforeEach(func() {
			mockPM.BIGIPURL = "bigip.com"
			mockPM.BIGIPUsername = "user"
			mockPM.BIGIPPassword = "pswd"
			agentCfg := agentConfig{
				data: "{}",
				as3APIURL: mockPM.getAS3APIURL([]string{"test"}),
				id:        0,
			}
			mockPM.Write(agentCfg)
		})
		It("Handle HTTP StatusOK", func() {
			mockPM.setResponses([]int{http.StatusOK}, "", http.MethodPost)
			_, ok := mockPM.postOnEventOrTimeout(0, &agentConfig{})
			Expect(ok).To(BeTrue(), "Posting Failed")
		})

		It("Handle HTTP StatusServiceUnavailable", func() {
			mockPM.setResponses([]int{http.StatusServiceUnavailable, http.StatusOK}, "", http.MethodPost)
			_, ok := mockPM.postOnEventOrTimeout(0, &agentConfig{})
			Expect(ok).To(BeTrue(), "Posting Failed")
		})

		It("Handle HTTP StatusNotFound", func() {
			mockPM.setResponses([]int{http.StatusNotFound}, "", http.MethodPost)
			_, ok := mockPM.postOnEventOrTimeout(0, &agentConfig{})
			Expect(ok).To(BeTrue(), "Posting Failed")
		})

		It("Handle HTTP StatusTimeout", func() {
			mockPM.setResponses([]int{http.StatusRequestTimeout, http.StatusOK}, "", http.MethodPost)
			_, ok := mockPM.postOnEventOrTimeout(0, &agentConfig{})
			Expect(ok).To(BeTrue(), "Posting Failed")
		})
	})

	Describe("BIGIP AS3 Version", func() {
		BeforeEach(func() {
			mockPM.BIGIPURL = "bigip.com"
			mockPM.BIGIPUsername = "user"
			mockPM.BIGIPPassword = "pswd"
		})

		It("Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]int{http.StatusOK}, `{"version":"v1", "release":"r1"}`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).To(BeNil(), "Failed to get BIG-IP AS3 Version")
		})

		It("Validation1: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]int{http.StatusNotFound}, `{"version":"v1", "release":"r1", "code":400}`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})

		It("Validation2: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]int{http.StatusNotFound}, `{"code":404}`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})

		It("Validation2: Get BIG-IP AS3 Version", func() {
			mockPM.setResponses([]int{http.StatusNotFound}, `{`, http.MethodGet)
			err := mockPM.GetBigipAS3Version()
			Expect(err).NotTo(BeNil(), "Failed Validation while get BIG-IP AS3 Version")
		})
	})
})
