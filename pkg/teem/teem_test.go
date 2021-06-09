package teem

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type testDataType struct {
	td     *TeemsData
	setEnv string
	setKey string
}

var _ = Describe("Test PostTeemsData", func() {
	testData := testDataType{td: &TeemsData{
		AccessEnabled: true,
		ResourceType: ResourceTypes{
			Ingresses:       make(map[string]int),
			Routes:          make(map[string]int),
			Configmaps:      make(map[string]int),
			VirtualServer:   make(map[string]int),
			TransportServer: make(map[string]int),
			ExternalDNS:     make(map[string]int),
			IngressLink:     make(map[string]int),
			IPAMVS:          make(map[string]int),
			IPAMTS:          make(map[string]int),
			IPAMSvcLB:       make(map[string]int),
		},
	}}

	Context("If accessEnabled flag", func() {
		It("is true", func() {
			// this is a valid case
			os.Unsetenv("TEEM_API_ENVIRONMENT")
			testData.td.PlatformInfo = "Unit test case suite"
			access := testData.td.PostTeemsData()
			Expect(access).To(BeTrue())
		})
		It("is false", func() {
			testData.td.AccessEnabled = false
			access := testData.td.PostTeemsData()
			Expect(access).To(BeFalse())
		})
	})

	Context("If posting to non-prod server", func() {
		BeforeEach(func() {
			testData.td.PlatformInfo = "Unit test case suite"
		})
		AfterEach(func() {
			os.Unsetenv("TEEM_API_ENVIRONMENT")
			os.Unsetenv("TEEM_API_KEY")
		})
		It("with invalid env and key", func() {
			testData.setKey = "random"
			testData.setEnv = "testing"
			_ = os.Setenv("TEEM_API_ENVIRONMENT", testData.setEnv)
			_ = os.Setenv("TEEM_API_KEY", testData.setKey)
			access := testData.td.PostTeemsData()
			Expect(access).To(BeFalse())
		})
		It("with valid env and empty key", func() {
			testData.setEnv = "staging"
			_ = os.Setenv("TEEM_API_ENVIRONMENT", testData.setEnv)
			access := testData.td.PostTeemsData()
			Expect(access).To(BeFalse())
		})
		It("with valid env and invalid key", func() {
			testData.setKey = "random"
			testData.setEnv = "staging"
			_ = os.Setenv("TEEM_API_ENVIRONMENT", testData.setEnv)
			_ = os.Setenv("TEEM_API_KEY", testData.setKey)
			access := testData.td.PostTeemsData()
			Expect(access).To(BeFalse())
		})
	})

})
