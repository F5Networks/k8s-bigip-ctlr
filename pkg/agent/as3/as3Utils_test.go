package as3

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
)

var configPath = "../test/configs/"

func readConfigFile(path string) string {
	defer GinkgoRecover()
	data, err := ioutil.ReadFile(path)
	RegisterFailHandler(Fail)
	Expect(err).To(BeNil(), "Configuration files should be located in pkg/test/configs.")
	return string(data)
}

var _ = Describe("Override Simple Config Map", func() {
	It("TestValidateJSONStringAndFetchObject", func() {
		srcCfgMapData := readConfigFile(configPath + "as3config_override_simple_cfgmap_resource.json")
		dstCfgMapData := readConfigFile(configPath + "as3config_simple_cfgmap_resource.json")

		overrideData := ValidateAndOverrideAS3JsonData(srcCfgMapData, dstCfgMapData)

		Expect(overrideData != "").To(Equal(true))
	})

	It("Override Invalid AS3 Override Config Map", func() {
		srcCfgMapData := readConfigFile(configPath + "as3config_without_adc.json")
		dstCfgMapData := readConfigFile(configPath + "as3config_simple_cfgmap_resource.json")

		overrideData := ValidateAndOverrideAS3JsonData(srcCfgMapData, dstCfgMapData)
		Expect(overrideData == "").To(Equal(true))
	})

	It("Override Invalid AS3 Config Map", func() {
		srcCfgMapData := readConfigFile(configPath + "as3config_override_simple_cfgmap_resource.json")
		dstCfgMapData := readConfigFile(configPath + "as3config_invalid_JSON.json")

		overrideData := ValidateAndOverrideAS3JsonData(srcCfgMapData, dstCfgMapData)
		Expect(overrideData == "").To(Equal(true))
	})
})
