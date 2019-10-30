package appmanager

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

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
