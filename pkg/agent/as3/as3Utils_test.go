package as3

import (
	"os"
	"sort"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var configPath = "../../test/configs/"

func readConfigFile(path string) string {
	defer GinkgoRecover()
	data, err := os.ReadFile(path)
	RegisterFailHandler(Fail)
	Expect(err).To(BeNil(), "Configuration files should be located in pkg/test/configs.")
	return string(data)
}

var _ = Describe("Override Simple Config Map", func() {
	It("TestValidateJSONStringAndFetchObject", func() {
		srcCfgMapData := readConfigFile(configPath + "as3config_override_cfgmap.json")
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
		srcCfgMapData := readConfigFile(configPath + "as3config_override_cfgmap.json")
		dstCfgMapData := readConfigFile(configPath + "as3config_invalid_JSON.json")

		overrideData := ValidateAndOverrideAS3JsonData(srcCfgMapData, dstCfgMapData)
		Expect(overrideData == "").To(Equal(true))
	})
})

var _ = Describe("JSON comparision of AS3 declaration", func() {
	It("Verify with two empty declarations", func() {
		ok := DeepEqualJSON("", "")
		Expect(ok).To(BeTrue(), "Failed to compare empty declarations")
	})
	It("Verify with empty and non empty declarations", func() {
		cmcfg1 := readConfigFile(configPath + "as3config_valid_1.json")
		ok := DeepEqualJSON("", as3Declaration(cmcfg1))
		Expect(ok).To(BeFalse())
		ok = DeepEqualJSON(as3Declaration(cmcfg1), "")
		Expect(ok).To(BeFalse())
	})
})

var _ = Describe("Tenant parsing in AS3 declaration", func() {
	It("Get Tenants from a declaration", func() {
		cmcfg1 := readConfigFile(configPath + "as3config_multi_cm_unified.json")
		tenants := getTenants(as3Declaration(cmcfg1), true)
		sort.Strings(tenants)
		Expect(tenants).To(Equal([]string{"Tenant1", "Tenant2"}), "Failed to get tenants")
	})
})
