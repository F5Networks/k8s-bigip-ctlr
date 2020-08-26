/*-
 * Copyright (c) 2016-2020, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package as3

import (
	"encoding/json"

	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockAS3Manager struct {
	*AS3Manager
}

func newMockAS3Manager(params *Params) *mockAS3Manager {
	return &mockAS3Manager{
		NewAS3Manager(params),
	}
}

func mockGetEndPoints(string, string) []Member {
	return []Member{{Address: "1.1.1.1", Port: 80},
		{Address: "2.2.2.2", Port: 80}}
}

func (m *mockAS3Manager) shutdown() error {
	return nil
}

var _ = Describe("AS3Manager Tests", func() {
	var mockMgr *mockAS3Manager
	BeforeEach(func() {
		mockMgr = newMockAS3Manager(&Params{
			As3Version: "3.21.0",
			As3Release: "3.21.0-4",
		})
	})
	AfterEach(func() {
		mockMgr.shutdown()
	})

	Describe("Validating AS3 ConfigMap with AS3Manager", func() {
		It("AS3 declaration with Invalid JSON", func() {
			data := readConfigFile(configPath + "as3config_invalid_JSON.json")
			_, ok := getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template is not a valid JSON.")
		})
		It("AS3 declaration with all Tenants, Applications and Pools", func() {
			data := readConfigFile(configPath + "as3config_valid_1.json")
			_, ok := getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(true), "AS3 Template parsed succesfully.")
		})
		It("AS3 declaration without Pools", func() {
			data := readConfigFile(configPath + "as3config_without_pools.json")
			_, ok := getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(true), "AS3 Template parsed succesfully [No Pools].")
		})
		It("AS3 declaration without Applications", func() {
			data := readConfigFile(configPath + "as3config_without_apps.json")
			_, ok := getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(true), "AS3 Template parsed succesfully [No Applications].")
		})
		It("AS3 declaration without Tenants", func() {
			data := readConfigFile(configPath + "as3config_without_tenants.json")
			_, ok := getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template parsed succesfully, [No Tenants].")
		})
		It("AS3 template without ADC declaration", func() {
			data := readConfigFile(configPath + "as3config_without_adc.json")
			_, ok := getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template without ADC declaration should not be processed.")
		})
	})

	Describe("Validate Generated Unified Declaration", func() {
		It("Unified Declaration only with User Defined ConfigMaps", func() {
			cmcfg1 := readConfigFile(configPath + "as3config_valid_1.json")
			cmcfg2 := readConfigFile(configPath + "as3config_valid_2.json")
			unified := readConfigFile(configPath + "as3config_multi_cm_unified.json")

			mockMgr.ResourceRequest.AgentCfgmaps = append(
				mockMgr.ResourceRequest.AgentCfgmaps,
				&AgentCfgMap{
					GetEndpoints: mockGetEndPoints,
					Name:         "cfgmap1",
					Namespace:    "default",
					Data:         cmcfg1,
					Label: map[string]string{
						AS3Label:    TrueLabel,
						F5TypeLabel: VSLabel,
					},
				},
				&AgentCfgMap{
					GetEndpoints: mockGetEndPoints,
					Name:         "cfgmap2",
					Namespace:    "default",
					Data:         cmcfg2,
					Label: map[string]string{
						AS3Label:    TrueLabel,
						F5TypeLabel: VSLabel,
					},
				},
			)
			as3config := &AS3Config{}
			as3config.configmaps, _ = mockMgr.prepareResourceAS3ConfigMaps()

			result := mockMgr.getUnifiedDeclaration(as3config)

			Expect(string(result)).To(MatchJSON(unified), "Failed to Create JSON with correct configuration")
		})
		It("Unified Declaration only with Openshift Route", func() {
			var routeAdc map[string]interface{}
			routeCfg := readConfigFile(configPath + "as3_route_declaration.json")
			route := readConfigFile(configPath + "as3_route.json")
			err := json.Unmarshal([]byte(route), &routeAdc)
			Expect(err).To(BeNil(), "Original Config should be json")

			var tempAS3Config AS3Config
			tempAS3Config.resourceConfig = routeAdc

			result := mockMgr.getUnifiedDeclaration(&tempAS3Config)

			Expect(string(result)).To(MatchJSON(routeCfg), "Failed to Create JSON with correct configuration")
		})
		It("Unified Declaration with User Defined ConfigMap and Openshift Route", func() {
			var routeAdc map[string]interface{}

			unifiedConfig := readConfigFile(configPath + "as3_route_cfgmap_declaration.json")

			cmCfg := readConfigFile(configPath + "as3config_valid_1.json")
			mockMgr.ResourceRequest.AgentCfgmaps = append(
				mockMgr.ResourceRequest.AgentCfgmaps,
				&AgentCfgMap{
					GetEndpoints: mockGetEndPoints,
					Name:         "cfgmap",
					Namespace:    "default",
					Data:         cmCfg,
					Label: map[string]string{
						AS3Label:    TrueLabel,
						F5TypeLabel: VSLabel,
					},
				},
			)
			as3config := &AS3Config{}
			as3config.configmaps, _ = mockMgr.prepareResourceAS3ConfigMaps()

			routeCfg := readConfigFile(configPath + "as3_route.json")
			err := json.Unmarshal([]byte(routeCfg), &routeAdc)
			Expect(err).To(BeNil(), "Route Config should be json")
			as3config.resourceConfig = routeAdc

			result := mockMgr.getUnifiedDeclaration(as3config)

			Expect(string(result)).To(MatchJSON(unifiedConfig), "Failed to Create JSON with correct configuration")

			ok := DeepEqualJSON(as3Declaration(unifiedConfig), result)
			Expect(ok).To(BeTrue())
		})
		It("Validate staging of Configmap", func() {
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					AS3Label:    FalseLabel,
					F5TypeLabel: VSLabel,
				},
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(StagingAS3Label), "Wrong Label")
			Expect(valid).To(BeTrue())
		})
	})

	Describe("Validate Labels of Configmaps", func() {
		It("Validate non f5type Configmap", func() {
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					"app": "some-app",
				},
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(""), "Wrong Label")
			Expect(valid).To(BeFalse())
		})
		It("Validate non f5type Configmap", func() {
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					"f5type": "virtual-serverssssss",
				},
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(""), "Wrong Label")
			Expect(valid).To(BeFalse())
		})
		It("Validate staging of Configmap", func() {
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					AS3Label:    FalseLabel,
					F5TypeLabel: VSLabel,
				},
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(StagingAS3Label), "Wrong Label")
			Expect(valid).To(BeTrue())
		})

		It("Validate Override configmap labels", func() {
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					OverrideAS3Label: FalseLabel,
					F5TypeLabel:      VSLabel,
				},
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(OverrideAS3Label), "Wrong Label")
			Expect(valid).To(BeTrue())
			Expect(cfgmap.Operation).To(Equal(OprTypeDelete))
		})
	})

	Describe("Validate Override Configmap", func() {
		It("Override CIS generated config with Override Configmap", func() {
			var routeAdc map[string]interface{}

			unifiedConfig := readConfigFile(configPath + "as3_route_declaration_overridden.json")

			ovrdCmCfg := readConfigFile(configPath + "as3config_override_cfgmap.json")
			mockMgr.ResourceRequest.AgentCfgmaps = append(
				mockMgr.ResourceRequest.AgentCfgmaps,
				&AgentCfgMap{
					GetEndpoints: mockGetEndPoints,
					Name:         "override_cfgmap",
					Namespace:    "default",
					Data:         ovrdCmCfg,
					Label: map[string]string{
						OverrideAS3Label: TrueLabel,
						F5TypeLabel:      VSLabel,
					},
				},
			)
			as3config := &AS3Config{}
			_, as3config.overrideConfigmapData = mockMgr.prepareResourceAS3ConfigMaps()

			routeCfg := readConfigFile(configPath + "as3_route.json")
			err := json.Unmarshal([]byte(routeCfg), &routeAdc)
			Expect(err).To(BeNil(), "Route Config should be json")
			as3config.resourceConfig = routeAdc

			result := mockMgr.getUnifiedDeclaration(as3config)

			Expect(string(result)).To(MatchJSON(unifiedConfig), "Failed to Create JSON with correct configuration")
		})

		It("Validate Override configmap with wrong name", func() {
			mockMgr.OverriderCfgMapName = "default/ovCfgmap"
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					OverrideAS3Label: TrueLabel,
					F5TypeLabel:      VSLabel,
				},
				Namespace: "default",
				Name:      "wrongname",
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(""), "Wrong Label")
			Expect(valid).To(BeFalse())
		})
		It("Validate Override configmap with wrong namespace", func() {
			mockMgr.OverriderCfgMapName = "default/ovCfgmap"
			cfgmap := &AgentCfgMap{
				Label: map[string]string{
					OverrideAS3Label: TrueLabel,
					F5TypeLabel:      VSLabel,
				},
				Namespace: "wrongnamespace",
				Name:      "ovCfgmap",
			}
			label, valid := mockMgr.isValidConfigmap(cfgmap)
			Expect(label).To(Equal(""), "Wrong Label")
			Expect(valid).To(BeFalse())
		})
	})
})
