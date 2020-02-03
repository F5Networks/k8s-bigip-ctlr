/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockAS3Manager struct {
	as3Mgr *AS3Manager
}

func newMockAS3Manager(params *Params) *mockAS3Manager {
	return &mockAS3Manager{
		as3Mgr: NewAS3Manager(params),
	}
}

func (m *mockAS3Manager) shutdown() error {
	return nil
}

var _ = Describe("AS3Manager Tests", func() {
	var mockMgr *mockAS3Manager
	BeforeEach(func() {
		mockMgr = newMockAS3Manager(&Params{})
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
			data := readConfigFile(configPath + "as3config_valid.json")
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
		It("Unified Declaration only with User Defined ConfigMap", func() {
			data := readConfigFile(configPath + "as3config_valid.json")

			var tempAS3Config AS3Config
			tempAS3Config.configmap.Data = as3Declaration(data)

			result := mockMgr.as3Mgr.getUnifiedDeclaration(&tempAS3Config)

			Expect(string(result)).To(MatchJSON(data), "Failed to Create JSON with correct configuration")
		})
		It("Unified Declaration only with Openshift Route", func() {
			var routeConfig map[string]interface{}
			routedecl := readConfigFile(configPath + "as3_route_declaration.json")
			route := readConfigFile(configPath + "as3_route.json")
			err := json.Unmarshal([]byte(route), &routeConfig)
			Expect(err).To(BeNil(), "Original Config should be json")

			var tempAS3Config AS3Config
			tempAS3Config.adc = as3ADC(routeConfig)

			result := mockMgr.as3Mgr.getUnifiedDeclaration(&tempAS3Config)

			Expect(string(result)).To(MatchJSON(routedecl), "Failed to Create JSON with correct configuration")
		})
		It("Unified Declaration with User Defined ConfigMap and Openshift Route", func() {
			var routeCfg map[string]interface{}
			var tempAS3Config AS3Config

			unifiedConfig := readConfigFile(configPath + "as3_route_cfgmap_declaration.json")

			data := readConfigFile(configPath + "as3config_valid.json")
			tempAS3Config.configmap.Data = as3Declaration(data)

			data = readConfigFile(configPath + "as3_route.json")
			err := json.Unmarshal([]byte(data), &routeCfg)
			Expect(err).To(BeNil(), "Route Config should be json")
			tempAS3Config.adc = routeCfg

			result := mockMgr.as3Mgr.getUnifiedDeclaration(&tempAS3Config)

			Expect(string(result)).To(MatchJSON(unifiedConfig), "Failed to Create JSON with correct configuration")
		})
	})
})
