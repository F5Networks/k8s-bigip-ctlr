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

	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
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

func mockGetEndPoints(string) []Member {
	return []Member{{Address: "1.1.1.1", Port: 80},
		{Address: "2.2.2.2", Port: 80}}
}

func newMockAgentCfgMap(label, config string) *AgentCfgMap {
	return &AgentCfgMap{GetEndpoints: mockGetEndPoints,
		Data:      readConfigFile(configPath + config),
		Namespace: "default",
		Name:      "testCfgMap",
		Label:     map[string]string{label: "true", "f5type": "virtual-server"},
	}
}

func newMockAS3Config() AS3Config {
	as3Cfg := AS3Config{}
	as3Cfg.Init("test_AS3")
	return as3Cfg
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

	Describe("User Configured  user defined AS3 ConfigMap", func() {
		It("Create user configured Userdefined AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			as3Config.configmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"User configured UserDefinedCfgMap Created Successfully.")
		})
		It("Delete user configured Userdefined AS3 cfgMap with valid name and namespace", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			as3Config.configmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive), "UserDefinedCfgMap created.")
			Expect(string(as3Config.configmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			as3Config = mockMgr.as3Mgr.as3ActiveConfig
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmInit),
				"User configured UserDefinedCfgMap Deleted Successfully.")
		})
		It("Delete user configured userdefined AS3 cfgMap with invalid name", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			as3Config.configmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive), "UserDefinedCfgMap created.")
			Expect(string(as3Config.configmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Name = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"User configured UserDefinedCfgMap Unchanged.")
		})
		It("Delete user configured userdefined AS3 cfgMap with invalid namespace", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			as3Config.configmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive), "UserDefinedCfgMap created.")
			Expect(string(as3Config.configmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Namespace = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"User configured UserDefinedCfgMap Unchanged.")
		})
		It("Validate Userdefined AS3 cfgMap against agent cfgMap", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			as3Config.configmap.cfg = "default/testCfgMap"
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			label, ok := mockMgr.as3Mgr.as3ActiveConfig.isValidAS3CfgMap("testCfgMap",
				"default", agentCM.Label)
			Expect(ok).To(Equal(true),
				"UserDefined AS3 configMap validated successfully.")
			Expect(label).To(Equal("as3"),
				"UserDefinedCfgMap has a correct label as 'as3'.")
		})
		It("Prepare user configured Userdefined AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.cfg = "default/testCfgMap"
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.prepareUserDefinedAS3Declaration(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"User configured UserDefinedCfgMap Prepared Successfully.")
		})
		It("Create user configured Userdefined AS3 cfgMap with invalid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.cfg = "default/testCfgMap"
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			agentCM.Data = readConfigFile(configPath + "as3config_invalid_JSON.json")
			mockMgr.as3Mgr.prepareUserDefinedAS3Declaration(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmError),
				"Update of user configured UserDefinedCfgMap Unsuccessful.")
		})
		It("Generate user configured Userdefined AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.cfg = "default/testCfgMap"
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			data := mockMgr.as3Mgr.generateUserDefinedAS3Decleration(*agentCM)
			Expect(data).NotTo(Equal(""),
				"User configured UserDefinedCfgMap generated Successfully.")
		})
	})

	Describe("Labels based User defined AS3 ConfigMap", func() {
		It("Create Userdefined AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"UserDefinedCfgMap Created Successfully.")
		})
		It("Delete Userdefined AS3 cfgMap with valid name and namespace", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive), "UserDefinedCfgMap created.")
			Expect(string(as3Config.configmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			as3Config = mockMgr.as3Mgr.as3ActiveConfig
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmInit),
				"User UserDefinedCfgMap Deleted Successfully.")
		})
		It("Delete userdefined AS3 cfgMap with invalid name", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive), "UserDefinedCfgMap created.")
			Expect(string(as3Config.configmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Name = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"User UserDefinedCfgMap Unchanged.")
		})
		It("Delete userdefined AS3 cfgMap with invalid namespace", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive), "UserDefinedCfgMap created.")
			Expect(string(as3Config.configmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Namespace = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"UserDefinedCfgMap Unchanged.")
		})
		It("Validate Userdefined AS3 cfgMap against agent cfgMap", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			label, ok := mockMgr.as3Mgr.as3ActiveConfig.isValidAS3CfgMap("testCfgMap",
				"default", agentCM.Label)
			Expect(ok).To(Equal(true),
				"UserDefined AS3 configMap validated successfully.")
			Expect(label).To(Equal("as3"),
				"UserDefinedCfgMap has a correct label as 'as3'.")
		})
		It("Prepare user configured Userdefined AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			mockMgr.as3Mgr.prepareUserDefinedAS3Declaration(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmActive),
				"UserDefinedCfgMap Prepared Successfully.")
		})
		It("Create Userdefined AS3 cfgMap with invalid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			agentCM.Data = readConfigFile(configPath + "as3config_invalid_JSON.json")
			mockMgr.as3Mgr.prepareUserDefinedAS3Declaration(*agentCM, &as3Config)
			Expect(as3Config.configmap.State).To(Equal(cmInit),
				"Update of UserDefinedCfgMap Unsuccessful.")
		})
		It("Generate Userdefined AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid user-defined-config-map option
			as3Config.configmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("as3", "as3config_valid.json")
			data := mockMgr.as3Mgr.generateUserDefinedAS3Decleration(*agentCM)
			Expect(data).NotTo(Equal(""),
				"UserDefinedCfgMap generated Successfully.")
		})
	})

	Describe("User configured Override AS3 ConfigMap", func() {
		It("Create user configured Override AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			as3Config.overrideConfigmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"User configured Override CfgMap Created Successfully.")
		})
		It("Delete user configured 'override AS3 cfgMap with valid name and namespace", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			as3Config.overrideConfigmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive), "Override CfgMap created.")
			Expect(string(as3Config.overrideConfigmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			as3Config = mockMgr.as3Mgr.as3ActiveConfig
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmInit),
				"User configured override CfgMap Deleted Successfully.")
		})
		It("Delete user configured override AS3 cfgMap with invalid name", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			as3Config.overrideConfigmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive), "Override CfgMap created.")
			Expect(string(as3Config.overrideConfigmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Name = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"User configured Override CfgMap Unchanged.")
		})
		It("Delete user configured override AS3 cfgMap with invalid namespace", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			as3Config.overrideConfigmap.cfg = "default/testCfgMap"
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive), "Override CfgMap created.")
			Expect(string(as3Config.overrideConfigmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Namespace = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"User configured Override CfgMap Unchanged.")
		})
		It("Validate Userdefined AS3 cfgMap against agent cfgMap", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			as3Config.overrideConfigmap.cfg = "default/testCfgMap"
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			label, ok := mockMgr.as3Mgr.as3ActiveConfig.isValidAS3CfgMap("testCfgMap",
				"default", agentCM.Label)
			Expect(ok).To(Equal(true),
				"Override AS3 configMap validated successfully.")
			Expect(label).To(Equal("overrideAS3"),
				"Override CfgMap has a correct label as 'as3'.")
		})
		It("Prepare user configured override AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.cfg = "default/testCfgMap"
			as3Config.overrideConfigmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			as3Config.prepareAS3OverrideDeclaration(agentCM.Data)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"User configured Override CfgMap Prepared Successfully.")
		})
	})

	Describe("Labels based Override AS3 ConfigMap", func() {
		It("Create Override AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"Override CfgMap Created Successfully.")
		})
		It("Delete override AS3 cfgMap with valid name and namespace", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive), "Override CfgMap created.")
			Expect(string(as3Config.overrideConfigmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			as3Config = mockMgr.as3Mgr.as3ActiveConfig
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmInit),
				"Override CfgMap Deleted Successfully.")
		})
		It("Delete Override AS3 cfgMap with invalid name", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive), "Override CfgMap created.")
			Expect(string(as3Config.overrideConfigmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Name = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"Override CfgMap Unchanged.")
		})
		It("Delete override AS3 cfgMap with invalid namespace", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.processAS3ConfigMap(*agentCM, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive), "Override CfgMap created.")
			Expect(string(as3Config.overrideConfigmap.Data)).NotTo(Equal(""), "Should have data.")
			// Empty agent configMap Data
			agentCM.Operation = OprTypeDelete
			agentCM.Namespace = "invalid"
			mockMgr.as3Mgr.processAS3CfgMapDelete(agentCM.Name, agentCM.Namespace, &as3Config)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"Override CfgMap Unchanged.")
		})
		It("Validate Userdefined AS3 cfgMap against agent cfgMap", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			label, ok := mockMgr.as3Mgr.as3ActiveConfig.isValidAS3CfgMap("testCfgMap",
				"default", agentCM.Label)
			Expect(ok).To(Equal(true),
				"Override AS3 configMap validated successfully.")
			Expect(label).To(Equal("overrideAS3"),
				"Override CfgMap has a correct label as 'as3'.")
		})
		It("Prepare override AS3 cfgMap with valid JSON", func() {
			as3Config := newMockAS3Config()
			// Valid override-config-map option
			as3Config.overrideConfigmap.Init()
			mockMgr.as3Mgr.as3ActiveConfig = as3Config
			agentCM := newMockAgentCfgMap("overrideAS3", "as3config_override_simple_cfgmap_resource.json")
			as3Config.prepareAS3OverrideDeclaration(agentCM.Data)
			Expect(as3Config.overrideConfigmap.State).To(Equal(cmActive),
				"Override CfgMap Prepared Successfully.")
		})
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
			mockMgr.as3Mgr.as3Version = "3.20.0"
			mockMgr.as3Mgr.as3Release = "3.20.0-3"
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
