/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
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
	"fmt"
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"strings"
)

type mockAS3Manager struct {
	*AS3Manager
}

func newMockAS3Manager(params *Params) *mockAS3Manager {
	return &mockAS3Manager{
		NewAS3Manager(params),
	}
}

func mockGetEndPoints(string, string) ([]Member, error) {
	return []Member{{Address: "1.1.1.1", Port: 80, SvcPort: 80},
		{Address: "2.2.2.2", Port: 80, SvcPort: 80}}, nil
}

func (m *mockAS3Manager) shutdown() error {
	return nil
}

var _ = Describe("AS3Manager Tests", func() {
	var mockMgr *mockAS3Manager
	BeforeEach(func() {
		mockMgr = newMockAS3Manager(&Params{
			As3Version:       "3.50.0",
			As3Release:       "3.50.0-5",
			As3SchemaVersion: "3.50.0",
		})
		mockMgr.Resources = &AgentResources{}
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
		It("Unified Declaration only with User Defined ConfigMaps with filter tenant & nodeport local", func() {
			cmcfg1 := readConfigFile(configPath + "as3config_valid_1.json")
			cmcfg2 := readConfigFile(configPath + "as3config_valid_2.json")
			unified := readConfigFile(configPath + "as3_multi_cm_unified_nodeport_local.json")
			mockMgr.FilterTenants = true
			mockMgr.poolMemberType = NodePortLocal
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
			as3config.configmaps, _, _ = mockMgr.prepareResourceAS3ConfigMaps()
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
			as3config.configmaps, _, _ = mockMgr.prepareResourceAS3ConfigMaps()

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
			_, as3config.overrideConfigmapData, _ = mockMgr.prepareResourceAS3ConfigMaps()

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

	Describe("As3 Manager functions", func() {
		It("Default Cipher Group", func() {
			mockMgr.enableTLS = "1.3"
			sharedApp := as3Application{
				"virtualServer": &as3Service{},
			}

			prof := CustomProfile{
				Name: "profile",
				Cert: "Cert Hash",
				Key:  "Key Hash",
			}

			ok := mockMgr.createUpdateTLSServer(prof, "virtualServer", sharedApp)
			Expect(ok).To(BeTrue(), "Failed to create TLS Server Profile")

			Expect(sharedApp["virtualServer_tls_server"]).NotTo(BeNil(), "Failed to create TLS Server Profile")
			Expect(sharedApp["virtualServer"].(*as3Service).ServerTLS).To(Equal("virtualServer_tls_server"), "Failed to set TLS Server Profile")
			Expect(sharedApp["virtualServer_tls_server"].(*as3TLSServer).CipherGroup.BigIP).To(Equal("/Common/f5-default"), "Failed to set Default Cipher group for TLS Server Profile")
		})
		It("Check getTenantObjects function", func() {
			data := mockMgr.getTenantObjects([]string{"test1", "test2"})
			Expect(len(data)).ToNot(Equal(0))
			Expect(strings.Contains(data, "declaration")).To(BeTrue())
			Expect(strings.Contains(data, "class")).To(BeTrue())
			Expect(strings.Contains(data, "Tenant")).To(BeTrue())
			Expect(strings.Contains(data, "test1")).To(BeTrue())
			Expect(strings.Contains(data, "test2")).To(BeTrue())
		})
		It("Check BigIP App services available", func() {
			mockPM := newMockPostManger()
			mockMgr.PostManager = mockPM.PostManager
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusOK,
					body:   `{"version":"3.18.1", "release":"r1", "schemaCurrent":"test"}`,
				},
			}, http.MethodGet)
			Expect(mockMgr.IsBigIPAppServicesAvailable()).To(BeNil())
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusOK,
					body:   `{"version":"3.92.1", "release":"r1", "schemaCurrent":"test"}`,
				},
			}, http.MethodGet)
			Expect(mockMgr.IsBigIPAppServicesAvailable()).To(BeNil())
			Expect(mockMgr.as3Version).To(Equal(defaultAS3Version))
			Expect(mockMgr.as3Release).To(Equal(defaultAS3Version + "-" + defaultAS3Build))
			Expect(mockMgr.as3SchemaVersion).To(Equal(fmt.Sprintf("%.2f.0", as3Version)))
			mockPM.setResponses([]responceCtx{
				{
					tenant: "test",
					status: http.StatusOK,
					body:   `{"version":"3.17.0", "release":"r1", "schemaCurrent":"test"}`,
				},
			}, http.MethodGet)
			Expect(mockMgr.IsBigIPAppServicesAvailable()).ToNot(BeNil())
		})
	})
	Describe("Post AS3 Declaration", func() {
		It("Post AS3 Declaration with config deployer", func() {
			mockMgr.l2l3Agent = L2L3Agent{
				eventChan: make(chan interface{}, 1)}
			mockMgr.RspChan = make(chan interface{}, 1)
			mockMgr.ReqChan = make(chan MessageRequest, 1)
			cfg := &ResourceConfig{
				MetaData: MetaData{
					Active: true,
				},
				Pools: []Pool{{Name: "test-pool", Partition: DEFAULT_PARTITION, ServiceName: "test-svc", ServicePort: 80, MonitorNames: []string{"test_monitor"}, Members: []Member{{Port: 80, Address: "192.168.1.1"}}}},
			}
			agentresources := &AgentResources{
				RsMap: ResourceConfigMap{},
			}
			agentresources.RsMap[NameRef{Name: "test", Partition: DEFAULT_PARTITION}] = cfg
			mockMgr.Resources = agentresources
			//as3ConfigMaps := []*AS3ConfigMap{{Name: "test"}}
			//mockMgr.as3ActiveConfig = AS3Config{configmaps: as3ConfigMaps}
			mockPM := newMockPostManger()
			mockPM.AS3PostDelay = 2
			mockMgr.PostManager = mockPM.PostManager
			go mockMgr.ConfigDeployer()
			mockPM.setResponses([]responceCtx{{
				tenant: "test",
				status: http.StatusOK,
				body:   "",
			}}, http.MethodPost)
			resourceRequest := ResourceRequest{
				PoolMembers:  make(map[Member]struct{}),
				Resources:    agentresources,
				Profs:        map[SecretKey]CustomProfile{},
				IrulesMap:    IRulesMap{},
				IntDgMap:     InternalDataGroupMap{},
				IntF5Res:     InternalF5ResourcesGroup{},
				AgentCfgmaps: []*AgentCfgMap{},
			}
			Expect(mockMgr.as3ActiveConfig.resourceConfig).To(BeNil())
			Expect(mockMgr.as3ActiveConfig.unifiedDeclaration).To(BeEmpty())
			// putting the first request on channel
			mockMgr.ReqChan <- MessageRequest{ReqID: 1, MsgType: "test", ResourceRequest: resourceRequest}
			l2msg := <-mockMgr.l2l3Agent.eventChan
			Expect(l2msg).ToNot(BeNil(), "l2l3 Channel should not be empty")
			msg := <-mockMgr.RspChan
			Expect(msg).ToNot(BeNil(), "response Channel should not be empty")
			Expect(mockMgr.as3ActiveConfig.resourceConfig).ToNot(BeNil())
			Expect(mockMgr.as3ActiveConfig.unifiedDeclaration).ToNot(BeEmpty())
			close(mockMgr.RspChan)
			close(mockMgr.l2l3Agent.eventChan)
			close(mockMgr.ReqChan)
		})
		It("Post AS3 Declaration on event timeout", func() {
			mockMgr.ReqChan = make(chan MessageRequest, 1)
			agentresource := &AgentResources{
				RsMap: ResourceConfigMap{},
			}
			tnt := "test"
			mockPM := newMockPostManger()
			mockMgr.PostManager = mockPM.PostManager
			mockPM.setResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   "",
			}}, http.MethodPost)
			resourceRequest := ResourceRequest{
				PoolMembers:  make(map[Member]struct{}),
				Resources:    agentresource,
				Profs:        map[SecretKey]CustomProfile{},
				IrulesMap:    IRulesMap{},
				IntDgMap:     InternalDataGroupMap{},
				IntF5Res:     InternalF5ResourcesGroup{},
				AgentCfgmaps: []*AgentCfgMap{},
			}
			mockMgr.ReqChan <- MessageRequest{ReqID: 1, MsgType: "test", ResourceRequest: resourceRequest}
			result, output, _ := mockMgr.postOnEventOrTimeout(timeoutSmall)
			close(mockMgr.ReqChan)
			Expect(result).To(BeTrue(), "Posting Failed")
			Expect(output).To(Equal("statusOK"), "Posting Failed")
		})
		It("Validate partition deletion with tenant filtering", func() {
			cmcfg1 := readConfigFile(configPath + "as3config_valid_1.json")
			mockMgr.FilterTenants = true
			mockMgr.as3ActiveConfig.tenantMap["Tenant1"] = true
			mockMgr.as3ActiveConfig.tenantMap["Tenant2"] = true
			mockPM := newMockPostManger()
			mockMgr.PostManager = mockPM.PostManager
			mockPM.setResponses([]responceCtx{{
				tenant: "Tenant1",
				status: http.StatusOK,
				body:   ""},
				{
					tenant: "Tenant1",
					status: http.StatusOK,
					body:   ""},
				{
					tenant: "Tenant1",
					status: http.StatusOK,
					body:   ""},
			}, http.MethodPost)
			agentresource := &AgentResources{
				RsMap: ResourceConfigMap{},
			}
			resourceRequest := ResourceRequest{
				PoolMembers: make(map[Member]struct{}),
				Resources:   agentresource,
				Profs:       map[SecretKey]CustomProfile{},
				IrulesMap:   IRulesMap{},
				IntDgMap:    InternalDataGroupMap{},
				IntF5Res:    InternalF5ResourcesGroup{},
			}
			resourceRequest.AgentCfgmaps = append(
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
			)
			mockMgr.as3ActiveConfig.unifiedDeclaration = as3Declaration(readConfigFile(configPath + "as3config_multi_cm_unified.json"))
			result, output, _ := mockMgr.postAS3Declaration(resourceRequest)
			Expect(result).To(BeTrue(), "Posting Failed")
			Expect(output).To(Equal(responseStatusOk), "Posting Failed")
			// Verify that tenant3 is deleted from active configMap
			_, ok := mockMgr.as3ActiveConfig.tenantMap["Tenant2"]
			Expect(ok).To(BeFalse(), "Tenant2 Should be deleted from active configMap")
			Expect(len(mockMgr.as3ActiveConfig.tenantMap)).To(Equal(1), "Tenant2 Should be deleted from active configMap")
		})
		It("Clean CIS managed Partition", func() {
			mockPM := newMockPostManger()
			mockMgr.PostManager = mockPM.PostManager
			mockPM.setResponses([]responceCtx{{
				tenant: "Tenant1",
				status: http.StatusOK,
				body:   ""},
			}, http.MethodPost)
			result, output := mockMgr.CleanAS3Tenant("Tenant1")
			Expect(result).To(BeTrue(), "Posting Failed")
			Expect(output).To(Equal(responseStatusOk), "Posting Failed")
		})
		It("Handle Post Failures", func() {
			mockPM := newMockPostManger()
			mockMgr.PostManager = mockPM.PostManager
			mockPM.setResponses([]responceCtx{{
				tenant: "Tenant1",
				status: http.StatusOK,
				body:   ""},
			}, http.MethodPost)
			mockMgr.as3ActiveConfig.unifiedDeclaration = as3Declaration(readConfigFile(configPath + "as3config_multi_cm_unified.json"))
			result, output := mockMgr.failureHandler()
			Expect(result).To(BeTrue(), "Posting Failed")
			Expect(output).To(Equal(responseStatusOk), "Posting Failed")
			mockMgr.FilterTenants = true
			// setting failed tenant context
			mockMgr.failedContext.failedTenants["Tenant1"] = as3Declaration("")
			mockPM.setResponses([]responceCtx{{
				tenant: "Tenant1",
				status: http.StatusOK,
				body:   ""},
			}, http.MethodPost)
			result, output = mockMgr.failureHandler()
			Expect(result).To(BeTrue(), "Posting Failed")
			Expect(output).To(Equal(responseStatusOk), "Posting Failed")
			Expect(len(mockMgr.failedContext.failedTenants)).To(Equal(0), "Posting Failed")
		})
	})
	Describe("Test processResponseCodeList", func() {
		It("Test processResponseCodeList without any entry in Map", func() {
			responseList := make(map[string]int)
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeFalse(), "Incorrect status")
			Expect(output).To(Equal(responseStatusCommon), "Incorrect status")
		})
		It("Test processResponseCodeList with responseStatusServiceUnavailable", func() {
			responseList := make(map[string]int)
			responseList[responseStatusServiceUnavailable] = 1
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeFalse(), "Incorrect status")
			Expect(output).To(Equal(responseStatusServiceUnavailable), "Incorrect status")
		})
		It("Test processResponseCodeList with responseStatusNotFound", func() {
			responseList := make(map[string]int)
			responseList[responseStatusNotFound] = 1
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeTrue(), "Incorrect status")
			Expect(output).To(Equal(responseStatusNotFound), "Incorrect status")
		})
		It("Test processResponseCodeList with responseStatusCommon", func() {
			responseList := make(map[string]int)
			responseList[responseStatusCommon] = 1
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeFalse(), "Incorrect status")
			Expect(output).To(Equal(responseStatusCommon), "Incorrect status")
		})
		It("Test processResponseCodeList with responseStatusDummy", func() {
			responseList := make(map[string]int)
			responseList[responseStatusDummy] = 1
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeTrue(), "Incorrect status")
			Expect(output).To(Equal(responseStatusDummy), "Incorrect status")
		})
		It("Test processResponseCodeList with responseStatusUnprocessableEntity", func() {
			responseList := make(map[string]int)
			responseList[responseStatusUnprocessableEntity] = 1
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeTrue(), "Incorrect status")
			Expect(output).To(Equal(responseStatusUnprocessableEntity), "Incorrect status")
		})
		It("Test processResponseCodeList with responseStatusOk", func() {
			responseList := make(map[string]int)
			responseList[responseStatusOk] = 1
			result, output := processResponseCodeList(responseList)
			Expect(result).To(BeTrue(), "Incorrect status")
			Expect(output).To(Equal(responseStatusOk), "Incorrect status")
		})
	})
})
