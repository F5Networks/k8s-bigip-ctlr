package controller

import (
	"encoding/json"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Backend Tests", func() {

	Describe("Prepare AS3 Declaration", func() {
		var mem1, mem2, mem3, mem4 PoolMember
		var agent *Agent
		BeforeEach(func() {
			writer := &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			agent = newMockAgent(writer)
			agent.userAgent = "as3"

			mem1 = PoolMember{
				Address: "1.2.3.5",
				Port:    8080,
			}
			mem2 = PoolMember{
				Address: "1.2.3.6",
				Port:    8081,
			}
			mem3 = PoolMember{
				Address: "1.2.3.7",
				Port:    8082,
			}
			mem4 = PoolMember{
				Address: "1.2.3.8",
				Port:    8083,
			}
		})
		It("VirtualServer Declaration", func() {

			rsCfg := &ResourceConfig{}
			rsCfg.MetaData.Active = true
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Name = "crd_vs_172.13.14.15"
			rsCfg.Virtual.Destination = "/test/172.13.14.5:8080"
			rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
			rsCfg.Virtual.Policies = []nameRef{
				{
					Name:      "policy1",
					Partition: "test",
				},
				{
					Name:      "policy2",
					Partition: "test",
				},
			}
			rsCfg.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []PoolMember{mem1, mem2},
					MonitorNames: []MonitorName{
						{Name: "/test/http_monitor"},
					},
				},
			}
			rsCfg.IRulesMap = IRulesMap{
				NameRef{"custom_iRule", DEFAULT_PARTITION}: &IRule{
					Name:      "custom_iRule",
					Partition: DEFAULT_PARTITION,
					Code:      "tcl code blocks",
				},
				NameRef{HttpRedirectIRuleName, DEFAULT_PARTITION}: &IRule{
					Name:      HttpRedirectIRuleName,
					Partition: DEFAULT_PARTITION,
					Code:      "tcl code blocks",
				},
			}
			rsCfg.Policies = Policies{
				Policy{
					Name:     "policy1",
					Strategy: "first-match",
					Rules: Rules{
						&Rule{
							Conditions: []*condition{
								{
									Values: []string{"test.com"},
									Equals: true,
								},
							},
							Actions: []*action{
								{
									Forward:  true,
									Request:  true,
									Redirect: true,
									HTTPURI:  true,
									HTTPHost: true,
									Pool:     "default_svc_1",
								},
							},
						},
					},
				},
				Policy{
					Name:     "policy2",
					Strategy: "first-match",
					Rules: Rules{
						&Rule{
							Conditions: []*condition{
								{
									Host:     true,
									Values:   []string{"prod.com"},
									Equals:   true,
									HTTPHost: true,
									Request:  true,
								},
								{
									PathSegment: true,
									Index:       1,
									HTTPURI:     true,
									Equals:      true,
									Values:      []string{"/foo"},
									Request:     true,
								},
							},
							Actions: []*action{
								{
									Forward:  true,
									Request:  true,
									Redirect: true,
									HTTPURI:  true,
									HTTPHost: true,
									Pool:     "default_svc_2",
								},
							},
						},
					},
				},
			}
			rsCfg.Monitors = Monitors{
				{
					Name:       "http_monitor",
					Interval:   10,
					Type:       "http",
					TargetPort: 8080,
					Timeout:    10,
					Send:       "GET /health",
				},
				{
					Name:       "https_monitor",
					Interval:   10,
					Type:       "https",
					TargetPort: 8443,
					Timeout:    10,
					Send:       "GET /health",
				},
				{
					Name:       "tcp_monitor",
					Interval:   10,
					Type:       "tcp",
					TargetPort: 3600,
					Timeout:    10,
					Send:       "GET /health",
				},
			}

			rsCfg.Virtual.Profiles = ProfileRefs{
				ProfileRef{
					Name:      "serverssl",
					Partition: "Common",
					Context:   "serverside",
				},
				ProfileRef{
					Name:    "serversslnew",
					Context: "serverside",
				},
				ProfileRef{
					Name:      "clientssl",
					Partition: "Common",
					Context:   "clientside",
				},
				ProfileRef{
					Name:    "clientsslnew",
					Context: "clientside",
				},
			}

			rsCfg2 := &ResourceConfig{}
			rsCfg2.MetaData.Active = false
			rsCfg2.MetaData.ResourceType = VirtualServer
			rsCfg2.Virtual.Name = "crd_vs_172.13.14.16"
			rsCfg2.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []PoolMember{mem3, mem4},
				},
			}

			rsCfg2.customProfiles = make(map[SecretKey]CustomProfile)
			cert := certificate{Cert: "crthash", Key: "keyhash"}
			rsCfg2.customProfiles[SecretKey{
				Name:         "default_svc_test_com_cssl",
				ResourceName: "crd_vs_172.13.14.15",
			}] = CustomProfile{
				Name:         "default_svc_test_com_cssl",
				Partition:    "test",
				Context:      "clientside",
				Certificates: []certificate{cert},
				SNIDefault:   false,
			}
			certOnly := certificate{Cert: "crthash"}
			rsCfg2.customProfiles[SecretKey{
				Name:         "default_svc_test_com_sssl",
				ResourceName: "crd_vs_172.13.14.15",
			}] = CustomProfile{
				Name:         "default_svc_test_com_sssl",
				Partition:    "test",
				Context:      "serverside",
				Certificates: []certificate{certOnly},
				ServerName:   "test.com",
				SNIDefault:   false,
			}

			config := ResourceConfigRequest{
				ltmConfig:          make(LTMConfig),
				shareNodes:         true,
				gtmConfig:          GTMConfig{},
				defaultRouteDomain: 1,
			}

			config.ltmConfig["default"] = &PartitionConfig{make(ResourceMap), 0}
			config.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg
			config.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.16"] = rsCfg2

			decl := agent.createTenantAS3Declaration(config)

			Expect(string(decl)).ToNot(Equal(""), "Failed to Create AS3 Declaration")
		})
		It("TransportServer Declaration", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.MetaData.Active = true
			rsCfg.MetaData.ResourceType = TransportServer
			rsCfg.Virtual.Name = "crd_vs_172.13.14.16"
			rsCfg.Virtual.Mode = "standard"
			rsCfg.Virtual.IpProtocol = "tcp"
			rsCfg.Virtual.TranslateServerAddress = true
			rsCfg.Virtual.TranslateServerPort = true
			rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
			rsCfg.Virtual.Destination = "172.13.14.6:1600"
			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)
			rsCfg.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []PoolMember{mem1, mem2},
				},
			}

			config := ResourceConfigRequest{
				ltmConfig:          make(LTMConfig),
				shareNodes:         true,
				gtmConfig:          GTMConfig{},
				defaultRouteDomain: 1,
			}

			config.ltmConfig["default"] = &PartitionConfig{make(ResourceMap), 0}
			config.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg

			decl := agent.createTenantAS3Declaration(config)

			Expect(string(decl)).ToNot(Equal(""), "Failed to Create AS3 Declaration")

		})
		It("Delete partition", func() {
			config := ResourceConfigRequest{
				ltmConfig:          make(LTMConfig),
				shareNodes:         true,
				gtmConfig:          GTMConfig{},
				defaultRouteDomain: 1,
			}

			config.ltmConfig["default"] = &PartitionConfig{make(ResourceMap), 0}

			as3decl := agent.createTenantAS3Declaration(config)
			var as3Config map[string]interface{}
			_ = json.Unmarshal([]byte(as3decl), &as3Config)
			deletedTenantDecl := as3Tenant{
				"class": "Tenant",
			}
			adc := as3Config["declaration"].(map[string]interface{})

			Expect(agent.incomingTenantDeclMap["default"]).To(Equal(deletedTenantDecl), "Failed to Create AS3 Declaration for deleted tenant")
			Expect(adc["default"]).To(Equal(map[string]interface{}(deletedTenantDecl)), "Failed to Create AS3 Declaration for deleted tenant")
		})
		It("Handles Persistence Methods", func() {
			svc := &as3Service{}
			// Default persistence methods
			defaultValues := []string{"cookie", "destination-address", "hash", "msrdp",
				"sip-info", "source-address", "tls-session-id", "universal"}
			for _, defaultValue := range defaultValues {
				svc.addPersistenceMethod(defaultValue)
				Expect(svc.PersistenceMethods).To(Equal([]as3MultiTypeParam{as3MultiTypeParam(defaultValue)}))
			}

			// Persistence methods with no value and None
			svc = &as3Service{}
			svc.addPersistenceMethod("")
			Expect(svc.PersistenceMethods).To(BeNil())
			svc.addPersistenceMethod("none")
			Expect(svc.PersistenceMethods).To(Equal([]as3MultiTypeParam{}))

			// Custom persistence methods
			svc.addPersistenceMethod("/Common/pm1")
			Expect(svc.PersistenceMethods).To(Equal([]as3MultiTypeParam{as3ResourcePointer{BigIP: "/Common/pm1"}}))
			svc.addPersistenceMethod("pm2")
			Expect(svc.PersistenceMethods).To(Equal([]as3MultiTypeParam{as3ResourcePointer{BigIP: "pm2"}}))
		})
	})

	Describe("GTM Config", func() {
		var agent *Agent
		BeforeEach(func() {
			agent = newMockAgent(nil)
			DEFAULT_PARTITION = "default"
		})

		It("Empty GTM Config", func() {
			adc := as3ADC{}
			adc = agent.createAS3GTMConfigADC(ResourceConfigRequest{
				gtmConfig: GTMConfig{},
			}, adc)

			Expect(len(adc)).To(BeZero(), "Invalid GTM Config")
		})

		It("Empty GTM Partition Config / Delete Case", func() {
			adc := as3ADC{}
			adc = agent.createAS3GTMConfigADC(ResourceConfigRequest{
				gtmConfig: GTMConfig{
					DEFAULT_PARTITION: GTMPartitionConfig{},
				},
			}, adc)
			Expect(len(adc)).To(Equal(1), "Invalid GTM Config")

			Expect(adc).To(HaveKey(DEFAULT_PARTITION))
			tenant := adc[DEFAULT_PARTITION].(as3Tenant)

			Expect(tenant).To(HaveKey(as3SharedApplication))
			sharedApp := tenant[as3SharedApplication].(as3Application)
			Expect(len(sharedApp)).To(Equal(2))
			Expect(sharedApp).To(HaveKeyWithValue("class", "Application"))
			Expect(sharedApp).To(HaveKeyWithValue("template", "shared"))
		})

		It("Valid GTM Config", func() {
			monitors := []Monitor{
				{
					Name:     "pool1_monitor",
					Interval: 10,
					Timeout:  10,
					Type:     "http",
					Send:     "GET /health",
				},
			}
			gtmConfig := GTMConfig{
				DEFAULT_PARTITION: GTMPartitionConfig{
					WideIPs: map[string]WideIP{
						"test.com": WideIP{
							DomainName: "test.com",
							RecordType: "A",
							LBMethod:   "round-robin",
							Pools: []GSLBPool{
								{
									Name:       "pool1",
									RecordType: "A",
									LBMethod:   "round-robin",
									Members:    []string{"vs1", "vs2"},
									Monitors:   monitors,
								},
							},
						},
					},
				},
			}
			adc := agent.createAS3GTMConfigADC(
				ResourceConfigRequest{gtmConfig: gtmConfig},
				as3ADC{},
			)

			Expect(adc).To(HaveKey(DEFAULT_PARTITION))
			tenant := adc[DEFAULT_PARTITION].(as3Tenant)

			Expect(tenant).To(HaveKey(as3SharedApplication))
			sharedApp := tenant[as3SharedApplication].(as3Application)

			Expect(sharedApp).To(HaveKey("test.com"))
			Expect(sharedApp["test.com"].(as3GLSBDomain).Class).To(Equal("GSLB_Domain"))

			Expect(sharedApp).To(HaveKey("pool1"))
			Expect(sharedApp["pool1"].(as3GSLBPool).Class).To(Equal("GSLB_Pool"))

			Expect(sharedApp).To(HaveKey("pool1_monitor"))
			Expect(sharedApp["pool1_monitor"].(as3GSLBMonitor).Class).To(Equal("GSLB_Monitor"))
		})
	})

	Describe("Misc", func() {
		It("Service Address declaration", func() {
			rsCfg := &ResourceConfig{
				ServiceAddress: []ServiceAddress{
					{
						ArpEnabled: true,
					},
				},
			}
			app := as3Application{}
			createServiceAddressDecl(rsCfg, "1.2.3.4", app)

			val, ok := app["crd_service_address_1_2_3_4"]
			Expect(ok).To(BeTrue())
			Expect(val).NotTo(BeNil())
		})
	})

	Describe("JSON comparision of AS3 declaration", func() {
		It("Verify with two empty declarations", func() {
			ok := DeepEqualJSON("", "")
			Expect(ok).To(BeTrue(), "Failed to compare empty declarations")
		})
		It("Verify with empty and non empty declarations", func() {
			cmcfg1 := `{"key": "value"}`
			ok := DeepEqualJSON("", as3Declaration(cmcfg1))
			Expect(ok).To(BeFalse())
			ok = DeepEqualJSON(as3Declaration(cmcfg1), "")
			Expect(ok).To(BeFalse())
		})
		It("Verify two equal JSONs", func() {
			ok := DeepEqualJSON(`{"key": "value"}`, `{"key": "value"}`)
			Expect(ok).To(BeTrue())
		})
	})

})
