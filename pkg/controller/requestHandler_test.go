package controller

import (
	"encoding/json"
	v1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Backend Tests", func() {

	Describe("Prepare AS3 Declaration", func() {
		var mem1, mem2, mem3, mem4 PoolMember
		var agent *RequestHandler
		BeforeEach(func() {
			agent = newMockAgent(&PostManager{PostParams: PostParams{CMURL: "https://192.168.1.1"}}, "test", "as3")
			agent.PostManager.AS3PostManager = &AS3PostManager{}
			mem1 = PoolMember{
				Address:         "1.2.3.5",
				Port:            8080,
				ConnectionLimit: 5,
				AdminState:      "disable",
			}
			mem2 = PoolMember{
				Address:         "1.2.3.6",
				Port:            8081,
				ConnectionLimit: 5,
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
			rsCfg.Virtual.PoolName = "default_pool_svc1"
			rsCfg.Virtual.Destination = "/test/172.13.14.5:8080"
			rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
			rsCfg.Virtual.IpIntelligencePolicy = "/Common/ip-intelligence-policy"
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
					Name:            "pool1",
					MinimumMonitors: intstr.IntOrString{Type: 1, StrVal: "all"},
					Members:         []PoolMember{mem1, mem2},
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
			rsCfg2.MetaData.defaultPoolType = BIGIP
			rsCfg2.MetaData.ResourceType = VirtualServer
			rsCfg2.Virtual.Name = "crd_vs_172.13.14.16"
			rsCfg.Virtual.PoolName = "default_pool_svc2"
			rsCfg2.Pools = Pools{
				Pool{
					Name:            "pool1",
					Members:         []PoolMember{mem3, mem4},
					MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
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
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
				bigipConfig:         v1.BigIpConfig{},
			}
			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.16"] = rsCfg2

			decl := agent.createTenantDeclaration(config.bigIpResourceConfig, "test", make(map[string]as3Tenant))

			Expect(string(decl.(as3Declaration))).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(string(decl.(as3Declaration)), "pool1")).To(BeTrue())
			Expect(strings.Contains(string(decl.(as3Declaration)), "default_pool_svc2")).To(BeTrue())
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
					Name:            "pool1",
					Members:         []PoolMember{mem1, mem2},
					MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
				},
			}

			config := ResourceConfigRequest{
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
				bigipConfig:         v1.BigIpConfig{},
			}

			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg

			decl := agent.createTenantDeclaration(config.bigIpResourceConfig, "test", make(map[string]as3Tenant))

			Expect(string(decl.(as3Declaration))).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(string(decl.(as3Declaration)), "adminState")).To(BeTrue())
			Expect(strings.Contains(string(decl.(as3Declaration)), "connectionLimit")).To(BeTrue())

		})
		It("Delete partition", func() {
			config := ResourceConfigRequest{
				bigipConfig:         v1.BigIpConfig{},
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
			}

			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			as3decl := agent.createTenantDeclaration(config.bigIpResourceConfig, "test", make(map[string]as3Tenant))
			var as3Config map[string]interface{}
			_ = json.Unmarshal([]byte(as3decl.(as3Declaration)), &as3Config)
			deletedTenantDecl := as3Tenant{
				"class": "Tenant",
			}
			adc := as3Config["declaration"].(map[string]interface{})

			//Expect(requesthandler.incomingTenantDeclMap["default"]).To(Equal(deletedTenantDecl), "Failed to Create AS3 Declaration for deleted tenant")
			Expect(adc["default"]).To(Equal(map[string]interface{}(deletedTenantDecl)), "Failed to Create AS3 Declaration for deleted tenant")
		})
		It("Handles Persistence Methods", func() {
			svc := &as3Service{}
			// Default persistence methods
			defaultValues := []string{"cookie", "destination-address", "hash", "msrdp",
				"sip-info", "source-address", "tls-session-id", "universal"}
			for _, defaultValue := range defaultValues {
				svc.addPersistenceMethod(defaultValue)
				Expect(svc.PersistenceMethods).To(Equal(&[]as3MultiTypeParam{as3MultiTypeParam(defaultValue)}))
			}

			// Persistence methods with no value and None
			svc = &as3Service{}
			svc.addPersistenceMethod("")
			Expect(svc.PersistenceMethods).To(BeNil())
			svc.addPersistenceMethod("none")
			Expect(svc.PersistenceMethods).To(Equal(&[]as3MultiTypeParam{}))

			// Custom persistence methods
			svc.addPersistenceMethod("/Common/pm1")
			Expect(svc.PersistenceMethods).To(Equal(&[]as3MultiTypeParam{as3ResourcePointer{BigIP: "/Common/pm1"}}))
			svc.addPersistenceMethod("pm2")
			Expect(svc.PersistenceMethods).To(Equal(&[]as3MultiTypeParam{as3ResourcePointer{BigIP: "pm2"}}))
		})
	})

	Describe("Prepare AS3 Declaration with HAMode", func() {
		var agent *RequestHandler
		tnt := "test"
		BeforeEach(func() {
			client, _ := getMockHttpClient([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   `{"declaration": {"label":"test",  "testRemove": {"Shared": {"class": "application"}}, "test": {"Shared": {"class": "application"}}}}`,
			}}, http.MethodGet)
			agent = newMockAgent(&PostManager{PostParams: PostParams{CMURL: "https://192.168.1.1", httpClient: client},
				defaultPartition: "test"}, "test", "as3")
			agent.PostManager.HAMode = true
			agent.PostManager.AS3PostManager = &AS3PostManager{}

		})
		It("VirtualServer Declaration", func() {
			config := ResourceConfigRequest{
				bigipConfig:         v1.BigIpConfig{},
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
			}

			agent.PostManager.AS3PostManager.firstPost = true
			agent.PostManager.tokenManager = tokenmanager.NewTokenManager("https://0.0.0.0", tokenmanager.Credentials{Username: "admin", Password: "admin"}, "admin", false)
			currentConfig, _ := agent.PostManager.GetAS3DeclarationFromBigIP()
			removeDeletedTenantsForBigIP(&config.bigIpResourceConfig, agent.PostManager.defaultPartition, currentConfig, agent.PostManager.defaultPartition)
			decl := agent.createTenantDeclaration(config.bigIpResourceConfig, "test", make(map[string]as3Tenant))

			Expect(string(decl.(as3Declaration))).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(string(decl.(as3Declaration)), "\"declaration\":{\"class\":\"Tenant\"}")).To(BeTrue())

		})
	})

	Describe("GTM Config", func() {
		//var requesthandler Agent
		BeforeEach(func() {
			//requesthandler = newMockAgent()
			DEFAULT_PARTITION = "default"
		})
		// Commenting this test case
		// with new GTM partition support we will not delete partition, instead we flush contents
		//It("Empty GTM Config", func() {
		//	adc := as3ADC{}
		//	adc = requesthandler.createAS3GTMConfigADC(ResourceConfigRequest{
		//		gtmConfig: GTMConfig{},
		//	}, adc)
		//
		//	Expect(len(adc)).To(BeZero(), "Invalid GTM Config")
		//})

		//It("Empty GTM Partition Config / Delete Case", func() {
		//	adc := as3ADC{}
		//	adc = requesthandler.createAS3GTMConfigADC(BigIpResourceConfig{
		//		gtmConfig: GTMConfig{
		//			DEFAULT_PARTITION: GTMPartitionConfig{},
		//		},
		//	}, adc)
		//	Expect(len(adc)).To(Equal(1), "Invalid GTM Config")
		//
		//	Expect(adc).To(HaveKey(DEFAULT_PARTITION))
		//	tenant := adc[DEFAULT_PARTITION].(as3Tenant)
		//
		//	Expect(tenant).To(HaveKey(as3SharedApplication))
		//	sharedApp := tenant[as3SharedApplication].(as3Application)
		//	Expect(len(sharedApp)).To(Equal(2))
		//	Expect(sharedApp).To(HaveKeyWithValue("class", "Application"))
		//	Expect(sharedApp).To(HaveKeyWithValue("template", "shared"))
		//})

		//It("Valid GTM Config", func() {
		//	monitors := []Monitor{
		//		{
		//			Name:     "pool1_monitor",
		//			Interval: 10,
		//			Timeout:  10,
		//			Type:     "http",
		//			Send:     "GET /health",
		//		},
		//	}
		//	gtmConfig := GTMConfig{
		//		DEFAULT_PARTITION: GTMPartitionConfig{
		//			WideIPs: map[string]WideIP{
		//				"test.com": {
		//					DomainName: "test.com",
		//					RecordType: "A",
		//					LBMethod:   "round-robin",
		//					Pools: []GSLBPool{
		//						{
		//							Name:       "pool1",
		//							RecordType: "A",
		//							LBMethod:   "round-robin",
		//							Members:    []string{"vs1", "vs2"},
		//							Monitors:   monitors,
		//						},
		//					},
		//				},
		//			},
		//		},
		//	}
		//	adc := requesthandler.createAS3GTMConfigADC(
		//		BigIpResourceConfig{gtmConfig: gtmConfig},
		//		as3ADC{},
		//	)
		//
		//	Expect(adc).To(HaveKey(DEFAULT_PARTITION))
		//	tenant := adc[DEFAULT_PARTITION].(as3Tenant)
		//
		//	Expect(tenant).To(HaveKey(as3SharedApplication))
		//	sharedApp := tenant[as3SharedApplication].(as3Application)
		//
		//	Expect(sharedApp).To(HaveKey("test.com"))
		//	Expect(sharedApp["test.com"].(as3GLSBDomain).Class).To(Equal("GSLB_Domain"))
		//
		//	Expect(sharedApp).To(HaveKey("pool1"))
		//	Expect(sharedApp["pool1"].(as3GSLBPool).Class).To(Equal("GSLB_Pool"))
		//
		//	Expect(sharedApp).To(HaveKey("pool1_monitor"))
		//	Expect(sharedApp["pool1_monitor"].(as3GSLBMonitor).Class).To(Equal("GSLB_Monitor"))
		//})
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
		It("Test Deleted Partition", func() {
			cisLabel := "test"
			deletedPartition := getDeletedTenantDeclaration("test", "test", cisLabel)
			Expect(deletedPartition[as3SharedApplication]).NotTo(BeNil())
			deletedPartition = getDeletedTenantDeclaration("test", "default", cisLabel)
			Expect(deletedPartition[as3SharedApplication]).To(BeNil())
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

	Describe("Agent", func() {
		var (
			server *ghttp.Server
			//body   []byte
		)
		BeforeEach(func() {
			map1 := map[string]string{
				"version":       "3.98.0",
				"release":       "1",
				"schemaCurrent": "3.48.0",
				"schemaMinimum": "3.18.0",
			}
			// start a test http server
			server = ghttp.NewServer()

			statusCode := 200

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/mgmt/shared/appsvcs/info"),
					ghttp.RespondWithJSONEncoded(statusCode, map1),
				))
		})
		AfterEach(func() {
			server.Close()
		})
		//Commenting this as we no longer AS3 version from CM
		/*It("New Agent", func() {
			var agentParams AgentParams
			agentParams.EnableIPV6 = true
			agentParams.Partition = "test"
			agentParams.PostParams.CMURL = "http://" + server.Addr()
			requesthandler := NewAgent(agentParams, "bigip1")
			Expect(requesthandler.AS3VersionInfo.as3Version).To(Equal("3.48.0"))
		})*/
	})

})
