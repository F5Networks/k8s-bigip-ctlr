package controller

import (
	"encoding/json"
	"net/http"
	"strings"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Backend Tests", func() {

	Describe("Prepare AS3 Declaration", func() {
		var mem1, mem2, mem3, mem4 PoolMember
		var requestHandler *RequestHandler
		BeforeEach(func() {
			requestHandler = newMockAgent("as3")
			requestHandler.PostManagers.PostManagerMap[cisapiv1.BigIpConfig{}] = &PostManager{
				PostParams: PostParams{},
				AS3PostManager: &AS3PostManager{
					AS3Config: cisapiv1.AS3Config{},
				}}
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
			rsCfg.Virtual.Destination = "/test/172.13.14.15:8080"
			rsCfg.Virtual.Partition = "test"
			rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
			rsCfg.Virtual.IpIntelligencePolicy = "/Common/ip-intelligence-policy"
			rsCfg.Virtual.TCP.Client = "client1"
			rsCfg.IntDgMap = InternalDataGroupMap{
				NameRef{"crd_vs_172.13.14.15_ssl_passthrough_servername_dg", rsCfg.Virtual.Partition}: {
					"dg1": &InternalDataGroup{
						Name:      "dg1",
						Partition: "Common",
						Type:      "string",
						Records: []InternalDataGroupRecord{
							{
								Name: "dg1_int",
								Data: "data group1 data1",
							},
						},
					},
					"dg2": &InternalDataGroup{
						Name:      "dg1",
						Partition: "Common",
						Type:      "string",
						Records: []InternalDataGroupRecord{
							{
								Name: "dg2_int",
								Data: "data group1 data2",
							},
						},
					},
				},
			}
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
					Recv:       "Response /health",
				},
				{
					Name:       "https_monitor",
					Interval:   10,
					Type:       "https",
					TargetPort: 8443,
					Timeout:    10,
					Send:       "GET /health",
					Recv:       "Response /health",
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
					Name:         "serversslnew",
					Context:      "serverside",
					BigIPProfile: true,
				},
				ProfileRef{
					Name:      "clientssl",
					Partition: "Common",
					Context:   "clientside",
				},
				ProfileRef{
					Name:         "clientsslnew",
					Context:      "clientside",
					BigIPProfile: true,
				},
				ProfileRef{
					Name:         "httpsslnew",
					Context:      "http",
					BigIPProfile: true,
				},
				ProfileRef{
					Name:    "httpssl",
					Context: "http",
				},
			}
			rsCfg.Virtual.ProfileMultiplex = "/Common/profile_multiplex_1"
			rsCfg.ServiceAddress = []ServiceAddress{
				{
					RouteAdvertisement: "advertise",
				},
			}
			rsCfg.Virtual.AdditionalVirtualAddresses = []string{"1.2.3.4"}
			rsCfg2 := &ResourceConfig{}
			rsCfg2.MetaData.Active = false
			rsCfg2.MetaData.defaultPoolType = BIGIP
			rsCfg2.Virtual.Destination = "/test/172.13.14.16:8080"
			rsCfg2.MetaData.ResourceType = VirtualServer
			rsCfg2.Virtual.Name = "crd_vs_172.13.14.16"
			rsCfg2.Virtual.PoolName = "default_pool_svc2"
			rsCfg2.Virtual.TLSTermination = TLSPassthrough
			rsCfg.Virtual.IRules = []string{"none"}
			rsCfg2.ServiceAddress = []ServiceAddress{}
			rsCfg2.Virtual.AdditionalVirtualAddresses = []string{"1.2.3.4"}
			rsCfg2.Virtual.Policies = []nameRef{
				{
					Name:      "policy1",
					Partition: "test",
				},
			}
			rsCfg2.Virtual.ProfileDOS = "/Common/dos_profile"
			rsCfg2.Virtual.ProfileBotDefense = "/Common/bot_defense"
			rsCfg2.MetaData.Protocol = "https"
			rsCfg2.Virtual.HTTP2.Client = "http2_client"
			rsCfg2.Virtual.HTTP2.Server = "http2_server"
			rsCfg2.Virtual.TCP.Client = "client"
			rsCfg2.Virtual.TCP.Server = "server"
			routingEnabled := true
			rsCfg.Virtual.HttpMrfRoutingEnabled = &routingEnabled
			rsCfg.Virtual.AutoLastHop = "/Common/last_hop"
			rsCfg.MetaData.Protocol = "https"
			rsCfg.Virtual.HTTP2.Client = "http2_client"
			rsCfg2.Virtual.AnalyticsProfiles = AnalyticsProfiles{
				HTTPAnalyticsProfile: "/Common/analytic_profile",
			}
			rsCfg2.Virtual.WAF = "/Common/waf_policy"
			rsCfg2.Virtual.ProfileWebSocket = "/Common/web_socket"
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
				Name:         "default_svc_test_com_sssl-ca",
				ResourceName: "crd_vs_172.13.14.15",
			}] = CustomProfile{
				Name:         "default_svc_test_com_sssl",
				Partition:    "test",
				Context:      "serverside",
				Certificates: []certificate{certOnly},
				ServerName:   "test.com",
				SNIDefault:   false,
			}

			rsCfg3 := &ResourceConfig{}
			rsCfg3.MetaData.Active = true
			rsCfg3.MetaData.ResourceType = VirtualServer
			rsCfg3.Virtual.Name = "crd_vs_172.13.14.25"
			rsCfg3.Virtual.PoolName = "default_pool_svc4"
			rsCfg3.Virtual.Destination = "/test/172.13.14.25:8080"
			rsCfg3.Virtual.Partition = "test"
			rsCfg3.MetaData.Protocol = "https"
			rsCfg3.Virtual.HTTP2.Server = "server"
			rsCfg3.Virtual.TCP.Server = "server1"

			config := ResourceConfigRequest{
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
				bigIpConfig:         cisapiv1.BigIpConfig{},
			}
			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.16"] = rsCfg2
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.25"] = rsCfg3
			pm := &PostManager{
				AS3PostManager: &AS3PostManager{
					AS3Config: cisapiv1.AS3Config{},
				},
				tokenManager:        &tokenmanager.TokenManager{},
				cachedTenantDeclMap: make(map[string]as3Tenant),
				postChan:            make(chan agentConfig, 1),
				defaultPartition:    "test",
			}
			agentCfg := requestHandler.createDeclarationForBIGIP(config, pm)

			Expect(agentCfg.as3Config.data).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(agentCfg.as3Config.data, "pool1")).To(BeTrue())
			Expect(strings.Contains(agentCfg.as3Config.data, "default_pool_svc2")).To(BeTrue())
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
			rsCfg.Virtual.TCP.Server = "server1"
			rsCfg.Virtual.Firewall = "/Common/firewall"
			rsCfg.Virtual.ConnectionMirroring = "/Common/mirror"
			rsCfg.Virtual.SNAT = "none"
			rsCfg.IntDgMap = InternalDataGroupMap{
				NameRef{"custom_dg1", DEFAULT_PARTITION}: {
					"dg1": &InternalDataGroup{
						Name:      "dg1",
						Partition: "Common",
						Type:      "string",
						Records: []InternalDataGroupRecord{
							{
								Name: "dg1_int",
								Data: "data group1 data1",
							},
						},
					},
					"dg2": &InternalDataGroup{
						Name:      "dg1",
						Partition: "Common",
						Type:      "string",
						Records: []InternalDataGroupRecord{
							{
								Name: "dg2_int",
								Data: "data group1 data2",
							},
						},
					},
				},
			}
			rsCfg.Virtual.Profiles = ProfileRefs{
				ProfileRef{
					Name:         "udpsslnew",
					Partition:    "Common",
					Context:      "udp",
					BigIPProfile: true,
				},
				ProfileRef{
					Name:      "/Common/new/udpsslnew1",
					Partition: "Common",
					Context:   "udp",
				},
			}
			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)
			cert1 := certificate{Cert: "crthash1", Key: "keyhash1"}
			cert2 := certificate{Cert: "crthash2", Key: "keyhash2"}
			rsCfg.customProfiles[SecretKey{
				Name:         "default_svc_test_com_cssl",
				ResourceName: "crd_vs_172.13.14.16",
			}] = CustomProfile{
				Name:         "cs1",
				Partition:    "test",
				Context:      "clientside",
				Certificates: []certificate{cert1, cert2},
				SNIDefault:   false,
			}
			rsCfg.Pools = Pools{
				Pool{
					Name:            "pool1",
					Members:         []PoolMember{mem1, mem2},
					MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
				},
			}

			config := ResourceConfigRequest{
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
				bigIpConfig:         cisapiv1.BigIpConfig{},
			}

			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg
			pm := &PostManager{
				AS3PostManager: &AS3PostManager{
					AS3Config:       cisapiv1.AS3Config{},
					bigIPAS3Version: 3.51,
				},
				tokenManager:        &tokenmanager.TokenManager{},
				cachedTenantDeclMap: make(map[string]as3Tenant),
				postChan:            make(chan agentConfig, 1),
				defaultPartition:    "test",
			}
			agentCfg := requestHandler.createDeclarationForBIGIP(config, pm)

			Expect(agentCfg.as3Config.data).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(agentCfg.as3Config.data, "adminState")).To(BeTrue())
			Expect(strings.Contains(agentCfg.as3Config.data, "connectionLimit")).To(BeTrue())
		})
		It("Verify Transport Server Declaration with several resources", func() {
			rsCfg := &ResourceConfig{}
			enable := true
			rsCfg.MetaData.Active = true
			rsCfg.MetaData.ResourceType = TransportServer
			rsCfg.Virtual.Name = "crd_vs_172.13.14.17"
			rsCfg.Virtual.Mode = "performance"
			rsCfg.Virtual.IpProtocol = "tcp"
			rsCfg.Virtual.TranslateServerAddress = true
			rsCfg.Virtual.TranslateServerPort = true
			rsCfg.Virtual.TCP.Client = "client1"
			rsCfg.Virtual.TCP.Server = "server1"
			rsCfg.Virtual.Source = "source"
			rsCfg.ServiceAddress = []ServiceAddress{
				{
					RouteAdvertisement: "advertise",
				},
			}
			rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
			rsCfg.Virtual.Destination = "172.13.14.6:80"
			rsCfg.Virtual.IRules = []string{"common/test", "common/ab_deployment_path_irule", "common:ab_deployment_path_irule_1"}
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
									EndsWith: true,
								},
								{
									PathSegment: true,
									Index:       1,
									HTTPURI:     true,
									Equals:      true,
									Values:      []string{"/foo"},
									Request:     true,
									Name:        "segment1",
								},
								{
									Path:    true,
									Index:   1,
									HTTPURI: true,
									Equals:  true,
									Values:  []string{"/bar"},
									Name:    "path1",
								},
								{
									Tcp:     true,
									Address: true,
									Values:  []string{"/foobar"},
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
									Location: "loc1",
									Log:      true,
									Message:  "Logged message",
									Replace:  true,
									Value:    "test",
									WAF:      true,
									Policy:   "/Common/Policy1",
									Enabled:  &enable,
									Drop:     true,
								},
							},
						},
					},
				},
			}
			rsCfg.IntDgMap = InternalDataGroupMap{
				NameRef{"custom_dg1", DEFAULT_PARTITION}: {
					"dg1": &InternalDataGroup{
						Name:      "dg1",
						Partition: "Common",
						Type:      "string",
						Records: []InternalDataGroupRecord{
							{
								Name: "dg1_int",
								Data: "data group1 data1",
							},
						},
					},
					"dg2": &InternalDataGroup{
						Name:      "dg1",
						Partition: "Common",
						Type:      "string",
						Records: []InternalDataGroupRecord{
							{
								Name: "dg2_int",
								Data: "data group1 data2",
							},
						},
					},
				},
			}
			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)
			cert := certificate{Cert: "crthash"}
			rsCfg.customProfiles[SecretKey{
				Name:         "default_svc_test_com_cssl",
				ResourceName: "crd_vs_172.13.14.17",
			}] = CustomProfile{
				Name:         "default_svc_test_com_cssl",
				Partition:    "test",
				Context:      "clientside",
				Certificates: []certificate{cert},
				CipherGroup:  "cg",
				SNIDefault:   false,
			}
			rsCfg.customProfiles[SecretKey{
				Name: "default_svc_test_com_cssl-ca",
			}] = CustomProfile{
				Name:         "cs2",
				Partition:    "test",
				Context:      "clientside",
				Certificates: []certificate{cert},
				SNIDefault:   false,
			}
			rsCfg.Virtual.ProfileL4 = "/Common/profile4"
			rsCfg.Virtual.LogProfiles = []string{"/Common/log_profile1", "/Common/log_profile2"}
			rsCfg.Virtual.ProfileBotDefense = "/Common/bot_defense"
			rsCfg.Virtual.ProfileDOS = "/Common/dos_profile"

			rsCfg.Pools = Pools{
				Pool{
					Name:            "pool1",
					Members:         []PoolMember{mem1, mem2},
					MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
				},
			}

			config := ResourceConfigRequest{
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
				bigIpConfig:         cisapiv1.BigIpConfig{},
			}
			rsCfg2 := &ResourceConfig{}
			rsCfg2.MetaData.Active = true
			rsCfg2.MetaData.ResourceType = TransportServer
			rsCfg2.Virtual.Name = "crd_vs_172.13.14.18"
			rsCfg3 := &ResourceConfig{}
			rsCfg3.MetaData.Active = true
			rsCfg3.MetaData.ResourceType = TransportServer
			rsCfg3.Virtual.Name = "crd_vs_172.13.14.19"
			rsCfg4 := &ResourceConfig{}
			rsCfg4.MetaData.Active = true
			rsCfg4.MetaData.ResourceType = TransportServer
			rsCfg4.Virtual.Name = "crd_vs_172.13.14.20"
			rsCfg5 := &ResourceConfig{}
			rsCfg5.MetaData.Active = true
			rsCfg5.MetaData.ResourceType = TransportServer
			rsCfg5.Virtual.Name = "crd_vs_172.13.14.21"

			rsCfg2.Virtual.Mode = "standard"
			rsCfg2.Virtual.TCP.Client = "client2"
			rsCfg2.Virtual.IpProtocol = "udp"
			rsCfg3.Virtual.Mode = "standard"
			rsCfg3.Virtual.IpProtocol = "sctp"
			rsCfg4.Virtual.Mode = "performance"
			rsCfg4.Virtual.IpProtocol = "udp"
			rsCfg5.Virtual.Mode = "performance"
			rsCfg5.Virtual.IpProtocol = "sctp"

			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.17"] = rsCfg
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.18"] = rsCfg2
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.19"] = rsCfg3
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.20"] = rsCfg4
			config.bigIpResourceConfig.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.21"] = rsCfg5

			pm := &PostManager{
				AS3PostManager: &AS3PostManager{
					AS3Config: cisapiv1.AS3Config{},
				},
				tokenManager:        &tokenmanager.TokenManager{},
				cachedTenantDeclMap: make(map[string]as3Tenant),
				postChan:            make(chan agentConfig, 1),
				defaultPartition:    "test",
			}
			agentCfg := requestHandler.createDeclarationForBIGIP(config, pm)

			Expect(agentCfg.as3Config.data).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(agentCfg.as3Config.data, "adminState")).To(BeTrue())
			Expect(strings.Contains(agentCfg.as3Config.data, "connectionLimit")).To(BeTrue())
		})
		It("Delete partition", func() {
			config := ResourceConfigRequest{
				bigIpConfig:         cisapiv1.BigIpConfig{},
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{}},
			}

			zero := 0
			config.bigIpResourceConfig.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			pm := &PostManager{
				AS3PostManager: &AS3PostManager{
					AS3Config: cisapiv1.AS3Config{},
				},
				tokenManager:        &tokenmanager.TokenManager{},
				cachedTenantDeclMap: make(map[string]as3Tenant),
				postChan:            make(chan agentConfig, 1),
				defaultPartition:    "test",
			}
			agentConfig := requestHandler.createDeclarationForBIGIP(config, pm)
			var as3Config map[string]interface{}
			_ = json.Unmarshal([]byte(agentConfig.as3Config.data), &as3Config)
			deletedTenantDecl := as3Tenant{
				"class": "Tenant",
				"label": "test",
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
		var requestHandler *RequestHandler
		var pm *mockPostManager
		tnt := "test"
		BeforeEach(func() {
			response := []responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   `{"declaration": {"label":"test",  "testRemove": {"Shared": {"class": "application"}}, "test": {"Shared": {"class": "application"}}}}`,
			}}
			client, _ := getMockHttpClient(response, http.MethodGet)
			pm = newMockPostManger()
			pm.setResponses(response, http.MethodGet)
			requestHandler = newMockAgent("as3")
			pm.PostManager.defaultPartition = "test"
			requestHandler.PostManagers.PostManagerMap[cisapiv1.BigIpConfig{}] = &PostManager{
				PostParams: PostParams{
					httpClient: client},
				AS3PostManager: &AS3PostManager{
					AS3Config: cisapiv1.AS3Config{},
				}}
			requestHandler.HAMode = true
		})
		It("VirtualServer Declaration", func() {
			config := ResourceConfigRequest{
				bigIpConfig: cisapiv1.BigIpConfig{},
				bigIpResourceConfig: BigIpResourceConfig{ltmConfig: LTMConfig{
					"test": &PartitionConfig{ResourceMap: make(ResourceMap)},
				}},
			}
			pm.PostManager.AS3PostManager.firstPost = false
			agentCfg := requestHandler.createDeclarationForBIGIP(config, pm.PostManager)
			Expect(agentCfg.as3Config.data).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(agentCfg.as3Config.data, "\"class\":\"Tenant\"")).To(BeTrue())

			requestHandler.PrimaryClusterHealthProbeParams.EndPointType = "secondary"
			requestHandler.PrimaryClusterHealthProbeParams.statusRunning = true
			agentCfg = requestHandler.createDeclarationForBIGIP(config, pm.PostManager)
			Expect(agentCfg.as3Config.data).To(Equal(""), "Failed to Create AS3 Declaration")

			requestHandler.PrimaryClusterHealthProbeParams.statusRunning = false
			pm.PostManager.AS3PostManager.firstPost = true
			agentCfg = requestHandler.createDeclarationForBIGIP(config, pm.PostManager)
			Expect(agentCfg.as3Config.data).ToNot(Equal(""), "Failed to Create AS3 Declaration")
			Expect(strings.Contains(agentCfg.as3Config.data, "\"class\":\"Tenant\"")).To(BeTrue())

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
		//	app := tenant[as3SharedApplication].(as3Application)
		//	Expect(len(app)).To(Equal(2))
		//	Expect(app).To(HaveKeyWithValue("class", "Application"))
		//	Expect(app).To(HaveKeyWithValue("template", "shared"))
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
		//	app := tenant[as3SharedApplication].(as3Application)
		//
		//	Expect(app).To(HaveKey("test.com"))
		//	Expect(app["test.com"].(as3GLSBDomain).Class).To(Equal("GSLB_Domain"))
		//
		//	Expect(app).To(HaveKey("pool1"))
		//	Expect(app["pool1"].(as3GSLBPool).Class).To(Equal("GSLB_Pool"))
		//
		//	Expect(app).To(HaveKey("pool1_monitor"))
		//	Expect(app["pool1_monitor"].(as3GSLBMonitor).Class).To(Equal("GSLB_Monitor"))
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
			deletedPartition := getDeletedTenantDeclaration(cisLabel)
			Expect(deletedPartition["label"]).To(Equal(cisLabel))
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
					ghttp.VerifyRequest("GET", CmDeclareInfoApi),
					ghttp.RespondWithJSONEncoded(statusCode, map1),
				))
		})
		AfterEach(func() {
			server.Close()
		})
		//Commenting this as we no longer AS3 version from CM
		/*It("New Agent", func() {
			var agentParams PostParams
			agentParams.EnableIPV6 = true
			agentParams.Partition = "test"
			agentParams.PostParams.CMURL = "http://" + server.Addr()
			requesthandler := NewRequestHandler(agentParams, "bigip1")
			Expect(requesthandler.AS3VersionInfo.as3Version).To(Equal("3.48.0"))
		})*/
	})

})
