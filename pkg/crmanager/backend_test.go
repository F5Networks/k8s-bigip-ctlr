package crmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Backend Tests", func() {

	It("DNS Config", func() {
		dnsConfig := DNSConfig{
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
						Monitor: &Monitor{
							Name:     "pool1_monitor",
							Interval: 10,
							Timeout:  10,
							Type:     "http",
							Send:     "GET /health",
						},
					},
				},
			},
		}

		config := ResourceConfigWrapper{
			rsCfgs:             ResourceConfigs{},
			customProfiles:     NewCustomProfiles(),
			shareNodes:         true,
			dnsConfig:          dnsConfig,
			defaultRouteDomain: 1,
		}

		writer := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		agent := newMockAgent(writer)
		agent.PostGTMConfig(config)

		writer.FailStyle = test.ImmediateFail
		agent = newMockAgent(writer)
		agent.PostGTMConfig(config)

		writer.FailStyle = test.Timeout
		agent = newMockAgent(writer)
		agent.PostGTMConfig(config)

		writer.FailStyle = test.AsyncFail
		agent = newMockAgent(writer)
		agent.PostGTMConfig(config)
	})

	Describe("Prepare AS3 Declaration", func() {
		var mem1, mem2, mem3, mem4 Member
		BeforeEach(func() {
			mem1 = Member{
				Address: "1.2.3.5",
				Port:    8080,
			}
			mem2 = Member{
				Address: "1.2.3.6",
				Port:    8081,
			}
			mem3 = Member{
				Address: "1.2.3.7",
				Port:    8082,
			}
			mem4 = Member{
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
					Members: []Member{mem1, mem2},
					MonitorNames: []string{
						"/test/http_monitor",
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
									SSLExtensionClient: true,
									Values:             []string{"test.com"},
									Equals:             true,
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
			rsCfg2.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []Member{mem3, mem4},
				},
			}

			customProfiles := NewCustomProfiles()
			customProfiles.Profs[SecretKey{
				Name:         "default_svc_test_com_cssl",
				ResourceName: "crd_vs_172.13.14.15",
			}] = CustomProfile{
				Name:       "default_svc_test_com_cssl",
				Partition:  "test",
				Context:    "clientside",
				Cert:       "crthash",
				Key:        "keyhash",
				ServerName: "test.com",
				SNIDefault: false,
			}
			customProfiles.Profs[SecretKey{
				Name:         "default_svc_test_com_sssl",
				ResourceName: "crd_vs_172.13.14.15",
			}] = CustomProfile{
				Name:       "default_svc_test_com_sssl",
				Partition:  "test",
				Context:    "serverside",
				Cert:       "crthash",
				ServerName: "test.com",
				SNIDefault: false,
			}

			config := ResourceConfigWrapper{
				rsCfgs:             ResourceConfigs{rsCfg, rsCfg2},
				customProfiles:     customProfiles,
				shareNodes:         true,
				dnsConfig:          DNSConfig{},
				defaultRouteDomain: 1,
			}

			decl := createAS3Declaration(config, "as3")

			Expect(string(decl)).ToNot(Equal(""), "Failed to Create AS3 Declaration")
		})
		It("TransportServer Declaration", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.MetaData.Active = true
			rsCfg.MetaData.ResourceType = TransportServer
			rsCfg.Virtual.Mode = "standard"
			rsCfg.Virtual.IpProtocol = "tcp"
			rsCfg.Virtual.TranslateServerAddress = true
			rsCfg.Virtual.TranslateServerPort = true
			rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
			rsCfg.Virtual.Destination = "172.13.14.6:1600"
			rsCfg.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []Member{mem1, mem2},
				},
			}

			config := ResourceConfigWrapper{
				rsCfgs:             ResourceConfigs{rsCfg},
				customProfiles:     NewCustomProfiles(),
				shareNodes:         true,
				dnsConfig:          DNSConfig{},
				defaultRouteDomain: 1,
			}

			decl := createAS3Declaration(config, "as3")

			Expect(string(decl)).ToNot(Equal(""), "Failed to Create AS3 Declaration")

		})
	})
})
