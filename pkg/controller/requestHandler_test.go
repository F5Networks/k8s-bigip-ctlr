package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Request Handler Tests", func() {
	var mockRequestHandler *RequestHandler
	var mockBaseAPIHandler *BaseAPIHandler
	var agent *Agent
	BeforeEach(func() {
		mockWriter := &test.MockWriter{FailStyle: test.Success}
		mockRequestHandler = newMockRequestHandler(mockWriter)
		mockBaseAPIHandler = newMockBaseAPIHandler()
		agent = &Agent{
			StopChan: make(chan struct{}),
			APIHandler: &APIHandler{
				LTM: &LTMAPIHandler{
					BaseAPIHandler: mockBaseAPIHandler,
				},
				GTM: &GTMAPIHandler{
					BaseAPIHandler: mockBaseAPIHandler,
				},
			},
			EventChan: make(chan interface{}),
		}
	})
	It("Test Request handler routine", func() {
		mem1 := PoolMember{
			Address: "1.2.3.5",
			Port:    8080,
		}
		mem2 := PoolMember{
			Address: "1.2.3.6",
			Port:    8081,
		}
		rsCfg := &ResourceConfig{}
		rsCfg.MetaData.Active = true
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Name = "crd_vs_172.13.14.15"
		rsCfg.Virtual.PoolName = "default_pool_svc1"
		rsCfg.Virtual.Destination = "/test/172.13.14.5:8080"
		rsCfg.Virtual.AllowVLANs = []string{"flannel_vxlan"}
		rsCfg.Virtual.IpIntelligencePolicy = "/Common/ip-intelligence-policy"
		rsCfg.Virtual.HTTPCompressionProfile = "/Common/compressionProfile"
		rsCfg.Virtual.BigIPRouteDomain = 10
		rsCfg.Virtual.AdditionalVirtualAddresses = []string{"172.13.14.17", "172.13.14.18"}
		rsCfg.Virtual.ProfileAdapt = ProfileAdapt{"/Common/example-requestadapt", "/Common/example-responseadapt"}
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
		rsCfg.Virtual.IRules = []string{"none", "/common/irule1", "/common/irule_2", "/common/http_redirect_irule"}
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
		rsCfg.IntDgMap = InternalDataGroupMap{
			NameRef{"static-internal-dg", "test"}: DataGroupNamespaceMap{
				"intDg1": &InternalDataGroup{
					Name:      "static-internal-dg",
					Partition: "test",
					Type:      "string",
					Records: []InternalDataGroupRecord{
						{
							Name: "apiTye",
							Data: AS3,
						},
					},
				},
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
								Forward:       true,
								Request:       true,
								Redirect:      true,
								HTTPURI:       true,
								HTTPHost:      true,
								Pool:          "default_svc_2",
								Log:           true,
								Location:      PrimaryBigIP,
								Message:       "log action",
								Replace:       true,
								Value:         "urihost",
								WAF:           true,
								Policy:        "/common/policy3",
								Enabled:       true,
								Drop:          true,
								PersistMethod: SourceAddress,
							},
							{
								PersistMethod: DestinationAddress,
							},
							{
								PersistMethod: CookieHash,
							},
							{
								PersistMethod: CookieInsert,
							},
							{
								PersistMethod: CookieRewrite,
							},
							{
								PersistMethod: CookiePassive,
							},
							{
								PersistMethod: Universal,
							},
							{
								PersistMethod: Carp,
							},
							{
								PersistMethod: Hash,
							},
							{
								PersistMethod: Disable,
							},
							{
								PersistMethod: "Disable",
							},
						},
					},
				},
			},
			Policy{
				Name:     "policy3",
				Strategy: "first-match",
				Rules: Rules{
					&Rule{
						Conditions: []*condition{
							{
								Path:    true,
								Name:    "condition3",
								Values:  []string{"/common/test"},
								HTTPURI: true,
								Equals:  true,
								Index:   3,
							},
							{
								Tcp:     true,
								Address: true,
								Values:  []string{"10.10.10.10"},
								Request: true,
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
		zero := 0
		config := ResourceConfigRequest{
			ltmConfig:          make(LTMConfig),
			shareNodes:         true,
			gtmConfig:          GTMConfig{},
			defaultRouteDomain: 1,
		}
		config.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
		config.ltmConfig["default"].ResourceMap["crd_vs_172.13.14.15"] = rsCfg
		go mockRequestHandler.requestHandler()
		mockRequestHandler.reqChan <- config
	})
	AfterEach(func() {
		close(agent.EventChan)
		close(agent.StopChan)
		close(mockRequestHandler.reqChan)
		close(mockRequestHandler.respChan)
	})
})
