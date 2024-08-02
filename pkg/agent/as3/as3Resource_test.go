package as3

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AS3Manager Tests", func() {
	var mockMgr *mockAS3Manager
	var resourceConfig *ResourceConfig
	var as3Config *AS3Config
	BeforeEach(func() {
		as3Config = &AS3Config{
			tenantMap: make(map[string]interface{}),
		}
		mockMgr = newMockAS3Manager(&Params{
			As3Version:       "3.52.0",
			As3Release:       "3.52.0-5",
			As3SchemaVersion: "3.52.0",
			ShareNodes:       true,
		})
		agentResource := AgentResources{
			RsMap:      ResourceConfigMap{},
			Partitions: make(map[string]struct{}),
		}
		agentResource.Partitions[DEFAULT_PARTITION] = struct{}{}

		resourceRequest := ResourceRequest{
			Resources:    &agentResource,
			Profs:        map[SecretKey]CustomProfile{},
			IrulesMap:    IRulesMap{},
			IntDgMap:     InternalDataGroupMap{},
			IntF5Res:     InternalF5ResourcesGroup{},
			AgentCfgmaps: []*AgentCfgMap{},
		}
		ifr := InternalF5Resources{}
		ifr[Record{Host: "foo.com", Path: "/"}] = F5Resources{Virtual: HTTPANDS, WAFPolicy: "/Common/test"}
		resourceRequest.IntF5Res["test_virtual_secure"] = ifr
		resourceRequest.IntF5Res["test_virtual"] = ifr
		resourceRequest.IrulesMap[NameRef{Name: "test_irule", Partition: DEFAULT_PARTITION}] = &IRule{Name: "test_irule", Partition: DEFAULT_PARTITION, Code: "Dummy Code"}
		idg := InternalDataGroup{Name: "test_datagroup", Partition: DEFAULT_PARTITION, Records: InternalDataGroupRecords{InternalDataGroupRecord{Name: "test_record", Data: "test-data"}}}
		dgnm := DataGroupNamespaceMap{}
		dgnm[ReencryptServerSslDgName] = &idg
		resourceRequest.IntDgMap[NameRef{Name: ReencryptServerSslDgName, Partition: DEFAULT_PARTITION}] = dgnm
		mockMgr.ResourceRequest = resourceRequest
		resourceConfig = &ResourceConfig{
			MetaData: MetaData{
				Active:             true,
				DefaultIngressName: "test1",
				RouteProfs:         make(map[RouteKey]string),
			},
			Virtual: Virtual{Name: "test-virtual-secure", Policies: []NameRef{}, Profiles: ProfileRefs{{Name: "clientssl", Partition: "Common", Context: "clientside"}, {Name: "serverssl", Partition: "Common", Context: "serverside"}}, PoolName: "test-pool"},
			Policies: []Policy{{Name: "openshift_secure_routes", Controls: []string{"forwarding"}, Rules: Rules{},
				Requires: []string{}},
				{Name: "openshift_insecure_routes", Controls: []string{"forwarding"}, Rules: Rules{},
					Requires: []string{}}},
			Pools: []Pool{{Name: "test-pool", Partition: DEFAULT_PARTITION, ServiceName: "test-svc", ServicePort: 80, MonitorNames: []string{"test_monitor"}, Members: []Member{{Port: 80, Address: "192.168.1.1"}}}},
		}
		resourceConfig.Virtual.SetVirtualAddress("1.2.3.4", 443, true)
		resourceConfig.Monitors = []Monitor{{Name: "test_monitor", Partition: DEFAULT_PARTITION, Type: "tcp", Interval: 10, Send: "GET /", Recv: ""}}
		// url-rewrite host matches rule2 and rule3
		rule1 := &Rule{
			Name:    "url-rewrite-rule1",
			FullURI: "host.com/bar",
			Actions: []*Action{&Action{
				Name:     "0",
				HTTPHost: true,
				Replace:  true,
				Request:  true,
				Value:    "newhost.com",
			}},
			Conditions: []*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"foo.com"},
				},
				&Condition{
					Name:        "0",
					Equals:      true,
					PathSegment: true,
					HTTPHost:    true,
					Index:       0,
					Request:     true,
					Values:      []string{"foo.com"},
				},
				&Condition{
					Name:     "0",
					Equals:   true,
					Path:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"foo.com"},
				},
				&Condition{
					Name:     "0",
					Equals:   true,
					Tcp:      true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"foo.com"},
				},
			},
		}

		resourceConfig.Policies[0].Rules = []*Rule{rule1}
		resourceConfig.Policies[1].Rules = []*Rule{rule1}
		clientSecret := SecretKey{Name: "test-client-secret", ResourceName: "test_virtual_secure"}
		serverSecret := SecretKey{Name: "test-server-secret", ResourceName: "test_virtual_secure"}
		mockMgr.Profs[clientSecret] = CustomProfile{
			Name:         "test-clientssl",
			Partition:    DEFAULT_PARTITION,
			Context:      "clientside",
			Cert:         "cert",
			Key:          "key",
			ServerName:   "foo.com",
			SNIDefault:   true,
			PeerCertMode: PeerCertRequired,
			CAFile:       "ca-file",
			ChainCA:      "ca-chain",
		}
		mockMgr.Profs[serverSecret] = CustomProfile{
			Name:         "test-serverssl",
			Partition:    DEFAULT_PARTITION,
			Context:      "serverside",
			Cert:         "cert",
			Key:          "",
			ServerName:   "foo.com",
			SNIDefault:   true,
			PeerCertMode: PeerCertRequired,
			CAFile:       "ca-file",
			ChainCA:      "ca-chain",
		}
	})
	AfterEach(func() {
		mockMgr.shutdown()
	})
	It("Prepare AS3 Declaration 0 policy", func() {
		resourceConfig.MetaData.ResourceType = ResourceTypeIngress
		mockMgr.ResourceRequest.Resources.RsMap[NameRef{Name: "test_virtual_secure", Partition: DEFAULT_PARTITION}] = resourceConfig
		as3Config.resourceConfig = mockMgr.prepareAS3ResourceConfig()
		unifiedDecl := mockMgr.getUnifiedDeclaration(as3Config)
		mockMgr.as3ActiveConfig.unifiedDeclaration = "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.52.0/as3-schema-3.52.0-5.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"}],\"redirect80\":false,\"pool\":\"/k8s/Shared/test_pool\"},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.52.0\"}}"
		Expect(DeepEqualJSON(mockMgr.as3ActiveConfig.unifiedDeclaration, unifiedDecl)).To(BeTrue())

	})
	It("Prepare AS3 Declaration 1 policy", func() {
		resourceConfig.MetaData.ResourceType = ResourceTypeIngress
		resourceConfig.Virtual.Policies = []NameRef{{Name: "test-policy", Partition: DEFAULT_PARTITION}}
		resourceConfig.Virtual.PoolName = ""
		mockMgr.ResourceRequest.Resources.RsMap[NameRef{Name: "test_virtual_secure", Partition: DEFAULT_PARTITION}] = resourceConfig
		as3Config.resourceConfig = mockMgr.prepareAS3ResourceConfig()
		unifiedDecl := mockMgr.getUnifiedDeclaration(as3Config)
		mockMgr.as3ActiveConfig.unifiedDeclaration = "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.52.0/as3-schema-3.52.0-5.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"policyEndpoint\":\"/k8s/Shared/Test_Policy\",\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"}],\"redirect80\":false},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.52.0\"}}"
		Expect(DeepEqualJSON(mockMgr.as3ActiveConfig.unifiedDeclaration, unifiedDecl)).To(BeTrue())

	})
	It("Prepare AS3 Declaration 2 policy", func() {
		resourceConfig.MetaData.ResourceType = ResourceTypeIngress
		resourceConfig.Virtual.Policies = []NameRef{{Name: "test-policy1", Partition: DEFAULT_PARTITION}, {Name: "test-policy2", Partition: DEFAULT_PARTITION}}
		resourceConfig.Virtual.PoolName = ""
		mockMgr.ResourceRequest.Resources.RsMap[NameRef{Name: "test_virtual_secure", Partition: DEFAULT_PARTITION}] = resourceConfig
		as3Config.resourceConfig = mockMgr.prepareAS3ResourceConfig()
		unifiedDecl := mockMgr.getUnifiedDeclaration(as3Config)
		mockMgr.as3ActiveConfig.unifiedDeclaration = "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.52.0/as3-schema-3.52.0-5.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"policyEndpoint\":null,\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"}],\"redirect80\":false},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.52.0\"}}"
		Expect(DeepEqualJSON(mockMgr.as3ActiveConfig.unifiedDeclaration, unifiedDecl)).To(BeTrue())

	})

	It("Prepare AS3 Declaration for route config", func() {
		resourceConfig.MetaData.ResourceType = ResourceTypeRoute
		resourceConfig.MetaData.RouteProfs[RouteKey{Name: "test-clientssl", Namespace: DEFAULT_PARTITION, Context: "clientside"}] = "/Common/test-clientssl"
		resourceConfig.MetaData.RouteProfs[RouteKey{Name: "test-serverssl", Namespace: DEFAULT_PARTITION, Context: "serverside"}] = "/Common/test-serverssl"
		mockMgr.ResourceRequest.Resources.RsMap[NameRef{Name: "test_virtual_secure", Partition: DEFAULT_PARTITION}] = resourceConfig
		as3Config.resourceConfig = mockMgr.prepareAS3ResourceConfig()
		unifiedDecl := mockMgr.getUnifiedDeclaration(as3Config)
		Expect(mockMgr.validateAS3Template(string(unifiedDecl))).To(BeFalse())
		mockMgr.as3ActiveConfig.unifiedDeclaration = "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.52.0/as3-schema-3.52.0-5.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"class\":\"Application\",\"openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}},{\"type\":\"waf\",\"enabled\":false}]},{\"name\":\"openshift_route_waf_disable\",\"actions\":[{\"type\":\"drop\",\"event\":\"request\"},{\"type\":\"waf\",\"enabled\":false}]}]},\"openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}},{\"type\":\"waf\",\"enabled\":false}]},{\"name\":\"openshift_route_waf_disable\",\"actions\":[{\"type\":\"drop\",\"event\":\"request\"},{\"type\":\"waf\",\"enabled\":false}]}]},\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/test-serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"clientTLS\":{\"bigip\":\"/Common/test-serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/test-clientssl\"}],\"redirect80\":false,\"pool\":\"/k8s/Shared/test_pool\"},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.52.0\"}}"
		Expect(DeepEqualJSON(mockMgr.as3ActiveConfig.unifiedDeclaration, unifiedDecl)).To(BeTrue())

	})
	It("Prepare AS3 Declaration for ingress config", func() {
		resourceConfig.MetaData.ResourceType = ResourceTypeIngress
		resourceConfig.Virtual.Profiles = append(resourceConfig.Virtual.Profiles, ProfileRef{Name: "test-clientssl", Partition: DEFAULT_PARTITION, Context: "clientside"})
		resourceConfig.Virtual.Profiles = append(resourceConfig.Virtual.Profiles, ProfileRef{Name: "test-serverssl", Partition: DEFAULT_PARTITION, Context: "serverside"})
		resourceConfig.Virtual.Profiles = append(resourceConfig.Virtual.Profiles, ProfileRef{Name: "clientssl2", Partition: "Common", Context: "clientside"})
		mockMgr.ResourceRequest.Resources.RsMap[NameRef{Name: "test_virtual_secure", Partition: DEFAULT_PARTITION}] = resourceConfig
		as3Config.resourceConfig = mockMgr.prepareAS3ResourceConfig()
		unifiedDecl := mockMgr.getUnifiedDeclaration(as3Config)
		Expect(mockMgr.validateAS3Template(string(unifiedDecl))).To(BeFalse())
		mockMgr.as3ActiveConfig.unifiedDeclaration = "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.52.0/as3-schema-3.52.0-5.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"},{\"bigip\":\"/Common/clientssl2\"}],\"redirect80\":false,\"pool\":\"/k8s/Shared/test_pool\"},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.52.0\"}}"
		Expect(DeepEqualJSON(mockMgr.as3ActiveConfig.unifiedDeclaration, unifiedDecl)).To(BeTrue())

		// verify with multiple client ssl profiles
		mockMgr.bigIPAS3Version = 3.50
		clientSecret2 := SecretKey{Name: "test-client-secret2", ResourceName: "test_virtual_secure"}
		clientSecret3 := SecretKey{Name: "test-server-secret3", ResourceName: "test_virtual_secure"}
		mockMgr.Profs[clientSecret2] = CustomProfile{
			Name:         "test-clientssl2",
			Partition:    DEFAULT_PARTITION,
			Context:      "clientside",
			Cert:         "cert",
			Key:          "key",
			ServerName:   "foo2.com",
			SNIDefault:   true,
			PeerCertMode: PeerCertRequired,
			CAFile:       "ca-file",
			ChainCA:      "ca-chain",
		}
		mockMgr.Profs[clientSecret3] = CustomProfile{
			Name:         "test-clientssl3",
			Partition:    DEFAULT_PARTITION,
			Context:      "clientside",
			Cert:         "cert",
			Key:          "key",
			ServerName:   "foo3.com",
			SNIDefault:   true,
			PeerCertMode: PeerCertRequired,
			CAFile:       "ca-file",
			ChainCA:      "ca-chain",
		}
		resourceConfig.Virtual.Profiles = append(resourceConfig.Virtual.Profiles, ProfileRef{Name: "test-clientssl1", Partition: DEFAULT_PARTITION, Context: "clientside"})
		resourceConfig.Virtual.Profiles = append(resourceConfig.Virtual.Profiles, ProfileRef{Name: "test-clientssl2", Partition: DEFAULT_PARTITION, Context: "clientside"})
		mockMgr.ResourceRequest.Resources.RsMap[NameRef{Name: "test_virtual_secure", Partition: DEFAULT_PARTITION}] = resourceConfig
		as3Config.resourceConfig = mockMgr.prepareAS3ResourceConfig()
		unifiedDecl = mockMgr.getUnifiedDeclaration(as3Config)
		Expect(mockMgr.validateAS3Template(string(unifiedDecl))).To(BeFalse())
		// As per AS3 < v3.44, in case of multiple clientssl profiles, the first profile is used for default SNI
		mockMgr.as3ActiveConfig.unifiedDeclaration = "{\"$schema\":\"https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/3.52.0/as3-schema-3.52.0-5.json\",\"class\":\"AS3\",\"declaration\":{\"class\":\"ADC\",\"controls\":{\"class\":\"Controls\",\"userAgent\":\"\"},\"id\":\"urn:uuid:85626792-9ee7-46bb-8fc8-4ba708cfdc1d\",\"k8s\":{\"Shared\":{\"Openshift_insecure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"Openshift_secure_routes\":{\"class\":\"Endpoint_Policy\",\"rules\":[{\"name\":\"url_rewrite_rule1\",\"conditions\":[{\"type\":\"httpHeader\",\"name\":\"host\",\"event\":\"request\",\"all\":{\"values\":[\"foo.com:443\",\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"pathSegment\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"name\":\"0\",\"event\":\"request\",\"path\":{\"values\":[\"foo.com\"],\"operand\":\"equals\"}},{\"type\":\"tcp\",\"event\":\"request\",\"address\":{\"values\":[\"foo.com\"]}}],\"actions\":[{\"type\":\"httpHeader\",\"event\":\"request\",\"replace\":{\"value\":\"newhost.com\",\"name\":\"host\"}}]}]},\"class\":\"Application\",\"serverssl_ca_bundle\":{\"class\":\"CA_Bundle\",\"bundle\":\"\\ncert\"},\"template\":\"shared\",\"test_clientssl\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_clientssl2\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_clientssl3\":{\"class\":\"Certificate\",\"certificate\":\"cert\",\"privateKey\":\"key\",\"chainCA\":\"ca-file\"},\"test_datagroup\":{\"records\":[{\"key\":\"test_record\",\"value\":\"/Common/serverssl\"}],\"keyDataType\":\"string\",\"class\":\"Data_Group\"},\"test_irule\":{\"class\":\"iRule\",\"iRule\":\"Dummy Code\"},\"test_monitor\":{\"class\":\"Monitor\",\"interval\":10,\"monitorType\":\"tcp\",\"targetAddress\":\"\",\"timeUntilUp\":0,\"dscp\":0,\"receive\":\"none\",\"send\":\"GET /\",\"targetPort\":0},\"test_pool\":{\"class\":\"Pool\",\"members\":[{\"addressDiscovery\":\"static\",\"serverAddresses\":[\"192.168.1.1\"],\"servicePort\":80,\"shareNodes\":true}],\"monitors\":[{\"use\":\"/k8s/Shared/test_monitor\"}]},\"test_virtual_secure\":{\"source\":\"0.0.0.0/0\",\"translateServerAddress\":true,\"translateServerPort\":true,\"class\":\"Service_HTTPS\",\"virtualAddresses\":[\"1.2.3.4\"],\"virtualPort\":443,\"snat\":\"auto\",\"clientTLS\":{\"bigip\":\"/Common/serverssl\"},\"serverTLS\":[{\"bigip\":\"/Common/clientssl\"},{\"bigip\":\"/Common/clientssl2\"}],\"redirect80\":false,\"pool\":\"/k8s/Shared/test_pool\"},\"test_virtual_secure_tls_client\":{\"class\":\"TLS_Client\",\"trustCA\":{\"use\":\"serverssl_ca_bundle\"}},\"test_virtual_secure_tls_server\":{\"class\":\"TLS_Server\",\"certificates\":[{\"certificate\":\"test_clientssl\",\"sniDefault\": true},{\"certificate\": \"test_clientssl2\"},{\"certificate\": \"test_clientssl3\"}],\"renegotiationEnabled\":false}},\"class\":\"Tenant\",\"defaultRouteDomain\":0},\"label\":\"CIS Declaration\",\"remark\":\"Auto-generated by CIS\",\"schemaVersion\":\"3.52.0\"}}"
		Expect(DeepEqualJSON(mockMgr.as3ActiveConfig.unifiedDeclaration, unifiedDecl)).To(BeTrue())

	})
})
