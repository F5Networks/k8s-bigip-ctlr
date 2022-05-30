package controller

import (
	"sort"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Resource Config Tests", func() {
	namespace := "default"
	Describe("Virtual Ports", func() {
		var mockCtlr *mockController
		var vs *cisapiv1.VirtualServer

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.mode = CustomResourceMode
			vs = test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
				},
			)
		})

		It("Virtual Ports with Default Ports", func() {
			portStructs := mockCtlr.virtualPorts(vs)
			Expect(len(portStructs)).To(Equal(1), "Unexpected number of ports")
			Expect(portStructs[0]).To(Equal(portStruct{
				protocol: "http",
				port:     80,
			}), "Invalid Port")

			vs.Spec.TLSProfileName = "SampleTLS"
			portStructs = mockCtlr.virtualPorts(vs)
			Expect(len(portStructs)).To(Equal(2), "Unexpected number of ports")
			sort.SliceStable(portStructs, func(i, j int) bool { // Sort in reverse order based on port
				return portStructs[i].port > portStructs[j].port
			})
			Expect(portStructs).To(Equal([]portStruct{
				{
					protocol: "https",
					port:     443,
				},
				{
					protocol: "http",
					port:     80,
				},
			}), "Invalid Ports")
		})

		It("Virtual Ports with Default Ports", func() {
			vs.Spec.VirtualServerHTTPPort = 8080
			portStructs := mockCtlr.virtualPorts(vs)
			Expect(len(portStructs)).To(Equal(1), "Unexpected number of ports")
			Expect(portStructs[0]).To(Equal(portStruct{
				protocol: "http",
				port:     8080,
			}), "Invalid Port")

			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.VirtualServerHTTPSPort = 8443
			portStructs = mockCtlr.virtualPorts(vs)
			Expect(len(portStructs)).To(Equal(2), "Unexpected number of ports")
			sort.SliceStable(portStructs, func(i, j int) bool { // Sort in reverse order based on port
				return portStructs[i].port > portStructs[j].port
			})
			Expect(portStructs).To(Equal([]portStruct{
				{
					protocol: "https",
					port:     8443,
				},
				{
					protocol: "http",
					port:     8080,
				},
			}), "Invalid Ports")
		})
	})

	Describe("Name Formatting", func() {
		It("Replace Unwanted Characters", func() {
			inputName := "a.b:c/d%e-f=g"
			name := AS3NameFormatter(inputName)
			Expect(name).To(Equal("a_b_c_d.e_f_g"), "Invalid Name Format")
		})
		It("VirtualServer Name", func() {
			name := formatVirtualServerName("1.2.3.4", 80)
			Expect(name).To(Equal("crd_1_2_3_4_80"), "Invalid VirtualServer Name")
		})
		It("VirtualServer Custom Name", func() {
			name := formatCustomVirtualServerName("My_VS", 80)
			Expect(name).To(Equal("My_VS_80"), "Invalid VirtualServer Name")
		})
		It("Pool Name", func() {
			name := formatPoolName(namespace, "svc1", 80, "app=test")
			Expect(name).To(Equal("svc1_80_default_app_test"), "Invalid Pool Name")
		})
		It("Monitor Name", func() {
			name := formatMonitorName(namespace, "svc1", "http", 80)
			Expect(name).To(Equal("svc1_default_http_80"), "Invalid Monitor Name")
		})
		It("Rule Name", func() {
			name := formatVirtualServerRuleName("test.com", "", "", "sample_pool")
			Expect(name).To(Equal("vs_test_com_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "exams.com", "", "sample_pool")
			Expect(name).To(Equal("vs_exams_com_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "", "/foo", "sample_pool")
			Expect(name).To(Equal("vs_test_com_foo_sample_pool"))

		})
	})

	Describe("Handle iRules and DataGroups", func() {
		var rsCfg *ResourceConfig
		partition := "test"

		BeforeEach(func() {
			rsCfg = &ResourceConfig{}
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.Virtual.SetVirtualAddress(
				"1.2.3.4",
				80,
			)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
		})

		It("Handle IRule", func() {
			iRuleName := "sample_iRule"
			rsCfg.addIRule(iRuleName, partition, "tcl code blocks")
			Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to add iRule")

			rsCfg.addIRule(iRuleName, partition, "tcl code blocks new")
			Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to add iRule")
			Expect(rsCfg.IRulesMap[NameRef{iRuleName, partition}].Code).ToNot(Equal("tcl code blocks new"), "Validation Failed while adding iRule")

			rsCfg.removeIRule("non_existing", partition)
			Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Validation Failed while removing iRule")

			rsCfg.removeIRule(iRuleName, partition)
			Expect(len(rsCfg.IRulesMap)).To(Equal(0), "Failed to remove iRule")
		})

		It("Handle DataGroup", func() {
			dgName := "http_vs_dg"
			rsCfg.addInternalDataGroup(dgName, partition)
			Expect(len(rsCfg.IntDgMap)).To(Equal(1), "Failed to Add Internal DataGroup Map")
		})

		//It("Handle DataGroupIRules", func() {
		//	mockCtlr := newMockController()
		//	tls := test.NewTLSProfile(
		//		"SampleTLS",
		//		namespace,
		//		cisapiv1.TLSProfileSpec{
		//			TLS: cisapiv1.TLS{
		//				Termination: TLSEdge,
		//				ClientSSL:   "clientssl",
		//			},
		//		},
		//	)
		//	mockCtlr.handleDataGroupIRules(rsCfg, "vs", "test.com", tls)
		//	Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to Add iRuels")
		//	Expect(len(rsCfg.IntDgMap)).To(Equal(2), "Failed to Add DataGroup")
		//	tls1 := test.NewTLSProfile(
		//		"SampleTLS",
		//		namespace,
		//		cisapiv1.TLSProfileSpec{
		//			TLS: cisapiv1.TLS{
		//				Termination: TLSReencrypt,
		//				ClientSSL:   "clientssl",
		//				ServerSSL:   "serverssl",
		//				Reference:   BIGIP,
		//			},
		//		},
		//	)
		//	mockCtlr.handleDataGroupIRules(rsCfg, "vs", "test.com", tls1)
		//	Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to Add iRuels")
		//	Expect(len(rsCfg.IntDgMap)).To(Equal(4), "Failed to Add DataGroup")
		//
		//})
	})

	Describe("Prepare Resource Configs", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController

		//partition := "test"
		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.mode = CustomResourceMode
			mockCtlr.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
			_ = mockCtlr.addNamespacedInformers(namespace)

			rsCfg = &ResourceConfig{}
			rsCfg.Virtual.SetVirtualAddress(
				"1.2.3.4",
				80,
			)
		})

		It("Prepare Resource Config from a VirtualServer", func() {
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)

			vs := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.Pool{
						{
							Path:    "/foo",
							Service: "svc1",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
							Rewrite: "/bar",
						},
						{
							Path:    "/",
							Service: "svc2",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
						},
					},
					RewriteAppRoot: "/home",
					WAF:            "/Common/WAF",
					IRules:         []string{"SampleIRule"},
				},
			)
			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
		})

		It("Prepare Resource Config from a TransportServer", func() {
			ts := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.Pool{
						Service:     "svc1",
						ServicePort: 80,
						Monitor: cisapiv1.Monitor{
							Type:     "tcp",
							Timeout:  10,
							Interval: 10,
						},
					},
				},
			)
			err := mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from TransportServer")
		})

		It("Prepare Resource Config from a Service", func() {
			svcPort := v1.ServicePort{
				Name:     "port1",
				Port:     8080,
				Protocol: "http",
			}
			svc := test.NewService(
				"svc1",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				[]v1.ServicePort{svcPort},
			)
			svc.Annotations = make(map[string]string)
			svc.Annotations[HealthMonitorAnnotation] = `{"interval": 5, "timeout": 10}`

			err := mockCtlr.prepareRSConfigFromLBService(rsCfg, svc, svcPort)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from Service")
			Expect(len(rsCfg.Pools)).To(Equal(1), "Failed to Prepare Resource Config from Service")
			Expect(len(rsCfg.Monitors)).To(Equal(1), "Failed to Prepare Resource Config from Service")
		})

		It("Get Pool Members from Resource Configs", func() {
			mem1 := PoolMember{
				Address: "1.2.3.5",
				Port:    8080,
			}
			mem2 := PoolMember{
				Address: "1.2.3.6",
				Port:    8081,
			}
			mem3 := PoolMember{
				Address: "1.2.3.7",
				Port:    8082,
			}
			mem4 := PoolMember{
				Address: "1.2.3.8",
				Port:    8083,
			}
			mem5 := PoolMember{
				Address: "1.2.3.9",
				Port:    8084,
			}
			mem6 := PoolMember{
				Address: "1.2.3.10",
				Port:    8085,
			}

			rsCfg.MetaData.Active = true
			rsCfg.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []PoolMember{mem1, mem2},
				},
			}
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)

			rsCfg2 := &ResourceConfig{}
			rsCfg2.MetaData.Active = false
			rsCfg2.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []PoolMember{mem3, mem4},
				},
			}
			rsCfg2.Virtual.Name = formatCustomVirtualServerName("My_VS2", 80)

			rsCfg3 := &ResourceConfig{}
			rsCfg3.MetaData.Active = true
			rsCfg3.Pools = Pools{
				Pool{
					Name:    "pool1",
					Members: []PoolMember{mem5, mem6},
				},
			}
			rsCfg3.Virtual.Name = formatCustomVirtualServerName("My_VS3", 80)

			ltmConfig := make(LTMConfig)
			ltmConfig["default"] = make(ResourceMap)
			ltmConfig["default"][rsCfg.Virtual.Name] = rsCfg
			ltmConfig["default"][rsCfg2.Virtual.Name] = rsCfg2
			ltmConfig["default"][rsCfg3.Virtual.Name] = rsCfg3
			mems := ltmConfig.GetAllPoolMembers()
			Expect(len(mems)).To(Equal(4), "Invalid Pool Members")
		})
	})

	Describe("Profile Reference", func() {

		It("Frame Profile Reference", func() {
			ctx := "clientside"
			profRef := ConvertStringToProfileRef(
				"sample",
				ctx,
				namespace,
			)
			Expect(profRef).To(Equal(ProfileRef{
				Name:         "sample",
				Partition:    DEFAULT_PARTITION,
				Context:      ctx,
				Namespace:    namespace,
				BigIPProfile: true,
			},
			), "Invalid Profile Reference")

			profRef = ConvertStringToProfileRef(
				"/Common/sample",
				ctx,
				namespace,
			)
			Expect(profRef).To(Equal(ProfileRef{
				Name:         "sample",
				Partition:    "Common",
				Context:      ctx,
				Namespace:    namespace,
				BigIPProfile: true,
			},
			), "Invalid Profile Reference")

			profRef = ConvertStringToProfileRef(
				"/too/large/path",
				ctx,
				namespace,
			)
			Expect(profRef).To(Equal(ProfileRef{
				Name:         "",
				Partition:    "",
				Context:      ctx,
				Namespace:    namespace,
				BigIPProfile: true,
			},
			), "Invalid Profile Reference")
		})

		It("Sort Profile References", func() {
			ctx := "clientside"

			prof1 := ProfileRef{
				Name:      "basic",
				Partition: "Common",
				Context:   ctx,
				Namespace: namespace,
			}
			prof2 := ProfileRef{
				Name:      "standard",
				Partition: "Common",
				Context:   ctx,
				Namespace: namespace,
			}
			prof3 := ProfileRef{
				Name:      "prod",
				Partition: "Prod",
				Context:   ctx,
				Namespace: namespace,
			}

			profRefs := ProfileRefs{prof3, prof2, prof1}
			sort.Sort(profRefs)
			Expect(profRefs).To(Equal(ProfileRefs{prof1, prof2, prof3}), "Failed to sort Profile References")
		})
	})

	Describe("Internal DataGroups", func() {
		It("Internal DataGroup Methods", func() {
			idg := &InternalDataGroup{
				Name:      "ServerNameDG",
				Partition: DEFAULT_PARTITION,
				Records:   InternalDataGroupRecords{},
			}

			added := idg.AddOrUpdateRecord("test.com", "pool1")
			Expect(added).To(BeTrue(), "Failed to Add DataGroup Record")

			added = idg.AddOrUpdateRecord("prod.com", "pool2")
			Expect(added).To(BeTrue(), "Failed to Add DataGroup Record")

			added = idg.AddOrUpdateRecord("test.com", "pool3")
			Expect(added).To(BeTrue(), "Failed to Update DataGroup Record")

			added = idg.AddOrUpdateRecord("test.com", "pool3")
			Expect(added).To(BeFalse(), "Failed to Validate while Update DataGroup Record")

			removed := idg.RemoveRecord("test.com")
			Expect(removed).To(BeTrue(), "Failed to Remove Record from DataGroup ")

			removed = idg.RemoveRecord("prod.com")
			Expect(removed).To(BeTrue(), "Failed to Remove Record from DataGroup ")

			removed = idg.RemoveRecord("test.com")
			Expect(removed).To(BeFalse(), "Validation Failed while Removing Record from DataGroup ")

		})
	})

	It("Validate TLS Profiles", func() {
		tlsRenc := test.NewTLSProfile(
			"sampleTLS",
			namespace,
			cisapiv1.TLSProfileSpec{
				//Hosts: "test.com",
				TLS: cisapiv1.TLS{
					Termination: TLSReencrypt,
					ClientSSL:   "clientssl",
					ServerSSL:   "serverssl",
				},
			},
		)

		tlsEdge := test.NewTLSProfile(
			"sampleTLS",
			namespace,
			cisapiv1.TLSProfileSpec{
				//Hosts: "test.com",
				TLS: cisapiv1.TLS{
					Termination: TLSEdge,
					ClientSSL:   "clientssl",
				},
			},
		)

		tlsPst := test.NewTLSProfile(
			"sampleTLS",
			namespace,
			cisapiv1.TLSProfileSpec{
				//Hosts: "test.com",
				TLS: cisapiv1.TLS{
					Termination: TLSPassthrough,
				},
			},
		)

		ok := validateTLSProfile(tlsRenc)
		Expect(ok).To(BeTrue(), "TLS Re-encryption Validation Failed")

		ok = validateTLSProfile(tlsEdge)
		Expect(ok).To(BeTrue(), "TLS Edge Validation Failed")

		ok = validateTLSProfile(tlsPst)
		Expect(ok).To(BeTrue(), "TLS Passthrough Validation Failed")

		// Negative cases
		tlsPst.Spec.TLS.Termination = TLSEdge
		tlsEdge.Spec.TLS.Termination = TLSReencrypt
		tlsRenc.Spec.TLS.Termination = TLSPassthrough

		ok = validateTLSProfile(tlsRenc)
		Expect(ok).To(BeFalse(), "TLS Re-encryption Validation Failed")

		ok = validateTLSProfile(tlsEdge)
		Expect(ok).To(BeFalse(), "TLS Edge Validation Failed")

		ok = validateTLSProfile(tlsPst)
		Expect(ok).To(BeFalse(), "TLS Passthrough Validation Failed")

		tlsRenc.Spec.TLS.Termination = TLSEdge
		ok = validateTLSProfile(tlsRenc)
		Expect(ok).To(BeFalse(), "TLS Edge Validation Failed")
	})

	Describe("ResourceStore", func() {
		var rs ResourceStore
		BeforeEach(func() {
			rs.Init()
		})

		It("Get Partition Resource Map", func() {
			rsMap := rs.getPartitionResourceMap("default")
			Expect(len(rsMap)).To(Equal(0))
			rsMap["default"] = &ResourceConfig{}
			rsMap = rs.getPartitionResourceMap("default")
			Expect(len(rsMap)).To(Equal(1))
		})

		It("Get Resource", func() {

			rsCfg, err := rs.getResourceConfig("default", "sampleVS")
			Expect(err).ToNot(BeNil())
			_ = rs.getPartitionResourceMap("default")

			rsCfg, err = rs.getResourceConfig("default", "sampleVS")
			Expect(err).ToNot(BeNil())
			Expect(rsCfg).To(BeNil())

			rs.ltmConfig["default"] = make(ResourceMap)

			rs.ltmConfig["default"]["virtualServer"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer",
				},
			}

			rsCfg, err = rs.getResourceConfig("default", "virtualServer")
			Expect(err).To(BeNil())
			Expect(rsCfg).NotTo(BeNil())
			Expect(rsCfg.Virtual.Name).To(Equal("VirtualServer"))
		})

		It("Get all Resources", func() {
			rs.ltmConfig["default"] = make(ResourceMap)
			rs.ltmConfig["default"]["virtualServer1"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer1",
				},
			}
			rs.ltmConfig["default"]["virtualServer2"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer2",
				},
			}

			ltmCfg := rs.getLTMConfigDeepCopy()
			Expect(len(ltmCfg)).To(Equal(1), "Wrong number of Partitions")
			Expect(len(ltmCfg["default"])).To(Equal(2), "Wrong number of ResourceConfigs")
		})
	})

	Describe("Handle Virtual Server TLS", func() {
		var mockCtlr *mockController
		var vs *cisapiv1.VirtualServer
		var tlsProf *cisapiv1.TLSProfile
		var rsCfg, inSecRsCfg *ResourceConfig
		var ip string

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.SSLContext = make(map[string]*v1.Secret)

			ip = "1.2.3.4"

			vs = test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.Pool{
						cisapiv1.Pool{
							Path:    "/path",
							Service: "svc1",
						},
					},
				},
			)

			rsCfg = &ResourceConfig{}
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.Virtual.SetVirtualAddress(
				ip,
				443,
			)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)

			inSecRsCfg = &ResourceConfig{}
			inSecRsCfg.MetaData.ResourceType = VirtualServer
			inSecRsCfg.Virtual.Enabled = true
			inSecRsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			inSecRsCfg.Virtual.SetVirtualAddress(
				"1.2.3.4",
				80,
			)
			inSecRsCfg.IntDgMap = make(InternalDataGroupMap)
			inSecRsCfg.IRulesMap = make(IRulesMap)

			tlsProf = test.NewTLSProfile("SampleTLS", namespace, cisapiv1.TLSProfileSpec{
				TLS: cisapiv1.TLS{},
			})
		})

		It("Basic Validation", func() {
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Validation Failed")

			vs.Spec.TLSProfileName = "SampleTLS"
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, nil, ip)
			Expect(ok).To(BeFalse(), "Validation Failed")
		})

		It("Invalide TLS Reference", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Failed to Validate TLS Reference")
		})

		It("Passthrough Termination", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSPassthrough
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Passthrough")
		})

		It("TLS Edge with BIGIP Reference", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSEdge
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"

			profRef := ProfileRef{
				Name:         "clientssl",
				Partition:    "Common",
				Context:      CustomProfileClient,
				Namespace:    namespace,
				BigIPProfile: true,
			}

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(1), "Failed to Process TLS Termination: Edge")
			Expect(rsCfg.Virtual.Profiles[0]).To(Equal(profRef), "Failed to Process TLS Termination: Edge")

		})

		It("TLS Reencrypt with BIGIP Reference", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			clProfRef := ProfileRef{
				Name:         "clientssl",
				Partition:    "Common",
				Context:      CustomProfileClient,
				Namespace:    namespace,
				BigIPProfile: true,
			}
			svProfRef := ProfileRef{
				Name:         "serverssl",
				Partition:    "Common",
				Context:      CustomProfileServer,
				Namespace:    namespace,
				BigIPProfile: true,
			}

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Reencrypt")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(2), "Failed to Process TLS Termination: Reencrypt")
			Expect(rsCfg.Virtual.Profiles[0]).To(Equal(clProfRef), "Failed to Process TLS Termination: Reencrypt")
			Expect(rsCfg.Virtual.Profiles[1]).To(Equal(svProfRef), "Failed to Process TLS Termination: Reencrypt")
		})

		It("Validate TLS Reencrypt with AllowInsecure", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSAllowInsecure
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Failed to Validate TLS Termination: Reencrypt with AllowInsecure")
		})

		It("Handle HTTP Server when Redirect", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSRedirectInsecure
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Handle insecure virtual with Redirect config")
			Expect(len(inSecRsCfg.IRulesMap)).To(Equal(1))
			Expect(len(inSecRsCfg.Virtual.IRules)).To(Equal(1))
		})

		It("Handle HTTP Server when Redirect with out host", func() {
			vs.Spec.Host = ""
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSRedirectInsecure
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Handle insecure virtual with Redirect config")
			Expect(len(inSecRsCfg.IRulesMap)).To(Equal(1))
			Expect(len(inSecRsCfg.Virtual.IRules)).To(Equal(1))
		})

		It("Handle HTTP Server when Allow with Edge", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSAllowInsecure
			tlsProf.Spec.TLS.Termination = TLSEdge
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(0), "Failed to Process TLS Termination: Edge")
		})

		It("Handle HTTP Server when NoInsecure with Edge", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSNoInsecure
			tlsProf.Spec.TLS.Termination = TLSEdge
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(0), "Failed to Process TLS Termination: Edge")
		})

		It("TLS Edge with BIGIP Reference", func() {

			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSEdge
			tlsProf.Spec.TLS.Reference = Secret
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			mockCtlr.kubeClient = k8sfake.NewSimpleClientset(clSecret)

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")
			Expect(len(rsCfg.customProfiles)).To(Equal(2), "Failed to Process TLS Termination: Edge")
			Expect(len(mockCtlr.SSLContext)).To(Equal(1), "Failed to Process TLS Termination: Edge")

			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")
			Expect(len(rsCfg.customProfiles)).To(Equal(2), "Failed to Process TLS Termination: Edge")
			Expect(len(mockCtlr.SSLContext)).To(Equal(1), "Failed to Process TLS Termination: Edge")
		})

		It("TLS Reencrypt with BIGIP Reference", func() {

			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = Secret
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"
			tlsProf.Spec.TLS.ServerSSL = "serversecret"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			svSecret := test.NewSecret(
				"serversecret",
				namespace,
				"### cert ###",
				"",
			)
			mockCtlr.kubeClient = k8sfake.NewSimpleClientset(clSecret, svSecret)

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Reencrypt")
			Expect(len(rsCfg.customProfiles)).To(Equal(4), "Failed to Process TLS Termination: Reencrypt")
			Expect(len(mockCtlr.SSLContext)).To(Equal(2), "Failed to Process TLS Termination: Reencrypt")

			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Reencrypt")
			Expect(len(rsCfg.customProfiles)).To(Equal(4), "Failed to Process TLS Termination: Reencrypt")
			Expect(len(mockCtlr.SSLContext)).To(Equal(2), "Failed to Process TLS Termination: Reencrypt")
		})

		It("Validate API failures", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = Secret
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"
			tlsProf.Spec.TLS.ServerSSL = "serversecret"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			mockCtlr.kubeClient = k8sfake.NewSimpleClientset()

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			mockCtlr.kubeClient = k8sfake.NewSimpleClientset(clSecret)
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")
		})
	})

	Describe("SNAT in policy CRD", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController
		var plc *cisapiv1.Policy

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.mode = CustomResourceMode

			rsCfg = &ResourceConfig{}
			rsCfg.Virtual.SetVirtualAddress(
				"1.2.3.4",
				80,
			)

			plc = test.NewPolicy("plc1", namespace, cisapiv1.PolicySpec{})
		})

		It("Verifies SNAT whether is set properly for VirtualServer", func() {
			plc.Spec.SNAT = DEFAULT_SNAT
			err := mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
			Expect(rsCfg.Virtual.SNAT).To(Equal(DEFAULT_SNAT), "SNAT should be set to automap")

			plc.Spec.SNAT = "none"
			err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
			Expect(rsCfg.Virtual.SNAT).To(Equal(plc.Spec.SNAT), "SNAT should be set to none")

			plc.Spec.SNAT = "/Common/snatpool"
			err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
			Expect(rsCfg.Virtual.SNAT).To(Equal(plc.Spec.SNAT), "SNAT should be set "+
				"to /Common/snatpool")

			vs := test.NewVirtualServer(
				"SamplevS",
				namespace,
				cisapiv1.VirtualServerSpec{},
			)
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(plc.Spec.SNAT), "Default SNAT should be set "+
				"to /Common/snatpool")

			vs.Spec.SNAT = "none"
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(vs.Spec.SNAT), "SNAT should be set to none")

			vs.Spec.SNAT = "/Common/snatpool"
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(vs.Spec.SNAT), "SNAT should be set "+
				"to /Common/snatpool")

			rsCfg.Virtual.SNAT = ""
			vs.Spec.SNAT = ""
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(DEFAULT_SNAT), "Default SNAT should be set "+
				"to automap")

		})

		It("Verifies SNAT whether is set properly for TransportServer", func() {
			err := mockCtlr.handleTSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle TransportServer for policy")
			Expect(rsCfg.Virtual.SNAT).To(Equal(DEFAULT_SNAT), "Default SNAT should be set "+
				"to automap")

			plc.Spec.SNAT = "none"
			err = mockCtlr.handleTSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle TransportServer for policy")
			Expect(rsCfg.Virtual.SNAT).To(Equal("none"), "SNAT should be set to none")

			plc.Spec.SNAT = "/Common/snatpool"
			err = mockCtlr.handleTSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle TransportServer for policy")
			Expect(rsCfg.Virtual.SNAT).To(Equal(plc.Spec.SNAT), "SNAT should be set "+
				"to /Common/snatpool")

			ts := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{},
			)
			err = mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from TransportServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(plc.Spec.SNAT), "Default SNAT should be set "+
				"to /Common/snatpool")

			ts.Spec.SNAT = "none"
			err = mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from TransportServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(ts.Spec.SNAT), "SNAT should be set to none")

			ts.Spec.SNAT = "/Common/snatpool"
			err = mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from TransportServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(ts.Spec.SNAT), "SNAT should be set "+
				"to /Common/snatpool")

			ts.Spec.SNAT = DEFAULT_SNAT
			err = mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from TransportServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(DEFAULT_SNAT), "Default SNAT should be set "+
				"to automap")
		})
	})
})
