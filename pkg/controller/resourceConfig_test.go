package controller

import (
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
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
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.mode = CustomResourceMode
			mockCtlr.Agent = &Agent{
				PostManager: &PostManager{
					PostParams: PostParams{
						BIGIPURL: "10.10.10.1",
					},
				},
			}
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
		var mockCtlr *mockController

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.mode = CustomResourceMode
		})
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
		It("Pool name for TS", func() {
			var name string
			name = mockCtlr.formatPoolNameForTS(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "app=test", "cluster1")
			Expect(name).To(Equal("svc1_80_default_app_test"), "Invalid Pool Name for TS")
			mockCtlr.multiClusterMode = PrimaryCIS
			mockCtlr.discoveryMode = ""
			name = mockCtlr.formatPoolNameForTS(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "app=test", "cluster1")
			Expect(name).To(Equal("ts_7bb616e6f5_multicluster"), "Invalid Pool Name for TS")
			mockCtlr.discoveryMode = DefaultMode
			name = mockCtlr.formatPoolNameForTS(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "app=test", "cluster1")
			Expect(name).To(Equal("ts_5bd74b770d_cluster1"), "Invalid Pool Name for TS")
			mockCtlr.multiClusterMode = ""
			mockCtlr.discoveryMode = ""
		})
		It("Pool Name", func() {
			name := mockCtlr.formatPoolName(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "app=test", "foo", "")
			Expect(name).To(Equal("svc1_80_default_foo_app_test"), "Invalid Pool Name")
		})
		It("Monitor Name for TS", func() {
			name := mockCtlr.formatMonitorNameForTS(namespace, "svc1", "http", intstr.IntOrString{IntVal: 80}, "foo.com", "path", "hash123")
			Expect(name).To(Equal("svc1_default_foo_com_path_http_80"), "Invalid Monitor Name")
			mockCtlr.multiClusterMode = PrimaryCIS
			name = mockCtlr.formatMonitorNameForTS(namespace, "svc1", "http", intstr.IntOrString{IntVal: 80}, "foo.com", "path", "hash123")
			Expect(name).To(Equal("ts_hash123_80_http"), "Invalid Pool Name for TS")
			mockCtlr.multiClusterMode = ""
			mockCtlr.discoveryMode = ""
		})
		It("Monitor Name", func() {
			name := formatMonitorName(namespace, "svc1", "http", intstr.IntOrString{IntVal: 80}, "foo.com", "path")
			Expect(name).To(Equal("svc1_default_foo_com_path_http_80"), "Invalid Monitor Name")
		})
		It("Rule Name", func() {
			name := formatVirtualServerRuleName("test.com", "", "", "sample_pool", false)
			Expect(name).To(Equal("vs_test_com_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "exams.com", "", "sample_pool", false)
			Expect(name).To(Equal("vs_exams_com_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "", "/foo", "sample_pool", false)
			Expect(name).To(Equal("vs_test_com_foo_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "", "/++foo++", "sample_pool", false)
			Expect(name).To(Equal("vs_test_com___foo___sample_pool"))
		})
		It("Monitor Name with MultiCluster mode", func() {
			// Standalone, no ratio and monitor for local cluster pool
			mockCtlr.multiClusterMode = StandAloneCIS
			mockCtlr.clusterRatio = make(map[string]*int)
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			monitorName := "pytest_svc_1_default_foo_example_com_foo_http_80"
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName), "Invalid Monitor Name")
			// Standalone, no ratio and monitor for external cluster pool
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster2")).To(Equal(monitorName), "Invalid Monitor Name")
			// Standalone, ratio and monitor for local cluster pool
			mockCtlr.clusterRatio["cluster3"] = new(int)
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName+"_local_cluster"), "Invalid Monitor Name")
			// Standalone, ratio and monitor for external cluster pool
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster3")).To(Equal(monitorName+"_cluster3"), "Invalid Monitor Name")

			// Primary, no ratio and monitor for local cluster pool
			mockCtlr.multiClusterMode = PrimaryCIS
			mockCtlr.clusterRatio = make(map[string]*int)
			mockCtlr.multiClusterHandler.LocalClusterName = "cluster1"
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName), "Invalid Monitor Name")
			// Primary, no ratio and monitor for external cluster pool
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster2")).To(Equal(monitorName), "Invalid Monitor Name")
			// Primary, ratio and monitor for local cluster pool
			mockCtlr.clusterRatio["cluster2"] = new(int) // secondary cluster ratio
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName+"_"+mockCtlr.multiClusterHandler.LocalClusterName), "Invalid Monitor Name")
			// Primary, ratio and monitor for external cluster pool
			mockCtlr.clusterRatio["cluster3"] = new(int) // external cluster ratio
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster3")).To(Equal(monitorName+"_cluster3"), "Invalid Monitor Name")

			// Secondary, no ratio and monitor for local cluster pool
			mockCtlr.multiClusterMode = SecondaryCIS
			mockCtlr.multiClusterHandler.LocalClusterName = "cluster1"
			mockCtlr.clusterRatio = make(map[string]*int)
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName), "Invalid Monitor Name")
			// Secondary, no ratio and monitor for external cluster pool
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster2")).To(Equal(monitorName), "Invalid Monitor Name")
			// Secondary, ratio and monitor for local cluster pool
			mockCtlr.clusterRatio["cluster2"] = new(int) // secondary cluster ratio
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName+"_"+mockCtlr.multiClusterHandler.LocalClusterName), "Invalid Monitor Name")
			// Secondary, ratio and monitor for external cluster pool
			mockCtlr.clusterRatio["cluster3"] = new(int)
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster3")).To(Equal(monitorName+"_cluster3"), "Invalid Monitor Name")

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
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.mode = CustomResourceMode
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(), kubeCRClient: crdfake.NewSimpleClientset()}
			mockCtlr.multiClusterHandler.ClusterConfigs[""].InformerStore = initInformerStore()
			mockCtlr.multiClusterHandler.ClusterConfigs[""].nativeResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()
			_ = mockCtlr.addNamespacedInformers(namespace, false, "")

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
					Host:             "test.com",
					BigIPRouteDomain: 10,
					Pools: []cisapiv1.VSPool{
						{
							Path:             "/foo",
							Service:          "svc1",
							ServiceNamespace: "test",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
							Rewrite:         "/bar",
							MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
						},
						{
							Path:            "/",
							Service:         "svc2",
							MinimumMonitors: intstr.IntOrString{Type: 1, StrVal: "all"},
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
			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Pools[0].ServiceNamespace).To(Equal("test"), "Incorrect namespace defined for pool")
			Expect(rsCfg.Pools[0].MinimumMonitors).To(Equal(intstr.IntOrString{Type: 0, IntVal: 1}), "Incorrect minimum monitors defined for pool 0")
			Expect(rsCfg.Pools[1].MinimumMonitors).To(Equal(intstr.IntOrString{Type: 1, StrVal: "all"}), "Incorrect minimum monitors defined for pool 1")
			Expect(rsCfg.Virtual.IRules[0]).To(Equal("SampleIRule"))
		})

		It("Prepare Resource Config from a VirtualServer with HostAliases", func() {
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)

			vs := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:        "test.com",
					HostAliases: []string{"test1.com", "test2.com"},
					HostGroup:   "hg1",
					Pools: []cisapiv1.VSPool{
						{
							Path:             "/foo",
							Service:          "svc1",
							ServiceNamespace: "test",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
							Rewrite:         "/bar",
							MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
						},
						{
							Path:            "/",
							Service:         "svc2",
							MinimumMonitors: intstr.IntOrString{Type: 1, StrVal: "all"},
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
			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Pools[0].ServiceNamespace).To(Equal("test"), "Incorrect namespace defined for pool")
			Expect(rsCfg.Pools[0].MinimumMonitors).To(Equal(intstr.IntOrString{Type: 0, IntVal: 1}), "Incorrect minimum monitors defined for pool 0")
			Expect(rsCfg.Pools[1].MinimumMonitors).To(Equal(intstr.IntOrString{Type: 1, StrVal: "all"}), "Incorrect minimum monitors defined for pool 1")
			Expect(rsCfg.Virtual.IRules[0]).To(Equal("SampleIRule"))
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(10))
			//urisInRules := make(map[string]struct{})
			urisInRules := map[string]struct{}{"test.com": struct{}{}, "test.com/": struct{}{}, "test1.com/": struct{}{},
				"test2.com/": struct{}{}, "test.com/home": struct{}{}, "test1.com/home": struct{}{},
				"test2.com/home": struct{}{}, "test.com/foo": struct{}{}, "test1.com/foo": struct{}{}, "test2.com/foo": struct{}{}}
			for _, rule := range rsCfg.Policies[0].Rules {
				_, ok := urisInRules[rule.FullURI]
				Expect(ok).To(BeTrue(), "Incorrect rules defined for VirtualServer with hostAliases")
				// Verify correct ruleName is generated in case HostGroup is defined along with hostAliases
				uriArray := strings.Split(rule.FullURI, "/")
				Expect(len(uriArray)).To(BeNumerically(">=", 1), "Incorrect rules defined for VirtualServer with hostAliases")
				formatedUri := strings.ReplaceAll(uriArray[0], ".", "_")
				Expect(rule.Name).To(ContainSubstring("vs_hg1_"+formatedUri), "Incorrect rules defined for VirtualServer with hostAliases")
			}
		})

		It("Validate Resource Config from a AB Deployment VirtualServer", func() {
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
			weight1 := int32(70)
			weight2 := int32(30)
			vs := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.VSPool{
						{
							Path:             "/foo",
							Service:          "svc1",
							ServiceNamespace: "test",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
							Weight: &weight1,
							AlternateBackends: []cisapiv1.AlternateBackend{
								{
									Service:          "svc1-b",
									ServiceNamespace: "test2",
									Weight:           &weight2,
								},
							},
						},
					},
				},
			)
			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(len(rsCfg.Pools)).To(Equal(2), "AB pool not processed")
			Expect(rsCfg.Pools[0].ServiceNamespace).To(Equal("test"), "Incorrect namespace defined for pool")
			Expect(rsCfg.Pools[1].ServiceNamespace).To(Equal("test2"), "Incorrect namespace defined for pool")
		})
		It("Validate Virtual server config with multiple monitors(tcp and http)", func() {
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
					Pools: []cisapiv1.VSPool{
						{
							Path:    "/foo",
							Service: "svc1",
							Monitors: []cisapiv1.Monitor{
								{
									Type:       "http",
									Send:       "GET /health",
									Interval:   15,
									Timeout:    10,
									TargetPort: 80,
								},
								{
									Type:       "tcp",
									Send:       "GET /health",
									Interval:   15,
									Timeout:    10,
									TargetPort: 80,
								},
								{
									Name:      "/Common/monitor",
									Reference: "bigip",
								},
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
			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")

		})

		It("Validate default pool in Virtual server with svc", func() {
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
					DefaultPool: cisapiv1.DefaultPool{
						Reference:   ServiceRef,
						Service:     "svc1",
						ServicePort: intstr.IntOrString{IntVal: 80},
						Monitors: []cisapiv1.Monitor{
							{
								Type:       "http",
								Send:       "GET /health",
								Interval:   15,
								Timeout:    10,
								TargetPort: 80,
							},
							{
								Type:       "tcp",
								Send:       "GET /health",
								Interval:   15,
								Timeout:    10,
								TargetPort: 80,
							},
							{
								Name:      "/Common/monitor",
								Reference: "bigip",
							},
						},
					},
				},
			)
			rsRef := resourceRef{
				name:      "test-vs",
				namespace: "default",
				kind:      VirtualServer,
			}
			mockCtlr.handleDefaultPool(rsCfg, vs, rsRef)
			Expect(rsCfg.Virtual.PoolName).To(Equal("svc1_80_default_test_com"), "Failed to process default pool for VirtualServer")
			Expect(len(rsCfg.Pools)).To(Equal(1), "Failed to process default pool for VirtualServer")
			Expect(len(rsCfg.Monitors)).To(Equal(2), "Failed to process default pool for VirtualServer")
		})

		It("Validate default pool in Virtual server with bigip reference", func() {
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
					DefaultPool: cisapiv1.DefaultPool{
						Reference: BIGIP,
						Name:      "/Common/default_pool_svc1",
					},
				},
			)
			rsRef := resourceRef{
				name:      "test-vs",
				namespace: "default",
				kind:      VirtualServer,
			}
			mockCtlr.handleDefaultPool(rsCfg, vs, rsRef)
			Expect(rsCfg.Virtual.PoolName).To(Equal("/Common/default_pool_svc1"), "Failed to process default pool for VirtualServer")
			Expect(len(rsCfg.Pools)).To(Equal(0), "Failed to process default pool for VirtualServer")
			Expect(len(rsCfg.Monitors)).To(Equal(0), "Failed to process default pool for VirtualServer")
		})

		It("Validate default pool in Virtual server with bigip reference", func() {
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
					DefaultPool: cisapiv1.DefaultPool{
						Reference: BIGIP,
						Name:      "/Common/default_pool_svc1",
					},
				},
			)
			rsRef := resourceRef{
				name:      "test-vs",
				namespace: "default",
				kind:      VirtualServer,
			}
			mockCtlr.handleDefaultPool(rsCfg, vs, rsRef)
			Expect(rsCfg.Virtual.PoolName).To(Equal("/Common/default_pool_svc1"), "Failed to process default pool for VirtualServer")
			Expect(len(rsCfg.Pools)).To(Equal(0), "Failed to process default pool for VirtualServer")
			Expect(len(rsCfg.Monitors)).To(Equal(0), "Failed to process default pool for VirtualServer")
		})

		It("Prepare Resource Config from a TransportServer", func() {
			ts := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.TSPool{
						Service:          "svc1",
						ServicePort:      intstr.IntOrString{IntVal: 80},
						ServiceNamespace: "test",
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
			Expect(rsCfg.Pools[0].ServiceNamespace).To(Equal("test"), "Incorrect namespace defined for pool")
		})

		It("Prepare Resource Config from a TransportServer with HTTP Monitor", func() {
			ts := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.TSPool{
						Service:          "svc1",
						ServicePort:      intstr.IntOrString{IntVal: 80},
						ServiceNamespace: "test",
						Monitor: cisapiv1.Monitor{
							Type:       "http",
							Send:       "GET /health",
							Interval:   15,
							Timeout:    10,
							TargetPort: 80,
						},
					},
				},
			)
			err := mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from TransportServer with HTTP Monitor")
			Expect(rsCfg.Pools[0].ServiceNamespace).To(Equal("test"), "Incorrect namespace defined for pool")
		})
		It("Prepare Resource Config from a TransportServer", func() {
			ts := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.TSPool{
						Service:     "svc1",
						ServicePort: intstr.IntOrString{IntVal: 80},
						Monitors: []cisapiv1.Monitor{
							{
								Type:       "tcp",
								Timeout:    10,
								Interval:   10,
								TargetPort: 80,
							},
							{
								Type:       "tcp",
								Timeout:    10,
								Interval:   10,
								TargetPort: 22,
							},
							{
								Type:       "http",
								Timeout:    20,
								Interval:   20,
								TargetPort: 32,
							},
							{
								Type:       "http",
								Timeout:    30,
								Interval:   30,
								TargetPort: 42,
								Send:       "Get /api HTTP 1.1",
								Recv:       "200",
							},
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

			err := mockCtlr.prepareRSConfigFromLBService(rsCfg, svc, svcPort, "")
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
			zero := 0
			ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			ltmConfig["default"].ResourceMap[rsCfg.Virtual.Name] = rsCfg
			ltmConfig["default"].ResourceMap[rsCfg2.Virtual.Name] = rsCfg2
			ltmConfig["default"].ResourceMap[rsCfg3.Virtual.Name] = rsCfg3
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
				Type:      "string",
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

	It("Validate Multiple TLS Profiles", func() {
		tlsRenc := test.NewTLSProfile(
			"sampleTLS",
			namespace,
			cisapiv1.TLSProfileSpec{
				//Hosts: "test.com",
				TLS: cisapiv1.TLS{
					Termination: TLSReencrypt,
					ClientSSLs:  []string{"clientssl", "foo-clientssl"},
					ServerSSLs:  []string{"serverssl", "foo-serverssl"},
				},
			},
		)

		tlsRencComb := test.NewTLSProfile(
			"sampleTLS",
			namespace,
			cisapiv1.TLSProfileSpec{
				//Hosts: "test.com",
				TLS: cisapiv1.TLS{
					Termination: TLSReencrypt,
					ClientSSLs:  []string{"clientssl", "foo-clientssl"},
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
					ClientSSLs:  []string{"clientssl", "foo-clientssl"},
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

		ok = validateTLSProfile(tlsRencComb)
		Expect(ok).To(BeFalse(), "TLS Re-encryption Validation Failed")

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

	Describe("Fetch target ports", func() {
		var mockCtlr *mockController
		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.mode = CustomResourceMode
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset()}
			mockCtlr.multiClusterHandler.ClusterConfigs[""].InformerStore = initInformerStore()
			mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default", "")
		})
		It("Int target port is returned with integer targetPort", func() {
			svcPort := v1.ServicePort{
				Name:       "http-port",
				Port:       80,
				Protocol:   "http",
				TargetPort: intstr.IntOrString{IntVal: 8080},
			}
			svcPort2 := v1.ServicePort{
				Name:       "https-port",
				Port:       443,
				Protocol:   "http",
				TargetPort: intstr.IntOrString{IntVal: 8443},
			}
			svc := test.NewService(
				"svc1",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				[]v1.ServicePort{svcPort, svcPort2},
			)
			mockCtlr.addService(svc)
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "")).To(Equal(intstr.IntOrString{IntVal: 8080}), "Incorrect target port returned")
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{StrVal: "http-port"}, "")).To(Equal(intstr.IntOrString{IntVal: 8080}), "Incorrect target port returned")
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{IntVal: 443}, "")).To(Equal(intstr.IntOrString{IntVal: 8443}), "Incorrect target port returned")
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{StrVal: "https-port"}, "")).To(Equal(intstr.IntOrString{IntVal: 8443}), "Incorrect target port returned")
		})
		It("Service port name is returned with named target port", func() {
			svcPort := v1.ServicePort{
				Name:       "http-port",
				Port:       80,
				Protocol:   "http",
				TargetPort: intstr.IntOrString{StrVal: "http-web"},
			}
			svcPort2 := v1.ServicePort{
				Name:       "https-port",
				Port:       443,
				Protocol:   "http",
				TargetPort: intstr.IntOrString{StrVal: "https-web"},
			}
			svc := test.NewService(
				"svc1",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				[]v1.ServicePort{svcPort, svcPort2},
			)
			mockCtlr.addService(svc)
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "")).To(Equal(intstr.IntOrString{StrVal: "http-port"}), "Incorrect target port returned")
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{StrVal: "http-port"}, "")).To(Equal(intstr.IntOrString{StrVal: "http-port"}), "Incorrect target port returned")
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{IntVal: 443}, "")).To(Equal(intstr.IntOrString{StrVal: "https-port"}), "Incorrect target port returned")
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{StrVal: "https-port"}, "")).To(Equal(intstr.IntOrString{StrVal: "https-port"}), "Incorrect target port returned")
		})
		It("empty target port is returned without port name with named target port", func() {
			svcPort := v1.ServicePort{
				Port:       80,
				Protocol:   "http",
				TargetPort: intstr.IntOrString{StrVal: "http-web"},
			}
			svc := test.NewService(
				"svc1",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				[]v1.ServicePort{svcPort},
			)
			mockCtlr.addService(svc)
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "")).To(Equal(intstr.IntOrString{}), "Incorrect target port returned")
		})
		It("int target port is returned without port name with int target port", func() {
			svcPort := v1.ServicePort{
				Port:       80,
				Protocol:   "http",
				TargetPort: intstr.IntOrString{IntVal: 8080},
			}
			svc := test.NewService(
				"svc1",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				[]v1.ServicePort{svcPort},
			)
			mockCtlr.addService(svc)
			Expect(mockCtlr.fetchTargetPort(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "")).To(Equal(intstr.IntOrString{IntVal: 8080}), "Incorrect target port returned")
		})
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

			zero := 0
			rs.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}

			rs.ltmConfig["default"].ResourceMap["virtualServer"] = &ResourceConfig{
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
			zero := 0
			rs.ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			rs.ltmConfig["default"].ResourceMap["virtualServer1"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer1",
				},
			}
			rs.ltmConfig["default"].ResourceMap["virtualServer2"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer2",
				},
			}

			ltmCfg := rs.getLTMConfigDeepCopy()
			Expect(len(ltmCfg)).To(Equal(1), "Wrong number of Partitions")
			Expect(len(ltmCfg["default"].ResourceMap)).To(Equal(2), "Wrong number of ResourceConfigs")
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
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{InformerStore: initInformerStore()}

			mockCtlr.Agent = &Agent{
				PostManager: &PostManager{
					PostParams: PostParams{
						BIGIPURL: "10.10.10.1",
					},
				},
			}
			mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher = TLSCipher{
				"1.2",
				"",
				"",
				[]string{"1.1", "1.0"}}

			ip = "1.2.3.4"

			vs = test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.VSPool{
						{
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
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Validation Failed")

			vs.Spec.TLSProfileName = "SampleTLS"
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, nil, ip, false)
			Expect(ok).To(BeFalse(), "Validation Failed")
		})

		It("Invalide TLS Reference", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Failed to Validate TLS Reference")
		})

		It("Passthrough Termination", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSPassthrough
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
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

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
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

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Reencrypt")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(2), "Failed to Process TLS Termination: Reencrypt")
			Expect(rsCfg.Virtual.Profiles[0]).To(Equal(clProfRef), "Failed to Process TLS Termination: Reencrypt")
			Expect(rsCfg.Virtual.Profiles[1]).To(Equal(svProfRef), "Failed to Process TLS Termination: Reencrypt")
		})

		It("Validate disabling tls version,TLS Reencrypt with BIGIP Reference", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = Secret
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"
			tlsProf.Spec.TLS.ServerSSL = "serversecret"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(),
				InformerStore: initInformerStore()}
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(clSecret),
				InformerStore: initInformerStore()}
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")
		})

		It("Validate TLS Reencrypt with AllowInsecure", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSAllowInsecure
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Failed to Validate TLS Termination: Reencrypt with AllowInsecure")
		})

		It("Handle HTTP Server when Redirect", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSRedirectInsecure
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"
			tlsProf.Spec.Hosts = []string{"test.com"}
			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Handle insecure virtual with Redirect config")
			Expect(len(inSecRsCfg.IRulesMap)).To(Equal(1))
			Expect(len(inSecRsCfg.Virtual.IRules)).To(Equal(1))
			Expect(len(inSecRsCfg.IntDgMap)).To(Equal(1))
			for _, idg := range inSecRsCfg.IntDgMap {
				for _, dg := range idg {
					//record should have host and host:port match
					Expect(len(dg.Records)).To(Equal(2))
					Expect(dg.Records[0].Name).To(Equal("test.com/path"))
					Expect(dg.Records[0].Data).To(Equal("/path"))
					Expect(dg.Records[1].Name).To(Equal("test.com:80/path"))
					Expect(dg.Records[1].Data).To(Equal("/path"))
				}
			}

		})

		It("Handle HTTP Server when Redirect with out host", func() {
			vs.Spec.Host = ""
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSRedirectInsecure
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip, false)
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

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(0), "Failed to Process TLS Termination: Edge")
		})

		It("Handle HTTP Server when NoInsecure with Edge", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.HTTPTraffic = TLSNoInsecure
			tlsProf.Spec.TLS.Termination = TLSEdge
			tlsProf.Spec.TLS.Reference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "/Common/clientssl"

			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(0), "Failed to Process TLS Termination: Edge")
		})

		It("Validate API failures", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = Secret
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"
			tlsProf.Spec.TLS.ServerSSL = "serversecret"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(),
				InformerStore: initInformerStore()}

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(clSecret),
				InformerStore: initInformerStore()}
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")
		})

		It("Verifies hybrid profile reference is set properly for tlsProfile", func() {
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(),
				InformerStore: initInformerStore()}
			mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default", "")
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = Hybrid
			tlsProf.Spec.TLS.ClientSSLParams.ProfileReference = Secret
			tlsProf.Spec.TLS.ServerSSLParams.ProfileReference = BIGIP
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"
			tlsProf.Spec.TLS.ServerSSL = "/Common/serverssl"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset(),
				InformerStore: initInformerStore()}
			mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default", "")
			mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers["default"].secretsInformer.GetStore().Add(clSecret)
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Reencrypt")
			Expect(rsCfg.Virtual.Profiles[0].Name).To(Equal("clientsecret"), "profile name is not set properly")
			Expect(rsCfg.Virtual.Profiles[0].BigIPProfile).To(BeFalse(), "profile context is not set properly")
			Expect(rsCfg.Virtual.Profiles[1].Name).To(Equal("serverssl"), "profile name is not set properly")
			Expect(rsCfg.Virtual.Profiles[1].BigIPProfile).To(BeTrue(), "profile context is not set properly")
		})

		It("VS with TLS and default pool", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			vs.Spec.DefaultPool = cisapiv1.DefaultPool{
				Reference:   ServiceRef,
				Service:     "svc1",
				ServicePort: intstr.IntOrString{IntVal: 80},
				Monitors: []cisapiv1.Monitor{
					{
						Type:       "http",
						Send:       "GET /health",
						Interval:   15,
						Timeout:    10,
						TargetPort: 80,
					},
					{
						Type:       "tcp",
						Send:       "GET /health",
						Interval:   15,
						Timeout:    10,
						TargetPort: 80,
					},
					{
						Name:      "/Common/monitor",
						Reference: "bigip",
					},
				},
			}
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
			rsCfg.Virtual.PoolName = "default_pool_svc1"
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")

			Expect(len(rsCfg.Virtual.Profiles)).To(Equal(1), "Failed to Process TLS Termination: Edge")
			Expect(rsCfg.Virtual.Profiles[0]).To(Equal(profRef), "Failed to Process TLS Termination: Edge")
			Expect(len(rsCfg.IntDgMap)).To(Equal(3), "Failed to process default pool for VirtualServer")
		})

		It("Handle TLS for AB Virtual Server", func() {
			weight1 := int32(70)
			weight2 := int32(30)
			vs1 := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:           "test.com",
					TLSProfileName: "SampleTLS",
					Pools: []cisapiv1.VSPool{
						{
							Path:             "/foo",
							Service:          "svc1",
							ServiceNamespace: "test",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
							Weight: &weight1,
							AlternateBackends: []cisapiv1.AlternateBackend{
								{
									Service:          "svc1-b",
									ServiceNamespace: "test2",
									Weight:           &weight2,
								},
							},
						},
					},
				},
			)
			tlsProf1 := test.NewTLSProfile("SampleTLS", namespace, cisapiv1.TLSProfileSpec{
				TLS: cisapiv1.TLS{
					ClientSSL: "/Common/clientssl",
					ServerSSL: "/Common/serverssl",
					Reference: BIGIP,
				},
			})

			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs1, false, tlsProf1.Spec.TLS.Termination)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")

			Expect(len(rsCfg.IntDgMap)).To(Equal(1), "Failed to Process AB Deployment for Virtual Server")
			nameRef := NameRef{
				Name: "My_VS_80_ab_deployment_dg",
			}
			Expect(rsCfg.IntDgMap[nameRef][namespace].Records[0].Name).To(Equal("test.com/foo"), "Failed to Process TLS for AB Virtual Server")

			// path = /
			vs1.Spec.Pools[0].Path = "/"
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs1, false, tlsProf1.Spec.TLS.Termination)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")

			Expect(len(rsCfg.IntDgMap)).To(Equal(1), "Failed to Process AB Virtual Server")
			Expect(rsCfg.IntDgMap[nameRef][namespace].Records[0].Name).To(Equal("test.com"), "Failed to Process TLS for AB Virtual Server")

			// TLSPassthrough
			tlsProf1.Spec.TLS.Termination = TLSPassthrough
			vs1.Spec.Pools[0].Path = "/"
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs1, true, tlsProf1.Spec.TLS.Termination)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs1, tlsProf1, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")
			nameRef = NameRef{
				Name: "My_VS_80_ssl_passthrough_servername_dg",
			}
			Expect(len(rsCfg.IntDgMap)).To(Equal(2), "Failed to Process AB Virtual Server")
			Expect(rsCfg.IntDgMap[nameRef]["default"].Records[0].Name).To(Equal("test.com"), "Failed to Process TLS for AB Virtual Server")

			// Weight = 0
			zeroWeight := int32(0)
			vs1.Spec.Pools[0].Weight = &zeroWeight
			vs1.Spec.Pools[0].AlternateBackends[0].Weight = &zeroWeight
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs1, true, tlsProf1.Spec.TLS.Termination)
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs1, tlsProf1, ip, false)
			Expect(ok).To(BeTrue(), "Failed to Process TLS Termination: Edge")
			nameRef = NameRef{
				Name: "My_VS_80_ssl_passthrough_servername_dg",
			}
			Expect(len(rsCfg.IntDgMap)).To(Equal(2), "Failed to Process AB Virtual Server")
			Expect(rsCfg.IntDgMap[nameRef]["default"].Records[0].Name).To(Equal("test.com"), "Failed to Process TLS for AB Virtual Server")

		})
	})

	Describe("SNAT in policy CRD", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController
		var plc *cisapiv1.Policy

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.resources = NewResourceStore()
			mockCtlr.mode = CustomResourceMode
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()
			mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{InformerStore: initInformerStore()}

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
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(plc.Spec.SNAT), "Default SNAT should be set "+
				"to /Common/snatpool")

			vs.Spec.SNAT = "none"
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(vs.Spec.SNAT), "SNAT should be set to none")

			vs.Spec.SNAT = "/Common/snatpool"
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(vs.Spec.SNAT), "SNAT should be set "+
				"to /Common/snatpool")

			rsCfg.Virtual.SNAT = ""
			vs.Spec.SNAT = ""
			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.SNAT).To(Equal(DEFAULT_SNAT), "Default SNAT should be set "+
				"to automap")

		})

		It("verify defaultPool is set from policy", func() {
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
			plc.Spec.DefaultPool = cisapiv1.DefaultPool{
				Reference:   ServiceRef,
				Service:     "svc1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}
			rsRef := resourceRef{
				name:      "test-vs",
				namespace: "default",
				kind:      VirtualServer,
			}
			mockCtlr.handleDefaultPoolForPolicy(rsCfg, plc, rsRef, "test.com", "allow", true)
			Expect(rsCfg.Virtual.PoolName).To(Equal("svc1_80_default_test_com"), "Failed to set default pool from policy")
			Expect(len(rsCfg.Pools)).To(Equal(1), "Failed to process default pool for VirtualServer")
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

	Describe("Profiles in policy CRD", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController
		var plc *cisapiv1.Policy

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			mockCtlr.resources = NewResourceStore()
			mockCtlr.mode = CustomResourceMode
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()

			rsCfg = &ResourceConfig{}
			rsCfg.Virtual.SetVirtualAddress(
				"1.2.3.4",
				80,
			)

			plc = test.NewPolicy("plc1", namespace, cisapiv1.PolicySpec{})
		})

		It("Verifies FTP Profile for VirtualServer", func() {
			plc.Spec.Profiles.HTMLProfile = "/Common/htmlProfile1"
			plc.Spec.Profiles.FTPProfile = "/Common/ftpProfile1"
			err := mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
			Expect(rsCfg.Virtual.FTPProfile).To(BeEmpty(), "FTP Profile should not be set for Virtual Server")
			Expect(rsCfg.Virtual.HTMLProfile).To(Equal("/Common/htmlProfile1"), "FTP Profile should not be set for Virtual Server")
		})

		It("Verify FTP Profile for TransportServer", func() {
			plc.Spec.Profiles.FTPProfile = "/Common/ftpProfile1"
			err := mockCtlr.handleTSResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle TransportServer for policy")
			Expect(rsCfg.Virtual.FTPProfile).To(Equal("/Common/ftpProfile1"), "FTP Profile should be set for Transport Server")
		})
		Context("Verify Adapt Profiles", func() {
			It("Verify Adapt Profile supported in Policy CR for VirtualServer", func() {
				// Add request adapt profile
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Request = "/Common/example-requestadapt"
				err := mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/example-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Add response adapt profile
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Response = "/Common/example-responseadapt"
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/example-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/example-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Update request adapt profile
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Request = "/Common/new-requestadapt"
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/example-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Remove response adapt profile
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Response = ""
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Remove request adapt profile
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Request = ""
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

			})

			It("Verify Adapt Profile supported in Virutal Server CR for VirtualServer", func() {
				// Add request adapt profile
				vs := test.NewVirtualServer(
					"SamplevS",
					namespace,
					cisapiv1.VirtualServerSpec{},
				)
				vs.Spec.ProfileAdapt.Request = "/Common/example-requestadapt"
				rsCfg = &ResourceConfig{}
				err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/example-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Add response adapt profile
				vs.Spec.ProfileAdapt.Response = "/Common/example-responseadapt"
				rsCfg = &ResourceConfig{}
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/example-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/example-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Update request adapt profile
				vs.Spec.ProfileAdapt.Request = "/Common/new-requestadapt"
				rsCfg = &ResourceConfig{}
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/example-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Remove response adapt profile
				vs.Spec.ProfileAdapt.Response = ""
				rsCfg = &ResourceConfig{}
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Remove request adapt profile
				vs.Spec.ProfileAdapt.Request = ""
				rsCfg = &ResourceConfig{}
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

			})

			It("Verify Adapt Profile precedence in Virutal Server and Policy CR for VirtualServer", func() {
				// Add request adapt profile
				vs := test.NewVirtualServer(
					"SamplevS",
					namespace,
					cisapiv1.VirtualServerSpec{},
				)
				plc.Spec.L7Policies.ProfileAdapt.Request = "/Common/example-requestadapt"
				rsCfg = &ResourceConfig{}
				err := mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/example-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Add request adapt profile in VS spec and verify it takes precedence
				vs.Spec.ProfileAdapt.Request = "/Common/new-requestadapt"
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Add response adapt profile in VS
				vs.Spec.ProfileAdapt.Response = "/Common/example-responseadapt"
				rsCfg = &ResourceConfig{}
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/example-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Add response adapt profile in policy and verify it doesn't take precedence
				plc.Spec.L7Policies.ProfileAdapt.Request = "/Common/new-requestadapt"
				rsCfg = &ResourceConfig{}
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/example-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Update response adapt profile in VS and verify it takes precedence
				vs.Spec.ProfileAdapt.Response = "/Common/new-responseadapt"
				rsCfg = &ResourceConfig{}
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/new-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Remove request adapt profile from policy and verify value is taken from VS CR
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Request = ""
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(Equal("/Common/new-responseadapt"), "Request Adapt Profile should be set for Virtual Server")

				// Remove response adapt profile from VS CR
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Request = ""
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				vs.Spec.ProfileAdapt.Response = ""
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(Equal("/Common/new-requestadapt"), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

				// Remove request adapt profile from VS CR
				rsCfg = &ResourceConfig{}
				plc.Spec.L7Policies.ProfileAdapt.Request = ""
				err = mockCtlr.handleVSResourceConfigForPolicy(rsCfg, plc)
				Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
				vs.Spec.ProfileAdapt.Request = ""
				err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
				Expect(err).To(BeNil(), "Failed to Prepare Resource Config from VirtualServer")
				Expect(rsCfg.Virtual.ProfileAdapt.Request).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")
				Expect(rsCfg.Virtual.ProfileAdapt.Response).To(BeEmpty(), "Request Adapt Profile should be set for Virtual Server")

			})
		})
	})

	Describe("Handle pool resource config for a policy", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController
		var plc *cisapiv1.Policy

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.multiClusterHandler = NewClusterHandler("")
			rsCfg = &ResourceConfig{}
			rsCfg.Pools = Pools{
				{
					ReselectTries:     0,
					ServiceDownAction: "",
				},
				{
					ReselectTries:     0,
					ServiceDownAction: "",
				},
			}
			plc = test.NewPolicy("plc1", namespace, cisapiv1.PolicySpec{})
			plc.Spec.PoolSettings = cisapiv1.PoolSettingsSpec{
				ReselectTries:     10,
				ServiceDownAction: "reset",
				SlowRampTime:      300,
			}
		})
		It("Verifies pool settings are set properly for a policy", func() {
			err := mockCtlr.handlePoolResourceConfigForPolicy(rsCfg, plc)
			Expect(err).To(BeNil(), "Failed to handle pool resource config for policy")
			Expect(rsCfg.Pools[0].ReselectTries).To(Equal(plc.Spec.PoolSettings.ReselectTries), "ReselectTries should be set to 10")
			Expect(rsCfg.Pools[0].ServiceDownAction).To(Equal(plc.Spec.PoolSettings.ServiceDownAction), "ServiceDownAction should be set to reset")
			Expect(rsCfg.Pools[0].SlowRampTime).To(Equal(plc.Spec.PoolSettings.SlowRampTime), "SlowRampTime should be set to 300")
			Expect(rsCfg.Pools[1].ReselectTries).To(Equal(plc.Spec.PoolSettings.ReselectTries), "ReselectTries should be set to 10")
			Expect(rsCfg.Pools[1].ServiceDownAction).To(Equal(plc.Spec.PoolSettings.ServiceDownAction), "ServiceDownAction should be set to reset")
			Expect(rsCfg.Pools[1].SlowRampTime).To(Equal(plc.Spec.PoolSettings.SlowRampTime), "SlowRampTime should be set to 300")
		})
	})

	Describe("Verify helper functions", func() {
		vs := test.NewVirtualServer(
			"SampleVS",
			namespace,
			cisapiv1.VirtualServerSpec{
				Host: "test.com",
				Pools: []cisapiv1.VSPool{
					{
						Path:             "/foo",
						Service:          "svc1",
						ServiceNamespace: "test",
						Monitor: cisapiv1.Monitor{
							Type:     "http",
							Send:     "GET /health",
							Interval: 15,
							Timeout:  10,
						},
						Rewrite:         "/bar",
						MinimumMonitors: intstr.IntOrString{Type: 0, IntVal: 1},
					},
					{
						Path:            "/",
						Service:         "svc2",
						MinimumMonitors: intstr.IntOrString{Type: 1, StrVal: "all"},
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
		It("Verifies getUniqueHosts", func() {
			Expect(getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)).To(ConsistOf([]string{vs.Spec.Host}), "Incorrect unique hosts")
			vs.Spec.Host = ""
			Expect(getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)).To(ConsistOf([]string{""}), "Incorrect unique hosts")
			vs.Spec.HostAliases = []string{"test1.com", "test2.com", "test1.com", "test1.com", "test2.com"}
			Expect(getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)).To(ConsistOf([]string{"", "test1.com", "test2.com"}), "Incorrect unique hosts")
			vs.Spec.Host = "test.com"
			Expect(getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)).To(ConsistOf([]string{"test.com", "test1.com", "test2.com"}), "Incorrect unique hosts")
			vs.Spec.Host = "test1.com"
			Expect(getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)).To(ConsistOf([]string{"test1.com", "test2.com"}), "Incorrect unique hosts")
		})
	})
})
