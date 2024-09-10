package controller

import (
	"sort"

	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	"k8s.io/apimachinery/pkg/util/intstr"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Resource Config Tests", func() {
	namespace := "default"
	bigipLabel := BigIPLabel
	var bigipConfig cisapiv1.BigIpConfig
	Describe("Virtual Ports", func() {
		var mockCtlr *mockController
		var vs *cisapiv1.VirtualServer

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.resources = NewResourceStore()
			mockCtlr.managedResources.ManageCustomResources = true
			vs = test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
				},
			)
			bigipConfig = cisapiv1.BigIpConfig{BigIpLabel: "bigip1", BigIpAddress: "10.8.3.11", DefaultPartition: "test"}
			mockCtlr.bigIpConfigMap[bigipConfig] = BigIpResourceConfig{ltmConfig: make(LTMConfig), gtmConfig: make(GTMConfig)}
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
			mockCtlr.managedResources.ManageCustomResources = true
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
		It("Pool Name", func() {
			name := mockCtlr.formatPoolName(namespace, "svc1", intstr.IntOrString{IntVal: 80}, "app=test", "foo", "")
			Expect(name).To(Equal("svc1_80_default_foo_app_test"), "Invalid Pool Name")
		})
		It("Monitor Name", func() {
			name := formatMonitorName(namespace, "svc1", "http", intstr.IntOrString{IntVal: 80}, "foo.com", "path")
			Expect(name).To(Equal("svc1_default_foo_com_path_http_80"), "Invalid Monitor Name")
		})
		It("Rule Name", func() {
			name := formatVirtualServerRuleName("test.com", "", "", "sample_pool")
			Expect(name).To(Equal("vs_test_com_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "exams.com", "", "sample_pool")
			Expect(name).To(Equal("vs_exams_com_sample_pool"))
			name = formatVirtualServerRuleName("test.com", "", "/foo", "sample_pool")
			Expect(name).To(Equal("vs_test_com_foo_sample_pool"))

		})
		It("Monitor Name with MultiCluster mode", func() {
			// Standalone, no ratio and monitor for local cluster pool
			mockCtlr.multiClusterMode = StandAloneCIS
			mockCtlr.clusterRatio = make(map[string]*int)
			mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
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
			mockCtlr.multiClusterConfigs.LocalClusterName = "cluster1"
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName), "Invalid Monitor Name")
			// Primary, no ratio and monitor for external cluster pool
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster2")).To(Equal(monitorName), "Invalid Monitor Name")
			// Primary, ratio and monitor for local cluster pool
			mockCtlr.clusterRatio["cluster2"] = new(int) // secondary cluster ratio
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName+"_"+mockCtlr.multiClusterConfigs.LocalClusterName), "Invalid Monitor Name")
			// Primary, ratio and monitor for external cluster pool
			mockCtlr.clusterRatio["cluster3"] = new(int) // external cluster ratio
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster3")).To(Equal(monitorName+"_cluster3"), "Invalid Monitor Name")

			// Secondary, no ratio and monitor for local cluster pool
			mockCtlr.multiClusterMode = SecondaryCIS
			mockCtlr.multiClusterConfigs.LocalClusterName = "cluster1"
			mockCtlr.clusterRatio = make(map[string]*int)
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName), "Invalid Monitor Name")
			// Secondary, no ratio and monitor for external cluster pool
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "cluster2")).To(Equal(monitorName), "Invalid Monitor Name")
			// Secondary, ratio and monitor for local cluster pool
			mockCtlr.clusterRatio["cluster2"] = new(int) // secondary cluster ratio
			Expect(mockCtlr.formatMonitorNameForMultiCluster(monitorName, "")).To(Equal(monitorName+"_"+mockCtlr.multiClusterConfigs.LocalClusterName), "Invalid Monitor Name")
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

		It("Handle DataGroupIRules", func() {
			mockCtlr := newMockController()
			rsCfg.Virtual.MultiPoolPersistence = MultiPoolPersistence{
				Method:  "hashSourceAddress",
				TimeOut: 30,
			}
			mockCtlr.handleDataGroupIRules(rsCfg, "test.com", TLSEdge)
			Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to Add iRules")
			Expect(len(rsCfg.IntDgMap)).To(Equal(2), "Failed to Add DataGroup")
			rsCfg.Virtual.MultiPoolPersistence.Method = "uieSourceAddress"
			mockCtlr.handleDataGroupIRules(rsCfg, "test.com", TLSReencrypt)
			Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to Add iRules")
			Expect(len(rsCfg.IntDgMap)).To(Equal(4), "Failed to Add DataGroup")
			rsCfg.Virtual.MultiPoolPersistence.Method = ""
			mockCtlr.handleDataGroupIRules(rsCfg, "test.com", TLSPassthrough)
			Expect(len(rsCfg.IRulesMap)).To(Equal(1), "Failed to Add iRules")
			Expect(len(rsCfg.IntDgMap)).To(Equal(5), "Failed to Add DataGroup")

		})
	})

	Describe("Prepare Resource Configs", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController

		//partition := "test"
		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
			mockCtlr.managedResources.ManageCustomResources = true
			mockCtlr.clientsets.KubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()
			_ = mockCtlr.addNamespacedInformers(namespace, false)

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
			mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
			mockCtlr.managedResources.ManageCustomResources = true
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			mockCtlr.nsInformers = make(map[string]*NSInformer)
			mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default")
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
			rsMap := rs.getPartitionResourceMap("default", bigipConfig)
			Expect(len(rsMap)).To(Equal(0))
			rsMap["default"] = &ResourceConfig{}
			rsMap = rs.getPartitionResourceMap("default", bigipConfig)
			Expect(len(rsMap)).To(Equal(1))
		})

		It("Get Resource", func() {

			rsCfg, err := rs.getResourceConfig("default", "sampleVS", bigipLabel)
			Expect(err).ToNot(BeNil())
			_ = rs.getPartitionResourceMap("default", bigipConfig)

			rsCfg, err = rs.getResourceConfig("default", "sampleVS", bigipLabel)
			Expect(err).ToNot(BeNil())
			Expect(rsCfg).To(BeNil())

			zero := 0
			rs.bigIpMap[bigipConfig].ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}

			rs.bigIpMap[bigipConfig].ltmConfig["default"].ResourceMap["virtualServer"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer",
				},
			}

			rsCfg, err = rs.getResourceConfig("default", "virtualServer", bigipLabel)
			Expect(err).To(BeNil())
			Expect(rsCfg).NotTo(BeNil())
			Expect(rsCfg.Virtual.Name).To(Equal("VirtualServer"))
		})

		It("Get all Resources", func() {
			zero := 0
			rs.bigIpMap[bigipConfig] = BigIpResourceConfig{
				ltmConfig: make(LTMConfig),
			}
			rs.bigIpMap[bigipConfig].ltmConfig["default"] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			rs.bigIpMap[bigipConfig].ltmConfig["default"].ResourceMap["virtualServer1"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer1",
				},
			}
			rs.bigIpMap[bigipConfig].ltmConfig["default"].ResourceMap["virtualServer2"] = &ResourceConfig{
				Virtual: Virtual{
					Name: "VirtualServer2",
				},
			}

			ltmCfg := rs.getLTMConfigDeepCopy(bigipConfig)
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
			mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
			mockCtlr.resources = NewResourceStore()
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()
			mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher = cisapiv1.TLSCipher{
				TLSVersion: "1.2"}

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
			tlsProf.Spec.Hosts = []string{"test.com"}
			ok := mockCtlr.handleVirtualServerTLS(inSecRsCfg, vs, tlsProf, ip)
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

		It("Validate API failures", func() {
			vs.Spec.TLSProfileName = "SampleTLS"
			tlsProf.Spec.TLS.Termination = TLSReencrypt
			tlsProf.Spec.TLS.Reference = Secret
			tlsProf.Spec.TLS.ClientSSL = "clientsecret"
			tlsProf.Spec.TLS.ServerSSL = "serversecret"

			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

			mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()

			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")

			clSecret := test.NewSecret(
				"clientsecret",
				namespace,
				"### cert ###",
				"#### key ####",
			)
			mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset(clSecret)
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
			Expect(ok).To(BeFalse(), "Failed to Process TLS Termination: Reencrypt")
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
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs, tlsProf, ip)
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
			ok := mockCtlr.handleVirtualServerTLS(rsCfg, vs1, tlsProf1, ip)
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
			ok = mockCtlr.handleVirtualServerTLS(rsCfg, vs1, tlsProf1, ip)
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
			mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
			mockCtlr.resources = NewResourceStore()
			mockCtlr.managedResources.ManageCustomResources = true
			mockCtlr.multiClusterResources = newMultiClusterResourceStore()

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

	Describe("Handle pool resource config for a policy", func() {
		var rsCfg *ResourceConfig
		var mockCtlr *mockController
		var plc *cisapiv1.Policy

		BeforeEach(func() {
			mockCtlr = newMockController()
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
})

var _ = Describe("split_ip_with_route_domain", func() {
	var (
		address string
		ip      string
		rd      string
	)

	JustBeforeEach(func() {
		ip, rd = split_ip_with_route_domain(address)
	})

	Context("when the address contains a valid route domain", func() {
		BeforeEach(func() {
			address = "192.168.1.1%10"
		})

		It("should split the IP and the route domain correctly", func() {
			Expect(ip).To(Equal("192.168.1.1"))
			Expect(rd).To(Equal("10"))
		})
	})

	Context("when the address contains an invalid route domain", func() {
		BeforeEach(func() {
			address = "192.168.1.1%10f"
		})

		It("should return the entire address as the IP", func() {
			Expect(ip).To(Equal("192.168.1.1%10f"))
			Expect(rd).To(BeEmpty())
		})
	})

	Context("when the address does not contain a route domain", func() {
		BeforeEach(func() {
			address = "192.168.1.1"
		})

		It("should return the IP without a route domain", func() {
			Expect(ip).To(Equal("192.168.1.1"))
			Expect(rd).To(BeEmpty())
		})
	})

	Context("when the address is an IPv6 address with a valid route domain", func() {
		BeforeEach(func() {
			address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334%42"
		})

		It("should split the IP and the route domain correctly", func() {
			Expect(ip).To(Equal("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
			Expect(rd).To(Equal("42"))
		})
	})

	Context("when the address is an IPv6 address without a route domain", func() {
		BeforeEach(func() {
			address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
		})

		It("should return the IP without a route domain", func() {
			Expect(ip).To(Equal("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
			Expect(rd).To(BeEmpty())
		})
	})
})

var _ = Describe("ParseWhitelistSourceRangeAnnotations", func() {
	var (
		annotation string
		result     []string
	)

	JustBeforeEach(func() {
		result = ParseWhitelistSourceRangeAnnotations(annotation)
	})

	Context("when the annotation contains a single valid CIDR", func() {
		BeforeEach(func() {
			annotation = "192.168.1.0/24"
		})

		It("should return the CIDR in the result", func() {
			Expect(result).To(ContainElement("192.168.1.0/24"))
		})
	})

	Context("when the annotation contains multiple valid CIDRs", func() {
		BeforeEach(func() {
			annotation = "192.168.1.0/24, 10.0.0.0/8"
		})

		It("should return all CIDRs in the result", func() {
			Expect(result).To(ContainElements("192.168.1.0/24", "10.0.0.0/8"))
		})
	})

	Context("when the annotation contains an invalid CIDR", func() {
		BeforeEach(func() {
			annotation = "192.168.1.0/24, invalidCIDR"
		})

		It("should return the valid CIDR and skip the invalid one", func() {
			Expect(result).To(ContainElement("192.168.1.0/24"))
			Expect(result).To(ContainElement("invalidCIDR"))
		})
	})

	Context("when the annotation contains no commas", func() {
		BeforeEach(func() {
			annotation = "192.168.1.0/24"
		})

		It("should return the single value", func() {
			Expect(result).To(ContainElement("192.168.1.0/24"))
		})
	})

	Context("when the annotation contains extra spaces", func() {
		BeforeEach(func() {
			annotation = "192.168.1.0/24,  10.0.0.0/8"
		})

		It("should trim the spaces and return the CIDRs", func() {
			Expect(result).To(ContainElements("192.168.1.0/24", "10.0.0.0/8"))
		})
	})

	Context("when the annotation is empty", func() {
		BeforeEach(func() {
			annotation = ""
		})

		It("should return an empty result", func() {
			Expect(result).To(BeEmpty())
		})
	})
})

var _ = Describe("getExtendedRouteSpec", func() {
	var (
		rs *ResourceStore
	)

	BeforeEach(func() {
		rs = &ResourceStore{}
		rs.extdSpecMap = make(map[string]*extendedParsedSpec)
	})

	Describe("getExtendedRouteSpec", func() {
		Context("when routeGroup does not exist in extdSpecMap", func() {
			It("should return nil and empty partition", func() {
				extdSpec, partition := rs.getExtendedRouteSpec("nonexistent")
				Expect(extdSpec).To(BeNil())
				Expect(partition).To(BeEmpty())
			})
		})

		Context("when defaultrg is set in extdSpec", func() {
			It("should return defaultrg and partition", func() {
				rs.extdSpecMap["group1"] = &extendedParsedSpec{
					defaultrg: &cisapiv1.ExtendedRouteGroupSpec{
						VServerName: "default-server",
					},
					partition: "default-partition",
				}
				extdSpec, partition := rs.getExtendedRouteSpec("group1")
				Expect(extdSpec.VServerName).To(Equal("default-server"))
				Expect(partition).To(Equal("default-partition"))
			})
		})

		Context("when override is true and local is set in extdSpec", func() {
			It("should return overridden local spec and partition", func() {
				rs.extdSpecMap["group2"] = &extendedParsedSpec{
					global: &cisapiv1.ExtendedRouteGroupSpec{
						VServerName:   "global-server",
						VServerAddr:   "1.2.3.4",
						AllowOverride: "true",
					},
					local: &cisapiv1.ExtendedRouteGroupSpec{
						VServerName: "local-server",
					},
					override:  true,
					partition: "override-partition",
				}
				extdSpec, partition := rs.getExtendedRouteSpec("group2")
				Expect(extdSpec.VServerName).To(Equal("local-server"))
				Expect(extdSpec.VServerAddr).To(Equal("1.2.3.4"))
				Expect(partition).To(Equal("override-partition"))
			})
		})

		Context("when override is false or local is not set", func() {
			It("should return global spec and partition", func() {
				rs.extdSpecMap["group3"] = &extendedParsedSpec{
					global: &cisapiv1.ExtendedRouteGroupSpec{
						VServerName: "global-server",
					},
					override:  false,
					partition: "global-partition",
				}
				extdSpec, partition := rs.getExtendedRouteSpec("group3")
				Expect(extdSpec.VServerName).To(Equal("global-server"))
				Expect(partition).To(Equal("global-partition"))
			})
		})
	})
})

var _ = Describe("updatePoolMembersConfig", func() {
	var (
		mockCtlr       *mockController
		poolMembers    []PoolMember
		clusterName    string
		podConnections int32
	)

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.clusterAdminState = make(map[string]cisapiv1.AdminState)
		poolMembers = []PoolMember{
			{AdminState: "oldState1", ConnectionLimit: 10},
			{AdminState: "oldState2", ConnectionLimit: 20},
		}
	})

	Describe("updatePoolMembersConfig", func() {
		Context("when admin state is set in clusterAdminState", func() {
			BeforeEach(func() {
				clusterName = "cluster1"
				mockCtlr.clusterAdminState[clusterName] = "newState"
				podConnections = 50
				mockCtlr.updatePoolMembersConfig(&poolMembers, clusterName, podConnections)
			})

			It("should update the admin state of pool members", func() {
				Expect(poolMembers[0].AdminState).To(Equal("newState"))
				Expect(poolMembers[1].AdminState).To(Equal("newState"))
			})

			It("should update the connection limit of pool members", func() {
				Expect(poolMembers[0].ConnectionLimit).To(Equal(podConnections))
				Expect(poolMembers[1].ConnectionLimit).To(Equal(podConnections))
			})
		})

		Context("when admin state is not set in clusterAdminState", func() {
			BeforeEach(func() {
				clusterName = "cluster2"
				podConnections = 30
				mockCtlr.updatePoolMembersConfig(&poolMembers, clusterName, podConnections)
			})

			It("should not update the admin state of pool members", func() {
				Expect(poolMembers[0].AdminState).To(Equal("oldState1"))
				Expect(poolMembers[1].AdminState).To(Equal("oldState2"))
			})

			It("should update the connection limit of pool members", func() {
				Expect(poolMembers[0].ConnectionLimit).To(Equal(podConnections))
				Expect(poolMembers[1].ConnectionLimit).To(Equal(podConnections))
			})
		})

		Context("when podConnections is zero", func() {
			BeforeEach(func() {
				clusterName = "cluster1"
				mockCtlr.clusterAdminState[clusterName] = "newState"
				podConnections = 0
				mockCtlr.updatePoolMembersConfig(&poolMembers, clusterName, podConnections)
			})

			It("should update the admin state of pool members", func() {
				Expect(poolMembers[0].AdminState).To(Equal("newState"))
				Expect(poolMembers[1].AdminState).To(Equal("newState"))
			})

			It("should not update the connection limit of pool members", func() {
				Expect(poolMembers[0].ConnectionLimit).To(Equal(int32(10)))
				Expect(poolMembers[1].ConnectionLimit).To(Equal(int32(20)))
			})
		})
	})
})
