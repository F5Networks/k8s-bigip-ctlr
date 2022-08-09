package controller

import (
	"fmt"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/teem"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Routes", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.mode = OpenShiftMode
		mockCtlr.routeClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces["default"] = true
		mockCtlr.kubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.nrInformers = make(map[string]*NRInformer)
		mockCtlr.esInformers = make(map[string]*EssentialInformer)
		mockCtlr.resourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.esInformers["default"] = mockCtlr.newNamespacedEssentialResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.esInformers["test"] = mockCtlr.newNamespacedEssentialResourceInformer("test")
		mockCtlr.esInformers["default"] = mockCtlr.newNamespacedEssentialResourceInformer("default")
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
			},
		}
	})

	Describe("Routes", func() {
		var rt *routeapi.Route
		var ns string
		BeforeEach(func() {
			ns = "default"
			rt = test.NewRoute(
				"sampleroute",
				"v1",
				ns,
				routeapi.RouteSpec{
					Host: "foo.com",
					Path: "bar",
					To: routeapi.RouteTargetReference{
						Name: "samplesvc",
					},
				},
				nil,
			)
		})

		It("Basic Route", func() {
			mockCtlr.mockResources[ns] = []interface{}{rt}
			mockCtlr.resources = NewResourceStore()
			var override = false
			mockCtlr.resources.extdSpecMap[ns] = &extendedParsedSpec{
				override: override,
				global: &ExtendedRouteGroupSpec{
					VServerName:    "samplevs",
					VServerAddr:    "10.10.10.10",
					AllowOverride:  "false",
					SNAT:           "auto",
					WAF:            "/Common/WAFPolicy",
					IRules:         []string{"/Common/iRule1"},
					HealthMonitors: Monitors{Monitor{Send: "HTTP GET /", Interval: 2, Timeout: 3}},
				},
			}
			err := mockCtlr.processRoutes(ns, false)
			Expect(err).To(BeNil(), "Failed to process routes")
		})
		It("Passthrough Route", func() {
			mockCtlr.mockResources[ns] = []interface{}{rt}
			mockCtlr.resources = NewResourceStore()
			var override = false
			mockCtlr.resources.extdSpecMap[ns] = &extendedParsedSpec{
				override: override,
				global: &ExtendedRouteGroupSpec{
					VServerName:   "samplevs",
					VServerAddr:   "10.10.10.10",
					AllowOverride: "False",
					SNAT:          "auto",
					WAF:           "/Common/WAFPolicy",
					IRules:        []string{"/Common/iRule1"},
				},
				namespaces: []string{ns},
				partition:  "test",
			}
			tlsConfig := &routeapi.TLSConfig{}
			tlsConfig.Termination = TLSPassthrough
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: tlsConfig,
			}
			route1 := test.NewRoute("route1", "1", ns, spec1, nil)
			mockCtlr.addRoute(route1)
			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
				{Port: 8080, NodePort: 38001},
				{Port: 9090, NodePort: 39001}}
			foo := test.NewService("foo", "1", ns, "NodePort", fooPorts)
			mockCtlr.addService(foo)
			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", ns, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			err := mockCtlr.processRoutes(ns, false)
			mapKey := NameRef{
				Name:      getRSCfgResName("samplevs_443", PassthroughHostsDgName),
				Partition: "test",
			}
			Expect(err).To(BeNil(), "Failed to process routes")
			Expect(len(mockCtlr.resources.ltmConfig["test"].ResourceMap["samplevs_443"].Policies)).To(BeEquivalentTo(0), "Policy should not be created for passthrough route")
			dg, ok := mockCtlr.resources.ltmConfig["test"].ResourceMap["samplevs_443"].IntDgMap[mapKey]
			Expect(ok).To(BeTrue(), "datagroup should be created for passthrough route")
			Expect(dg[ns].Records[0].Name).To(BeEquivalentTo("foo.com"), "Invalid hostname in datagroup")
			Expect(dg[ns].Records[0].Data).To(BeEquivalentTo("foo_80_default"), "Invalid hostname in datagroup")
		})

		It("Route Admit Status", func() {
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
			}
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			mockCtlr.addRoute(route1)
			rskey := fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			mockCtlr.updateRouteAdmitStatus(rskey, "", "", v1.ConditionTrue)
			route := mockCtlr.fetchRoute(rskey)
			Expect(route.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionTrue), "Incorrect route admit status")
			// Update the status for route with duplicate host path
			mockCtlr.updateRouteAdmitStatus(rskey, "HostAlreadyClaimed", "Testing", v1.ConditionFalse)
			route = mockCtlr.fetchRoute(rskey)
			Expect(route.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("HostAlreadyClaimed"), "Incorrect route admit reason")
			Expect(route.Status.Ingress[0].Conditions[0].Message).To(BeEquivalentTo("Testing"), "Incorrect route admit message")
			//fetch invalid route
			Expect(mockCtlr.fetchRoute(fmt.Sprintf("%v-invalid", rskey))).To(BeNil(), "We should not be able to fetch the route")

		})
		It("Check Valid Route", func() {
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
			}
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			route2 := test.NewRoute("route2", "1", "test", spec1, nil)
			route3 := test.NewRoute("route3", "1", "default", spec2, nil)
			mockCtlr.addRoute(route1)
			mockCtlr.addRoute(route2)
			mockCtlr.addRoute(route3)
			rskey1 := fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			rskey2 := fmt.Sprintf("%v/%v", route2.Namespace, route2.Name)
			rskey3 := fmt.Sprintf("%v/%v", route3.Namespace, route3.Name)
			Expect(mockCtlr.checkValidRoute(route1, nil)).To(BeFalse())
			mockCtlr.processedHostPath.processedHostPathMap[route1.Spec.Host+route1.Spec.Path] = route1.ObjectMeta.CreationTimestamp
			Expect(mockCtlr.checkValidRoute(route2, nil)).To(BeFalse())
			Expect(mockCtlr.checkValidRoute(route3, nil)).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			route1 = mockCtlr.fetchRoute(rskey1)
			route2 = mockCtlr.fetchRoute(rskey2)
			route3 = mockCtlr.fetchRoute(rskey3)
			Expect(route1.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route2.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route1.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route2.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route1.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("ExtendedValidationFailed"), "Incorrect route admit reason")
			Expect(route2.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("HostAlreadyClaimed"), "incorrect the route admit reason")
			// checkValidRoute should fail with ServiceNotFound error
			Expect(route3.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route3.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route3.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("ServiceNotFound"), "Incorrect route admit reason")
		})
		It("Check Host-Path Map functions", func() {
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			mockCtlr.addRoute(route1)
			// test hostpathMap update function
			oldURI := route1.Spec.Host + route1.Spec.Path
			route1.Spec.Path = "/test"
			newURI := route1.Spec.Host + route1.Spec.Path
			mockCtlr.updateRoute(route1)
			mockCtlr.updateHostPathMap(route1.ObjectMeta.CreationTimestamp, route1.Spec.Host+route1.Spec.Path)
			_, found := mockCtlr.processedHostPath.processedHostPathMap[oldURI]
			Expect(found).To(BeFalse())
			_, found = mockCtlr.processedHostPath.processedHostPathMap[newURI]
			Expect(found).To(BeTrue())
			Expect(len(mockCtlr.processedHostPath.processedHostPathMap)).To(BeEquivalentTo(1))
			mockCtlr.deleteRoute(route1)
		})
		It("Remove unused health monitors", func() {
			rsCfg := &ResourceConfig{}
			monitor1 := Monitor{Path: "hello.com/health", Interval: 1, Timeout: 2, InUse: true}
			monitor2 := Monitor{Path: "unused.com/", Interval: 2, Timeout: 3, InUse: false}
			monitor3 := Monitor{Path: "demo.com/", Interval: 3, Timeout: 4, InUse: true}
			monitor4 := Monitor{Path: "unused.com/", Interval: 4, Timeout: 6, InUse: false}

			rsCfg.Monitors = []Monitor{monitor1, monitor2, monitor3, monitor4}
			mockCtlr.removeUnusedHealthMonitors(rsCfg)
			Expect(len(rsCfg.Monitors)).To(BeEquivalentTo(2))

		})
		It("Checks whether Forwarding policy is added correctly", func() {
			routeGroup := "default"
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			route1 := test.NewRoute("route1", "1", routeGroup, spec1, nil)
			route2 := test.NewRoute("route2", "1", routeGroup, spec2, nil)

			// Resource Config for unsecured virtual server
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_80"
			rsCfg.MetaData.Protocol = HTTP
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTP_PORT)
			// Portstruct for unsecured virtual server
			ps := portStruct{HTTP, DEFAULT_HTTP_PORT}
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = ""
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, false, ps)).To(BeNil())
			Expect(rsCfg.Policies).To(BeNil())
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = "None"
			route1.Spec.TLS.InsecureEdgeTerminationPolicy = routeapi.InsecureEdgeTerminationPolicyNone
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, false, ps)).To(BeNil())
			Expect(rsCfg.Policies).To(BeNil())
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = "Allow"
			route1.Spec.TLS.InsecureEdgeTerminationPolicy = routeapi.InsecureEdgeTerminationPolicyAllow
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, false, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = ""
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route2, intstr.IntOrString{IntVal: 80}, false, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))
			Expect(rsCfg.Policies[0].Rules[0].FullURI).To(Equal("foo.com/foo"))

			// ResourceConfig for secured virtual server
			rsCfg = &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_443"
			rsCfg.MetaData.Protocol = HTTPS
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTPS_PORT)
			// Portstruct for secured virtual server
			ps.protocol = HTTPS
			ps.port = DEFAULT_HTTPS_PORT
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, false, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))
			Expect(rsCfg.Policies[0].Rules[0].FullURI).To(Equal("foo.com/foo"))
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route2, intstr.IntOrString{IntVal: 80}, false, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(2))
			Expect(rsCfg.Policies[0].Rules[0].FullURI).To(Equal("foo.com/foo"))
			Expect(rsCfg.Policies[0].Rules[1].FullURI).To(Equal("bar.com/bar"))

		})

		It("Check Route TLS", func() {

			tls := TLS{
				ClientSSL: "/Common/clientssl",
				ServerSSL: "/Common/serverssl",
				Reference: "bigip",
			}

			clientTls := TLS{
				ClientSSL: "/Common/clientssl",
				Reference: "bigip",
			}
			serverTls := TLS{
				ServerSSL: "/Common/serverssl",
				Reference: "bigip",
			}

			extdSpec := &ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				TLS:           tls,
				AllowOverride: "0",
			}

			//with no tls defined
			extdSpec1 := &ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				TLS:           serverTls,
				AllowOverride: "0",
			}

			// with only client tls defined
			extdSpec2 := &ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				TLS:           clientTls,
				AllowOverride: "0",
			}

			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge"},
			}

			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: "reencrypt"},
			}

			routeGroup := "default"

			route1 := test.NewRoute("route1", "1", routeGroup, spec1, nil)
			route2 := test.NewRoute("route2", "2", routeGroup, spec2, nil)
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_443"
			rsCfg.MetaData.Protocol = HTTPS
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTPS_PORT)
			ps := portStruct{HTTP, DEFAULT_HTTP_PORT}
			// Portstruct for secured virtual server
			ps.protocol = HTTPS
			ps.port = DEFAULT_HTTPS_PORT
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 443}, false, ps)).To(BeNil())

			//for edge route, and big ip reference in global config map - It should pass
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route1,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443}, extdSpec)).To(BeTrue())

			//for edge route and global config map without client ssl profile - It should fail
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route1,
				extdSpec1.VServerAddr,
				intstr.IntOrString{IntVal: 443}, extdSpec1)).To(BeFalse())

			//for re-encrypt route, and big ip reference in global config map - It should pass
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route2,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443}, extdSpec)).To(BeTrue())

			//for re encrypt route and global config map without server ssl profile - It should fail
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route2,
				extdSpec2.VServerAddr,
				intstr.IntOrString{IntVal: 443}, extdSpec2)).To(BeFalse())
		})

	})

	Describe("Extended Spec ConfigMap", func() {
		var cm *v1.ConfigMap
		var data map[string]string
		BeforeEach(func() {
			cmName := "escm"
			cmNamespace := "system"
			mockCtlr.routeSpecCMKey = cmNamespace + "/" + cmName
			mockCtlr.resources = NewResourceStore()
			data = make(map[string]string)
			cm = test.NewConfigMap(
				cmName,
				"v1",
				cmNamespace,
				data)
		})

		It("Extended Route Spec Global", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
    - namespace: new
      vserverAddr: 10.8.3.12
      allowOverride: true
`
			err, ok := mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: invalid
    - namespace: new
      vserverAddr: 10.8.3.12
      allowOverride: true
`
			err, ok = mockCtlr.processConfigMap(cm, false)
			Expect(err).ToNot(BeNil(), "invalid allowOverride value")
			Expect(ok).To(BeFalse())

			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
    - namespace: new
      vserverAddr: 10.8.3.12
      allowOverride: true
      vserverName: newroutes
`
			err, ok = mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended Route Spec Allow local", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
    - namespace: new
      vserverAddr: 10.8.3.12
      allowOverride: true
`
			err, ok := mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			localData := make(map[string]string)
			localCm := test.NewConfigMap(
				"localESCM",
				"v1",
				"default",
				localData)
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.110
      vserverName: nextgenroutes
`
			err, ok = mockCtlr.processConfigMap(localCm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended Route Spec Do not Allow local", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: false
    - namespace: new
      vserverAddr: 10.8.3.12
      allowOverride: false
`
			err, ok := mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			localData := make(map[string]string)
			localCm := test.NewConfigMap(
				"localESCM",
				"v1",
				"default",
				localData)
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.110
      vserverName: nextgenroutes
`
			err, ok = mockCtlr.processConfigMap(localCm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended Route Spec Allow local Update with out spec change", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
    - namespace: new
      vserverAddr: 10.8.3.12
      allowOverride: true
`

			err, ok := mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			localData := make(map[string]string)
			localCm := test.NewConfigMap(
				"localESCM",
				"v1",
				"default",
				localData)
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.110
      vserverName: nextgenroutes
`
			err, ok = mockCtlr.processConfigMap(localCm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverName: nextgenroutes
      vserverAddr: 10.8.3.110
`
			err, ok = mockCtlr.processConfigMap(localCm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended local Route Spec pickup alternate configmap when latest gets deleted", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      allowOverride: true
`
			namespace := "default"
			err, ok := mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			localData := make(map[string]string)
			localCm1 := test.NewConfigMap(
				"localESCM1",
				"v1",
				namespace,
				localData)
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.110
      vserverName: nextgenroutes
`
			localCm2 := test.NewConfigMap(
				"localESCM2",
				"v1",
				namespace,
				localData)
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.110
      vserverName: newvs
`
			localCm3 := test.NewConfigMap(
				"localESCM3",
				"v1",
				namespace,
				localData)
			localData["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.110
      vserverName: latestserver
`

			_ = mockCtlr.nrInformers[namespace].cmInformer.GetIndexer().Add(localCm1)
			_ = mockCtlr.nrInformers[namespace].cmInformer.GetIndexer().Add(localCm2)
			_ = mockCtlr.nrInformers[namespace].cmInformer.GetIndexer().Add(localCm3)
			err, ok = mockCtlr.processConfigMap(localCm3, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			_ = mockCtlr.nrInformers[namespace].cmInformer.GetIndexer().Delete(localCm3)
			err, ok = mockCtlr.processConfigMap(localCm3, true)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			Expect(mockCtlr.resources.extdSpecMap[namespace].local.VServerName).To(Equal("latestserver"), "Spec from wrong configmap")
		})

		It("Operational Specs on configmap Create/Update/Delete events", func() {
			cachedExtdSpecMap := make(map[string]*extendedParsedSpec)
			newExtdSpecMap := make(map[string]*extendedParsedSpec)

			newExtdSpecMap["default"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &ExtendedRouteGroupSpec{
					VServerName:   "defaultServer",
					VServerAddr:   "10.8.3.11",
					WAF:           "/Common/defaultWAF",
					AllowOverride: "0",
				},
			}
			newExtdSpecMap["new"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &ExtendedRouteGroupSpec{
					VServerName:   "newServer",
					VServerAddr:   "10.8.3.12",
					WAF:           "/Common/newWAF",
					AllowOverride: "f",
				},
			}
			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs := getOperationalExtendedConfigMapSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(BeZero())
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(Equal(2))

			cachedExtdSpecMap["default"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &ExtendedRouteGroupSpec{
					VServerName:   "defaultServer",
					VServerAddr:   "10.8.3.11",
					WAF:           "/Common/defaultWAF",
					AllowOverride: "false",
				},
			}
			cachedExtdSpecMap["new"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &ExtendedRouteGroupSpec{
					VServerName:   "newServer",
					VServerAddr:   "10.8.3.12",
					WAF:           "/Common/newWAF",
					AllowOverride: "FALSE",
				},
			}

			newExtdSpecMap["default"].global.WAF = "/Common/defaultWAF1"
			newExtdSpecMap["new"].global.WAF = "/Common/newWAF1"

			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigMapSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(BeZero())
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(Equal(2))
			Expect(len(createdSpecs)).To(BeZero())

			newExtdSpecMap["default"].global.VServerName = "defaultServer1"
			newExtdSpecMap["new"].global.VServerName = "newServer1"

			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigMapSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(BeZero())
			Expect(len(modifiedSpecs)).To(Equal(2))
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(BeZero())

			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigMapSpecs(
				cachedExtdSpecMap, newExtdSpecMap, true,
			)
			Expect(len(deletedSpecs)).To(Equal(2))
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(BeZero())

			delete(newExtdSpecMap, "new")
			newExtdSpecMap["default"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &ExtendedRouteGroupSpec{
					VServerName:   "defaultServer",
					VServerAddr:   "10.8.3.11",
					WAF:           "/Common/defaultWAF",
					AllowOverride: "false",
				},
			}
			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigMapSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(Equal(1))
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(BeZero())
		})
	})
})

var _ = Describe("With NamespaceLabel parameter in deployment", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.mode = OpenShiftMode
		mockCtlr.routeClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces["default"] = true
		mockCtlr.kubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.nrInformers = make(map[string]*NRInformer)
		mockCtlr.esInformers = make(map[string]*EssentialInformer)
		mockCtlr.nsInformers = make(map[string]*NSInformer)
		mockCtlr.resourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.esInformers["default"] = mockCtlr.newNamespacedEssentialResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.esInformers["test"] = mockCtlr.newNamespacedEssentialResourceInformer("test")
		mockCtlr.esInformers["default"] = mockCtlr.newNamespacedEssentialResourceInformer("default")
		mockCtlr.namespaceLabel = "environment=dev"
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
			},
		}
	})
	Describe("Extended Spec ConfigMap", func() {
		var cm *v1.ConfigMap
		var data map[string]string
		BeforeEach(func() {
			cmName := "escm"
			cmNamespace := "system"
			mockCtlr.routeSpecCMKey = cmNamespace + "/" + cmName
			mockCtlr.resources = NewResourceStore()
			data = make(map[string]string)
			cm = test.NewConfigMap(
				cmName,
				"v1",
				cmNamespace,
				data)
		})

		It("namespace and namespaceLabel combination", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespace: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
      bigIpPartition: foo
    - namespaceLabel: bar=true
      vserverAddr: 10.8.3.12
      allowOverride: true
`
			err := mockCtlr.setNamespaceLabelMode(cm)
			Expect(err).To(MatchError(fmt.Sprintf("can not specify both namespace and namespace-label in extended configmap %v/%v", cm.Namespace, cm.Name)))
		})
		It("with namespaceLabel only", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespaceLabel: foo=true
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
      bigIpPartition: foo
    - namespaceLabel: bar=true
      vserverAddr: 10.8.3.12
      allowOverride: true
`
			mockCtlr.namespaceLabelMode = true
			err, ok := mockCtlr.processConfigMap(cm, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})
	})
})

var _ = Describe("Without NamespaceLabel parameter in deployment", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.mode = OpenShiftMode
	})
	Describe("Extended Spec ConfigMap", func() {
		var cm *v1.ConfigMap
		var data map[string]string
		BeforeEach(func() {
			cmName := "escm"
			cmNamespace := "system"
			mockCtlr.routeSpecCMKey = cmNamespace + "/" + cmName
			mockCtlr.resources = NewResourceStore()
			data = make(map[string]string)
			cm = test.NewConfigMap(
				cmName,
				"v1",
				cmNamespace,
				data)
		})
		It("namespaceLabel only without namespace-label deployment parameter", func() {
			data["extendedSpec"] = `
extendedRouteSpec:
    - namespaceLabel: default
      vserverAddr: 10.8.3.11
      vserverName: nextgenroutes
      allowOverride: true
      bigIpPartition: foo
    - namespaceLabel: bar=true
      vserverAddr: 10.8.3.12
      allowOverride: true
`
			err := mockCtlr.setNamespaceLabelMode(cm)
			Expect(err).To(MatchError("--namespace-label deployment parameter is required with namespace-label in extended configmap"))
		})
	})
})
