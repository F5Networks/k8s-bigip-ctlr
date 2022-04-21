package controller

import (
	"fmt"
	"time"

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
		mockCtlr.resourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]string)
		mockCtlr.processedHostPath = &processedHostPath
	})

	Describe("Routes", func() {
		var rt *routeapi.Route
		var ns string
		BeforeEach(func() {
			ns = "samplens"
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
					AllowOverride:  false,
					SNAT:           "auto",
					WAF:            "/Common/WAFPolicy",
					IRules:         []string{"/Common/iRule1"},
					HealthMonitors: Monitors{Monitor{Send: "HTTP GET /", Interval: 2, Timeout: 3}},
				},
			}
			err := mockCtlr.processRoutes(ns, false)
			Expect(err).To(BeNil(), "Failed to process routes")
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
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			route2 := test.NewRoute("route2", "1", "test", spec1, nil)
			mockCtlr.addRoute(route1)
			mockCtlr.addRoute(route2)
			rskey1 := fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			rskey2 := fmt.Sprintf("%v/%v", route2.Namespace, route2.Name)
			Expect(mockCtlr.checkValidRoute(route1)).To(BeFalse())
			mockCtlr.processedHostPath.processedHostPathMap[route1.Spec.Host+route1.Spec.Path] = fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			Expect(mockCtlr.checkValidRoute(route2)).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			route1 = mockCtlr.fetchRoute(rskey1)
			route2 = mockCtlr.fetchRoute(rskey2)
			Expect(route1.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route2.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route1.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route2.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route1.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("ExtendedValidationFailed"), "Incorrect route admit reason")
			Expect(route2.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("HostAlreadyClaimed"), "incorrect the route admit reason")
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
			mockCtlr.updateHostPathMap(route1)
			_, found := mockCtlr.processedHostPath.processedHostPathMap[oldURI]
			Expect(found).To(BeFalse())
			_, found = mockCtlr.processedHostPath.processedHostPathMap[newURI]
			Expect(found).To(BeTrue())
			Expect(len(mockCtlr.processedHostPath.processedHostPathMap)).To(BeEquivalentTo(1))
			mockCtlr.deleteRoute(route1)
			mockCtlr.removeDeletedRouteFromHostPathMap()
			Expect(len(mockCtlr.processedHostPath.processedHostPathMap)).To(BeEquivalentTo(0))
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

	})
})
