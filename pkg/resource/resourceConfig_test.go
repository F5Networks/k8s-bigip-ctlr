/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package resource

import (
	"fmt"
	"k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"os"
	"sort"

	"encoding/json"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	routeapi "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type simpleTestConfig struct {
	name    string
	addr    VirtualAddress
	nameRef NameRef
}

type resourceMap map[ServiceKey][]simpleTestConfig

func newServiceKey(svcPort int32, svcName, namespace string) ServiceKey {
	return ServiceKey{
		ServiceName: svcName,
		ServicePort: svcPort,
		Namespace:   namespace,
	}
}

func newResourceConfig(
	key ServiceKey, rsName string,
	bindAddr string, bindPort int32) *ResourceConfig {
	var cfg ResourceConfig
	cfg.Pools = append(cfg.Pools, Pool{})
	cfg.Pools[0].ServiceName = key.ServiceName
	cfg.Pools[0].ServicePort = key.ServicePort
	cfg.Virtual.Name = rsName
	cfg.Virtual.SetVirtualAddress(bindAddr, bindPort, false)
	return &cfg
}

func newTestMap(nbrBackends, nbrConfigsPer int) *resourceMap {
	// Add nbrBackends backends each with nbrConfigsPer configs
	rm := make(resourceMap)
	namespace := "velcro"
	svcName := "svc"
	svcPort := 80
	bindPort := 8000
	for i := 0; i < nbrBackends; i++ {
		svcKey := newServiceKey(int32(svcPort+i), svcName, namespace)
		for j := 0; j < nbrConfigsPer; j++ {
			cfgName := fmt.Sprintf("rs-%d-%d", i, j)
			addr := VirtualAddress{"10.0.0.1", int32(bindPort + j)}
			rm[svcKey] = append(rm[svcKey], simpleTestConfig{cfgName, addr, NameRef{Name: cfgName, Partition: "velcro"}})
		}
	}
	return &rm
}

func assignTestMap(rs *Resources, rm *resourceMap) {
	for key, val := range *rm {
		for _, tf := range val {
			rs.Assign(key, tf.nameRef, newResourceConfig(
				key, tf.name, tf.addr.BindAddr, tf.addr.Port))
		}
	}
}

var _ = Describe("Resource Config Tests", func() {
	Describe("RS Config utils", func() {
		var rs *Resources
		var rm *resourceMap
		var nbrBackends, nbrCfgsPer int
		BeforeEach(func() {
			rs = NewResources()
			Expect(rs).ToNot(BeNil())

			nbrBackends = 2
			nbrCfgsPer = 2
			rm = newTestMap(nbrBackends, nbrCfgsPer)
			Expect(rm).ToNot(BeNil())
			assignTestMap(rs, rm)
		})

		It("sorts virtuals", func() {
			virtuals := Virtuals{}
			expectedList := make(Virtuals, 5)

			v := Virtual{}
			v.Partition = "a"
			v.Name = "foo"
			virtuals = append(virtuals, v)
			expectedList[1] = v

			v = Virtual{}
			v.Partition = "a"
			v.Name = "bar"
			virtuals = append(virtuals, v)
			expectedList[0] = v

			v = Virtual{}
			v.Partition = "c"
			v.Name = "bar"
			virtuals = append(virtuals, v)
			expectedList[3] = v

			v = Virtual{}
			v.Partition = "c"
			v.Name = "foo"
			virtuals = append(virtuals, v)
			expectedList[4] = v

			v = Virtual{}
			v.Partition = "b"
			v.Name = "bar"
			virtuals = append(virtuals, v)
			expectedList[2] = v

			var cfg BigIPConfig
			cfg.Virtuals = virtuals
			cfg.SortVirtuals()

			for i, _ := range expectedList {
				Expect(cfg.Virtuals[i]).To(Equal(expectedList[i]),
					"Sorted list elements should be equal.")
			}
		})

		It("sorts pools", func() {
			pools := Pools{}
			expectedList := make(Pools, 5)

			p := Pool{}
			p.Partition = "b"
			p.Name = "foo"
			pools = append(pools, p)
			expectedList[3] = p

			p = Pool{}
			p.Partition = "a"
			p.Name = "foo"
			pools = append(pools, p)
			expectedList[1] = p

			p = Pool{}
			p.Partition = "b"
			p.Name = "bar"
			pools = append(pools, p)
			expectedList[2] = p

			p = Pool{}
			p.Partition = "a"
			p.Name = "bar"
			pools = append(pools, p)
			expectedList[0] = p

			p = Pool{}
			p.Partition = "c"
			p.Name = "foo"
			pools = append(pools, p)
			expectedList[4] = p

			var cfg BigIPConfig
			cfg.Pools = pools
			cfg.SortPools()

			for i, _ := range expectedList {
				Expect(cfg.Pools[i]).To(Equal(expectedList[i]),
					"Sorted list elements should be equal.")
			}
		})

		It("sorts monitors", func() {
			monitors := Monitors{}
			expectedList := make(Monitors, 5)

			m := Monitor{}
			m.Partition = "a"
			m.Name = "bar"
			monitors = append(monitors, m)
			expectedList[0] = m

			m = Monitor{}
			m.Partition = "b"
			m.Name = "foo"
			monitors = append(monitors, m)
			expectedList[3] = m

			m = Monitor{}
			m.Partition = "b"
			m.Name = "bar"
			monitors = append(monitors, m)
			expectedList[2] = m

			m = Monitor{}
			m.Partition = "a"
			m.Name = "foo"
			monitors = append(monitors, m)
			expectedList[1] = m

			m = Monitor{}
			m.Partition = "c"
			m.Name = "foo"
			monitors = append(monitors, m)
			expectedList[4] = m

			var cfg BigIPConfig
			cfg.Monitors = monitors
			cfg.SortMonitors()

			for i, _ := range expectedList {
				Expect(cfg.Monitors[i]).To(Equal(expectedList[i]),
					"Sorted list elements should be equal.")

			}
		})

		It("Sets and Removes monitors", func() {
			var rc ResourceConfig

			m := Monitor{}
			m.Partition = "foo"
			m.Name = "mon"

			p := Pool{}
			p.Partition = "b"
			p.Name = "foo"

			m.Name = FormatMonitorName(p.Name, "http")

			rc.Pools = []Pool{p}
			//Set Monitor sets the monitor in the pool
			Expect(rc.SetMonitor(&p, m)).To(Equal(true))
			Expect(rc.SetMonitor(&p, m)).To(Equal(false))
			Expect(rc.Monitors).To(Equal(Monitors{m}))
			rc.Pools[0].MonitorNames = []string{"/foo/foo_0_http"}
			rc.SortMonitors()
			Expect(rc.Pools).To(Equal(Pools{p}))
			Expect(rc.Monitors).To(Equal(Monitors{m}))
			Expect(rc.RemoveMonitor(p.Name)).To(Equal(true))
			Expect(rc.RemoveMonitor(p.Name)).To(Equal(false))
			p.MonitorNames = []string{}
			Expect(rc.Pools).To(Equal(Pools{p}))
			Expect(len(rc.Monitors)).To(Equal(0))
		})

		It("creates new resources", func() {
			// Test that we can create a new/empty resources object.
			rs = NewResources()
			Expect(rs).ToNot(BeNil())
			Expect(rs.rm).ToNot(BeNil())
		})

		It("assigns configs to backends", func() {
			// Test Assign() to make sure we can add multiple configs for a backend.
			// Make sure rs has the correct number of objects without using other
			// interface functions.
			Expect(len(rs.rm)).To(Equal(nbrBackends))
			for _, rsCfgs := range rs.rm {
				Expect(len(rsCfgs)).To(Equal(nbrCfgsPer))
			}
		})

		It("can count all pool resources", func() {
			// Test PoolCount() to make sure we count all items
			// Only one pool gets created for all configs
			Expect(rs.PoolCount()).To(Equal(1))
		})

		It("can count all virtual resources", func() {
			// Test VirtualCount() to make sure we count all items
			Expect(rs.VirtualCount()).To(Equal(nbrBackends * nbrCfgsPer))
		})

		It("can count configs per backend", func() {
			// Test CountOf() to make sure we count configs per backend correctly.
			Expect(len(rs.rm)).To(Equal(nbrBackends))
			for key, _ := range *rm {
				Expect(rs.CountOf(key)).To(Equal(nbrCfgsPer))
			}
		})

		It("deletes configs", func() {
			// Test Delete() to make sure we can delete specific/all configs.
			// delete each config one at a time
			for key, val := range *rm {
				for _, tf := range val {
					countBefore := rs.CountOf(key)
					Expect(countBefore).To(BeNumerically(">", 0))
					ok := rs.Delete(key, tf.nameRef)
					Expect(ok).To(BeTrue())
					countAfter := rs.CountOf(key)
					Expect(countAfter).To(Equal(countBefore - 1))
					// Test double-delete fails correctly
					ok = rs.Delete(key, tf.nameRef)
					Expect(ok).To(BeFalse())
					Expect(rs.CountOf(key)).To(Equal(countAfter))
				}
			}

			// should be completely empty now
			Expect(len(rs.rm)).To(Equal(0))
		})

		It("can iterate over all configs", func() {
			// Test ForEach() to make sure we can iterate over all configs.
			totalConfigs := 0
			rs.ForEach(func(key ServiceKey, cfg *ResourceConfig) {
				totalConfigs += 1
				testObj := (*rm)[key]
				Expect(testObj).ToNot(BeNil())
				found := false
				for _, val := range testObj {
					if val.name == cfg.Virtual.Name {
						found = true
					}
				}
				Expect(found).To(BeTrue())
			})
			Expect(totalConfigs).To(Equal(nbrBackends * nbrCfgsPer))
		})

		It("can get a specific config", func() {
			// Test Get() to make sure we can access specific configs.
			for key, val := range *rm {
				for _, tf := range val {
					r, ok := rs.Get(key, tf.nameRef)
					Expect(ok).To(BeTrue())
					Expect(r).ToNot(BeNil())
					Expect(r.Virtual.VirtualAddress.BindAddr).To(Equal(tf.addr.BindAddr))
					Expect(r.Virtual.VirtualAddress.Port).To(Equal(tf.addr.Port))
				}
			}
		})

		It("can get all configs", func() {
			// Test GetAll() to make sure we can get all configs.
			for key, _ := range *rm {
				rsCfgs := rs.GetAll(key)
				Expect(rsCfgs).ToNot(BeNil())
				Expect(len(rsCfgs)).To(Equal(nbrCfgsPer))
			}
		})
		It("route Services", func() {
			//var weight *int32
			weight := new(int32)
			*weight = 50
			spec := routeapi.RouteSpec{
				Host: "host.com",
				Path: "/foo",
				Port: &routeapi.RoutePort{
					TargetPort: intstr.FromInt(80),
				},
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				AlternateBackends: []routeapi.RouteTargetReference{
					{
						Kind:   "Service",
						Name:   "bar",
						Weight: weight,
					}, {
						Kind:   "Service",
						Name:   "baz",
						Weight: weight,
					},
				},
			}

			annotations := map[string]string{
				F5VsURLRewriteAnnotation:           "foo/baz",
				F5VsAppRootAnnotation:              "chfo",
				F5VsWhitelistSourceRangeAnnotation: "10.10.10.1/23,2.2.2.2",
				F5VsAllowSourceRangeAnnotation:     "10.10.10.1/255.255.0.0",
			}
			route := test.NewRoute("route", "1", "ns1", spec, annotations)
			Expect(ExistsRouteServiceName(route, "foo")).To(Equal(true))
			Expect(ExistsRouteServiceName(route, "foo1")).To(Equal(false))

			svcs := GetRouteServiceNames(route)
			Expect(svcs).To(Equal([]string{"bar", "baz", "foo"}))

			// IS Route AB Deployment
			Expect(IsABServiceOfRoute(route, "baz")).To(Equal(true))
			Expect(IsABServiceOfRoute(route, "foo")).To(Equal(false))
			Expect(IsABServiceOfRoute(route, "bar")).To(Equal(true))

			Expect(IsRouteABDeployment(route)).To(Equal(true))
			val := ParseWhitelistSourceRangeAnnotations(annotations[F5VsWhitelistSourceRangeAnnotation])
			Expect(val).To(Equal([]string{"10.10.10.1/23", "2.2.2.2"}))
			val = ParseWhitelistSourceRangeAnnotations(annotations[F5VsAllowSourceRangeAnnotation])
			Expect(val).To(Equal([]string{"10.10.10.1/255.255.0.0"}))

		})

		It("route object dependencies", func() {
			// Make sure NewObjectDependencies finds all the services in a Route.
			spec := routeapi.RouteSpec{
				Host: "host.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				AlternateBackends: []routeapi.RouteTargetReference{
					{
						Kind: "Service",
						Name: "bar",
					}, {
						Kind: "Service",
						Name: "baz",
					},
				},
			}

			annotations := map[string]string{
				F5VsURLRewriteAnnotation:           "foo/baz",
				F5VsAppRootAnnotation:              "chfo",
				F5VsWhitelistSourceRangeAnnotation: "10.10.10.1",
				F5VsAllowSourceRangeAnnotation:     "10.10.10.1",
			}
			route := test.NewRoute("route", "1", "ns1", spec, annotations)
			key, deps := NewObjectDependencies(route)
			Expect(key).To(Equal(ObjectDependency{
				Kind: "Route", Namespace: "ns1", Name: "route"}))
			routeDeps := []ObjectDependency{
				{Kind: "Service", Namespace: "ns1", Name: "foo"},
				{Kind: "Service", Namespace: "ns1", Name: "bar"},
				{Kind: "Service", Namespace: "ns1", Name: "baz"},
				{Kind: "Rule", Namespace: "ns1", Name: "host.com/foo"},
				{Kind: "Whitelist-Annotation", Namespace: "ns1", Name: "10.10.10.1"},
				{Kind: "URL-Rewrite-Annotation", Namespace: "ns1", Name: "url-rewrite-rule-host.com_foo-foo_baz"},
				{Kind: "App-Root-Annotation", Namespace: "ns1", Name: "app-root-redirect-rule-host.com_foo-chfo,app-root-forward-rule-host.com_foo-chfo"},
			}
			for _, dep := range routeDeps {
				_, found := deps[dep]
				Expect(found).To(BeTrue())
			}

			routeAlwaysFound := func(key ObjectDependency) bool {
				return false
			}
			routeNeverFound := func(key ObjectDependency) bool {
				return true
			}

			// First add
			Expect(len(rs.objDeps)).To(BeZero())
			added, removed := rs.UpdateDependencies(
				key, deps, routeDeps[0], routeAlwaysFound)
			Expect(len(added)).To(Equal(len(routeDeps)))
			Expect(len(removed)).To(BeZero())
			Expect(len(rs.objDeps)).To(Equal(1))

			// Change a dependent service
			route.Spec.AlternateBackends[1].Name = "boo"
			key, deps = NewObjectDependencies(route)
			added, removed = rs.UpdateDependencies(
				key, deps, routeDeps[0], routeAlwaysFound)
			Expect(len(added)).To(Equal(1))
			Expect(len(removed)).To(Equal(1))
			Expect(len(rs.objDeps)).To(Equal(1))

			// 'remove' Route. Should remove entry from rs.objDeps
			added, removed = rs.UpdateDependencies(
				key, deps, routeDeps[0], routeNeverFound)
			Expect(len(added)).To(BeZero())
			Expect(len(removed)).To(Equal(len(annotations)))
			Expect(len(rs.objDeps)).To(BeZero())
		})

		It("Netv1 ingress object dependencies", func() {
			// Make sure NewObjectDependencies finds all the services in an Ingress.
			ingressConfig := netv1.IngressSpec{
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{
						Name: "foo",
						Port: netv1.ServiceBackendPort{
							Number: 80,
							Name:   "http",
						},
					},
				},
				Rules: []netv1.IngressRule{
					{
						Host: "host1",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: "/bar",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{
												Name: "bar",
												Port: netv1.ServiceBackendPort{
													Number: 80,
													Name:   "http",
												},
											},
										},
									}, {
										Path: "/baz",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{
												Name: "baz",
												Port: netv1.ServiceBackendPort{
													Number: 80,
													Name:   "http",
												},
											},
										},
									},
								},
							},
						},
					}, {
						Host: "host2",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: "/baz",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{
												Name: "baz",
												Port: netv1.ServiceBackendPort{
													Number: 80,
													Name:   "http",
												},
											},
										},
									},
									{
										Path: "/foobarbaz",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{
												Name: "foobarbaz",
												Port: netv1.ServiceBackendPort{
													Number: 80,
													Name:   "http",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
			// Add a new Ingress
			annotations := map[string]string{
				F5VsURLRewriteAnnotation: "foo/baz",
				F5VsAppRootAnnotation:    "chfo",
			}
			vsName := FormatIngressVSName("1.2.3.4", 80)
			ingress := test.NewIngressNetV1(vsName, "1", "ns2", ingressConfig, annotations)
			key, deps := NewObjectDependencies(ingress)
			Expect(key).To(Equal(ObjectDependency{
				Kind: "Ingress", Namespace: "ns2", Name: vsName}))
			ingressDeps := []ObjectDependency{
				{Kind: "Service", Namespace: "ns2", Name: "foo"},
				{Kind: "Service", Namespace: "ns2", Name: "bar"},
				{Kind: "Service", Namespace: "ns2", Name: "baz"},
				{Kind: "Service", Namespace: "ns2", Name: "foobarbaz"},
				{Kind: "Rule", Namespace: "ns2", Name: "host1/bar"},
				{Kind: "Rule", Namespace: "ns2", Name: "host1/baz"},
				{Kind: "Rule", Namespace: "ns2", Name: "host2/baz"},
				{Kind: "Rule", Namespace: "ns2", Name: "host2/foobarbaz"},
				{Kind: "App-Root-Annotation", Namespace: "ns2", Name: ","},
				{Kind: "URL-Rewrite-Annotation", Namespace: "ns2"},
			}
			for _, dep := range ingressDeps {
				_, found := deps[dep]
				Expect(found).To(BeTrue())
			}

			ingAlwaysFound := func(key ObjectDependency) bool {
				return false
			}
			ingNeverFound := func(key ObjectDependency) bool {
				return true
			}

			// First add
			Expect(len(rs.objDeps)).To(BeZero())
			added, removed := rs.UpdateDependencies(
				key, deps, ingressDeps[0], ingAlwaysFound)
			Expect(len(added)).To(Equal(len(ingressDeps)))
			Expect(len(removed)).To(BeZero())
			Expect(len(rs.objDeps)).To(Equal(1))

			// Change a dependent service
			ingress.Spec.Rules[1].HTTP.Paths[1].Backend.Service.Name = "boo"
			key, deps = NewObjectDependencies(ingress)
			added, removed = rs.UpdateDependencies(
				key, deps, ingressDeps[0], ingAlwaysFound)
			Expect(len(added)).To(Equal(1))
			Expect(len(removed)).To(Equal(1))
			Expect(len(rs.objDeps)).To(Equal(1))

			// 'remove' Ingress. Should remove entry from rs.objDeps
			added, removed = rs.UpdateDependencies(
				key, deps, ingressDeps[0], ingNeverFound)
			Expect(len(added)).To(BeZero())
			Expect(len(removed)).To(Equal(6))
			Expect(len(rs.objDeps)).To(BeZero())

			ingress = test.NewIngressNetV1("ingress", "1", "ns3", ingressConfig, nil)
			key, deps = NewObjectDependencies(ingress)
			Expect(key).To(Equal(ObjectDependency{
				Kind: "Ingress", Namespace: "ns3", Name: "ingress"}))
			depKey := ObjectDependency{
				Kind: "Ingress", Namespace: "ns3", Name: "ingress"}
			Expect(len(rs.objDeps)).To(BeZero())
			added, removed = rs.UpdateDependencies(
				key, deps, depKey, ingAlwaysFound)
			Expect(len(added)).To(Equal(8))
			Expect(len(removed)).To(BeZero())
			Expect(len(rs.objDeps)).To(Equal(1))
			//Expect(len(rs.objDeps)).To(BeZero())
			rs.RemoveDependency(depKey)
			Expect(len(rs.objDeps)).To(BeZero())

		})

		It("Verifies whether netmask is set properly", func() {
			v := Virtual{}
			v.SetVirtualAddressNetMask("1.2.3.4")
			Expect(v.Mask).To(Equal(""))

			v.SetVirtualAddressNetMask("1.2.3.4/31")
			Expect(v.Mask).To(Equal("255.255.255.254"))

			v.Mask = ""
			v.SetVirtualAddressNetMask("1.2.3.4/30%5")
			Expect(v.Mask).To(Equal("255.255.255.252"))

			v.Mask = ""
			v.SetVirtualAddressNetMask("1.2.3.4%5/30")
			Expect(v.Mask).To(Equal(""))

			v.Mask = ""
			v.SetVirtualAddressNetMask("2001:0DB8:ABCD:0012:0000:0000:0000:0000")
			Expect(v.Mask).To(Equal(""))

			v.Mask = ""
			v.SetVirtualAddressNetMask("2001:1234:5678:1234:5678:ABCD:EF12:1234/64")
			Expect(v.Mask).To(Equal("ffff:ffff:ffff:ffff:0000:0000:0000:0000"))

			v.Mask = ""
			v.SetVirtualAddressNetMask("2002::1234:abcd:ffff:c0a8:101/31")
			Expect(v.Mask).To(Equal("ffff:fffe:0000:0000:0000:0000:0000:0000"))

			v.Mask = ""
			v.SetVirtualAddressNetMask("2002::1234:abcd:ffff:c0a8:101/30%5")
			Expect(v.Mask).To(Equal("ffff:fffc:0000:0000:0000:0000:0000:0000"))

		})

		It("Verifies that resource config is copied correctly and ensures safe concurrent usage", func() {
			// Create resource config
			rule, _ := CreateRule("*.host.com/bar", "poolname", "k8s", "policy_rule_1_rule1")

			resourceConfig := &ResourceConfig{
				MetaData: MetaData{
					Active:             true,
					ResourceType:       "route",
					DefaultIngressName: "test1",
					RouteProfs:         make(map[RouteKey]string),
				},
				Virtual: Virtual{Name: "test-virtual", Policies: []NameRef{}, Profiles: ProfileRefs{}},
				Policies: []Policy{Policy{Name: "test-policy", Controls: []string{"forwarding"}, Rules: Rules{rule},
					Requires: []string{}}},
				Pools: []Pool{
					Pool{
						Name:        "poolname",
						Partition:   "ns",
						ServiceName: "svc",
						ServicePort: 80,
						MonitorNames: []string{
							"test-monitor-1",
						},
						Members: []Member{
							Member{
								Address: "1.1.1.1",
								Port:    8080,
								SvcPort: 80,
							},
						},
					},
				},
				Monitors: []Monitor{
					Monitor{
						Name:     "test-monitor-1",
						Interval: 10,
						Type:     "http",
					},
				},
			}
			// Create a copy of resource config
			rcConfigCopy := &ResourceConfig{}
			rcConfigCopy.CopyConfig(resourceConfig)
			// Verify that copy is done correctly
			Expect(resourceConfig).To(Equal(rcConfigCopy))
			//Verify that Remove Pool removes Pool and respective Pool Members
			cfgChanged, svcKey := resourceConfig.RemovePool("ns", "poolname", make(map[string]map[string]MergedRuleEntry))
			Expect(svcKey).To(Equal(&ServiceKey{ServiceName: "svc", ServicePort: 80, Namespace: "ns"}))
			Expect(cfgChanged).To(Equal(true))
			rcConfigCopy.Pools = []Pool{}
			rcConfigCopy.Policies = nil
			Expect(resourceConfig).To(Equal(rcConfigCopy))
			// Verify that route profile map is copied safely so that concurrent usage can be done
			// Go routine that simulates writing route profiles to the original resource config
			go func(rcfg *ResourceConfig) {
				// Populate random route profiles
				for i := 0; i < 100000; i++ {
					rtKey := RouteKey{
						Name:      fmt.Sprintf("%d", i),
						Namespace: fmt.Sprintf("%d", i),
						Context:   fmt.Sprintf("%d", i),
					}
					rcfg.MetaData.RouteProfs[rtKey] = fmt.Sprintf("%d", i)
				}
			}(resourceConfig)
			// Go routine that simulates reading route profiles from the copy of resource config
			go func(rcfg *ResourceConfig) {
				for i := 0; i < 50000; i++ {
					for _, _ = range rcfg.MetaData.RouteProfs {
					}
				}
			}(rcConfigCopy)

		})

		It("FormatIngressPoolName", func() {
			Expect(FormatIngressPoolName("default", "svc1")).To(Equal("ingress_default_svc1"))
		})

		It("GetRouteCanonicalServiceName", func() {
			Expect(GetRouteCanonicalServiceName(&routeapi.Route{Spec: routeapi.RouteSpec{To: routeapi.RouteTargetReference{Name: "svc1"}}})).To(Equal("svc1"))
		})

		It("GetRouteAssociatedRuleNames", func() {
			anno := make(map[string]string)
			anno["virtual-server.f5.com/whitelist-source-range"] = "10.244.0.0/28"
			rt := &routeapi.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "route1",
					Namespace:   "default",
					Annotations: anno,
				},
				Spec: routeapi.RouteSpec{
					To: routeapi.RouteTargetReference{Name: "svc1"},
				},
			}
			expectedRuleNames := []string{"openshift_route_default_route1",
				"openshift_route_default_route1-reset"}
			Expect(GetRouteAssociatedRuleNames(rt)).To(Equal(expectedRuleNames))

			anno = make(map[string]string)
			anno["virtual-server.f5.com/allow-source-range"] = "10.244.0.0/28"
			rt.Annotations = anno
			Expect(GetRouteAssociatedRuleNames(rt)).To(Equal(expectedRuleNames))

		})
	})

	Describe("Config Manipulation", func() {
		It("configures ssl profile names", func() {
			getClientProfileNames := func(vs Virtual) []string {
				clientProfs := []string{}
				for _, prof := range vs.Profiles {
					if prof.Context == CustomProfileClient {
						var profName string
						if len(prof.Partition) > 0 {
							profName = fmt.Sprintf("%s/%s", prof.Partition, prof.Name)
						} else {
							profName = prof.Name
						}
						clientProfs = append(clientProfs, profName)
					}
				}
				return clientProfs
			}
			var rs ResourceConfig
			// verify initial state
			empty := []string{}
			Expect(getClientProfileNames(rs.Virtual)).To(Equal(empty))

			// set a name and make sure it is saved
			profileName := "profileName"
			firstProfile := ProfileRef{Name: profileName, Context: CustomProfileClient}
			rs.Virtual.AddOrUpdateProfile(
				firstProfile)
			Expect(getClientProfileNames(rs.Virtual)).To(
				Equal([]string{profileName}))

			// add a second profile
			newProfileName := "newProfileName"
			secondProfile := ProfileRef{Name: newProfileName, Context: CustomProfileClient}
			rs.Virtual.AddOrUpdateProfile(
				secondProfile)
			Expect(getClientProfileNames(rs.Virtual)).To(
				Equal([]string{newProfileName, profileName}))

			var expectedProfiles = ProfileRefs{secondProfile, firstProfile}
			// Verify swaping the one profile with second profile
			Expect(rs.Virtual.Profiles).To(Equal(expectedProfiles))
			rs.Virtual.Profiles.Swap(0, 1)
			expectedProfiles = ProfileRefs{firstProfile, secondProfile}
			Expect(rs.Virtual.Profiles).To(Equal(expectedProfiles))
			rs.Virtual.Profiles.Swap(0, 1)
			expectedProfiles = ProfileRefs{secondProfile, firstProfile}
			Expect(rs.Virtual.Profiles).To(Equal(expectedProfiles))

			// Remove both profiles and make sure the pointer goes back to nil
			r := rs.Virtual.RemoveProfile(
				ProfileRef{Name: profileName, Context: CustomProfileClient})
			Expect(r).To(BeTrue())
			Expect(getClientProfileNames(rs.Virtual)).To(
				Equal([]string{newProfileName}))
			r = rs.Virtual.RemoveProfile(
				ProfileRef{Name: newProfileName, Context: CustomProfileClient})
			Expect(r).To(BeTrue())
			Expect(getClientProfileNames(rs.Virtual)).To(Equal(empty))
		})

		It("sets and removes irule", func() {
			var rs ResourceConfig
			// verify initial state
			Expect(len(rs.Virtual.IRules)).To(Equal(0))
			Expect(rs.Virtual.AddIRule("firstIRule")).To(Equal(true))
			Expect(rs.Virtual.AddIRule("SecondIRule")).To(Equal(true))
			Expect(rs.Virtual.AddIRule("ThirdIRule")).To(Equal(true))
			Expect(rs.Virtual.AddIRule("ThirdIRule")).To(Equal(false))
			expectedIRules := []string{"firstIRule", "SecondIRule", "ThirdIRule"}
			Expect(len(rs.Virtual.IRules)).To(Equal(3))
			Expect(rs.Virtual.IRules).To(Equal(expectedIRules))
			Expect(rs.Virtual.IRules[1]).To(Equal("SecondIRule"))
			// Remove Non-Existing IRule
			Expect(rs.Virtual.RemoveIRule("testIrule")).To(Equal(false))
			//Remove Existing Irule
			Expect(rs.Virtual.RemoveIRule("SecondIRule")).To(Equal(true))
			Expect(len(rs.Virtual.IRules)).To(Equal(2))
			Expect(rs.Virtual.IRules).To(Equal([]string{"firstIRule", "ThirdIRule"}))
			// Verify ToString Works
			Expect(rs.Virtual.ToString()).To(Equal("{\"name\":\"\",\"destination\":\"\",\"enabled\":false,\"sourceAddressTranslation\":{\"type\":\"\"},\"rules\":[\"firstIRule\",\"ThirdIRule\"]}"))
			//Verify NewIRule
			var newiRule = &IRule{
				Name:      "uri",
				Partition: "test",
				Code:      "{client:l}",
			}
			Expect(NewIRule("uri", "test", "{client:l}")).To(Equal(newiRule))
		})

		It("TODO Add and  removes Rule & policies", func() {
			var rc ResourceConfig

			lenValidate := func(expectedLen int) {
				Expect(len(rc.Virtual.Policies)).To(Equal(expectedLen))
				Expect(len(rc.Policies)).To(Equal(len(rc.Virtual.Policies)))
			}

			// verify initial state
			lenValidate(0)

			// add a policy
			policyname := "policy1"
			partition := "k8s"

			var rule, rule1 *Rule
			rule, _ = CreateRule("*.host.com/bar", "poolname", partition, "url-rewrite-rule1")
			rule1, _ = CreateRule("host.com/foo", "poolname", partition, "url-rewrite-rule2")
			// create policy
			samplePolicy := Policy{
				Name:      policyname,
				Partition: partition,
				Controls:  []string{"forwarding"},
				Legacy:    true,
				Requires:  []string{"http"},
				Rules:     Rules{rule},
				Strategy:  "/Common/first-match",
			}

			Expect(CreatePolicy(Rules{rule}, policyname, partition)).To(Equal(&samplePolicy))

			rc.SetPolicy(samplePolicy)
			lenValidate(1)
			Expect(rc.Policies[0].Strategy).To(Equal("/Common/first-match"))
			// Add Rule to policy
			rc.AddRuleToPolicy(policyname, rule)
			Expect(rc.Policies[0]).To(Equal(samplePolicy))

			//Delete Rule From policy
			mergedRulesMap := make(map[string]map[string]MergedRuleEntry)
			rc.DeleteRuleFromPolicy(policyname, rule, mergedRulesMap)
			samplePolicy.Rules = Rules{}
			Expect(len(rc.Policies)).To(Equal(0))
			rc.SetPolicy(samplePolicy)
			lenValidate(1)

			// change data in existing policy
			samplePolicy.Strategy = "best-match"
			Expect(rc.Policies[0].Strategy).To(Equal("/Common/first-match"))
			rc.SetPolicy(samplePolicy)
			lenValidate(1)
			Expect(rc.Policies[0].Strategy).To(Equal("best-match"))

			secondpolicy := "policy2"
			// create policy
			policy2 := Policy{
				Name:      secondpolicy,
				Partition: partition,
				Controls:  []string{"forwarding"},
				Legacy:    true,
				Requires:  []string{"http"},
				Rules:     Rules{rule1},
				Strategy:  "first-match",
			}
			rc.SetPolicy(policy2)
			lenValidate(2)

			// make sure it is appended
			Expect(rc.Policies[0].Name).To(Equal(policyname))
			Expect(rc.Policies[1].Name).To(Equal(secondpolicy))

			// Remove Rules
			policy2.RemoveRules([]int{0})
			rc.Policies[1].Rules = []*Rule{}
			Expect(rc.Policies[1]).To(Equal(policy2))
			// remove first policy
			rc.RemovePolicy(samplePolicy)

			lenValidate(1)
			Expect(rc.Policies[0].Name).To(Equal("policy2"))

			// remove last policy
			rc.RemovePolicy(policy2)
			lenValidate(0)

			// make sure deleting something that isn't there doesn't fail badly
			rc.RemovePolicy(policy2)
			lenValidate(0)
		})

		It("sets and removes policies", func() {
			var rc ResourceConfig

			lenValidate := func(expectedLen int) {
				Expect(len(rc.Virtual.Policies)).To(Equal(expectedLen))
				Expect(len(rc.Policies)).To(Equal(len(rc.Virtual.Policies)))
			}

			// verify initial state
			lenValidate(0)

			// add a policy
			policy1 := Policy{
				Name:      "policy1",
				Partition: "k8s",
				Strategy:  "first-match",
			}
			rc.SetPolicy(policy1)
			lenValidate(1)
			Expect(rc.Policies[0].Strategy).To(Equal("first-match"))

			// change data in existing policy
			policy1.Strategy = "best-match"
			Expect(rc.Policies[0].Strategy).To(Equal("first-match"))
			rc.SetPolicy(policy1)
			lenValidate(1)
			Expect(rc.Policies[0].Strategy).To(Equal("best-match"))

			// add a second policy
			policy2 := Policy{
				Name:      "policy2",
				Partition: "k8s",
				Strategy:  "first-match",
			}
			rc.SetPolicy(policy2)
			lenValidate(2)

			// make sure it is appended
			Expect(rc.Policies[0].Name).To(Equal("policy1"))
			Expect(rc.Policies[1].Name).To(Equal("policy2"))

			// remove first policy
			rc.RemovePolicy(policy1)
			lenValidate(1)
			Expect(rc.Policies[0].Name).To(Equal("policy2"))

			// remove last policy
			rc.RemovePolicy(policy2)
			lenValidate(0)

			// make sure deleting something that isn't there doesn't fail badly
			rc.RemovePolicy(policy2)
			lenValidate(0)
		})

		It("sets and removes internal data group records", func() {
			idg := NewInternalDataGroup("test-dg", "test")
			Expect(idg).ToNot(BeNil())
			Expect(idg.Records.Len()).To(Equal(0))

			// Test add. Add items out of sort order and make sure order is maintained.
			testData := []string{
				"second",
				"third",
				"first",
			}
			for i, val := range testData {
				updated := idg.AddOrUpdateRecord(val+" name", val+" data")
				Expect(updated).To(BeTrue())
				Expect(idg.Records.Len()).To(Equal(i + 1))
			}
			Expect(sort.IsSorted(idg.Records)).To(BeTrue())

			// Test updates of existing items.
			for _, val := range testData {
				updated := idg.AddOrUpdateRecord(val+" name", val+" updated data")
				Expect(updated).To(BeTrue())
			}
			// Make sure updates with same data does not indicate an update.
			for _, val := range testData {
				updated := idg.AddOrUpdateRecord(val+" name", val+" updated data")
				Expect(updated).To(BeFalse())
			}

			// Test remove for both existing and non-existing records.
			expectedRecCt := len(testData)
			for _, val := range testData {
				// remove existing.
				updated := idg.RemoveRecord(val + " name")
				Expect(updated).To(BeTrue())
				expectedRecCt--
				Expect(idg.Records.Len()).To(Equal(expectedRecCt))
				// remove non-existing.
				updated = idg.RemoveRecord(val + " name")
				Expect(updated).To(BeFalse())
				Expect(idg.Records.Len()).To(Equal(expectedRecCt))
			}
		})

		It("sets and removes profiles", func() {
			virtual := Virtual{}
			Expect(virtual.Profiles.Len()).To(Equal(0))

			// Test add. Add items out of sort order and make sure order is maintained.
			testData := []ProfileRef{
				{Partition: "test1", Name: "second"},
				{Partition: "test2", Name: "first"},
				{Partition: "test1", Name: "first"},
			}
			for i, prof := range testData {
				updated := virtual.AddOrUpdateProfile(prof)
				Expect(updated).To(BeTrue())
				Expect(virtual.Profiles.Len()).To(Equal(i + 1))
			}
			Expect(sort.IsSorted(virtual.Profiles)).To(BeTrue())

			// Test updates of existing items.
			for _, prof := range testData {
				prof.Context = CustomProfileAll
				updated := virtual.AddOrUpdateProfile(prof)
				Expect(updated).To(BeTrue())
			}
			// Make sure updates with same data does not indicate an update.
			for _, prof := range testData {
				prof.Context = CustomProfileAll
				updated := virtual.AddOrUpdateProfile(prof)
				Expect(updated).To(BeFalse())
			}

			// Test remove for both existing and non-existing records.
			expectedProfCt := len(testData)
			for _, prof := range testData {
				// remove existing.
				updated := virtual.RemoveProfile(prof)
				Expect(updated).To(BeTrue())
				expectedProfCt--
				Expect(virtual.Profiles.Len()).To(Equal(expectedProfCt))
				// remove non-existing.
				updated = virtual.RemoveProfile(prof)
				Expect(updated).To(BeFalse())
				Expect(virtual.Profiles.Len()).To(Equal(expectedProfCt))
			}
		})

		It("handles profile context", func() {
			virtual := Virtual{}
			Expect(virtual.Profiles.Len()).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(CustomProfileAll)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(CustomProfileClient)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(CustomProfileServer)).To(Equal(0))

			// Test add. Add one profile of each type to Virtual.Profiles[].
			testData := []ProfileRef{
				{Partition: "test1", Name: "second", Context: CustomProfileAll},
				{Partition: "test2", Name: "first", Context: CustomProfileClient},
				{Partition: "test1", Name: "first", Context: CustomProfileServer},
			}
			for _, prof := range testData {
				updated := virtual.AddOrUpdateProfile(prof)
				Expect(updated).To(BeTrue())
			}
			Expect(virtual.GetProfileCountByContext(CustomProfileAll)).To(Equal(1))
			Expect(virtual.GetProfileCountByContext(CustomProfileClient)).To(Equal(1))
			Expect(virtual.GetProfileCountByContext(CustomProfileServer)).To(Equal(1))

			// Change existing items and check counts change correctly.
			for _, prof := range testData {
				prof.Context = CustomProfileServer
				virtual.AddOrUpdateProfile(prof)
			}
			Expect(virtual.GetProfileCountByContext(CustomProfileAll)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(CustomProfileClient)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(CustomProfileServer)).To(Equal(3))
			for _, prof := range testData {
				prof.Context = CustomProfileClient
				virtual.AddOrUpdateProfile(prof)
			}
			Expect(virtual.GetProfileCountByContext(CustomProfileAll)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(CustomProfileClient)).To(Equal(3))
			Expect(virtual.GetProfileCountByContext(CustomProfileServer)).To(Equal(0))

			// Add some frontend client profiles.
			virtual.AddOrUpdateProfile(
				ProfileRef{
					Partition: "test3",
					Name:      "firstprofile",
					Context:   CustomProfileClient,
				})
			Expect(virtual.GetProfileCountByContext(CustomProfileClient)).To(Equal(4))
			virtual.AddOrUpdateProfile(
				ProfileRef{
					Partition: "test3",
					Name:      "secondprofile",
					Context:   CustomProfileClient,
				})
			Expect(virtual.GetProfileCountByContext(CustomProfileClient)).To(Equal(5))
		})

		It("can tell which profile each virtual references", func() {
			virtual := Virtual{}

			testData := []ProfileRef{
				{Partition: "test1", Name: "second", Context: CustomProfileAll},
				{Partition: "test2", Name: "first", Context: CustomProfileClient},
				{Partition: "test1", Name: "first", Context: CustomProfileServer},
				{Partition: "test2", Name: "second", Context: CustomProfileClient},
			}
			for _, prof := range testData {
				cprof := NewCustomProfile(
					prof,
					"crt",
					"key",
					"srver",
					false,
					PeerCertDefault,
					"",
					"")
				refs := virtual.ReferencesProfile(cprof)
				Expect(refs).To(BeFalse())
			}

			// add profiles to virtual.
			for _, prof := range testData {
				if prof.Partition == "test1" {
					virtual.AddOrUpdateProfile(prof)
				}
			}

			for _, prof := range testData {
				switch prof.Partition {
				case "test1":
					cprof := NewCustomProfile(
						prof,
						"crt",
						"key",
						"srver",
						false,
						PeerCertDefault,
						"",
						"")
					refs := virtual.ReferencesProfile(cprof)
					Expect(refs).To(BeTrue())
				case "test2":
					cprof := NewCustomProfile(
						prof,
						"crt",
						"key",
						"srver",
						false,
						PeerCertDefault,
						"",
						"")
					refs := virtual.ReferencesProfile(cprof)
					Expect(refs).To(BeFalse())
				}
			}
		})
	})
	Describe("url-rewrite and app-root Annotation Tests", func() {
		It("parses annotations correctly", func() {
			result := ParseAppRootURLRewriteAnnotations("foo")
			Expect(result["single"]).To(Equal("foo"))

			result = ParseAppRootURLRewriteAnnotations("foo=bar")
			Expect(result["foo"]).To(Equal("bar"))

			result = ParseAppRootURLRewriteAnnotations("foo=bar,bar=baz")
			Expect(result["foo"]).To(Equal("bar"))
			Expect(result["bar"]).To(Equal("baz"))

			result = ParseAppRootURLRewriteAnnotations("=bar")
			Expect(result[""]).To(Equal("bar"))

			result = ParseAppRootURLRewriteAnnotations("foo=")
			Expect(result["foo"]).To(Equal(""))

			result = ParseAppRootURLRewriteAnnotations("=foo,bar=")
			Expect(result[""]).To(Equal("foo"))
			Expect(result["bar"]).To(Equal(""))

			result = ParseAppRootURLRewriteAnnotations("foo=,=bar")
			Expect(result["foo"]).To(Equal(""))
			Expect(result[""]).To(Equal("bar"))

			result = ParseAppRootURLRewriteAnnotations(",")
			Expect(len(result)).To(Equal(0))

			result = ParseAppRootURLRewriteAnnotations("foo,")
			Expect(len(result)).To(Equal(0))

			result = ParseAppRootURLRewriteAnnotations("foo=bar,")
			Expect(len(result)).To(Equal(1))
			Expect(result["foo"]).To(Equal("bar"))

			result = ParseAppRootURLRewriteAnnotations("foo=bar,bar=baz,")
			Expect(len(result)).To(Equal(2))
			Expect(result["foo"]).To(Equal("bar"))
			Expect(result["bar"]).To(Equal("baz"))

			result = ParseAppRootURLRewriteAnnotations("foo=bar,bar")
			Expect(len(result)).To(Equal(1))
			Expect(result["foo"]).To(Equal("bar"))

			result = ParseAppRootURLRewriteAnnotations("foo,bar=baz")
			Expect(len(result)).To(Equal(1))
			Expect(result["bar"]).To(Equal("baz"))

			result = ParseAppRootURLRewriteAnnotations("foo=bar,=bar=")
			Expect(len(result)).To(Equal(1))
			Expect(result["foo"]).To(Equal("bar"))

			result = ParseAppRootURLRewriteAnnotations(",bar=baz")
			Expect(len(result)).To(Equal(1))
			Expect(result["bar"]).To(Equal("baz"))

			result = ParseAppRootURLRewriteAnnotations("/hello=/good-bye/hi=/bye")
			Expect(len(result)).To(Equal(0))

			result = ParseAppRootURLRewriteAnnotations("/hello=/good-bye/hi=/bye,")
			Expect(len(result)).To(Equal(0))

			result = ParseAppRootURLRewriteAnnotations(",/hello=/good-bye/hi=/bye,")
			Expect(len(result)).To(Equal(0))
		})

		It("processes app-root annotations correctly", func() {
			poolName := "test-pool"

			// multi-service ingress missing host fail case
			result := ProcessAppRoot("", "/approot", poolName, MultiServiceIngressType)
			Expect(len(result)).To(Equal(0))

			// multi-service ingress targeted path fail case
			result = ProcessAppRoot("host.com/path", "/approot", poolName, MultiServiceIngressType)
			Expect(len(result)).To(Equal(0))

			// route targeted path fail case
			result = ProcessAppRoot("host.com/path", "/approot", poolName, RouteType)
			Expect(len(result)).To(Equal(0))

			// non-empty value host fail case
			result = ProcessAppRoot("host.com", "newhost.com/approot", poolName, MultiServiceIngressType)
			Expect(len(result)).To(Equal(0))

			// empty value path fail case
			result = ProcessAppRoot("host.com", "", poolName, MultiServiceIngressType)
			Expect(len(result)).To(Equal(0))

			// multi-service ingress success case
			result = ProcessAppRoot("host.com", "/approot", poolName, MultiServiceIngressType)
			Expect(len(result)).To(Equal(2))
			Expect(result[0].Actions).To(Equal([]*Action{&Action{
				Name:      "0",
				HttpReply: true,
				Redirect:  true,
				Location:  "/approot",
				Request:   true,
			}}))
			Expect(result[0].Conditions).To(Equal([]*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"host.com"},
				},
				&Condition{
					Name:    "1",
					Equals:  true,
					HTTPURI: true,
					Path:    true,
					Request: true,
					Values:  []string{"/"},
				},
			}))
			Expect(result[1].Actions).To(Equal([]*Action{&Action{
				Name:    "0",
				Pool:    poolName,
				Forward: true,
				Request: true,
			}}))
			Expect(result[1].Conditions).To(Equal([]*Condition{
				result[0].Conditions[0],
				&Condition{
					Name:    "1",
					Equals:  true,
					HTTPURI: true,
					Path:    true,
					Request: true,
					Values:  []string{"/approot"},
				},
			}))

			// route success case
			result = ProcessAppRoot("host.com", "/approot", poolName, RouteType)
			Expect(len(result)).To(Equal(2))
			Expect(result[0].Actions).To(Equal([]*Action{&Action{
				Name:      "0",
				HttpReply: true,
				Redirect:  true,
				Location:  "/approot",
				Request:   true,
			}}))
			Expect(result[0].Conditions).To(Equal([]*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"host.com"},
				},
				&Condition{
					Name:    "1",
					Equals:  true,
					HTTPURI: true,
					Path:    true,
					Request: true,
					Values:  []string{"/"},
				},
			}))
			Expect(result[1].Actions).To(Equal([]*Action{&Action{
				Name:    "0",
				Pool:    poolName,
				Forward: true,
				Request: true,
			}}))
			Expect(result[1].Conditions).To(Equal([]*Condition{
				result[0].Conditions[0],
				&Condition{
					Name:    "1",
					Equals:  true,
					HTTPURI: true,
					Path:    true,
					Request: true,
					Values:  []string{"/approot"},
				},
			}))

			// single-service ingress success case
			result = ProcessAppRoot("", "/approot", poolName, SingleServiceIngressType)
			Expect(len(result)).To(Equal(2))
			Expect(result[0].Actions).To(Equal([]*Action{&Action{
				Name:      "0",
				HttpReply: true,
				Redirect:  true,
				Location:  "/approot",
				Request:   true,
			}}))
			Expect(result[0].Conditions).To(Equal([]*Condition{&Condition{
				Name:    "0",
				Equals:  true,
				HTTPURI: true,
				Path:    true,
				Request: true,
				Values:  []string{"/"},
			}}))
			Expect(result[1].Actions).To(Equal([]*Action{&Action{
				Name:    "0",
				Pool:    poolName,
				Forward: true,
				Request: true,
			}}))
			Expect(result[1].Conditions).To(Equal([]*Condition{&Condition{
				Name:    "0",
				Equals:  true,
				HTTPURI: true,
				Path:    true,
				Request: true,
				Values:  []string{"/approot"},
			}}))
		})

		It("processes url-rewrite annotations correctly", func() {
			// multi-service ingress missing target host host fail case
			result := ProcessURLRewrite("", "newhost.com", MultiServiceIngressType)
			Expect(result).To(BeNil())

			// multi-service ingress missing target host path fail case
			result = ProcessURLRewrite("/path", "/newpath", MultiServiceIngressType)
			Expect(result).To(BeNil())

			// multi-service ingress missing target path path fail case
			result = ProcessURLRewrite("host.com", "/newpath", MultiServiceIngressType)
			Expect(result).To(BeNil())

			// route missing target path path fail case
			result = ProcessURLRewrite("host.com", "/newpath", RouteType)
			Expect(result).To(BeNil())

			// route missing target host host fail case
			result = ProcessURLRewrite("", "newhost.com", RouteType)
			Expect(result).To(BeNil())

			// empty values fail case
			result = ProcessURLRewrite("host.com/path", "", RouteType)
			Expect(result).To(BeNil())

			// multi-service ingress rewrite host
			result = ProcessURLRewrite("host.com", "newhost.com", MultiServiceIngressType)
			Expect(result.Conditions).To(Equal([]*Condition{&Condition{
				Name:     "0",
				Equals:   true,
				Host:     true,
				HTTPHost: true,
				Index:    0,
				Request:  true,
				Values:   []string{"host.com"},
			}}))
			Expect(result.Actions).To(Equal([]*Action{&Action{
				Name:     "0",
				HTTPHost: true,
				Replace:  true,
				Request:  true,
				Value:    "newhost.com",
			}}))

			// multi-service ingress rewrite path
			result = ProcessURLRewrite("host.com/oldpath/path", "/newpath/path", MultiServiceIngressType)
			Expect(result.Conditions).To(Equal([]*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"host.com"},
				},
				&Condition{
					Name:        "1",
					Equals:      true,
					HTTPURI:     true,
					Index:       1,
					PathSegment: true,
					Request:     true,
					Values:      []string{"oldpath"},
				},
				&Condition{
					Name:        "2",
					Equals:      true,
					HTTPURI:     true,
					Index:       2,
					PathSegment: true,
					Request:     true,
					Values:      []string{"path"},
				},
			}))
			Expect(result.Actions).To(Equal([]*Action{&Action{
				Name:    "0",
				HTTPURI: true,
				Path:    "/oldpath/path",
				Replace: true,
				Request: true,
				Value:   "tcl:[regsub /oldpath/path [HTTP::uri] /newpath/path ]",
			}}))

			// mutli-service ingress rewrite host and path
			result = ProcessURLRewrite("host.com/path", "newhost.com/newpath", MultiServiceIngressType)
			Expect(result.Conditions).To(Equal([]*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"host.com"},
				},
				&Condition{
					Name:        "1",
					Equals:      true,
					HTTPURI:     true,
					Index:       1,
					PathSegment: true,
					Request:     true,
					Values:      []string{"path"},
				},
			}))
			Expect(result.Actions).To(Equal([]*Action{
				&Action{
					Name:     "0",
					HTTPHost: true,
					Replace:  true,
					Request:  true,
					Value:    "newhost.com",
				},
				&Action{
					Name:    "1",
					HTTPURI: true,
					Path:    "/path",
					Replace: true,
					Request: true,
					Value:   "tcl:[regsub /path [HTTP::uri] /newpath ]",
				},
			}))

			// route rewrite host
			result = ProcessURLRewrite("host.com", "newhost.com", RouteType)
			Expect(result.Conditions).To(Equal([]*Condition{&Condition{
				Name:     "0",
				Equals:   true,
				Host:     true,
				HTTPHost: true,
				Index:    0,
				Request:  true,
				Values:   []string{"host.com"},
			}}))
			Expect(result.Actions).To(Equal([]*Action{&Action{
				Name:     "0",
				HTTPHost: true,
				Replace:  true,
				Request:  true,
				Value:    "newhost.com",
			}}))

			// route rewrite path
			result = ProcessURLRewrite("host.com/path", "/newpath", RouteType)
			Expect(result.Conditions).To(Equal([]*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"host.com"},
				},
				&Condition{
					Name:        "1",
					Equals:      true,
					HTTPURI:     true,
					Index:       1,
					PathSegment: true,
					Request:     true,
					Values:      []string{"path"},
				},
			}))
			Expect(result.Actions).To(Equal([]*Action{&Action{
				Name:    "0",
				HTTPURI: true,
				Path:    "/path",
				Replace: true,
				Request: true,
				Value:   "tcl:[regsub /path [HTTP::uri] /newpath ]",
			}}))

			// route rewrite host and path
			result = ProcessURLRewrite("host.com/path", "newhost.com/newpath", RouteType)
			Expect(result.Conditions).To(Equal([]*Condition{
				&Condition{
					Name:     "0",
					Equals:   true,
					Host:     true,
					HTTPHost: true,
					Index:    0,
					Request:  true,
					Values:   []string{"host.com"},
				},
				&Condition{
					Name:        "1",
					Equals:      true,
					HTTPURI:     true,
					Index:       1,
					PathSegment: true,
					Request:     true,
					Values:      []string{"path"},
				},
			}))
			Expect(result.Actions).To(Equal([]*Action{
				&Action{
					Name:     "0",
					HTTPHost: true,
					Replace:  true,
					Request:  true,
					Value:    "newhost.com",
				},
				&Action{
					Name:    "1",
					HTTPURI: true,
					Path:    "/path",
					Replace: true,
					Request: true,
					Value:   "tcl:[regsub /path [HTTP::uri] /newpath ]",
				},
			}))
		})

		It("merges and sorts rules correctly with matching Conditions", func() {
			mergedRulesMap := make(map[string]map[string]MergedRuleEntry)
			resourceConfig := &ResourceConfig{
				Virtual:  Virtual{Name: "test-virtual"},
				Policies: []Policy{Policy{Name: "test-policy", Controls: []string{"forwarding"}}},
			}

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
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:        "1",
						Equals:      true,
						PathSegment: true,
						Index:       1,
						Request:     true,
						Values:      []string{"bar"},
					},
				},
			}

			// url-rewrite path matches rule1 and rule3
			rule2 := &Rule{
				Name:    "url-rewrite-rule2",
				FullURI: "host.com/bar",
				Actions: []*Action{&Action{
					Name:    "0",
					HTTPURI: true,
					Path:    "/bar",
					Replace: true,
					Request: true,
					Value:   "/foobar",
				}},
				Conditions: []*Condition{
					&Condition{
						Name:     "0",
						Equals:   true,
						Host:     true,
						HTTPHost: true,
						Index:    0,
						Request:  true,
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:        "1",
						Equals:      true,
						PathSegment: true,
						Index:       1,
						Request:     true,
						Values:      []string{"bar"},
					},
				},
			}

			// forwarding rule matches rule1 and rule2
			rule3 := &Rule{
				Name:    "regular-rule1",
				FullURI: "host.com/bar",
				Actions: []*Action{&Action{
					Name:    "0",
					Pool:    "default-pool1",
					Forward: true,
				}},
				Conditions: []*Condition{
					&Condition{
						Name:     "0",
						Equals:   true,
						Host:     true,
						HTTPHost: true,
						Index:    0,
						Request:  true,
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:        "1",
						Equals:      true,
						PathSegment: true,
						Index:       1,
						Request:     true,
						Values:      []string{"bar"},
					},
				},
			}

			// forwarding rule does not match anything
			rule4 := &Rule{
				Name:    "regular-rule2",
				FullURI: "host.com/foo",
				Actions: []*Action{&Action{
					Name:    "0",
					Pool:    "default-pool2",
					Forward: true,
				}},
				Conditions: []*Condition{
					&Condition{
						Name:     "0",
						Equals:   true,
						Host:     true,
						HTTPHost: true,
						Index:    0,
						Request:  true,
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:        "1",
						Equals:      true,
						PathSegment: true,
						Index:       1,
						Request:     true,
						Values:      []string{"foo"},
					},
				},
			}

			// app-root forward rule does not match anything
			rule5 := &Rule{
				Name:    "app-root-forward-rule1",
				FullURI: "host.com/foo",
				Actions: []*Action{&Action{
					Name:    "0",
					Pool:    "default-pool3",
					Forward: true,
				}},
				Conditions: []*Condition{
					&Condition{
						Name:     "0",
						Equals:   true,
						Host:     true,
						HTTPHost: true,
						Index:    0,
						Request:  true,
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:    "1",
						Equals:  true,
						HTTPURI: true,
						Path:    true,
						Index:   1,
						Request: true,
						Values:  []string{"/buz"},
					},
				},
			}

			// forwarding rule does not match anything
			rule6 := &Rule{
				Name:    "regular-rule3",
				FullURI: "host.com/foo/baz",
				Actions: []*Action{&Action{
					Name:    "0",
					Pool:    "default-pool4",
					Forward: true,
				}},
				Conditions: []*Condition{
					&Condition{
						Name:     "0",
						Equals:   true,
						Host:     true,
						HTTPHost: true,
						Index:    0,
						Request:  true,
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:        "1",
						Equals:      true,
						PathSegment: true,
						Index:       1,
						Request:     true,
						Values:      []string{"foo"},
					},
					&Condition{
						Name:        "2",
						Equals:      true,
						PathSegment: true,
						Index:       2,
						Request:     true,
						Values:      []string{"baz"},
					},
				},
			}

			// app-root redirect rule
			rule7 := &Rule{
				Name:    "app-root-redirect-rule1",
				FullURI: "host.com/foo",
				Actions: []*Action{&Action{
					Name:     "0",
					Location: "/buz",
					Redirect: true,
				}},
				Conditions: []*Condition{
					&Condition{
						Name:     "0",
						Equals:   true,
						Host:     true,
						HTTPHost: true,
						Index:    0,
						Request:  true,
						Values:   []string{"host.com"},
					},
					&Condition{
						Name:    "1",
						Equals:  true,
						HTTPURI: true,
						Path:    true,
						Index:   1,
						Request: true,
						Values:  []string{"/"},
					},
				},
			}

			resourceConfig.Policies[0].Rules = []*Rule{rule1, rule2, rule3, rule4, rule5, rule6, rule7}
			resourceConfig.MergeRules(mergedRulesMap)

			// app-root redirects are sorted first
			Expect(len(resourceConfig.Policies[0].Rules)).To(Equal(5))
			Expect(resourceConfig.Policies[0].Rules[0].Name).To(Equal(rule7.Name))
			Expect(resourceConfig.Policies[0].Rules[0].Ordinal).To(Equal(0))
			Expect(resourceConfig.Policies[0].Rules[0].Actions).To(Equal(rule7.Actions))
			Expect(resourceConfig.Policies[0].Rules[0].Conditions).To(Equal(rule7.Conditions))

			// app-root forwards are sorted next
			Expect(resourceConfig.Policies[0].Rules[1].Name).To(Equal(rule5.Name))
			Expect(resourceConfig.Policies[0].Rules[1].Ordinal).To(Equal(1))
			Expect(resourceConfig.Policies[0].Rules[1].Actions).To(Equal(rule5.Actions))
			Expect(resourceConfig.Policies[0].Rules[1].Conditions).To(Equal(rule5.Conditions))

			// longest URI regular forward rules are sorted next
			Expect(resourceConfig.Policies[0].Rules[2].Name).To(Equal(rule6.Name))
			Expect(resourceConfig.Policies[0].Rules[2].Ordinal).To(Equal(2))
			Expect(resourceConfig.Policies[0].Rules[2].Actions).To(Equal(rule6.Actions))
			Expect(resourceConfig.Policies[0].Rules[2].Conditions).To(Equal(rule6.Conditions))

			// alphabetically greater URI regular forward rules are sorted next
			Expect(resourceConfig.Policies[0].Rules[3].Name).To(Equal(rule4.Name))
			Expect(resourceConfig.Policies[0].Rules[3].Ordinal).To(Equal(3))
			Expect(resourceConfig.Policies[0].Rules[3].Actions).To(Equal(rule4.Actions))
			Expect(resourceConfig.Policies[0].Rules[3].Conditions).To(Equal(rule4.Conditions))

			// shortest and alphabetically least URI regular forward rule
			Expect(resourceConfig.Policies[0].Rules[4].Name).To(Equal(rule3.Name))
			Expect(resourceConfig.Policies[0].Rules[4].Ordinal).To(Equal(4))
			Expect(resourceConfig.Policies[0].Rules[4].Actions).To(Equal([]*Action{rule3.Actions[0], rule1.Actions[0], rule2.Actions[0]}))
			Expect(resourceConfig.Policies[0].Rules[4].Conditions).To(Equal(rule3.Conditions))

			// Merged rules map entry for rule3 (Merger)
			Expect(len(mergedRulesMap["test-virtual"])).To(Equal(3))
			Expect(mergedRulesMap["test-virtual"][rule3.Name].RuleName).To(Equal(rule3.Name))
			Expect(mergedRulesMap["test-virtual"][rule3.Name].OtherRuleNames).To(Equal([]string{rule2.Name, rule1.Name}))
			Expect(mergedRulesMap["test-virtual"][rule3.Name].MergedActions[rule2.Name]).To(Equal([]*Action{rule2.Actions[0]}))
			Expect(mergedRulesMap["test-virtual"][rule3.Name].MergedActions[rule1.Name]).To(Equal([]*Action{rule1.Actions[0]}))
			Expect(mergedRulesMap["test-virtual"][rule3.Name].OriginalRule).To(Equal(rule3))

			// Merged rules map entry for rule2 (Mergee)
			Expect(mergedRulesMap["test-virtual"][rule2.Name].RuleName).To(Equal(rule2.Name))
			Expect(mergedRulesMap["test-virtual"][rule2.Name].OtherRuleNames).To(Equal([]string{rule3.Name}))
			Expect(len(mergedRulesMap["test-virtual"][rule2.Name].MergedActions)).To(Equal(0))
			Expect(mergedRulesMap["test-virtual"][rule2.Name].OriginalRule).To(Equal(rule2))

			// Merged rules map entry for rule1 (Mergee)
			Expect(mergedRulesMap["test-virtual"][rule1.Name].RuleName).To(Equal(rule1.Name))
			Expect(mergedRulesMap["test-virtual"][rule1.Name].OtherRuleNames).To(Equal([]string{rule3.Name}))
			Expect(len(mergedRulesMap["test-virtual"][rule1.Name].MergedActions)).To(Equal(0))
			Expect(mergedRulesMap["test-virtual"][rule1.Name].OriginalRule).To(Equal(rule1))

			// Unmerge merger rule3
			resourceConfig.UnmergeRule(rule3.Name, mergedRulesMap)
			Expect(len(mergedRulesMap["test-virtual"])).To(Equal(2))
			Expect(mergedRulesMap["test-virtual"][rule3.Name]).To(Equal(MergedRuleEntry{}))
			Expect(mergedRulesMap["test-virtual"][rule1.Name].RuleName).To(Equal(rule1.Name))
			Expect(mergedRulesMap["test-virtual"][rule1.Name].OtherRuleNames).To(Equal([]string{rule2.Name}))
			Expect(len(mergedRulesMap["test-virtual"][rule1.Name].MergedActions)).To(Equal(1))
			Expect(mergedRulesMap["test-virtual"][rule1.Name].MergedActions[rule2.Name]).To(Equal([]*Action{rule2.Actions[0]}))
			Expect(mergedRulesMap["test-virtual"][rule1.Name].OriginalRule).To(Equal(rule1))
			Expect(mergedRulesMap["test-virtual"][rule2.Name].RuleName).To(Equal(rule2.Name))
			Expect(mergedRulesMap["test-virtual"][rule2.Name].OtherRuleNames).To(Equal([]string{rule1.Name}))
			Expect(len(mergedRulesMap["test-virtual"][rule2.Name].MergedActions)).To(Equal(0))
			Expect(mergedRulesMap["test-virtual"][rule2.Name].OriginalRule).To(Equal(rule2))

			// Verify first rule has not changed
			Expect(len(resourceConfig.Policies[0].Rules)).To(Equal(5))
			Expect(resourceConfig.Policies[0].Rules[0].Name).To(Equal(rule7.Name))
			Expect(resourceConfig.Policies[0].Rules[0].Ordinal).To(Equal(0))
			Expect(resourceConfig.Policies[0].Rules[0].Actions).To(Equal(rule7.Actions))
			Expect(resourceConfig.Policies[0].Rules[0].Conditions).To(Equal(rule7.Conditions))

			// Verify second rule has not changed
			Expect(resourceConfig.Policies[0].Rules[1].Name).To(Equal(rule5.Name))
			Expect(resourceConfig.Policies[0].Rules[1].Ordinal).To(Equal(1))
			Expect(resourceConfig.Policies[0].Rules[1].Actions).To(Equal(rule5.Actions))
			Expect(resourceConfig.Policies[0].Rules[1].Conditions).To(Equal(rule5.Conditions))

			// Verify rule1 (url-rewrite) has been sorted in front of non-matching regular forwarding rules
			Expect(resourceConfig.Policies[0].Rules[2].Name).To(Equal(rule1.Name))
			Expect(resourceConfig.Policies[0].Rules[2].Ordinal).To(Equal(2))
			Expect(resourceConfig.Policies[0].Rules[2].Actions).To(Equal([]*Action{rule1.Actions[0], rule2.Actions[0]}))
			Expect(resourceConfig.Policies[0].Rules[2].Conditions).To(Equal(rule1.Conditions))

			// Verify rule6 (longest URI) was sorted behind url-rewrite but ahead of shorter URIs
			Expect(resourceConfig.Policies[0].Rules[3].Name).To(Equal(rule6.Name))
			Expect(resourceConfig.Policies[0].Rules[3].Ordinal).To(Equal(3))
			Expect(resourceConfig.Policies[0].Rules[3].Actions).To(Equal(rule6.Actions))
			Expect(resourceConfig.Policies[0].Rules[3].Conditions).To(Equal(rule6.Conditions))

			// Verify last rule is the shorted URI rule
			Expect(resourceConfig.Policies[0].Rules[4].Name).To(Equal(rule4.Name))
			Expect(resourceConfig.Policies[0].Rules[4].Ordinal).To(Equal(4))
			Expect(resourceConfig.Policies[0].Rules[4].Actions).To(Equal(rule4.Actions))
			Expect(resourceConfig.Policies[0].Rules[4].Conditions).To(Equal(rule4.Conditions))

			// Verify calling UnmergeRule on an unmerged rule does nothing
			result := resourceConfig.UnmergeRule(rule7.Name, mergedRulesMap)
			Expect(len(resourceConfig.Policies[0].Rules)).To(Equal(5))
			Expect(result).To(BeFalse())

			// Verify calling UnmergeRule on an already unmerged rule does nothing
			result = resourceConfig.UnmergeRule(rule3.Name, mergedRulesMap)
			Expect(len(resourceConfig.Policies[0].Rules)).To(Equal(5))
			Expect(result).To(BeFalse())

			// Unmerge mergee rule2
			resourceConfig.UnmergeRule(rule2.Name, mergedRulesMap)
			Expect(len(mergedRulesMap["test-virtual"])).To(Equal(0))
			Expect(len(resourceConfig.Policies[0].Rules)).To(Equal(5))

			// Verify second rule has not changed
			Expect(resourceConfig.Policies[0].Rules[1].Name).To(Equal(rule5.Name))
			Expect(resourceConfig.Policies[0].Rules[1].Ordinal).To(Equal(1))
			Expect(resourceConfig.Policies[0].Rules[1].Actions).To(Equal(rule5.Actions))
			Expect(resourceConfig.Policies[0].Rules[1].Conditions).To(Equal(rule5.Conditions))

			// Verify rule2 has been unmerged from rule1
			Expect(resourceConfig.Policies[0].Rules[2].Name).To(Equal(rule1.Name))
			Expect(resourceConfig.Policies[0].Rules[2].Ordinal).To(Equal(2))
			Expect(resourceConfig.Policies[0].Rules[2].Actions).To(Equal(rule1.Actions))
			Expect(resourceConfig.Policies[0].Rules[2].Conditions).To(Equal(rule1.Conditions))

			// Verify fourth rule has not changed
			Expect(resourceConfig.Policies[0].Rules[3].Name).To(Equal(rule6.Name))
			Expect(resourceConfig.Policies[0].Rules[3].Ordinal).To(Equal(3))
			Expect(resourceConfig.Policies[0].Rules[3].Actions).To(Equal(rule6.Actions))
			Expect(resourceConfig.Policies[0].Rules[3].Conditions).To(Equal(rule6.Conditions))

			// Verify last rule has not changed
			Expect(resourceConfig.Policies[0].Rules[4].Name).To(Equal(rule4.Name))
			Expect(resourceConfig.Policies[0].Rules[4].Ordinal).To(Equal(4))
			Expect(resourceConfig.Policies[0].Rules[4].Actions).To(Equal(rule4.Actions))
			Expect(resourceConfig.Policies[0].Rules[4].Conditions).To(Equal(rule4.Conditions))

			// Verify unmerging a rule that has been unmerged does nothing
			result = resourceConfig.UnmergeRule(rule1.Name, mergedRulesMap)
			Expect(len(resourceConfig.Policies[0].Rules)).To(Equal(5))
			Expect(result).To(BeFalse())
		})
	})
	Describe("Configmap Manipulation", func() {
		It("properly handles ConfigMap keys ", func() {
			var cfg ResourceConfig
			var key = ServiceKey{
				ServiceName: "svc",
				ServicePort: 80,
				Namespace:   "ns",
			}
			cfg.Pools = append(cfg.Pools, Pool{})
			cfg.Pools[0].ServiceName = key.ServiceName
			cfg.Pools[0].ServicePort = key.ServicePort
			cfg.Virtual.Name = "cm_Name"
			cfg.Virtual.SetVirtualAddress("10.0.0.1", 80, false)

			workingDir, _ := os.Getwd()
			schemaUrl := "file://" + workingDir + "/../../schemas/bigip-virtual-server_v0.1.7.json"
			DEFAULT_PARTITION = "velcro"
			var configPath = "../test/configs/"
			var configmapFoo = test.ReadConfigFile(configPath + "configmapFoo.json")

			// Config map with no schema key
			noschemakey := test.NewConfigMap("noschema", "1", key.Namespace,
				map[string]string{"data": configmapFoo})
			cfgmap, err := ParseConfigMap(noschemakey, "", "")
			Expect(err.Error()).To(Equal("configmap noschema does not contain schema key"),
				"Should receive 'no schema' error.")

			// Config map with no data key
			nodatakey := test.NewConfigMap("nodata", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
			})
			cfgmap, err = ParseConfigMap(nodatakey, "", "")
			Expect(cfgmap).To(BeNil(), "Should not have parsed bad configmap.")
			Expect(err.Error()).To(Equal("configmap nodata does not contain data key"),
				"Should receive 'no data' error.")

			// Config map with bad json
			badjson := test.NewConfigMap("badjson", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
				"data":   "///// **invalid json** /////",
			})
			cfgmap, err = ParseConfigMap(badjson, "", "")
			Expect(cfgmap).To(BeNil(), "Should not have parsed bad configmap.")
			Expect(err.Error()).To(Equal(
				"invalid character '/' looking for beginning of value"))

			// Config map with invalid schemapath
			badjson = test.NewConfigMap("badjson", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
				"data":   "///// **invalid json** /////",
			})
			cfgmap, err = ParseConfigMap(badjson, "junkdbpath", "")
			Expect(cfgmap).To(BeNil(), "Should not have parsed bad configmap.")
			Expect(err.Error()).To(Equal(
				"invalid character '/' looking for beginning of value"))

			// Config map with extra keys
			extrakeys := test.NewConfigMap("extrakeys", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo,
				"key1":   "value1",
				"key2":   "value2",
			})
			cfgmap, err = ParseConfigMap(extrakeys, "", "")
			Expect(cfgmap).ToNot(BeNil(), "Config map should parse with extra keys.")
			Expect(err).To(BeNil(), "Should not receive errors.")

			// Config map with no mode or balance
			var configmapNoModeBalance = test.ReadConfigFile(configPath + "configmapNoModeBalance.json")
			defaultModeAndBalance := test.NewConfigMap("mode_balance", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapNoModeBalance,
			})
			cfgmap, err = ParseConfigMap(defaultModeAndBalance, "", "")
			Expect(cfgmap).ToNot(BeNil(), "Config map should exist and contain default mode and balance.")
			Expect(err).To(BeNil(), "Should not receive errors.")

			// Normal config map with source address translation set
			setSourceAddrTranslation := test.NewConfigMap("source_addr_translation", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo,
			})
			cfgmap, err = ParseConfigMap(setSourceAddrTranslation, "", "test-snat-pool")
			Expect(cfgmap).ToNot(BeNil(), "Config map should exist and contain default mode and balance.")
			Expect(err).To(BeNil(), "Should not receive errors.")
			Expect(cfgmap.Virtual.SourceAddrTranslation).To(Equal(SourceAddrTranslation{
				Type: "snat",
				Pool: "test-snat-pool",
			}))

			//Normal Configmap with iapp
			var cfgMapiApp ConfigMap
			configmapiAPP := test.ReadConfigFile(configPath + "configmapIApp1.json")
			cfgIAPP := test.NewConfigMap("source_addr_translation", "1", key.Namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapiAPP,
			})
			FormatConfigMapVSName(cfgIAPP)
			json.Unmarshal([]byte(cfgIAPP.Data["data"]), &cfgMapiApp)
			cfgmap, err = ParseConfigMap(cfgIAPP, "", "test-snat-pool")
			Expect(cfgmap).ToNot(BeNil(), "Config map should exist and contain default mode and balance.")
			Expect(err).To(BeNil(), "Should not receive errors.")
			Expect(cfgmap.IApp.IApp).To(Equal(cfgMapiApp.VirtualServer.Frontend.IApp))
			Expect(cfgmap.GetPartition()).To(Equal(cfgMapiApp.VirtualServer.Frontend.Partition))
			Expect(cfgmap.GetName()).To(Equal("ns_source_addr_translation"))

		})

	})

	Describe("Verify ResourceConfig Helper functions", func() {

		It("Test GetNameRef", func() {
			cfg := ResourceConfig{
				Virtual: Virtual{Name: "vs1", Partition: "test"},
			}
			Expect(cfg.GetNameRef()).To(Equal(NameRef{Name: "vs1", Partition: "test"}))
		})

		It("Test GetByName", func() {
			rs := &Resources{
				RsMap: make(map[NameRef]*ResourceConfig),
			}
			rs.RsMap[NameRef{Name: "vs1", Partition: "test"}] = &ResourceConfig{}
			resource, ok := rs.GetByName(NameRef{Name: "vs1", Partition: "test"})
			Expect(ok).To(BeTrue())
			Expect(resource).NotTo(BeNil())
		})

		It("Test FormatRoutePoolName", func() {
			Expect(FormatRoutePoolName("default", "svc1")).To(Equal("openshift_default_svc1"))
		})

		It("Test DeleteWhitelistCondition", func() {
			policy := Policy{
				Name:     "policy1",
				Strategy: "first-match",
				Rules: Rules{
					&Rule{
						Name: "test-reset",
						Conditions: []*Condition{
							{},
						},
					},
				},
			}
			cfg := ResourceConfig{
				Policies: Policies{
					policy,
				},
			}
			cfg.DeleteWhitelistCondition()
			Expect(len(cfg.Policies)).To(Equal(1))
			Expect(len(cfg.Policies[0].Rules)).To(Equal(0))
			Expect(policy.RemoveRuleAt(2)).To(BeFalse())

		})
		It("Test MakeCertificateFileName", func() {
			Expect(MakeCertificateFileName("test", "")).To(Equal(".crt"))
			Expect(MakeCertificateFileName("test", "cert1")).To(Equal("/test/cert1.crt"))
		})
		It("Test ExtractCertificateName", func() {
			Expect(ExtractCertificateName("test/cert1.crt")).To(Equal("cert1"))
		})
		It("Test FormatIngressSslProfileName", func() {
			Expect(FormatIngressSslProfileName("default/secret1")).To(Equal("default/secret1"))
			Expect(FormatIngressSslProfileName("secret1")).To(Equal("secret1"))
			Expect(FormatIngressSslProfileName("a/b/c")).To(Equal("a/b/c"))
		})
		It("Test ConvertStringToProfileRef", func() {
			Expect(ConvertStringToProfileRef("prof1", "bigip", "test")).To(Equal(ProfileRef{Name: "prof1", Context: "bigip", Partition: DEFAULT_PARTITION, Namespace: "test"}))
			Expect(ConvertStringToProfileRef("a/b/c", "bigip", "test")).To(Equal(ProfileRef{Context: "bigip", Namespace: "test"}))
		})
		It("Test NewCustomProfiles", func() {
			Expect(NewCustomProfiles().Profs).NotTo(BeNil())
		})
		It("Test AgentCfgMap Init", func() {
			cm := &AgentCfgMap{}
			label := make(map[string]string)
			getEP := func(string, string) ([]Member, error) { return nil, nil }
			cm.Init("test1", "default", "", label, getEP)
			Expect(cm.Name).To(Equal("test1"))
			Expect(cm.Namespace).To(Equal("default"))
		})
		It("Test UpdatePolicy", func() {
			rs := &Resources{
				RsMap: make(map[NameRef]*ResourceConfig),
			}
			policy := Policy{
				Name:     "plc1",
				Strategy: "first-match",
				Rules: Rules{
					&Rule{
						Name: "rule1",
						Conditions: []*Condition{
							{},
						},
					},
				},
			}
			cfg := &ResourceConfig{
				Policies: Policies{
					policy,
				},
			}
			nr := NameRef{Name: "vs1", Partition: "test"}
			rs.RsMap[nr] = cfg
			policyName := "plc1"
			ruleName := "rule1"
			rs.UpdatePolicy(nr, policyName, ruleName)
			Expect(rs.RsMap[nr]).NotTo(BeNil())
			Expect(len(rs.RsMap[nr].Policies)).To(Equal(1))
			Expect(len(rs.RsMap[nr].Policies[0].Rules)).To(Equal(0))
		})
		It("Test DeleteKeyRef", func() {
			rs := &Resources{
				RsMap: make(map[NameRef]*ResourceConfig),
				rm:    make(map[ServiceKey]resourceList),
			}
			cfg := &ResourceConfig{}
			nr := NameRef{Name: "vs1", Partition: "test"}
			rs.RsMap[nr] = cfg
			sKey := ServiceKey{ServiceName: "svc1"}
			nameRef := NameRef{Name: "test1"}
			Expect(rs.DeleteKeyRef(sKey, nameRef)).To(BeFalse())

			rs.rm[sKey] = make(map[NameRef]bool)
			Expect(rs.DeleteKeyRef(sKey, nameRef)).To(BeFalse())
			rs.rm[sKey][nameRef] = true
			Expect(rs.DeleteKeyRef(sKey, nameRef)).To(BeTrue())

		})

		It("Test GetAllWithName", func() {
			rs := &Resources{
				RsMap: make(map[NameRef]*ResourceConfig),
				rm:    make(map[ServiceKey]resourceList),
			}
			cfg := &ResourceConfig{Virtual: Virtual{Name: "vs1", Partition: "test"}}
			nr := NameRef{Name: "vs1", Partition: "test"}
			rs.RsMap[nr] = cfg
			rs.rm = make(map[ServiceKey]resourceList)
			svcKey := ServiceKey{ServiceName: "svc1"}
			rs.rm[svcKey] = make(map[NameRef]bool)
			rs.rm[svcKey][nr] = true
			cfgs, keys := rs.GetAllWithName(nr)
			Expect(len(cfgs)).To(Equal(1))
			Expect(len(keys)).To(Equal(1))
		})

		It("Test InternalDataGroupRecords Sorting", func() {
			dg := InternalDataGroupRecords([]InternalDataGroupRecord{
				{Name: "test1", Data: "data1"},
				{Name: "test3", Data: "data3"},
				{Name: "test2", Data: "data2"},
			})
			sort.Sort(dg)
			expectedDG := InternalDataGroupRecords([]InternalDataGroupRecord{
				{Name: "test1", Data: "data1"},
				{Name: "test2", Data: "data2"},
				{Name: "test3", Data: "data3"},
			})
			Expect(dg).To(Equal(expectedDG))
		})

		It("Test GetServicePort", func() {
			// svc in test namespace
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			fooPorts := []v1.ServicePort{{Port: 80}}
			svc1 := test.NewService("svc1", "1", "test", "Cluster", fooPorts)
			err1 := indexer.Add(svc1)
			Expect(err1).To(BeNil())
			port, err := GetServicePort("default", "svc1", indexer, "", ResourceTypeRoute)
			Expect(err).NotTo(BeNil())
			Expect(port).To(Equal(int32(0)))

			// svc in default namespace
			svc2 := test.NewService("svc2", "1", "default", "Cluster", fooPorts)
			err1 = indexer.Add(svc2)
			Expect(err1).To(BeNil())
			port, err = GetServicePort("default", "svc2", indexer, "", ResourceTypeRoute)
			Expect(err).To(BeNil())
			Expect(port).To(Equal(int32(80)))

			// Invalid case with portname
			port, err = GetServicePort("default", "svc2", indexer, "port1", ResourceTypeRoute)
			Expect(err).NotTo(BeNil())
			Expect(port).To(Equal(int32(0)))

			// Valid case with portname
			fooPorts = []v1.ServicePort{{Port: 80, Name: "port1"}}
			svc3 := test.NewService("svc3", "1", "default", "Cluster", fooPorts)
			err1 = indexer.Add(svc3)
			Expect(err1).To(BeNil())
			port, err = GetServicePort("default", "svc3", indexer, "port1", ResourceTypeRoute)
			Expect(err).To(BeNil())
			Expect(port).To(Equal(int32(80)))
		})

		It("Test Contains", func() {
			Expect(Contains(nil, nil)).To(BeFalse())
			Expect(Contains("a", "a")).To(BeFalse())
			Expect(Contains([]string{"a"}, []string{"b"})).To(BeFalse())
			Expect(Contains([]string{"a"}, []string{"a"})).To(BeFalse())
			Expect(Contains([]string{}, "")).To(BeFalse())
			Expect(Contains([]string{"a"}, "a")).To(BeTrue())
		})

		It("Test IsAnnotationRule", func() {
			Expect(IsAnnotationRule("app-root")).To(BeTrue())
			Expect(IsAnnotationRule("rule1")).To(BeFalse())
		})

		It("Test SetAnnotationRulesForRoute", func() {
			urlRewriteRule := &Rule{}
			rc := &ResourceConfig{
				Policies: []Policy{
					{
						Name:     "plc1",
						Strategy: "first-match",
					},
				},
			}
			SetAnnotationRulesForRoute("plc1", urlRewriteRule, nil, rc, false)
			Expect(len(rc.Policies[0].Rules)).To(Equal(1))

			appRootRules := []*Rule{
				&Rule{Name: "rule1"},
				&Rule{Name: "rule2"},
			}
			rc = &ResourceConfig{
				Policies: []Policy{
					{
						Name:     "plc1",
						Strategy: "first-match",
					},
				},
			}
			SetAnnotationRulesForRoute("plc1", nil, appRootRules, rc, false)
			Expect(len(rc.Policies[0].Rules)).To(Equal(2))

		})
	})

})
