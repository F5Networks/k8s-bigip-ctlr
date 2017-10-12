/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
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

package appmanager

import (
	"fmt"
	"sort"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

type simpleTestConfig struct {
	name string
	addr virtualAddress
}

type resourceMap map[serviceKey][]simpleTestConfig

func newServiceKey(svcPort int32, svcName, namespace string) serviceKey {
	return serviceKey{
		ServiceName: svcName,
		ServicePort: svcPort,
		Namespace:   namespace,
	}
}

func newResourceConfig(
	key serviceKey, rsName string,
	bindAddr string, bindPort int32) *ResourceConfig {
	var cfg ResourceConfig
	cfg.Pools = append(cfg.Pools, Pool{})
	cfg.Pools[0].ServiceName = key.ServiceName
	cfg.Pools[0].ServicePort = key.ServicePort
	cfg.Virtual.VirtualServerName = rsName
	cfg.Virtual.VirtualAddress = new(virtualAddress)
	cfg.Virtual.VirtualAddress.BindAddr = bindAddr
	cfg.Virtual.VirtualAddress.Port = bindPort
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
			addr := virtualAddress{"10.0.0.1", int32(bindPort + j)}
			rm[svcKey] = append(rm[svcKey], simpleTestConfig{cfgName, addr})
		}
	}
	return &rm
}

func assignTestMap(rs *Resources, rm *resourceMap) {
	for key, val := range *rm {
		for _, tf := range val {
			rs.Assign(key, tf.name, newResourceConfig(
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
			v.VirtualServerName = "foo"
			virtuals = append(virtuals, v)
			expectedList[1] = v

			v = Virtual{}
			v.Partition = "a"
			v.VirtualServerName = "bar"
			virtuals = append(virtuals, v)
			expectedList[0] = v

			v = Virtual{}
			v.Partition = "c"
			v.VirtualServerName = "bar"
			virtuals = append(virtuals, v)
			expectedList[3] = v

			v = Virtual{}
			v.Partition = "c"
			v.VirtualServerName = "foo"
			virtuals = append(virtuals, v)
			expectedList[4] = v

			v = Virtual{}
			v.Partition = "b"
			v.VirtualServerName = "bar"
			virtuals = append(virtuals, v)
			expectedList[2] = v

			sort.Sort(virtuals)

			for i, _ := range expectedList {
				Expect(virtuals[i]).To(Equal(expectedList[i]),
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

			sort.Sort(pools)

			for i, _ := range expectedList {
				Expect(pools[i]).To(Equal(expectedList[i]),
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

			sort.Sort(monitors)

			for i, _ := range expectedList {
				Expect(monitors[i]).To(Equal(expectedList[i]),
					"Sorted list elements should be equal.")
			}
		})

		It("creates new resources", func() {
			// Test that we can create a new/empty resources object.
			rs := NewResources()
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

		It("can count all resources", func() {
			// Test Count() to make sure we count all items
			Expect(rs.Count()).To(Equal(nbrBackends * nbrCfgsPer))
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
					ok := rs.Delete(key, tf.name)
					Expect(ok).To(BeTrue())
					countAfter := rs.CountOf(key)
					Expect(countAfter).To(Equal(countBefore - 1))
					// Test double-delete fails correctly
					ok = rs.Delete(key, tf.name)
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
			rs.ForEach(func(key serviceKey, cfg *ResourceConfig) {
				totalConfigs += 1
				testObj := (*rm)[key]
				Expect(testObj).ToNot(BeNil())
				found := false
				for _, val := range testObj {
					if val.name == cfg.Virtual.VirtualServerName {
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
					r, ok := rs.Get(key, tf.name)
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
				rsCfgMap, ok := rs.GetAll(key)
				Expect(ok).To(BeTrue())
				Expect(rsCfgMap).ToNot(BeNil())
				Expect(len(rsCfgMap)).To(Equal(nbrCfgsPer))
			}
		})
	})

	Describe("Config Manipulation", func() {
		It("configures ssl profile names", func() {
			var rs ResourceConfig
			// verify initial state
			Expect(rs.Virtual.SslProfile).To(BeNil())
			empty := []string{}
			Expect(rs.Virtual.GetFrontendSslProfileNames()).To(Equal(empty))

			// set a name and make sure it is saved
			profileName := "profileName"
			rs.Virtual.AddFrontendSslProfileName(profileName)
			Expect(rs.Virtual.SslProfile).ToNot(BeNil())
			Expect(rs.Virtual.SslProfile.F5ProfileName).To(Equal(profileName))
			Expect(rs.Virtual.GetFrontendSslProfileNames()).To(Equal([]string{profileName}))

			// add a second profile
			newProfileName := "newProfileName"
			rs.Virtual.AddFrontendSslProfileName(newProfileName)
			Expect(rs.Virtual.SslProfile).ToNot(BeNil())
			Expect(rs.Virtual.SslProfile.F5ProfileName).To(Equal(""))
			Expect(rs.Virtual.SslProfile.F5ProfileNames).To(
				Equal([]string{newProfileName, profileName}))
			Expect(rs.Virtual.GetFrontendSslProfileNames()).To(
				Equal([]string{newProfileName, profileName}))

			// Remove both profiles and make sure the pointer goes back to nil
			r := rs.Virtual.RemoveFrontendSslProfileName(profileName)
			Expect(r).To(BeTrue())
			Expect(rs.Virtual.SslProfile.F5ProfileName).To(Equal(newProfileName))
			Expect(rs.Virtual.GetFrontendSslProfileNames()).To(Equal([]string{newProfileName}))
			r = rs.Virtual.RemoveFrontendSslProfileName(newProfileName)
			Expect(r).To(BeTrue())
			Expect(rs.Virtual.SslProfile).To(BeNil())
			Expect(rs.Virtual.GetFrontendSslProfileNames()).To(Equal(empty))
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
			toRemove := nameRef{
				Name:      policy1.Name,
				Partition: policy1.Partition,
			}
			rc.RemovePolicy(toRemove)
			lenValidate(1)
			Expect(rc.Policies[0].Name).To(Equal("policy2"))

			// remove last policy
			toRemove.Name = policy2.Name
			toRemove.Partition = policy2.Partition
			rc.RemovePolicy(toRemove)
			lenValidate(0)

			// make sure deleting something that isn't there doesn't fail badly
			rc.RemovePolicy(toRemove)
			lenValidate(0)
		})

		It("properly configures ingress resources", func() {
			namespace := "default"
			ingressConfig := v1beta1.IngressSpec{
				Backend: &v1beta1.IngressBackend{
					ServiceName: "foo",
					ServicePort: intstr.IntOrString{IntVal: 80},
				},
			}
			ingress := test.NewIngress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					"virtual-server.f5.com/ip":        "1.2.3.4",
					"virtual-server.f5.com/partition": "velcro",
				})
			ps := portStruct{
				protocol: "http",
				port:     80,
			}
			cfg := createRSConfigFromIngress(ingress, namespace, nil, ps)
			Expect(cfg.Pools[0].Balance).To(Equal("round-robin"))
			Expect(cfg.Virtual.Mode).To(Equal("http"))
			Expect(cfg.Virtual.Partition).To(Equal("velcro"))
			Expect(cfg.Virtual.VirtualAddress.BindAddr).To(Equal("1.2.3.4"))
			Expect(cfg.Virtual.VirtualAddress.Port).To(Equal(int32(80)))

			ingress = test.NewIngress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					"virtual-server.f5.com/ip":        "1.2.3.4",
					"virtual-server.f5.com/partition": "velcro",
					"virtual-server.f5.com/http-port": "100",
					"virtual-server.f5.com/balance":   "foobar",
					"kubernetes.io/ingress.class":     "f5",
				})
			ps = portStruct{
				protocol: "http",
				port:     100,
			}
			cfg = createRSConfigFromIngress(ingress, namespace, nil, ps)
			Expect(cfg.Pools[0].Balance).To(Equal("foobar"))
			Expect(cfg.Virtual.VirtualAddress.Port).To(Equal(int32(100)))

			ingress = test.NewIngress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					"kubernetes.io/ingress.class": "notf5",
				})
			cfg = createRSConfigFromIngress(ingress, namespace, nil, ps)
			Expect(cfg).To(BeNil())
		})

		It("properly configures route resources", func() {
			namespace := "default"
			spec := routeapi.RouteSpec{
				Host: "foobar.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				Port: &routeapi.RoutePort{
					TargetPort: intstr.FromInt(80),
				},
				TLS: &routeapi.TLSConfig{
					Termination: "edge",
					Certificate: "cert",
					Key:         "key",
				},
			}
			route := test.NewRoute("route", "1", namespace, spec, nil)
			ps := portStruct{
				protocol: "https",
				port:     443,
			}
			rc := RouteConfig{
				HttpVs:  "ose-vserver",
				HttpsVs: "https-ose-vserver",
			}
			cfg, _, _ := createRSConfigFromRoute(route, Resources{}, rc, ps, nil)
			Expect(cfg.Virtual.VirtualServerName).To(Equal("https-ose-vserver"))
			Expect(cfg.Pools[0].Name).To(Equal("openshift_default_foo"))
			Expect(cfg.Pools[0].ServiceName).To(Equal("foo"))
			Expect(cfg.Pools[0].ServicePort).To(Equal(int32(80)))
			Expect(cfg.Policies[0].Name).To(Equal("openshift_secure_routes"))
			Expect(cfg.Policies[0].Rules[0].Name).To(Equal("openshift_route_default_route"))

			spec = routeapi.RouteSpec{
				Host: "foobar.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				Port: &routeapi.RoutePort{
					TargetPort: intstr.FromInt(80),
				},
			}
			route2 := test.NewRoute("route2", "1", namespace, spec, nil)
			ps = portStruct{
				protocol: "http",
				port:     80,
			}
			cfg, _, _ = createRSConfigFromRoute(route2, Resources{}, rc, ps, nil)
			Expect(cfg.Virtual.VirtualServerName).To(Equal("ose-vserver"))
			Expect(cfg.Pools[0].Name).To(Equal("openshift_default_bar"))
			Expect(cfg.Pools[0].ServiceName).To(Equal("bar"))
			Expect(cfg.Pools[0].ServicePort).To(Equal(int32(80)))
			Expect(cfg.Policies[0].Name).To(Equal("openshift_insecure_routes"))
			Expect(cfg.Policies[0].Rules[0].Name).To(Equal("openshift_route_default_route2"))
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
				prof.Context = customProfileAll
				updated := virtual.AddOrUpdateProfile(prof)
				Expect(updated).To(BeTrue())
			}
			// Make sure updates with same data does not indicate an update.
			for _, prof := range testData {
				prof.Context = customProfileAll
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
			Expect(virtual.GetProfileCountByContext(customProfileAll)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(customProfileClient)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(customProfileServer)).To(Equal(0))

			// Test add. Add one profile of each type to Virtual.Profiles[].
			testData := []ProfileRef{
				{Partition: "test1", Name: "second", Context: customProfileAll},
				{Partition: "test2", Name: "first", Context: customProfileClient},
				{Partition: "test1", Name: "first", Context: customProfileServer},
			}
			for _, prof := range testData {
				updated := virtual.AddOrUpdateProfile(prof)
				Expect(updated).To(BeTrue())
			}
			Expect(virtual.GetProfileCountByContext(customProfileAll)).To(Equal(1))
			Expect(virtual.GetProfileCountByContext(customProfileClient)).To(Equal(1))
			Expect(virtual.GetProfileCountByContext(customProfileServer)).To(Equal(1))

			// Change existing items and check counts change correctly.
			for _, prof := range testData {
				prof.Context = customProfileServer
				virtual.AddOrUpdateProfile(prof)
			}
			Expect(virtual.GetProfileCountByContext(customProfileAll)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(customProfileClient)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(customProfileServer)).To(Equal(3))
			for _, prof := range testData {
				prof.Context = customProfileClient
				virtual.AddOrUpdateProfile(prof)
			}
			Expect(virtual.GetProfileCountByContext(customProfileAll)).To(Equal(0))
			Expect(virtual.GetProfileCountByContext(customProfileClient)).To(Equal(3))
			Expect(virtual.GetProfileCountByContext(customProfileServer)).To(Equal(0))

			// Add some frontend client profiles.
			virtual.AddFrontendSslProfileName("test3/firstprofile")
			Expect(virtual.GetProfileCountByContext(customProfileClient)).To(Equal(4))
			virtual.AddFrontendSslProfileName("test3/secondprofile")
			Expect(virtual.GetProfileCountByContext(customProfileClient)).To(Equal(5))
		})

		It("can tell which profile each virtual references", func() {
			virtual := Virtual{}

			testData := []ProfileRef{
				{Partition: "test1", Name: "second", Context: customProfileAll},
				{Partition: "test2", Name: "first", Context: customProfileClient},
				{Partition: "test1", Name: "first", Context: customProfileServer},
				{Partition: "test3", Name: "third", Context: customProfileClient},
			}
			for _, prof := range testData {
				cprof := NewCustomProfile(
					prof,
					"crt",
					"key",
					"srver",
					false,
					CustomProfileStore{})
				refs := virtual.ReferencesProfile(cprof)
				Expect(refs).To(BeFalse())
			}

			// add profiles from 'test1' to Profiles[] and 'test3' to frontend.
			for _, prof := range testData {
				switch prof.Partition {
				case "test1":
					virtual.AddOrUpdateProfile(prof)
				case "test3":
					profName := fmt.Sprintf("%s/%s", prof.Partition, prof.Name)
					virtual.AddFrontendSslProfileName(profName)
				}
			}

			for _, prof := range testData {
				switch prof.Partition {
				case "test1", "test3":
					cprof := NewCustomProfile(
						prof,
						"crt",
						"key",
						"srver",
						false,
						CustomProfileStore{},
					)
					refs := virtual.ReferencesProfile(cprof)
					Expect(refs).To(BeTrue())
				case "test2":
					cprof := NewCustomProfile(
						prof,
						"crt",
						"key",
						"srver",
						false,
						CustomProfileStore{})
					refs := virtual.ReferencesProfile(cprof)
					Expect(refs).To(BeFalse())
				}
			}
		})
	})
})
