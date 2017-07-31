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
	"testing"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestResourceSort(t *testing.T) {
	resources := ResourceConfigs{}

	expectedList := make(ResourceConfigs, 10)

	rs := ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "bar"
	rs.Pools[0].ServicePort = 80
	resources = append(resources, &rs)
	expectedList[1] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "foo"
	rs.Pools[0].ServicePort = 2
	resources = append(resources, &rs)
	expectedList[5] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "foo"
	rs.Pools[0].ServicePort = 8080
	resources = append(resources, &rs)
	expectedList[7] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "baz"
	rs.Pools[0].ServicePort = 1
	resources = append(resources, &rs)
	expectedList[2] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "foo"
	rs.Pools[0].ServicePort = 80
	resources = append(resources, &rs)
	expectedList[6] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "foo"
	rs.Pools[0].ServicePort = 9090
	resources = append(resources, &rs)
	expectedList[9] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "baz"
	rs.Pools[0].ServicePort = 1000
	resources = append(resources, &rs)
	expectedList[3] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "foo"
	rs.Pools[0].ServicePort = 8080
	resources = append(resources, &rs)
	expectedList[8] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "foo"
	rs.Pools[0].ServicePort = 1
	resources = append(resources, &rs)
	expectedList[4] = &rs

	rs = ResourceConfig{}
	rs.Pools = append(rs.Pools, Pool{})
	rs.Pools[0].ServiceName = "bar"
	rs.Pools[0].ServicePort = 1
	resources = append(resources, &rs)
	expectedList[0] = &rs

	sort.Sort(resources)

	for i, _ := range expectedList {
		require.EqualValues(t, expectedList[i], resources[i],
			"Sorted list elements should be equal")
	}
}

func TestNewResources(t *testing.T) {
	// Test that we can create a new/empty resources object.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)
	require.NotNil(rs.rm)
}

func TestAssign(t *testing.T) {
	// Test Assign() to make sure we can add multiple configs for a backend.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)

	// Make sure rs has the correct number of objects without using other
	// interface functions.
	require.Equal(nbrBackends, len(rs.rm))
	for _, rsCfgs := range rs.rm {
		assert.Equal(t, nbrCfgsPer, len(rsCfgs))
	}
}

func TestCount(t *testing.T) {
	// Test Count() to make sure we count all items
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)

	require.Equal(nbrBackends*nbrCfgsPer, rs.Count())
}

func TestCountOf(t *testing.T) {
	// Test CountOf() to make sure we count configs per backend correctly.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)
	require.Equal(nbrBackends, len(rs.rm))
	for key, _ := range *rm {
		assert.Equal(t, nbrCfgsPer, rs.CountOf(key))
	}
}

func TestDelete(t *testing.T) {
	// Test Delete() to make sure we can delete specific/all configs.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)

	// delete each config one at a time
	for key, val := range *rm {
		for _, tf := range val {
			countBefore := rs.CountOf(key)
			assert.True(t, countBefore > 0)
			ok := rs.Delete(key, tf.name)
			require.True(ok)
			countAfter := rs.CountOf(key)
			require.Equal(countBefore-1, countAfter)
			// Test double-delete fails correctly
			ok = rs.Delete(key, tf.name)
			require.False(ok)
			assert.Equal(t, countAfter, rs.CountOf(key))
		}
	}

	// should be completely empty now
	require.Equal(0, len(rs.rm))
}

func TestForEach(t *testing.T) {
	// Test ForEach() to make sure we can iterate over all configs.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)

	totalConfigs := 0
	rs.ForEach(func(key serviceKey, cfg *ResourceConfig) {
		totalConfigs += 1
		testObj := (*rm)[key]
		require.NotNil(testObj)
		found := false
		for _, val := range testObj {
			if val.name == cfg.Virtual.VirtualServerName {
				found = true
			}
		}
		assert.True(t, found)
	})
	require.Equal(nbrBackends*nbrCfgsPer, totalConfigs)
}

func TestGet(t *testing.T) {
	// Test Get() to make sure we can access specific configs.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)

	for key, val := range *rm {
		for _, tf := range val {
			r, ok := rs.Get(key, tf.name)
			require.True(ok)
			require.NotNil(rs)
			assert.Equal(t, tf.addr.BindAddr,
				r.Virtual.VirtualAddress.BindAddr)
			assert.Equal(t, tf.addr.Port,
				r.Virtual.VirtualAddress.Port)
		}
	}
}

func TestGetAll(t *testing.T) {
	// Test GetAll() to make sure we can get all configs.
	require := require.New(t)
	rs := NewResources()
	require.NotNil(rs)

	nbrBackends := 2
	nbrCfgsPer := 2
	rm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(rm)
	assignTestMap(rs, rm)

	for key, _ := range *rm {
		rsCfgMap, ok := rs.GetAll(key)
		require.True(ok)
		require.NotNil(rsCfgMap)
		assert.Equal(t, nbrCfgsPer, len(rsCfgMap))
	}
}

func TestSslProfileName(t *testing.T) {
	assert := assert.New(t)
	var rs ResourceConfig
	// verify initial state
	assert.Nil(rs.Virtual.SslProfile)
	empty := []string{}
	assert.Equal(empty, rs.Virtual.GetFrontendSslProfileNames())

	// set a name and make sure it is saved
	profileName := "profileName"
	rs.Virtual.AddFrontendSslProfileName(profileName)
	assert.NotNil(rs.Virtual.SslProfile)
	assert.Equal(profileName,
		rs.Virtual.SslProfile.F5ProfileName)
	assert.Equal([]string{profileName}, rs.Virtual.GetFrontendSslProfileNames())

	// add a second profile
	newProfileName := "newProfileName"
	rs.Virtual.AddFrontendSslProfileName(newProfileName)
	assert.NotNil(rs.Virtual.SslProfile)
	assert.Equal("", rs.Virtual.SslProfile.F5ProfileName)
	assert.Equal([]string{newProfileName, profileName},
		rs.Virtual.SslProfile.F5ProfileNames)
	assert.Equal([]string{newProfileName, profileName},
		rs.Virtual.GetFrontendSslProfileNames())

	// Remove both profiles and make sure the pointer goes back to nil
	r := rs.Virtual.RemoveFrontendSslProfileName(profileName)
	assert.True(r)
	assert.Equal(newProfileName,
		rs.Virtual.SslProfile.F5ProfileName)
	assert.Equal([]string{newProfileName}, rs.Virtual.GetFrontendSslProfileNames())
	r = rs.Virtual.RemoveFrontendSslProfileName(newProfileName)
	assert.True(r)
	assert.Nil(rs.Virtual.SslProfile)
	assert.Equal(empty, rs.Virtual.GetFrontendSslProfileNames())
}

func TestSetAndRemovePolicy(t *testing.T) {
	assert := assert.New(t)
	var rc ResourceConfig

	lenValidate := func(expectedLen int) {
		assert.Equal(expectedLen, len(rc.Virtual.Policies))
		assert.Equal(len(rc.Virtual.Policies), len(rc.Policies))
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
	assert.Equal("first-match", rc.Policies[0].Strategy)

	// change data in existing policy
	policy1.Strategy = "best-match"
	assert.Equal("first-match", rc.Policies[0].Strategy)
	rc.SetPolicy(policy1)
	lenValidate(1)
	assert.Equal("best-match", rc.Policies[0].Strategy)

	// add a second policy
	policy2 := Policy{
		Name:      "policy2",
		Partition: "k8s",
		Strategy:  "first-match",
	}
	rc.SetPolicy(policy2)
	lenValidate(2)

	// make sure it is appended
	assert.Equal("policy1", rc.Policies[0].Name)
	assert.Equal("policy2", rc.Policies[1].Name)

	// remove first policy
	toRemove := nameRef{
		Name:      policy1.Name,
		Partition: policy1.Partition,
	}
	rc.RemovePolicy(toRemove)
	lenValidate(1)
	assert.Equal("policy2", rc.Policies[0].Name)

	// remove last policy
	toRemove.Name = policy2.Name
	toRemove.Partition = policy2.Partition
	rc.RemovePolicy(toRemove)
	lenValidate(0)

	// make sure deleting something that isn't there doesn't fail badly
	rc.RemovePolicy(toRemove)
	lenValidate(0)
}

func TestIngressConfiguration(t *testing.T) {
	require := require.New(t)
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
	require.Equal("round-robin", cfg.Pools[0].Balance)
	require.Equal("http", cfg.Virtual.Mode)
	require.Equal("velcro", cfg.Virtual.Partition)
	require.Equal("1.2.3.4", cfg.Virtual.VirtualAddress.BindAddr)
	require.Equal(int32(80), cfg.Virtual.VirtualAddress.Port)

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
	require.Equal("foobar", cfg.Pools[0].Balance)
	require.Equal(int32(100), cfg.Virtual.VirtualAddress.Port)

	ingress = test.NewIngress("ingress", "1", namespace, ingressConfig,
		map[string]string{
			"kubernetes.io/ingress.class": "notf5",
		})
	cfg = createRSConfigFromIngress(ingress, namespace, nil, ps)
	require.Nil(cfg)
}

func TestRouteConfiguration(t *testing.T) {
	require := require.New(t)
	namespace := "default"
	spec := routeapi.RouteSpec{
		Host: "foobar.com",
		Path: "/foo",
		To: routeapi.RouteTargetReference{
			Kind: "Service",
			Name: "foo",
		},
		TLS: &routeapi.TLSConfig{
			Termination: "edge",
			Certificate: "cert",
			Key:         "key",
		},
	}
	route := test.NewRoute("route", "1", namespace, spec)
	ps := portStruct{
		protocol: "https",
		port:     443,
	}
	cfg, _ := createRSConfigFromRoute(route, Resources{}, RouteConfig{}, ps, 443)

	require.Equal("openshift_default_https", cfg.Virtual.VirtualServerName)
	require.Equal("openshift_default_foo", cfg.Pools[0].Name)
	require.Equal("foo", cfg.Pools[0].ServiceName)
	require.Equal(int32(443), cfg.Pools[0].ServicePort)
	require.Equal("openshift_secure_routes", cfg.Policies[0].Name)
	require.Equal("openshift_route_default_route", cfg.Policies[0].Rules[0].Name)

	spec = routeapi.RouteSpec{
		Host: "foobar.com",
		Path: "/foo",
		To: routeapi.RouteTargetReference{
			Kind: "Service",
			Name: "bar",
		},
	}
	route2 := test.NewRoute("route2", "1", namespace, spec)
	ps = portStruct{
		protocol: "http",
		port:     80,
	}
	cfg, _ = createRSConfigFromRoute(route2, Resources{}, RouteConfig{}, ps, 80)

	require.Equal("openshift_default_http", cfg.Virtual.VirtualServerName)
	require.Equal("openshift_default_bar", cfg.Pools[0].Name)
	require.Equal("bar", cfg.Pools[0].ServiceName)
	require.Equal(int32(80), cfg.Pools[0].ServicePort)
	require.Equal("openshift_insecure_routes", cfg.Policies[0].Name)
	require.Equal("openshift_route_default_route2", cfg.Policies[0].Rules[0].Name)
}
