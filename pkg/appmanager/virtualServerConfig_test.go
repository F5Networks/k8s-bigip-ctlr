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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type simpleTestConfig struct {
	key  resourceKey
	name string
	addr virtualAddress
}

type resourceMap map[serviceKey][]simpleTestConfig

func newResourceKey(rsName, rsType, namespace string) resourceKey {
	return resourceKey{
		ResourceName: rsName,
		ResourceType: rsType,
		Namespace:    namespace,
	}
}

func newServiceKey(svcPort int32, svcName, namespace string) serviceKey {
	return serviceKey{
		ServiceName: svcName,
		ServicePort: svcPort,
		Namespace:   namespace,
	}
}

func newResourceConfig(
	key resourceKey, vsName string,
	bindAddr string, bindPort, svcPort int32) *ResourceConfig {
	var cfg ResourceConfig
	cfg.Pools = append(cfg.Pools, Pool{})
	cfg.Pools[0].ServiceName = "svc"
	cfg.Pools[0].ServicePort = svcPort
	cfg.Virtual.VirtualServerName = vsName
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
	rsName := "testmap"
	rsType := "configmap"
	bindPort := 8000
	for i := 0; i < nbrBackends; i++ {
		svcKey := newServiceKey(int32(svcPort+i), svcName, namespace)
		for j := 0; j < nbrConfigsPer; j++ {
			name := fmt.Sprintf("%s_%d_%d", rsName, i, j)
			rsKey := newResourceKey(name, rsType, namespace)
			cfgName := fmt.Sprintf("rs-%d-%d", i, j)
			addr := virtualAddress{"10.0.0.1", int32(bindPort + j)}
			rm[svcKey] = append(rm[svcKey], simpleTestConfig{rsKey, cfgName, addr})
		}
	}
	return &rm
}

func assignTestMap(rs *Resources, rm *resourceMap) {
	for key, val := range *rm {
		for _, tf := range val {
			rs.Assign(tf.key, newResourceConfig(
				tf.key, tf.name, tf.addr.BindAddr, tf.addr.Port, key.ServicePort))
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
	require.Equal(nbrBackends*nbrCfgsPer, len(rs.rm))
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
	require.Equal(nbrBackends*nbrCfgsPer, len(rs.rm))
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
	for _, val := range *rm {
		for _, tf := range val {
			countBefore := rs.Count()
			assert.True(t, countBefore > 0)
			ok := rs.Delete(tf.key)
			require.True(ok)
			countAfter := rs.Count()
			require.Equal(countBefore-1, countAfter)
			// Test double-delete fails correctly
			ok = rs.Delete(tf.key)
			require.False(ok)
			assert.Equal(t, countAfter, rs.Count())
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
	rs.ForEach(func(key resourceKey, cfg *ResourceConfig) {
		svcKey := serviceKey{
			ServiceName: cfg.Pools[0].ServiceName,
			ServicePort: cfg.Pools[0].ServicePort,
			Namespace:   key.Namespace,
		}
		totalConfigs += 1
		testObj := (*rm)[svcKey]
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

	for _, val := range *rm {
		for _, tf := range val {
			r, ok := rs.Get(tf.key)
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
		cfgMap := rs.GetAll(key)
		require.NotNil(cfgMap)
		assert.Equal(t, nbrCfgsPer, len(cfgMap))
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
