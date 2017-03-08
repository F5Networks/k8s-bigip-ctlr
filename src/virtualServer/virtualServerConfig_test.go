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

package virtualServer

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

type simpleTestConfig struct {
	name string
	addr virtualAddress
}

type testMap map[serviceKey][]simpleTestConfig

func newServiceKey(svcPort int32, svcName, namespace string) serviceKey {
	return serviceKey{
		ServiceName: svcName,
		ServicePort: svcPort,
		Namespace:   namespace,
	}
}

func newVirtualServerConfig(
	key serviceKey, vsName string,
	bindAddr string, bindPort int32) *VirtualServerConfig {
	var cfg VirtualServerConfig
	cfg.VirtualServer.Backend.ServiceName = key.ServiceName
	cfg.VirtualServer.Backend.ServicePort = key.ServicePort
	cfg.VirtualServer.Frontend.VirtualServerName = vsName
	cfg.VirtualServer.Frontend.VirtualAddress = new(virtualAddress)
	cfg.VirtualServer.Frontend.VirtualAddress.BindAddr = bindAddr
	cfg.VirtualServer.Frontend.VirtualAddress.Port = bindPort
	return &cfg
}

func newTestMap(nbrBackends, nbrConfigsPer int) *testMap {
	// Add nbrBackends backends each with nbrConfigsPer configs
	namespace := "velcro"
	svcName := "svc"
	tm := make(testMap)
	svcPort := 80
	bindPort := 8000
	for i := 0; i < nbrBackends; i++ {
		key := newServiceKey(int32(svcPort+i), svcName, namespace)
		for j := 0; j < nbrConfigsPer; j++ {
			cfgName := fmt.Sprintf("vs-%d-%d", i, j)
			addr := virtualAddress{"10.0.0.1", int32(bindPort + j)}
			tm[key] = append(tm[key], simpleTestConfig{cfgName, addr})
		}
	}
	return &tm
}

func assignTestMap(vss *VirtualServers, tm *testMap) {
	for key, val := range *tm {
		for _, tf := range val {
			vss.Assign(key, newVirtualServerConfig(
				key, tf.name, tf.addr.BindAddr, tf.addr.Port))
		}
	}
}

func TestVirtualServerSort(t *testing.T) {
	virtualServers := VirtualServerConfigs{}

	expectedList := make(VirtualServerConfigs, 10)

	vs := VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "bar"
	vs.VirtualServer.Backend.ServicePort = 80
	virtualServers = append(virtualServers, &vs)
	expectedList[1] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "foo"
	vs.VirtualServer.Backend.ServicePort = 2
	virtualServers = append(virtualServers, &vs)
	expectedList[5] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "foo"
	vs.VirtualServer.Backend.ServicePort = 8080
	virtualServers = append(virtualServers, &vs)
	expectedList[7] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "baz"
	vs.VirtualServer.Backend.ServicePort = 1
	virtualServers = append(virtualServers, &vs)
	expectedList[2] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "foo"
	vs.VirtualServer.Backend.ServicePort = 80
	virtualServers = append(virtualServers, &vs)
	expectedList[6] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "foo"
	vs.VirtualServer.Backend.ServicePort = 9090
	virtualServers = append(virtualServers, &vs)
	expectedList[9] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "baz"
	vs.VirtualServer.Backend.ServicePort = 1000
	virtualServers = append(virtualServers, &vs)
	expectedList[3] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "foo"
	vs.VirtualServer.Backend.ServicePort = 8080
	virtualServers = append(virtualServers, &vs)
	expectedList[8] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "foo"
	vs.VirtualServer.Backend.ServicePort = 1
	virtualServers = append(virtualServers, &vs)
	expectedList[4] = &vs

	vs = VirtualServerConfig{}
	vs.VirtualServer.Backend.ServiceName = "bar"
	vs.VirtualServer.Backend.ServicePort = 1
	virtualServers = append(virtualServers, &vs)
	expectedList[0] = &vs

	sort.Sort(virtualServers)

	for i, _ := range expectedList {
		require.EqualValues(t, expectedList[i], virtualServers[i],
			"Sorted list elements should be equal")
	}
}

func TestNewVirtualServers(t *testing.T) {
	// Test that we can create a new/empty VirtualServers object.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)
	require.NotNil(vss.m)
}

func TestAssign(t *testing.T) {
	// Test Assign() to make sure we can add multiple configs for a backend.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)

	// Make sure vss has the correct number of objects without using other
	// interface functions.
	require.Equal(nbrBackends, len(vss.m))
	for _, vsCfgs := range vss.m {
		require.Equal(nbrCfgsPer, len(vsCfgs))
	}
}

func TestCount(t *testing.T) {
	// Test Count() to make sure we count all items
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)

	require.Equal(nbrBackends*nbrCfgsPer, vss.Count())
}

func TestCountOf(t *testing.T) {
	// Test CountOf() to make sure we count configs per backend correctly.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)
	require.Equal(nbrBackends, len(vss.m))

	for key, _ := range *tm {
		require.Equal(nbrCfgsPer, vss.CountOf(key))
	}
}

func TestDelete(t *testing.T) {
	// Test Delete() to make sure we can delete specific/all configs.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)

	// delete each config one at a time
	for key, val := range *tm {
		for _, tf := range val {
			countBefore := vss.CountOf(key)
			require.True(countBefore > 0)
			ok := vss.Delete(key, tf.name)
			require.True(ok)
			countAfter := vss.CountOf(key)
			require.Equal(countBefore-1, countAfter)
			// Test double-delete fails correctly
			ok = vss.Delete(key, tf.name)
			require.False(ok)
			require.Equal(countAfter, vss.CountOf(key))
		}
	}

	// should be completely empty now
	require.Equal(0, len(vss.m))
}

func TestForEach(t *testing.T) {
	// Test ForEach() to make sure we can iterate over all configs.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)

	totalConfigs := 0
	vss.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
		totalConfigs += 1
		testObj := (*tm)[key]
		require.NotNil(testObj)
		found := false
		for _, val := range testObj {
			if val.name == cfg.VirtualServer.Frontend.VirtualServerName {
				found = true
			}
		}
		require.True(found)
	})
	require.Equal(nbrBackends*nbrCfgsPer, totalConfigs)
}

func TestGet(t *testing.T) {
	// Test Get() to make sure we can access specific configs.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)

	for key, val := range *tm {
		for _, tf := range val {
			vs, ok := vss.Get(key, tf.name)
			require.True(ok)
			require.NotNil(vs)
			require.Equal(tf.addr.BindAddr,
				vs.VirtualServer.Frontend.VirtualAddress.BindAddr)
			require.Equal(tf.addr.Port,
				vs.VirtualServer.Frontend.VirtualAddress.Port)
		}
	}
}

func TestGetAll(t *testing.T) {
	// Test GetAll() to make sure we can get all configs.
	require := require.New(t)
	vss := NewVirtualServers()
	require.NotNil(vss)

	nbrBackends := 2
	nbrCfgsPer := 2
	tm := newTestMap(nbrBackends, nbrCfgsPer)
	require.NotNil(tm)
	assignTestMap(vss, tm)

	for key, _ := range *tm {
		vsCfgMap, ok := vss.GetAll(key)
		require.True(ok)
		require.NotNil(vsCfgMap)
		require.Equal(nbrCfgsPer, len(vsCfgMap))
	}
}
