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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

func init() {
	workingDir, _ := os.Getwd()
	schemaUrl = "file://" + workingDir + "/../../vendor/src/f5/schemas/bigip-virtual-server_v0.1.3.json"
}

var schemaUrl string

var configmapFoo string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 80,
      "healthMonitors": [ {
        "interval": 30,
        "timeout": 20,
        "send": "GET /",
        "protocol": "tcp"
        }
      ]
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      },
      "sslProfile": {
        "f5ProfileName": "velcro/testcert"
      }
    }
  }
}`)

var configmapFoo8080 string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 8080
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      }
    }
  }
}`)

var configmapFoo9090 string = string(`{
	"virtualServer": {
		"backend": {
			"serviceName": "foo",
			"servicePort": 9090
		},
		"frontend": {
			"balance": "round-robin",
			"mode": "tcp",
			"partition": "velcro",
			"virtualAddress": {
				"bindAddr": "10.128.10.200",
				"port": 4041
			}
		}
	}
}`)

var configmapFooTcp string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 80
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "tcp",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 5051
      }
    }
  }
}`)

var configmapFooInvalid string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "",
      "servicePort": 0
    },
    "frontend": {
      "balance": "super-duper-mojo",
      "mode": "udp",
      "partition": "",
      "virtualAddress": {
        "bindAddr": "10.128.10.260",
        "port": 500000
      },
      "sslProfile": {
        "f5ProfileName": ""
      }
    }
  }
}`)

var configmapBar string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "bar",
      "servicePort": 80
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 6051
      }
    }
  }
}`)

var configmapNoAddr string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "bar",
      "servicePort": 80
    },
    "frontend": {
      "balance": "round-robin",
      "mode": "http",
      "partition": "velcro",
      "virtualAddress": {
        "port": 80
      }
    }
  }
}`)

var configmapNoModeBalance string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "bar",
      "servicePort": 80
    },
    "frontend": {
      "partition": "velcro",
      "virtualAddress": {
        "bindAddr": "10.128.10.240",
        "port": 80
      }
    }
  }
}`)

var configmapIApp1 string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "iapp1",
      "servicePort": 80
    },
    "frontend": {
      "partition": "velcro",
      "iapp": "/Common/f5.http",
      "iappPoolMemberTable": {
        "name": "pool__members",
        "columns": [
          {"name": "IPAddress", "kind": "IPAddress"},
          {"name": "Port", "kind": "Port"},
          {"name": "ConnectionLimit", "value": "0"},
          {"name": "SomeOtherValue", "value": "value-1"}
        ]
      },
      "iappOptions": {
        "description": "iApp 1"
      },
      "iappVariables": {
        "monitor__monitor": "/#create_new#",
        "monitor__resposne": "none",
        "monitor__uri": "/",
        "net__client_mode": "wan",
        "net__server_mode": "lan",
        "pool__addr": "127.0.0.1",
        "pool__pool_to_use": "/#create_new#",
        "pool__port": "8080"
      }
    }
  }
}`)

var configmapIApp2 string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "iapp2",
      "servicePort": 80
    },
    "frontend": {
      "partition": "velcro",
      "iapp": "/Common/f5.http",
      "iappOptions": {
        "description": "iApp 2"
      },
      "iappTables": {
        "pool__Pools": {
          "columns": ["Index", "Name", "Description", "LbMethod", "Monitor",
                      "AdvOptions"],
          "rows": [["0", "", "", "round-robin", "0", "none"]]
        },
        "monitor__Monitors": {
          "columns": ["Index", "Name", "Type", "Options"],
          "rows": [["0", "/Common/tcp", "none", "none"]]
        }
      },
      "iappPoolMemberTable": {
        "name": "pool__members",
        "columns": [
          {"name": "IPAddress", "kind": "IPAddress"},
          {"name": "Port", "kind": "Port"},
          {"name": "ConnectionLimit", "value": "0"},
          {"name": "SomeOtherValue", "value": "value-1"}
        ]
      },
      "iappVariables": {
        "monitor__monitor": "/#create_new#",
        "monitor__resposne": "none",
        "monitor__uri": "/",
        "net__client_mode": "wan",
        "net__server_mode": "lan",
        "pool__addr": "127.0.0.2",
        "pool__pool_to_use": "/#create_new#",
        "pool__port": "4430"
      }
    }
  }
}`)

var emptyConfig string = string(`{"services":[]}`)

var twoSvcsFourPortsThreeNodesConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"poolMemberAddrs":["127.0.0.1:37001","127.0.0.2:37001","127.0.0.3:37001"]},"frontend":{"virtualServerName":"default_barmap","partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"healthMonitors":[{"interval":30,"protocol":"tcp","send":"GET /","timeout":20}],"serviceName":"foo","servicePort":80,"poolMemberAddrs":["127.0.0.1:30001","127.0.0.2:30001","127.0.0.3:30001"]},"frontend":{"virtualServerName":"default_foomap","partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":8080,"poolMemberAddrs":["127.0.0.1:38001","127.0.0.2:38001","127.0.0.3:38001"]},"frontend":{"virtualServerName":"default_foomap8080","partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":5051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":9090,"poolMemberAddrs":["127.0.0.1:39001","127.0.0.2:39001","127.0.0.3:39001"]},"frontend":{"virtualServerName":"default_foomap9090","partition":"velcro","balance":"round-robin","mode":"tcp","virtualAddress":{"bindAddr":"10.128.10.200","port":4041}}}}]}`)

var twoSvcsTwoNodesConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"poolMemberAddrs":["127.0.0.1:37001","127.0.0.2:37001"]},"frontend":{"virtualServerName":"default_barmap","balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"healthMonitors":[{"interval":30,"protocol":"tcp","send":"GET /","timeout":20}],"serviceName":"foo","servicePort":80,"poolMemberAddrs":["127.0.0.1:30001","127.0.0.2:30001"]},"frontend":{"virtualServerName":"default_foomap","balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}}]}`)

var twoSvcsOneNodeConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"poolMemberAddrs":["127.0.0.3:37001"]},"frontend":{"virtualServerName":"default_barmap","balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"healthMonitors":[{"interval":30,"protocol":"tcp","send":"GET /","timeout":20}],"serviceName":"foo","servicePort":80,"poolMemberAddrs":["127.0.0.3:30001"]},"frontend":{"virtualServerName":"default_foomap","balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}}]}`)

var oneSvcOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"poolMemberAddrs":["127.0.0.3:37001"]},"frontend":{"virtualServerName":"default_barmap","balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}}]}`)

var twoIappsThreeNodesConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp1","servicePort":80,"poolMemberAddrs":["192.168.0.1:10101","192.168.0.2:10101","192.168.0.4:10101"]},"frontend":{"virtualServerName":"default_iapp1map","partition":"velcro","iapp":"/Common/f5.http","iappOptions":{"description":"iApp 1"},"iappPoolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}]},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}}}},{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"poolMemberAddrs":["192.168.0.1:20202","192.168.0.2:20202","192.168.0.4:20202"]},"frontend":{"virtualServerName":"default_iapp2map","partition":"velcro","iapp":"/Common/f5.http","iappOptions":{"description":"iApp 2"},"iappTables":{"pool__Pools":{"columns":["Index","Name","Description","LbMethod","Monitor","AdvOptions"],"rows":[["0","","","round-robin","0","none"]]},"monitor__Monitors":{"columns":["Index","Name","Type","Options"],"rows":[["0","/Common/tcp","none","none"]]}},"iappPoolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}]},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var twoIappsOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp1","servicePort":80,"poolMemberAddrs":["192.168.0.4:10101"]},"frontend":{"virtualServerName":"default_iapp1map","partition":"velcro","iapp":"/Common/f5.http","iappOptions":{"description":"iApp 1"},"iappPoolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}]},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}}}},{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"poolMemberAddrs":["192.168.0.4:20202"]},"frontend":{"virtualServerName":"default_iapp2map","partition":"velcro","iapp":"/Common/f5.http","iappOptions":{"description":"iApp 2"},"iappTables":{"pool__Pools":{"columns":["Index","Name","Description","LbMethod","Monitor","AdvOptions"],"rows":[["0","","","round-robin","0","none"]]},"monitor__Monitors":{"columns":["Index","Name","Type","Options"],"rows":[["0","/Common/tcp","none","none"]]}},"iappPoolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}]},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var oneIappOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"poolMemberAddrs":["192.168.0.4:20202"]},"frontend":{"virtualServerName":"default_iapp2map","partition":"velcro","iapp":"/Common/f5.http","iappOptions":{"description":"iApp 2"},"iappTables":{"pool__Pools":{"columns":["Index","Name","Description","LbMethod","Monitor","AdvOptions"],"rows":[["0","","","round-robin","0","none"]]},"monitor__Monitors":{"columns":["Index","Name","Type","Options"],"rows":[["0","/Common/tcp","none","none"]]}},"iappPoolMemberTable":{"name":"pool__members","columns":[{"name":"IPAddress","kind":"IPAddress"},{"name":"Port","kind":"Port"},{"name":"ConnectionLimit","value":"0"},{"name":"SomeOtherValue","value":"value-1"}]},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var twoSvcTwoPodsConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"poolMemberAddrs":["10.2.96.0:80","10.2.96.3:80"]},"frontend":{"virtualServerName":"default_barmap","partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":8080,"poolMemberAddrs":["10.2.96.1:8080","10.2.96.2:8080"]},"frontend":{"virtualServerName":"default_foomap","partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":5051}}}}]}`)

var oneSvcTwoPodsConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"poolMemberAddrs":["10.2.96.0:80","10.2.96.3:80"]},"frontend":{"virtualServerName":"default_barmap","balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}}]}`)

func generateExpectedAddrs(port int32, ips []string) []string {
	var ret []string
	for _, ip := range ips {
		ret = append(ret, ip+":"+strconv.Itoa(int(port)))
	}
	return ret
}

func convertSvcPortsToEndpointPorts(svcPorts []v1.ServicePort) []v1.EndpointPort {
	eps := make([]v1.EndpointPort, len(svcPorts))
	for i, v := range svcPorts {
		eps[i].Name = v.Name
		eps[i].Port = v.Port
	}
	return eps
}

func newServicePort(name string, svcPort int32) v1.ServicePort {
	return v1.ServicePort{
		Port: svcPort,
		Name: name,
	}
}

// Adapter function to translate Store events to virtualServer calls
type onChangeFunc func(change changeType, changed ChangedObject)

type mockStore struct {
	storage  cache.ThreadSafeStore
	keyFunc  cache.KeyFunc
	onChange onChangeFunc
}

func NewStore(onChange onChangeFunc) cache.Store {
	return &mockStore{
		storage:  cache.NewThreadSafeStore(cache.Indexers{}, cache.Indices{}),
		keyFunc:  cache.MetaNamespaceKeyFunc,
		onChange: onChange,
	}
}

func (ms *mockStore) Add(obj interface{}) error {
	key, err := ms.keyFunc(obj)
	if err != nil {
		return cache.KeyError{obj, err}
	}
	ms.storage.Add(key, obj)
	if ms.onChange != nil {
		ms.onChange(added, ChangedObject{
			nil,
			obj,
		})
	}
	return nil
}
func (ms *mockStore) Update(obj interface{}) error {
	key, err := ms.keyFunc(obj)
	if err != nil {
		return cache.KeyError{obj, err}
	}
	oldObj, _ := ms.storage.Get(key)
	ms.storage.Update(key, obj)
	if ms.onChange != nil {
		ms.onChange(updated, ChangedObject{
			oldObj,
			obj,
		})
	}
	return nil
}
func (ms *mockStore) Delete(obj interface{}) error {
	key, err := ms.keyFunc(obj)
	if err != nil {
		return cache.KeyError{obj, err}
	}
	ms.storage.Delete(key)
	if ms.onChange != nil {
		ms.onChange(deleted, ChangedObject{
			obj,
			nil,
		})
	}
	return nil
}
func (ms *mockStore) List() []interface{} {
	return nil
}
func (ms *mockStore) ListKeys() []string {
	return nil
}
func (ms *mockStore) Get(obj interface{}) (item interface{}, exists bool, err error) {
	key, err := ms.keyFunc(obj)
	if err != nil {
		return nil, false, cache.KeyError{obj, err}
	}
	return ms.GetByKey(key)
}
func (ms *mockStore) GetByKey(key string) (item interface{}, exists bool, err error) {
	item, exists = ms.storage.Get(key)
	if exists {
		return item, exists, nil
	}
	return item, exists, errors.New("item does not exist")
}
func (ms *mockStore) Replace(list []interface{}, resourceVersion string) error {
	return errors.New("mock unimplemented")
}
func (ms *mockStore) Resync() error {
	return errors.New("mock unimplemented")
}

func TestVirtualServerSendFail(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.ImmediateFail,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	require.NotNil(t, mw)
	assert.True(t, ok)

	require.NotPanics(t, func() {
		outputConfig()
	})
	assert.Equal(t, 1, mw.WrittenTimes)
}

func TestVirtualServerSendFailAsync(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.AsyncFail,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	require.NotNil(t, mw)
	assert.True(t, ok)

	require.NotPanics(t, func() {
		outputConfig()
	})
	assert.Equal(t, 1, mw.WrittenTimes)
}

func TestVirtualServerSendFailTimeout(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Timeout,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	require.NotNil(t, mw)
	assert.True(t, ok)

	require.NotPanics(t, func() {
		outputConfig()
	})
	assert.Equal(t, 1, mw.WrittenTimes)
}

func TestGetAddresses(t *testing.T) {
	// Existing Node data
	expectedNodes := []*v1.Node{
		test.NewNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		test.NewNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		test.NewNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
		test.NewNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.3"}}),
		test.NewNode("node4", "4", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.4"}}),
		test.NewNode("node5", "5", false, []v1.NodeAddress{
			{"Hostname", "127.0.0.5"}}),
	}

	expectedReturn := []string{
		"127.0.0.1",
		"127.0.0.2",
		"127.0.0.3",
	}

	fake := fake.NewSimpleClientset()
	assert.NotNil(t, fake, "Mock client cannot be nil")

	for _, expectedNode := range expectedNodes {
		node, err := fake.Core().Nodes().Create(expectedNode)
		require.Nil(t, err, "Should not fail creating node")
		require.EqualValues(t, expectedNode, node, "Nodes should be equal")
	}

	useNodeInternal = false
	nodes, err := fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	addresses, err := getNodeAddresses(nodes.Items)
	require.Nil(t, err, "Should not fail getting addresses")
	assert.EqualValues(t, expectedReturn, addresses,
		"Should receive the correct addresses")

	// test filtering
	expectedInternal := []string{
		"127.0.0.4",
	}

	useNodeInternal = true
	addresses, err = getNodeAddresses(nodes.Items)
	require.Nil(t, err, "Should not fail getting internal addresses")
	assert.EqualValues(t, expectedInternal, addresses,
		"Should receive the correct addresses")

	for _, node := range expectedNodes {
		err := fake.Core().Nodes().Delete(node.ObjectMeta.Name,
			&v1.DeleteOptions{})
		require.Nil(t, err, "Should not fail deleting node")
	}

	expectedReturn = []string{}
	useNodeInternal = false
	nodes, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	addresses, err = getNodeAddresses(nodes.Items)
	require.Nil(t, err, "Should not fail getting empty addresses")
	assert.EqualValues(t, expectedReturn, addresses, "Should get no addresses")
}

func validateConfig(t *testing.T, mw *test.MockWriter, expected string) {
	mw.Lock()
	_, ok := mw.Sections["services"].(VirtualServerConfigs)
	mw.Unlock()
	assert.True(t, ok)

	services := struct {
		Services VirtualServerConfigs `json:"services"`
	}{
		Services: mw.Sections["services"].(VirtualServerConfigs),
	}

	// Sort virtual-servers configs for comparison
	sort.Sort(services.Services)

	// Read JSON from exepectedOutput into array of structs
	expectedOutput := struct {
		Services VirtualServerConfigs `json:"services"`
	}{
		Services: VirtualServerConfigs{},
	}

	err := json.Unmarshal([]byte(expected), &expectedOutput)
	if nil != err {
		assert.Nil(t, err)
		return
	}

	for i, vs := range expectedOutput.Services {
		require.Condition(t, func() bool {
			return i < len(services.Services)
		})
		assert.ObjectsAreEqualValues(vs.VirtualServer, services.Services[i].VirtualServer)
	}
}

func TestProcessNodeUpdate(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	originalSet := []v1.Node{
		*test.NewNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		*test.NewNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		*test.NewNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
		*test.NewNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.3"}}),
		*test.NewNode("node4", "4", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.4"}}),
		*test.NewNode("node5", "5", false, []v1.NodeAddress{
			{"Hostname", "127.0.0.5"}}),
	}

	expectedOgSet := []string{
		"127.0.0.1",
		"127.0.0.2",
		"127.0.0.3",
	}

	fake := fake.NewSimpleClientset(&v1.NodeList{Items: originalSet})
	assert.NotNil(t, fake, "Mock client should not be nil")

	useNodeInternal = false
	nodes, err := fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	ProcessNodeUpdate(nodes.Items, err)
	validateConfig(t, mw, emptyConfig)
	require.EqualValues(t, expectedOgSet, oldNodes,
		"Should have cached correct node set")

	cachedNodes := getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedOgSet, cachedNodes,
		"Cached nodes should be expected set")

	// test filtering
	expectedInternal := []string{
		"127.0.0.4",
	}

	useNodeInternal = true
	nodes, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	ProcessNodeUpdate(nodes.Items, err)
	validateConfig(t, mw, emptyConfig)
	require.EqualValues(t, expectedInternal, oldNodes,
		"Should have cached correct node set")

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedInternal, cachedNodes,
		"Cached nodes should be expected set")

	// add some nodes
	_, err = fake.Core().Nodes().Create(test.NewNode("nodeAdd", "nodeAdd", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.6"}}))
	require.Nil(t, err, "Create should not return err")

	_, err = fake.Core().Nodes().Create(test.NewNode("nodeExclude", "nodeExclude",
		true, []v1.NodeAddress{{"InternalIP", "127.0.0.7"}}))

	useNodeInternal = false
	nodes, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	ProcessNodeUpdate(nodes.Items, err)
	validateConfig(t, mw, emptyConfig)
	expectedAddSet := append(expectedOgSet, "127.0.0.6")

	require.EqualValues(t, expectedAddSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedAddSet, cachedNodes,
		"Cached nodes should be expected set")

	// make no changes and re-run process
	useNodeInternal = false
	nodes, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	ProcessNodeUpdate(nodes.Items, err)
	validateConfig(t, mw, emptyConfig)
	expectedAddSet = append(expectedOgSet, "127.0.0.6")

	require.EqualValues(t, expectedAddSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedAddSet, cachedNodes,
		"Cached nodes should be expected set")

	// remove nodes
	err = fake.Core().Nodes().Delete("node1", &v1.DeleteOptions{})
	require.Nil(t, err)
	fake.Core().Nodes().Delete("node2", &v1.DeleteOptions{})
	require.Nil(t, err)
	fake.Core().Nodes().Delete("node3", &v1.DeleteOptions{})
	require.Nil(t, err)

	expectedDelSet := []string{"127.0.0.6"}

	useNodeInternal = false
	nodes, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(t, err, "Should not fail listing nodes")
	ProcessNodeUpdate(nodes.Items, err)
	validateConfig(t, mw, emptyConfig)

	require.EqualValues(t, expectedDelSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedDelSet, cachedNodes,
		"Cached nodes should be expected set")
}

func testOverwriteAddImpl(t *testing.T, isNodePort bool) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	defer test.NewMockWatchManager()

	r := processConfigMap(added,
		ChangedObject{nil, cfgFoo}, isNodePort)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have entry")
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	require.Equal("http", vs.VirtualServer.Frontend.Mode, "Mode should be http")

	cfgFoo = test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFooTcp})

	r = processConfigMap(added,
		ChangedObject{nil, cfgFoo}, isNodePort)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have new entry")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	require.Equal("tcp", vs.VirtualServer.Frontend.Mode,
		"Mode should be tcp after overwrite")
}

func TestOverwriteAddNodePort(t *testing.T) {
	testOverwriteAddImpl(t, true)
}

func TestOverwriteAddCluster(t *testing.T) {
	testOverwriteAddImpl(t, false)
}

func testServiceChangeUpdateImpl(t *testing.T, isNodePort bool) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	defer test.NewMockWatchManager()

	r := processConfigMap(added,
		ChangedObject{nil, cfgFoo}, true)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have an entry")

	cfgFoo8080 := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})

	r = processConfigMap(updated,
		ChangedObject{cfgFoo, cfgFoo8080}, true)
	require.True(r, "Config map should be processed")
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}),
		"Virtual servers should have new entry")
	require.Equal(0, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have old config removed")
}

func TestServiceChangeUpdateNodePort(t *testing.T) {
	testServiceChangeUpdateImpl(t, true)
}

func TestServiceChangeUpdateCluster(t *testing.T) {
	testServiceChangeUpdateImpl(t, false)
}

func TestServicePortsRemovedNodePort(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	require := require.New(t)

	defer virtualServers.Init()

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	defer test.NewMockWatchManager()

	nodeSet := []v1.Node{
		*test.NewNode("node0", "0", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.0"}}),
		*test.NewNode("node1", "1", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.1"}}),
		*test.NewNode("node2", "2", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.2"}}),
	}

	useNodeInternal = true
	ProcessNodeUpdate(nodeSet, nil)

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := test.NewConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := test.NewConfigMap("foomap9090", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})

	foo := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001},
			{Port: 8080, NodePort: 38001},
			{Port: 9090, NodePort: 39001}})

	r := processConfigMap(added, ChangedObject{
		nil,
		cfgFoo}, true)
	require.True(r, "Config map should be processed")

	r = processConfigMap(added, ChangedObject{
		nil,
		cfgFoo8080}, true)
	require.True(r, "Config map should be processed")

	r = processConfigMap(added, ChangedObject{
		nil,
		cfgFoo9090}, true)
	require.True(r, "Config map should be processed")

	require.Equal(3, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 9090, "default"}))

	// Create a new service with less ports and update
	newFoo := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})

	r = processService(updated, ChangedObject{
		foo,
		newFoo}, true)
	require.True(r, "Service should be processed")

	require.Equal(3, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 9090, "default"}))

	addrs := []string{
		"127.0.0.0",
		"127.0.0.1",
		"127.0.0.2",
	}
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	require.EqualValues(generateExpectedAddrs(30001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Existing NodePort should be set on address")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 8080, "default"}, formatVirtualServerName(cfgFoo8080))
	require.True(ok)
	require.False(vs.MetaData.Active)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 9090, "default"}, formatVirtualServerName(cfgFoo9090))
	require.True(ok)
	require.False(vs.MetaData.Active)

	// Re-add port in new service
	newFoo2 := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 20001},
			{Port: 8080, NodePort: 45454}})

	r = processService(updated, ChangedObject{
		newFoo,
		newFoo2}, true)
	require.True(r, "Service should be processed")

	require.Equal(3, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 9090, "default"}))

	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	require.EqualValues(generateExpectedAddrs(20001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Existing NodePort should be set on address")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 8080, "default"}, formatVirtualServerName(cfgFoo8080))
	require.True(ok)
	require.EqualValues(generateExpectedAddrs(45454, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Existing NodePort should be set on address")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 9090, "default"}, formatVirtualServerName(cfgFoo9090))
	require.True(ok)
	require.False(vs.MetaData.Active)
}

func TestUpdatesConcurrentNodePort(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	assert := assert.New(t)
	require := require.New(t)

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgBar := test.NewConfigMap("barmap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapBar})
	foo := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})
	bar := test.NewService("bar", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 37001}})
	nodes := []*v1.Node{
		test.NewNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		test.NewNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		test.NewNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
	}
	extraNode := test.NewNode("node3", "3", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.3"}})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	watchManager.(*test.MockWatchManager).Store["services"].Add(foo)
	watchManager.(*test.MockWatchManager).Store["services"].Add(bar)

	nodeCh := make(chan struct{})
	mapCh := make(chan struct{})
	serviceCh := make(chan struct{})

	go func() {
		for _, node := range nodes {
			n, err := fake.Core().Nodes().Create(node)
			require.Nil(err, "Should not fail creating node")
			require.EqualValues(node, n, "Nodes should be equal")

			useNodeInternal = false
			nodes, err := fake.Core().Nodes().List(v1.ListOptions{})
			assert.Nil(err, "Should not fail listing nodes")
			ProcessNodeUpdate(nodes.Items, err)
		}

		nodeCh <- struct{}{}
	}()

	go func() {
		f, err := fake.Core().ConfigMaps("default").Create(cfgFoo)
		require.Nil(err, "Should not fail creating configmap")
		require.EqualValues(f, cfgFoo, "Maps should be equal")

		ProcessConfigMapUpdate(added, ChangedObject{
			nil,
			cfgFoo,
		}, true)

		b, err := fake.Core().ConfigMaps("default").Create(cfgBar)
		require.Nil(err, "Should not fail creating configmap")
		require.EqualValues(b, cfgBar, "Maps should be equal")

		ProcessConfigMapUpdate(added, ChangedObject{
			nil,
			cfgBar,
		}, true)

		mapCh <- struct{}{}
	}()

	go func() {
		fSvc, err := fake.Core().Services("default").Create(foo)
		require.Nil(err, "Should not fail creating service")
		require.EqualValues(fSvc, foo, "Service should be equal")

		ProcessServiceUpdate(added, ChangedObject{
			nil,
			foo}, true)

		bSvc, err := fake.Core().Services("default").Create(bar)
		require.Nil(err, "Should not fail creating service")
		require.EqualValues(bSvc, bar, "Maps should be equal")

		ProcessServiceUpdate(added, ChangedObject{
			nil,
			bar}, true)

		serviceCh <- struct{}{}
	}()

	select {
	case <-nodeCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting node channel notification")
	}
	select {
	case <-mapCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting configmap channel notification")
	}
	select {
	case <-serviceCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out excpecting service channel notification")
	}

	validateConfig(t, mw, twoSvcsTwoNodesConfig)

	go func() {
		err := fake.Core().Nodes().Delete("node1", &v1.DeleteOptions{})
		require.Nil(err)
		err = fake.Core().Nodes().Delete("node2", &v1.DeleteOptions{})
		require.Nil(err)
		_, err = fake.Core().Nodes().Create(extraNode)
		require.Nil(err)
		useNodeInternal = false
		nodes, err := fake.Core().Nodes().List(v1.ListOptions{})
		assert.Nil(err, "Should not fail listing nodes")
		ProcessNodeUpdate(nodes.Items, err)

		nodeCh <- struct{}{}
	}()

	go func() {
		err := fake.Core().ConfigMaps("default").Delete("foomap",
			&v1.DeleteOptions{})
		require.Nil(err, "Should not error deleting map")
		m, _ := fake.Core().ConfigMaps("").List(v1.ListOptions{})
		assert.Equal(1, len(m.Items))
		ProcessConfigMapUpdate(deleted, ChangedObject{
			cfgFoo,
			nil,
		}, true)
		assert.Equal(1, virtualServers.Count())

		mapCh <- struct{}{}
	}()

	go func() {
		err := fake.Core().Services("default").Delete("foo",
			&v1.DeleteOptions{})
		require.Nil(err, "Should not error deleting service")
		s, _ := fake.Core().Services("").List(v1.ListOptions{})
		assert.Equal(1, len(s.Items))
		ProcessServiceUpdate(deleted, ChangedObject{
			foo,
			nil}, true)

		serviceCh <- struct{}{}
	}()

	select {
	case <-nodeCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting node channel notification")
	}
	select {
	case <-mapCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting configmap channel notification")
	}
	select {
	case <-serviceCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out excpecting service channel notification")
	}

	validateConfig(t, mw, oneSvcOneNodeConfig)
}

func TestProcessUpdatesNodePort(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	assert := assert.New(t)
	require := require.New(t)

	// Create a test env with two ConfigMaps, two Services, and three Nodes
	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := test.NewConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := test.NewConfigMap("foomap9090", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})
	cfgBar := test.NewConfigMap("barmap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapBar})
	foo := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001},
			{Port: 8080, NodePort: 38001},
			{Port: 9090, NodePort: 39001}})
	bar := test.NewService("bar", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 37001}})
	nodes := []v1.Node{
		*test.NewNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		*test.NewNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		*test.NewNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
	}
	extraNode := test.NewNode("node3", "3", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.3"}})

	addrs := []string{"127.0.0.1", "127.0.0.2"}

	fake := fake.NewSimpleClientset(
		&v1.ConfigMapList{Items: []v1.ConfigMap{*cfgFoo, *cfgBar}},
		&v1.ServiceList{Items: []v1.Service{*foo, *bar}},
		&v1.NodeList{Items: nodes})
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	watchManager.(*test.MockWatchManager).Store["services"].Add(foo)
	watchManager.(*test.MockWatchManager).Store["services"].Add(bar)

	m, err := fake.Core().ConfigMaps("").List(v1.ListOptions{})
	require.Nil(err)
	s, err := fake.Core().Services("").List(v1.ListOptions{})
	require.Nil(err)
	n, err := fake.Core().Nodes().List(v1.ListOptions{})
	require.Nil(err)

	assert.Equal(2, len(m.Items))
	assert.Equal(2, len(s.Items))
	assert.Equal(3, len(n.Items))

	useNodeInternal = false
	ProcessNodeUpdate(n.Items, err)

	// ConfigMap added
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfgFoo,
	}, true)
	assert.Equal(1, virtualServers.Count())
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Second ConfigMap added
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfgBar,
	}, true)
	assert.Equal(2, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"bar", 80, "default"}, formatVirtualServerName(cfgBar))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(37001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Service ADDED
	ProcessServiceUpdate(added, ChangedObject{
		nil,
		foo}, true)
	assert.Equal(2, virtualServers.Count())

	// Second Service ADDED
	ProcessServiceUpdate(added, ChangedObject{
		nil,
		bar}, true)
	assert.Equal(2, virtualServers.Count())

	// ConfigMap UPDATED
	ProcessConfigMapUpdate(updated, ChangedObject{
		cfgFoo,
		cfgFoo,
	}, true)
	assert.Equal(2, virtualServers.Count())

	// Service UPDATED
	ProcessServiceUpdate(updated, ChangedObject{
		foo,
		foo}, true)
	assert.Equal(2, virtualServers.Count())

	// ConfigMap ADDED second foo port
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfgFoo8080}, true)
	assert.Equal(3, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 8080, "default"}, formatVirtualServerName(cfgFoo8080))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(38001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"bar", 80, "default"}, formatVirtualServerName(cfgBar))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(37001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// ConfigMap ADDED third foo port
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfgFoo9090}, true)
	assert.Equal(4, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 9090, "default"}, formatVirtualServerName(cfgFoo9090))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(39001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 8080, "default"}, formatVirtualServerName(cfgFoo8080))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(38001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"bar", 80, "default"}, formatVirtualServerName(cfgBar))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(37001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Nodes ADDED
	_, err = fake.Core().Nodes().Create(extraNode)
	require.Nil(err)
	useNodeInternal = false
	n, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(err, "Should not fail listing nodes")
	ProcessNodeUpdate(n.Items, err)
	assert.Equal(4, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, append(addrs, "127.0.0.3")),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"bar", 80, "default"}, formatVirtualServerName(cfgBar))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(37001, append(addrs, "127.0.0.3")),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 8080, "default"}, formatVirtualServerName(cfgFoo8080))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(38001, append(addrs, "127.0.0.3")),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 9090, "default"}, formatVirtualServerName(cfgFoo9090))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(39001, append(addrs, "127.0.0.3")),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	validateConfig(t, mw, twoSvcsFourPortsThreeNodesConfig)

	// ConfigMap DELETED third foo port
	ProcessConfigMapUpdate(deleted, ChangedObject{
		cfgFoo9090,
		nil}, true)
	assert.Equal(3, virtualServers.Count())
	assert.Equal(0, virtualServers.CountOf(serviceKey{"foo", 9090, "default"}),
		"Virtual servers should not contain removed port")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"bar", 80, "default"}),
		"Virtual servers should contain remaining ports")

	// ConfigMap UPDATED second foo port
	ProcessConfigMapUpdate(updated, ChangedObject{
		cfgFoo8080,
		cfgFoo8080}, true)
	assert.Equal(3, virtualServers.Count())
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"bar", 80, "default"}),
		"Virtual servers should contain remaining ports")

	// ConfigMap DELETED second foo port
	ProcessConfigMapUpdate(deleted, ChangedObject{
		cfgFoo8080,
		nil}, true)
	assert.Equal(2, virtualServers.Count())
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"bar", 80, "default"}),
		"Virtual servers should contain remaining ports")

	// Nodes DELETES
	err = fake.Core().Nodes().Delete("node1", &v1.DeleteOptions{})
	require.Nil(err)
	err = fake.Core().Nodes().Delete("node2", &v1.DeleteOptions{})
	require.Nil(err)
	useNodeInternal = false
	n, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(err, "Should not fail listing nodes")
	ProcessNodeUpdate(n.Items, err)
	assert.Equal(2, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"bar", 80, "default"}, formatVirtualServerName(cfgBar))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	validateConfig(t, mw, twoSvcsOneNodeConfig)

	// ConfigMap DELETED
	err = fake.Core().ConfigMaps("default").Delete("foomap", &v1.DeleteOptions{})
	m, err = fake.Core().ConfigMaps("").List(v1.ListOptions{})
	assert.Equal(1, len(m.Items))
	ProcessConfigMapUpdate(deleted, ChangedObject{
		cfgFoo,
		nil,
	}, true)
	assert.Equal(1, virtualServers.Count())
	assert.Equal(0, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Config map should be removed after delete")
	validateConfig(t, mw, oneSvcOneNodeConfig)

	// Service deletedD
	err = fake.Core().Services("default").Delete("bar", &v1.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(v1.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(deleted, ChangedObject{
		bar,
		nil}, true)
	assert.Equal(1, virtualServers.Count())
	validateConfig(t, mw, emptyConfig)
}

func TestDontCareConfigMapNodePort(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	assert := assert.New(t)
	require := require.New(t)

	cfg := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   "bar"})
	svc := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})

	fake := fake.NewSimpleClientset(&v1.ConfigMapList{Items: []v1.ConfigMap{*cfg}},
		&v1.ServiceList{Items: []v1.Service{*svc}})
	require.NotNil(fake, "Mock client cannot be nil")

	m, err := fake.Core().ConfigMaps("").List(v1.ListOptions{})
	require.Nil(err)
	s, err := fake.Core().Services("").List(v1.ListOptions{})
	require.Nil(err)

	assert.Equal(1, len(m.Items))
	assert.Equal(1, len(s.Items))

	// ConfigMap ADDED
	assert.Equal(0, virtualServers.Count())
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfg,
	}, true)
	assert.Equal(0, virtualServers.Count())
}

func testConfigMapKeysImpl(t *testing.T, isNodePort bool) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)
	assert := assert.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client should not be nil")

	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)

	// Config map with no schema key
	noschemakey := test.NewConfigMap("noschema", "1", "default", map[string]string{
		"data": configmapFoo})
	cfg, err := parseVirtualServerConfig(noschemakey)
	require.EqualError(err, "configmap noschema does not contain schema key",
		"Should receive no schema error")
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		noschemakey,
	}, isNodePort)
	require.Equal(0, virtualServers.Count())

	// Config map with no data key
	nodatakey := test.NewConfigMap("nodata", "1", "default", map[string]string{
		"schema": schemaUrl,
	})
	cfg, err = parseVirtualServerConfig(nodatakey)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err, "configmap nodata does not contain data key",
		"Should receive no data error")
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		nodatakey,
	}, isNodePort)
	require.Equal(0, virtualServers.Count())

	// Config map with bad json
	badjson := test.NewConfigMap("badjson", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   "///// **invalid json** /////",
	})
	cfg, err = parseVirtualServerConfig(badjson)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err,
		"invalid character '/' looking for beginning of value")
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		badjson,
	}, isNodePort)
	require.Equal(0, virtualServers.Count())

	// Config map with no bind address
	noBindAddr := test.NewConfigMap("noBindAddr", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapNoAddr,
	})
	cfg, err = parseVirtualServerConfig(noBindAddr)
	require.NotNil(cfg, "Config map should parse with missing bindAddr")
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		noBindAddr,
	}, isNodePort)
	require.Equal(0, virtualServers.Count())

	// Config map with extra keys
	extrakeys := test.NewConfigMap("extrakeys", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo,
		"key1":   "value1",
		"key2":   "value2",
	})
	cfg, err = parseVirtualServerConfig(extrakeys)
	require.NotNil(cfg, "Config map should parse with extra keys")
	require.Nil(err, "Should not receive errors")
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		extrakeys,
	}, isNodePort)
	require.Equal(1, virtualServers.Count())
	virtualServers.Delete(serviceKey{"foo", 80, "default"},
		formatVirtualServerName(extrakeys))

	// Config map with no mode or balance
	defaultModeAndBalance := test.NewConfigMap("mode_balance", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapNoModeBalance,
	})
	cfg, err = parseVirtualServerConfig(defaultModeAndBalance)
	require.NotNil(cfg, "Config map should exist and contain default mode and balance.")
	require.Nil(err, "Should not receive errors")
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		defaultModeAndBalance,
	}, isNodePort)
	require.Equal(1, virtualServers.Count())

	vs, ok := virtualServers.Get(
		serviceKey{"bar", 80, "default"}, formatVirtualServerName(defaultModeAndBalance))
	assert.True(ok, "Config map should be accessible")
	assert.NotNil(vs, "Config map should be object")

	require.Equal("round-robin", vs.VirtualServer.Frontend.Balance)
	require.Equal("tcp", vs.VirtualServer.Frontend.Mode)
	require.Equal("velcro", vs.VirtualServer.Frontend.Partition)
	require.Equal("10.128.10.240",
		vs.VirtualServer.Frontend.VirtualAddress.BindAddr)
	require.Equal(int32(80), vs.VirtualServer.Frontend.VirtualAddress.Port)
}

func TestNamespaceIsolation(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)
	assert := assert.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client should not be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	defer test.NewMockWatchManager()

	node := test.NewNode("node3", "3", false,
		[]v1.NodeAddress{{"InternalIP", "127.0.0.3"}})
	_, err := fake.Core().Nodes().Create(node)
	require.Nil(err)
	useNodeInternal = true
	n, err := fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(err, "Should not fail listing nodes")
	ProcessNodeUpdate(n.Items, err)

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgBar := test.NewConfigMap("foomap", "1", "wrongnamespace", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	servFoo := test.NewService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 37001}})
	servBar := test.NewService("foo", "1", "wrongnamespace", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 50000}})

	ProcessConfigMapUpdate(added, ChangedObject{
		nil, cfgFoo}, true)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Config map should be accessible")

	ProcessConfigMapUpdate(added, ChangedObject{
		nil, cfgBar}, true)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, formatVirtualServerName(cfgBar))
	assert.False(ok, "Config map should not be added if namespace does not match flag")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain original config")
	assert.Equal(1, virtualServers.Count(), "There should only be 1 virtual server")

	ProcessConfigMapUpdate(updated, ChangedObject{
		cfgBar, cfgBar}, true)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, formatVirtualServerName(cfgBar))
	assert.False(ok, "Config map should not be added if namespace does not match flag")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain original config")
	assert.Equal(1, virtualServers.Count(), "There should only be 1 virtual server")

	ProcessConfigMapUpdate(deleted, ChangedObject{
		cfgBar, nil}, true)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, formatVirtualServerName(cfgBar))
	assert.False(ok, "Config map should not be deleted if namespace does not match flag")
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Config map should be accessible after delete called on incorrect namespace")

	ProcessServiceUpdate(added, ChangedObject{
		nil, servFoo}, true)
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")

	ProcessServiceUpdate(added, ChangedObject{
		nil, servBar}, true)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, "foomap")
	assert.False(ok, "Service should not be added if namespace does not match flag")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")

	ProcessServiceUpdate(updated, ChangedObject{
		servBar, servBar}, true)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, "foomap")
	assert.False(ok, "Service should not be added if namespace does not match flag")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")

	ProcessServiceUpdate(deleted, ChangedObject{
		servBar, nil}, true)
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should not have been deleted")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")
}

func TestConfigMapKeysNodePort(t *testing.T) {
	testConfigMapKeysImpl(t, true)
}

func TestConfigMapKeysCluster(t *testing.T) {
	testConfigMapKeysImpl(t, false)
}

func TestProcessUpdatesIAppNodePort(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	assert := assert.New(t)
	require := require.New(t)

	// Create a test env with two ConfigMaps, two Services, and three Nodes
	cfgIapp1 := test.NewConfigMap("iapp1map", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapIApp1})
	cfgIapp2 := test.NewConfigMap("iapp2map", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapIApp2})
	iapp1 := test.NewService("iapp1", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 10101}})
	iapp2 := test.NewService("iapp2", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 20202}})
	nodes := []v1.Node{
		*test.NewNode("node0", "0", true, []v1.NodeAddress{
			{"InternalIP", "192.168.0.0"}}),
		*test.NewNode("node1", "1", false, []v1.NodeAddress{
			{"InternalIP", "192.168.0.1"}}),
		*test.NewNode("node2", "2", false, []v1.NodeAddress{
			{"InternalIP", "192.168.0.2"}}),
		*test.NewNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "192.168.0.3"}}),
	}
	extraNode := test.NewNode("node4", "4", false, []v1.NodeAddress{{"InternalIP",
		"192.168.0.4"}})

	addrs := []string{"192.168.0.1", "192.168.0.2"}

	fake := fake.NewSimpleClientset(
		&v1.ConfigMapList{Items: []v1.ConfigMap{*cfgIapp1, *cfgIapp2}},
		&v1.ServiceList{Items: []v1.Service{*iapp1, *iapp2}},
		&v1.NodeList{Items: nodes})
	require.NotNil(fake, "Mock client cannot be nil")

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	watchManager.(*test.MockWatchManager).Store["services"].Add(iapp1)
	watchManager.(*test.MockWatchManager).Store["services"].Add(iapp2)

	m, err := fake.Core().ConfigMaps("").List(v1.ListOptions{})
	require.Nil(err)
	s, err := fake.Core().Services("").List(v1.ListOptions{})
	require.Nil(err)
	n, err := fake.Core().Nodes().List(v1.ListOptions{})
	require.Nil(err)

	assert.Equal(2, len(m.Items))
	assert.Equal(2, len(s.Items))
	assert.Equal(4, len(n.Items))

	useNodeInternal = true
	ProcessNodeUpdate(n.Items, err)

	// ConfigMap ADDED
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfgIapp1,
	}, true)
	assert.Equal(1, virtualServers.Count())
	vs, ok := virtualServers.Get(
		serviceKey{"iapp1", 80, "default"}, formatVirtualServerName(cfgIapp1))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(10101, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Second ConfigMap ADDED
	ProcessConfigMapUpdate(added, ChangedObject{
		nil,
		cfgIapp2,
	}, true)
	assert.Equal(2, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"iapp1", 80, "default"}, formatVirtualServerName(cfgIapp1))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(10101, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"iapp2", 80, "default"}, formatVirtualServerName(cfgIapp2))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(20202, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Service ADDED
	ProcessServiceUpdate(added, ChangedObject{
		nil,
		iapp1}, true)
	assert.Equal(2, virtualServers.Count())

	// Second Service ADDED
	ProcessServiceUpdate(added, ChangedObject{
		nil,
		iapp2}, true)
	assert.Equal(2, virtualServers.Count())

	// ConfigMap UPDATED
	ProcessConfigMapUpdate(updated, ChangedObject{
		cfgIapp1,
		cfgIapp1,
	}, true)
	assert.Equal(2, virtualServers.Count())

	// Service UPDATED
	ProcessServiceUpdate(updated, ChangedObject{
		iapp1,
		iapp1}, true)
	assert.Equal(2, virtualServers.Count())

	// Nodes ADDED
	_, err = fake.Core().Nodes().Create(extraNode)
	require.Nil(err)
	useNodeInternal = true
	n, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(err, "Should not fail listing nodes")
	ProcessNodeUpdate(n.Items, err)
	assert.Equal(2, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"iapp1", 80, "default"}, formatVirtualServerName(cfgIapp1))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(10101, append(addrs, "192.168.0.4")),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"iapp2", 80, "default"}, formatVirtualServerName(cfgIapp2))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(20202, append(addrs, "192.168.0.4")),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	validateConfig(t, mw, twoIappsThreeNodesConfig)

	// Nodes DELETES
	err = fake.Core().Nodes().Delete("node1", &v1.DeleteOptions{})
	require.Nil(err)
	err = fake.Core().Nodes().Delete("node2", &v1.DeleteOptions{})
	require.Nil(err)
	useNodeInternal = true
	n, err = fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(err, "Should not fail listing nodes")
	ProcessNodeUpdate(n.Items, err)
	assert.Equal(2, virtualServers.Count())
	vs, ok = virtualServers.Get(
		serviceKey{"iapp1", 80, "default"}, formatVirtualServerName(cfgIapp1))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(10101, []string{"192.168.0.4"}),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	vs, ok = virtualServers.Get(
		serviceKey{"iapp2", 80, "default"}, formatVirtualServerName(cfgIapp2))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(20202, []string{"192.168.0.4"}),
		vs.VirtualServer.Backend.PoolMemberAddrs)
	validateConfig(t, mw, twoIappsOneNodeConfig)

	// ConfigMap DELETED
	err = fake.Core().ConfigMaps("default").Delete("iapp1map",
		&v1.DeleteOptions{})
	m, err = fake.Core().ConfigMaps("").List(v1.ListOptions{})
	assert.Equal(1, len(m.Items))
	ProcessConfigMapUpdate(deleted, ChangedObject{
		cfgIapp1,
		nil,
	}, true)
	assert.Equal(1, virtualServers.Count())
	assert.Equal(0, virtualServers.CountOf(serviceKey{"iapp1", 80, "default"}),
		"Config map should be removed after delete")
	validateConfig(t, mw, oneIappOneNodeConfig)

	// Service DELETED
	err = fake.Core().Services("default").Delete("iapp2", &v1.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(v1.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(deleted, ChangedObject{
		iapp2,
		nil}, true)
	assert.Equal(1, virtualServers.Count())
	validateConfig(t, mw, emptyConfig)
}

func TestSchemaValidation(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)
	assert := assert.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client should not be nil")

	badjson := test.NewConfigMap("badjson", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFooInvalid,
	})
	_, err := parseVirtualServerConfig(badjson)
	assert.Contains(err.Error(),
		"virtualServer.frontend.partition: String length must be greater than or equal to 1")
	assert.Contains(err.Error(),
		"virtualServer.frontend.mode: virtualServer.frontend.mode must be one of the following: \\\"http\\\", \\\"tcp\\\"")
	assert.Contains(err.Error(),
		"virtualServer.frontend.balance: virtualServer.frontend.balance must be one of the following:")
	assert.Contains(err.Error(),
		"virtualServer.frontend.sslProfile.f5ProfileName: String length must be greater than or equal to 1")
	assert.Contains(err.Error(),
		"virtualServer.frontend.virtualAddress.bindAddr: Does not match format 'ipv4'")
	assert.Contains(err.Error(),
		"virtualServer.frontend.virtualAddress.port: Must be less than or equal to 65535")
	assert.Contains(err.Error(),
		"virtualServer.backend.serviceName: String length must be greater than or equal to 1")
	assert.Contains(err.Error(),
		"virtualServer.backend.servicePort: Must be greater than or equal to 1")
}

func validateServiceIps(t *testing.T, serviceName, namespace string,
	svcPorts []v1.ServicePort, ips []string) {
	for _, p := range svcPorts {
		vsMap, ok := virtualServers.GetAll(serviceKey{serviceName, p.Port, namespace})
		require.True(t, ok)
		require.NotNil(t, vsMap)
		for _, vs := range vsMap {
			var expectedIps []string
			if ips != nil {
				expectedIps = []string{}
				for _, ip := range ips {
					ip = ip + ":" + strconv.Itoa(int(p.Port))
					expectedIps = append(expectedIps, ip)
				}
			}
			require.EqualValues(t, expectedIps, vs.VirtualServer.Backend.PoolMemberAddrs,
				"nodes are not correct")
		}
	}
}

func TestVirtualServerWhenEndpointsEmpty(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	svcName := "foo"
	emptyIps := []string{}
	readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	notReadyIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5", "10.2.96.6"}
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
	}

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	foo := test.NewService(svcName, "1", "default", v1.ServiceTypeClusterIP, svcPorts)

	svcStore := NewStore(nil)
	svcStore.Add(foo)
	var endptStore cache.Store
	onEndptChange := func(changeType changeType, obj ChangedObject) {
		ProcessEndpointsUpdate(changeType, obj)
	}
	endptStore = NewStore(onEndptChange)

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["endpoints"] = NewStore(nil)
	watchManager.(*test.MockWatchManager).Store["services"] = NewStore(nil)
	watchManager.(*test.MockWatchManager).Store["endpoints"] = endptStore
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore

	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	goodEndpts := test.NewEndpoints(svcName, "1", "default", emptyIps, emptyIps,
		endptPorts)

	err := endptStore.Add(goodEndpts)
	require.Nil(err)
	// this is for another service
	badEndpts := test.NewEndpoints("wrongSvc", "1", "default", []string{"10.2.96.7"},
		[]string{}, endptPorts)
	err = endptStore.Add(badEndpts)
	require.Nil(err)

	r := processConfigMap(added, ChangedObject{
		nil, cfgFoo}, false)
	require.True(r, "Config map should be processed")

	require.Equal(len(svcPorts), virtualServers.Count())
	for _, p := range svcPorts {
		require.Equal(1, virtualServers.CountOf(serviceKey{"foo", p.Port, "default"}))
		vs, ok := virtualServers.Get(
			serviceKey{"foo", p.Port, "default"}, formatVirtualServerName(cfgFoo))
		require.True(ok)
		require.EqualValues([]string(nil), vs.VirtualServer.Backend.PoolMemberAddrs)
	}

	validateServiceIps(t, svcName, "default", svcPorts, nil)

	// Move it back to ready from not ready and make sure it is re-added
	err = endptStore.Update(test.NewEndpoints(svcName, "2", "default", readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, readyIps)

	// Remove all endpoints make sure they are removed but virtual server exists
	err = endptStore.Update(test.NewEndpoints(svcName, "3", "default", emptyIps,
		emptyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, nil)

	// Move it back to ready from not ready and make sure it is re-added
	err = endptStore.Update(test.NewEndpoints(svcName, "4", "default", readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, readyIps)
}

func TestVirtualServerWhenEndpointsChange(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	svcName := "foo"
	emptyIps := []string{}
	readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	notReadyIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5", "10.2.96.6"}
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
		newServicePort("port1", 8080),
		newServicePort("port2", 9090),
	}

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := test.NewConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := test.NewConfigMap("foomap9090", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})

	foo := test.NewService(svcName, "1", "default", v1.ServiceTypeClusterIP, svcPorts)

	svcStore := NewStore(nil)
	svcStore.Add(foo)
	var endptStore cache.Store
	onEndptChange := func(changeType changeType, obj ChangedObject) {
		ProcessEndpointsUpdate(changeType, obj)
	}
	endptStore = NewStore(onEndptChange)

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["endpoints"] = endptStore
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore

	r := processConfigMap(added, ChangedObject{
		nil, cfgFoo}, false)
	require.True(r, "Config map should be processed")

	r = processConfigMap(added, ChangedObject{
		nil, cfgFoo8080}, false)
	require.True(r, "Config map should be processed")

	r = processConfigMap(added, ChangedObject{
		nil, cfgFoo9090}, false)
	require.True(r, "Config map should be processed")

	require.Equal(len(svcPorts), virtualServers.Count())
	for _, p := range svcPorts {
		require.Equal(1,
			virtualServers.CountOf(serviceKey{"foo", p.Port, "default"}))
	}

	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	goodEndpts := test.NewEndpoints(svcName, "1", "default", readyIps, notReadyIps,
		endptPorts)
	err := endptStore.Add(goodEndpts)
	require.Nil(err)
	// this is for another service
	badEndpts := test.NewEndpoints("wrongSvc", "1", "default", []string{"10.2.96.7"},
		[]string{}, endptPorts)
	err = endptStore.Add(badEndpts)
	require.Nil(err)

	validateServiceIps(t, svcName, "default", svcPorts, readyIps)

	// Move an endpoint from ready to not ready and make sure it
	// goes away from virtual servers
	notReadyIps = append(notReadyIps, readyIps[len(readyIps)-1])
	readyIps = readyIps[:len(readyIps)-1]
	err = endptStore.Update(test.NewEndpoints(svcName, "2", "default", readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, readyIps)

	// Move it back to ready from not ready and make sure it is re-added
	readyIps = append(readyIps, notReadyIps[len(notReadyIps)-1])
	notReadyIps = notReadyIps[:len(notReadyIps)-1]
	err = endptStore.Update(test.NewEndpoints(svcName, "3", "default", readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, readyIps)

	// Remove all endpoints make sure they are removed but virtual server exists
	err = endptStore.Update(test.NewEndpoints(svcName, "4", "default", emptyIps,
		emptyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, nil)

	// Move it back to ready from not ready and make sure it is re-added
	err = endptStore.Update(test.NewEndpoints(svcName, "5", "default", readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, "default", svcPorts, readyIps)
}

func TestVirtualServerWhenServiceChanges(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	svcName := "foo"
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
		newServicePort("port1", 8080),
		newServicePort("port2", 9090),
	}
	svcPodIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endptStore := NewStore(nil)

	foo := test.NewService(svcName, "1", "default", v1.ServiceTypeClusterIP, svcPorts)

	onSvcChange := func(changeType changeType, obj ChangedObject) {
		processService(changeType, obj, false)
	}
	svcStore := NewStore(onSvcChange)
	svcStore.Add(foo)

	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	err := endptStore.Add(test.NewEndpoints(svcName, "1", "default", svcPodIps,
		[]string{}, endptPorts))
	require.Nil(err)

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["endpoints"] = endptStore
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := test.NewConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := test.NewConfigMap("foomap9090", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})

	r := processConfigMap(added, ChangedObject{
		nil, cfgFoo}, false)
	require.True(r, "Config map should be processed")

	r = processConfigMap(added, ChangedObject{
		nil, cfgFoo8080}, false)
	require.True(r, "Config map should be processed")

	r = processConfigMap(added, ChangedObject{
		nil, cfgFoo9090}, false)
	require.True(r, "Config map should be processed")

	require.Equal(len(svcPorts), virtualServers.Count())
	validateServiceIps(t, svcName, "default", svcPorts, svcPodIps)

	// delete the service and make sure the IPs go away on the VS
	svcStore.Delete(foo)
	require.Equal(len(svcPorts), virtualServers.Count())
	validateServiceIps(t, svcName, "default", svcPorts, nil)

	// re-add the service
	foo.ObjectMeta.ResourceVersion = "2"
	svcStore.Add(foo)
	require.Equal(len(svcPorts), virtualServers.Count())
	validateServiceIps(t, svcName, "default", svcPorts, svcPodIps)
}

func TestVirtualServerWhenConfigMapChanges(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	require := require.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	svcName := "foo"
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
		newServicePort("port1", 8080),
		newServicePort("port2", 9090),
	}
	svcPodIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}

	foo := test.NewService(svcName, "1", "default", v1.ServiceTypeClusterIP, svcPorts)

	onSvcChange := func(changeType changeType, obj ChangedObject) {
		processService(changeType, obj, false)
	}
	svcStore := NewStore(onSvcChange)
	svcStore.Add(foo)

	endptStore := NewStore(nil)
	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	err := endptStore.Add(test.NewEndpoints(svcName, "1", "default", svcPodIps,
		[]string{}, endptPorts))
	require.Nil(err)

	// no virtual servers yet
	require.Equal(0, virtualServers.Count())

	onCfgChange := func(changeType changeType, obj ChangedObject) {
		processConfigMap(changeType, obj, false)
	}
	cfgStore := NewStore(onCfgChange)

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["endpoints"] = endptStore
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore

	// add a config map
	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgStore.Add(cfgFoo)
	require.Equal(1, virtualServers.Count())
	validateServiceIps(t, svcName, "default", svcPorts[:1], svcPodIps)

	// add another
	cfgFoo8080 := test.NewConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgStore.Add(cfgFoo8080)
	require.Equal(2, virtualServers.Count())
	validateServiceIps(t, svcName, "default", svcPorts[:2], svcPodIps)

	// remove first one
	cfgStore.Delete(cfgFoo)
	require.Equal(1, virtualServers.Count())
	validateServiceIps(t, svcName, "default", svcPorts[1:2], svcPodIps)
}

func TestUpdatesConcurrentCluster(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)

	defer virtualServers.Init()

	assert := assert.New(t)
	require := require.New(t)

	fooIps := []string{"10.2.96.1", "10.2.96.2"}
	fooPorts := []v1.ServicePort{newServicePort("port0", 8080)}
	barIps := []string{"10.2.96.0", "10.2.96.3"}
	barPorts := []v1.ServicePort{newServicePort("port1", 80)}

	cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgBar := test.NewConfigMap("barmap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapBar})

	foo := test.NewService("foo", "1", "default", v1.ServiceTypeClusterIP, fooPorts)
	bar := test.NewService("bar", "1", "default", v1.ServiceTypeClusterIP, barPorts)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	var cfgStore cache.Store
	var endptStore cache.Store
	var svcStore cache.Store

	onCfgChange := func(changeType changeType, obj ChangedObject) {
		ProcessConfigMapUpdate(changeType, obj, false)
	}
	cfgStore = NewStore(onCfgChange)

	onEndptChange := func(changeType changeType, obj ChangedObject) {
		ProcessEndpointsUpdate(changeType, obj)
	}
	endptStore = NewStore(onEndptChange)

	onSvcChange := func(changeType changeType, obj ChangedObject) {
		ProcessServiceUpdate(changeType, obj, false)
		require.True(ok, "expected ChangedObject")
		switch changeType {
		case added:
			svc := obj.New.(*v1.Service)
			fSvc, err := fake.Core().Services("default").Create(svc)
			require.Nil(err, "Should not fail creating service")
			require.EqualValues(fSvc, svc, "Service should be equal")
		case deleted:
			svc := obj.Old.(*v1.Service)
			err := fake.Core().Services("default").Delete(svc.ObjectMeta.Name,
				&v1.DeleteOptions{})
			require.Nil(err, "Should not error deleting service")
		}
	}
	svcStore = NewStore(onSvcChange)

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["endpoints"] = endptStore
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore

	fooEndpts := test.NewEndpoints("foo", "1", "default", fooIps, barIps,
		convertSvcPortsToEndpointPorts(fooPorts))
	barEndpts := test.NewEndpoints("bar", "1", "default", barIps, fooIps,
		convertSvcPortsToEndpointPorts(barPorts))
	cfgCh := make(chan struct{})
	endptCh := make(chan struct{})
	svcCh := make(chan struct{})

	go func() {
		err := endptStore.Add(fooEndpts)
		require.Nil(err)
		err = endptStore.Add(barEndpts)
		require.Nil(err)

		endptCh <- struct{}{}
	}()

	go func() {
		err := cfgStore.Add(cfgFoo)
		require.Nil(err, "Should not fail creating configmap")

		err = cfgStore.Add(cfgBar)
		require.Nil(err, "Should not fail creating configmap")

		cfgCh <- struct{}{}
	}()

	go func() {
		err := svcStore.Add(foo)
		require.Nil(err, "Should not fail creating service")

		err = svcStore.Add(bar)
		require.Nil(err, "Should not fail creating service")

		svcCh <- struct{}{}
	}()

	select {
	case <-endptCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting endpoints channel notification")
	}
	select {
	case <-cfgCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting configmap channel notification")
	}
	select {
	case <-svcCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out excpecting service channel notification")
	}

	validateConfig(t, mw, twoSvcTwoPodsConfig)

	go func() {
		// delete endpoints for foo
		err := endptStore.Delete(fooEndpts)
		require.Nil(err)

		endptCh <- struct{}{}
	}()

	go func() {
		// delete cfgmap for foo
		err := cfgStore.Delete(cfgFoo)
		require.Nil(err, "Should not error deleting map")

		cfgCh <- struct{}{}
	}()

	go func() {
		// Delete service for foo
		err := svcStore.Delete(foo)
		require.Nil(err, "Should not error deleting service")

		svcCh <- struct{}{}
	}()

	select {
	case <-endptCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting endpoints channel notification")
	}
	select {
	case <-cfgCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out expecting configmap channel notification")
	}
	select {
	case <-svcCh:
	case <-time.After(time.Second * 30):
		assert.FailNow("Timed out excpecting service channel notification")
	}
	assert.Equal(1, virtualServers.Count())
	validateConfig(t, mw, oneSvcTwoPodsConfig)
}

func TestNonNodePortServiceModeNodePort(t *testing.T) {
	defer virtualServers.Init()

	assert := assert.New(t)
	require := require.New(t)

	cfgFoo := test.NewConfigMap(
		"foomap",
		"1",
		"default",
		map[string]string{
			"schema": schemaUrl,
			"data":   configmapFoo,
		},
	)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	svcName := "foo"
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
	}

	foo := test.NewService(svcName, "1", "default", v1.ServiceTypeClusterIP, svcPorts)

	svcStore := NewStore(nil)
	svcStore.Add(foo)

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["endpoints"] = NewStore(nil)
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore

	r := processConfigMap(
		added,
		ChangedObject{nil, cfgFoo},
		true,
	)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have an entry",
	)

	foo = test.NewService(
		"foo",
		"1",
		"default",
		"ClusterIP",
		[]v1.ServicePort{{Port: 80}},
	)

	r = processService(
		added,
		ChangedObject{nil, foo},
		true,
	)

	assert.False(r, "Should not process non NodePort Service")
}

func TestMultipleVirtualServersForOneBackend(t *testing.T) {
	config = &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	mw, ok := config.(*test.MockWriter)
	assert.NotNil(t, mw)
	assert.True(t, ok)
	require := require.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")
	kubeClient = fake
	var resetClient kubernetes.Interface
	defer func() { kubeClient = resetClient }()

	defer virtualServers.Init()

	svcPorts := []v1.ServicePort{
		newServicePort("port80", 80),
	}
	svc := test.NewService("app", "1", "default", v1.ServiceTypeClusterIP, svcPorts)
	svcStore := NewStore(nil)
	svcStore.Add(svc)

	cfgStore := NewStore(func(change changeType, obj ChangedObject) {
		ProcessConfigMapUpdate(change, obj, false)
	})

	watchManager = test.NewMockWatchManager()
	defer func() { watchManager = test.NewMockWatchManager() }()
	watchManager.(*test.MockWatchManager).Store["services"] = svcStore
	watchManager.(*test.MockWatchManager).Store["endpoints"] = NewStore(nil)

	vsTemplate := `{
		"virtualServer": {
			"backend": {
				"serviceName": "app",
				"servicePort": 80,
				"healthMonitors": [
					{
						"interval": %d,
						"timeout": 20,
						"send": "GET /",
						"protocol": "tcp"
					}
				]
			},
			"frontend": {
				"balance": "round-robin",
				"mode": "http",
				"partition": "velcro",
				"virtualAddress": {
					"bindAddr": "10.128.10.240",
					"port": %d
				}
			}
		}
	}`

	require.Equal(0, virtualServers.Count())
	cfgStore.Add(test.NewConfigMap("cmap-1", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   fmt.Sprintf(vsTemplate, 5, 80),
	}))
	require.Equal(1, virtualServers.Count())
	cfgStore.Update(test.NewConfigMap("cmap-1", "2", "default", map[string]string{
		"schema": schemaUrl,
		"data":   fmt.Sprintf(vsTemplate, 5, 80),
	}))
	require.Equal(1, virtualServers.Count())
	cfgStore.Add(test.NewConfigMap("cmap-2", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   fmt.Sprintf(vsTemplate, 5, 8080),
	}))
	require.Equal(2, virtualServers.Count())
}
