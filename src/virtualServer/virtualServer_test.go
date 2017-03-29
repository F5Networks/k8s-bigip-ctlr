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
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

func init() {
	namespace = "default"

	workingDir, _ := os.Getwd()
	schemaUrl = "file://" + workingDir + "/../../vendor/src/f5/schemas/bigip-virtual-server_v0.1.2.json"
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

func newConfigMap(id, rv, namespace string,
	keys map[string]string) *v1.ConfigMap {
	return &v1.ConfigMap{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
		},
		Data: keys,
	}
}

func newService(id, rv, namespace string, serviceType v1.ServiceType,
	portSpecList []v1.ServicePort) *v1.Service {
	return &v1.Service{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
		},
		Spec: v1.ServiceSpec{
			Type:  serviceType,
			Ports: portSpecList,
		},
	}
}

func newNode(id, rv string, unsched bool,
	addresses []v1.NodeAddress) *v1.Node {
	return &v1.Node{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
		},
		Spec: v1.NodeSpec{
			Unschedulable: unsched,
		},
		Status: v1.NodeStatus{
			Addresses: addresses,
		},
	}
}

func convertSvcPortsToEndpointPorts(svcPorts []v1.ServicePort) []v1.EndpointPort {
	eps := make([]v1.EndpointPort, len(svcPorts))
	for i, v := range svcPorts {
		eps[i].Name = v.Name
		eps[i].Port = v.Port
	}
	return eps
}

func newEndpointAddress(ips []string) []v1.EndpointAddress {
	eps := make([]v1.EndpointAddress, len(ips))
	for i, v := range ips {
		eps[i].IP = v
	}
	return eps
}

func newEndpointPort(portName string, ports []int32) []v1.EndpointPort {
	epp := make([]v1.EndpointPort, len(ports))
	for i, v := range ports {
		epp[i].Name = portName
		epp[i].Port = v
	}
	return epp
}

func newEndpoints(svcName, rv, namespace string,
	readyIps, notReadyIps []string, ports []v1.EndpointPort) *v1.Endpoints {
	ep := &v1.Endpoints{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:            svcName,
			Namespace:       namespace,
			ResourceVersion: rv,
		},
		Subsets: []v1.EndpointSubset{},
	}

	if 0 < len(readyIps) {
		ep.Subsets = append(
			ep.Subsets,
			v1.EndpointSubset{
				Addresses:         newEndpointAddress(readyIps),
				NotReadyAddresses: newEndpointAddress(notReadyIps),
				Ports:             ports,
			},
		)
	}

	return ep
}

func newServicePort(name string, svcPort int32) v1.ServicePort {
	return v1.ServicePort{
		Port: svcPort,
		Name: name,
	}
}

// Adapter function to translate Store events to virtualServer calls
type onChangeFunc func(change changeType, changed changedObject)

type mockStore struct {
	storage  cache.ThreadSafeStore
	keyFunc  cache.KeyFunc
	onChange onChangeFunc
}

func newStore(onChange onChangeFunc) cache.Store {
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
		ms.onChange(added, changedObject{
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
		ms.onChange(updated, changedObject{
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
		ms.onChange(deleted, changedObject{
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
	return item, exists, nil
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
		newNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		newNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		newNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
		newNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.3"}}),
		newNode("node4", "4", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.4"}}),
		newNode("node5", "5", false, []v1.NodeAddress{
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
		*newNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
		*newNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.3"}}),
		*newNode("node4", "4", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.4"}}),
		*newNode("node5", "5", false, []v1.NodeAddress{
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
	_, err = fake.Core().Nodes().Create(newNode("nodeAdd", "nodeAdd", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.6"}}))
	require.Nil(t, err, "Create should not return err")

	_, err = fake.Core().Nodes().Create(newNode("nodeExclude", "nodeExclude",
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

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")

	endptStore := newStore(nil)
	r := processConfigMap(fake, added,
		changedObject{nil, cfgFoo}, isNodePort, endptStore)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have entry")
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	require.Equal("http", vs.VirtualServer.Frontend.Mode, "Mode should be http")

	cfgFoo = newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFooTcp})

	r = processConfigMap(fake, added,
		changedObject{nil, cfgFoo}, isNodePort, endptStore)
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

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")

	endptStore := newStore(nil)
	r := processConfigMap(fake, added,
		changedObject{nil, cfgFoo}, true, endptStore)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have an entry")

	cfgFoo8080 := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})

	r = processConfigMap(fake, updated,
		changedObject{cfgFoo, cfgFoo8080}, true, endptStore)
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

	defer virtualServers.Init()

	require := require.New(t)
	nodeSet := []v1.Node{
		*newNode("node0", "0", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.0"}}),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.1"}}),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.2"}}),
	}

	useNodeInternal = true
	ProcessNodeUpdate(nodeSet, nil)

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := newConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := newConfigMap("foomap9090", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})

	foo := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001},
			{Port: 8080, NodePort: 38001},
			{Port: 9090, NodePort: 39001}})

	fake := fake.NewSimpleClientset(&v1.ServiceList{Items: []v1.Service{*foo}})

	endptStore := newStore(nil)
	r := processConfigMap(fake, added, changedObject{
		nil,
		cfgFoo}, true, endptStore)
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, added, changedObject{
		nil,
		cfgFoo8080}, true, endptStore)
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, added, changedObject{
		nil,
		cfgFoo9090}, true, endptStore)
	require.True(r, "Config map should be processed")

	require.Equal(3, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}))
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 9090, "default"}))

	// Create a new service with less ports and update
	newFoo := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})

	r = processService(fake, updated, changedObject{
		foo,
		newFoo}, true, endptStore)
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
	newFoo2 := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 20001},
			{Port: 8080, NodePort: 45454}})

	r = processService(fake, updated, changedObject{
		newFoo,
		newFoo2}, true, endptStore)
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

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgBar := newConfigMap("barmap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapBar})
	foo := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})
	bar := newService("bar", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 37001}})
	nodes := []*v1.Node{
		newNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		newNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		newNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
	}
	extraNode := newNode("node3", "3", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.3"}})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")

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

		endptStore := newStore(nil)
		ProcessConfigMapUpdate(fake, added, changedObject{
			nil,
			cfgFoo,
		}, true, endptStore)

		b, err := fake.Core().ConfigMaps("default").Create(cfgBar)
		require.Nil(err, "Should not fail creating configmap")
		require.EqualValues(b, cfgBar, "Maps should be equal")

		ProcessConfigMapUpdate(fake, added, changedObject{
			nil,
			cfgBar,
		}, true, endptStore)

		mapCh <- struct{}{}
	}()

	go func() {
		fSvc, err := fake.Core().Services("default").Create(foo)
		require.Nil(err, "Should not fail creating service")
		require.EqualValues(fSvc, foo, "Service should be equal")

		endptStore := newStore(nil)
		ProcessServiceUpdate(fake, added, changedObject{
			nil,
			foo}, true, endptStore)

		bSvc, err := fake.Core().Services("default").Create(bar)
		require.Nil(err, "Should not fail creating service")
		require.EqualValues(bSvc, bar, "Maps should be equal")

		ProcessServiceUpdate(fake, added, changedObject{
			nil,
			bar}, true, endptStore)

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
		endptStore := newStore(nil)
		ProcessConfigMapUpdate(fake, deleted, changedObject{
			cfgFoo,
			nil,
		}, true, endptStore)
		assert.Equal(1, virtualServers.Count())

		mapCh <- struct{}{}
	}()

	go func() {
		err := fake.Core().Services("default").Delete("foo",
			&v1.DeleteOptions{})
		require.Nil(err, "Should not error deleting service")
		s, _ := fake.Core().Services("").List(v1.ListOptions{})
		assert.Equal(1, len(s.Items))
		endptStore := newStore(nil)
		ProcessServiceUpdate(fake, deleted, changedObject{
			foo,
			nil}, true, endptStore)

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
	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := newConfigMap("foomap8080", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := newConfigMap("foomap9090", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})
	cfgBar := newConfigMap("barmap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapBar})
	foo := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001},
			{Port: 8080, NodePort: 38001},
			{Port: 9090, NodePort: 39001}})
	bar := newService("bar", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 37001}})
	nodes := []v1.Node{
		*newNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
	}
	extraNode := newNode("node3", "3", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.3"}})

	addrs := []string{"127.0.0.1", "127.0.0.2"}

	fake := fake.NewSimpleClientset(
		&v1.ConfigMapList{Items: []v1.ConfigMap{*cfgFoo, *cfgBar}},
		&v1.ServiceList{Items: []v1.Service{*foo, *bar}},
		&v1.NodeList{Items: nodes})
	require.NotNil(fake, "Mock client cannot be nil")

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
	endptStore := newStore(nil)
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfgFoo,
	}, true, endptStore)
	assert.Equal(1, virtualServers.Count())
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(30001, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Second ConfigMap added
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfgBar,
	}, true, endptStore)
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
	ProcessServiceUpdate(fake, added, changedObject{
		nil,
		foo}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// Second Service ADDED
	ProcessServiceUpdate(fake, added, changedObject{
		nil,
		bar}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// ConfigMap UPDATED
	ProcessConfigMapUpdate(fake, updated, changedObject{
		cfgFoo,
		cfgFoo,
	}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// Service UPDATED
	ProcessServiceUpdate(fake, updated, changedObject{
		foo,
		foo}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// ConfigMap ADDED second foo port
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfgFoo8080}, true, endptStore)
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
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfgFoo9090}, true, endptStore)
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
	ProcessConfigMapUpdate(fake, deleted, changedObject{
		cfgFoo9090,
		nil}, true, endptStore)
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
	ProcessConfigMapUpdate(fake, updated, changedObject{
		cfgFoo8080,
		cfgFoo8080}, true, endptStore)
	assert.Equal(3, virtualServers.Count())
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 8080, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain remaining ports")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"bar", 80, "default"}),
		"Virtual servers should contain remaining ports")

	// ConfigMap DELETED second foo port
	ProcessConfigMapUpdate(fake, deleted, changedObject{
		cfgFoo8080,
		nil}, true, endptStore)
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
	ProcessConfigMapUpdate(fake, deleted, changedObject{
		cfgFoo,
		nil,
	}, true, endptStore)
	assert.Equal(1, virtualServers.Count())
	assert.Equal(0, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Config map should be removed after delete")
	validateConfig(t, mw, oneSvcOneNodeConfig)

	// Service deletedD
	err = fake.Core().Services("default").Delete("bar", &v1.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(v1.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(fake, deleted, changedObject{
		bar,
		nil}, true, endptStore)
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

	cfg := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   "bar"})
	svc := newService("foo", "1", "default", "NodePort",
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
	endptStore := newStore(nil)
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfg,
	}, true, endptStore)
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

	noschemakey := newConfigMap("noschema", "1", "default", map[string]string{
		"data": configmapFoo})
	cfg, err := parseVirtualServerConfig(noschemakey)
	require.EqualError(err, "configmap noschema does not contain schema key",
		"Should receive no schema error")
	endptStore := newStore(nil)
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		noschemakey,
	}, isNodePort, endptStore)
	require.Equal(0, virtualServers.Count())

	nodatakey := newConfigMap("nodata", "1", "default", map[string]string{
		"schema": schemaUrl,
	})
	cfg, err = parseVirtualServerConfig(nodatakey)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err, "configmap nodata does not contain data key",
		"Should receive no data error")
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		nodatakey,
	}, isNodePort, endptStore)
	require.Equal(0, virtualServers.Count())

	badjson := newConfigMap("badjson", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   "///// **invalid json** /////",
	})
	cfg, err = parseVirtualServerConfig(badjson)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err,
		"invalid character '/' looking for beginning of value")
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		badjson,
	}, isNodePort, endptStore)
	require.Equal(0, virtualServers.Count())

	extrakeys := newConfigMap("extrakeys", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo,
		"key1":   "value1",
		"key2":   "value2",
	})
	cfg, err = parseVirtualServerConfig(extrakeys)
	require.NotNil(cfg, "Config map should parse with extra keys")
	require.Nil(err, "Should not receive errors")
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		extrakeys,
	}, isNodePort, endptStore)
	require.Equal(1, virtualServers.Count())

	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(extrakeys))
	assert.True(ok, "Config map should be accessible")
	assert.NotNil(vs, "Config map should be object")

	require.Equal("round-robin", vs.VirtualServer.Frontend.Balance)
	require.Equal("http", vs.VirtualServer.Frontend.Mode)
	require.Equal("velcro", vs.VirtualServer.Frontend.Partition)
	require.Equal("10.128.10.240",
		vs.VirtualServer.Frontend.VirtualAddress.BindAddr)
	require.Equal(int32(5051), vs.VirtualServer.Frontend.VirtualAddress.Port)
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

	node := newNode("node3", "3", false,
		[]v1.NodeAddress{{"InternalIP", "127.0.0.3"}})
	_, err := fake.Core().Nodes().Create(node)
	require.Nil(err)
	useNodeInternal = true
	n, err := fake.Core().Nodes().List(v1.ListOptions{})
	assert.Nil(err, "Should not fail listing nodes")
	ProcessNodeUpdate(n.Items, err)

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgBar := newConfigMap("foomap", "1", "wrongnamespace", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	servFoo := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 37001}})
	servBar := newService("foo", "1", "wrongnamespace", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 50000}})

	endptStore := newStore(nil)
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil, cfgFoo}, true, endptStore)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Config map should be accessible")

	ProcessConfigMapUpdate(fake, added, changedObject{
		nil, cfgBar}, true, endptStore)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, formatVirtualServerName(cfgBar))
	assert.False(ok, "Config map should not be added if namespace does not match flag")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain original config")
	assert.Equal(1, virtualServers.Count(), "There should only be 1 virtual server")

	ProcessConfigMapUpdate(fake, updated, changedObject{
		cfgBar, cfgBar}, true, endptStore)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, formatVirtualServerName(cfgBar))
	assert.False(ok, "Config map should not be added if namespace does not match flag")
	assert.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should contain original config")
	assert.Equal(1, virtualServers.Count(), "There should only be 1 virtual server")

	ProcessConfigMapUpdate(fake, deleted, changedObject{
		cfgBar, nil}, true, endptStore)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, formatVirtualServerName(cfgBar))
	assert.False(ok, "Config map should not be deleted if namespace does not match flag")
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Config map should be accessible after delete called on incorrect namespace")

	ProcessServiceUpdate(fake, added, changedObject{
		nil, servFoo}, true, endptStore)
	vs, ok := virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")

	ProcessServiceUpdate(fake, added, changedObject{
		nil, servBar}, true, endptStore)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, "foomap")
	assert.False(ok, "Service should not be added if namespace does not match flag")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")

	ProcessServiceUpdate(fake, updated, changedObject{
		servBar, servBar}, true, endptStore)
	_, ok = virtualServers.Get(
		serviceKey{"foo", 80, "wrongnamespace"}, "foomap")
	assert.False(ok, "Service should not be added if namespace does not match flag")
	vs, ok = virtualServers.Get(
		serviceKey{"foo", 80, "default"}, formatVirtualServerName(cfgFoo))
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(generateExpectedAddrs(37001, []string{"127.0.0.3"}),
		vs.VirtualServer.Backend.PoolMemberAddrs,
		"Port should match initial config")

	ProcessServiceUpdate(fake, deleted, changedObject{
		servBar, nil}, true, endptStore)
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
	cfgIapp1 := newConfigMap("iapp1map", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapIApp1})
	cfgIapp2 := newConfigMap("iapp2map", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapIApp2})
	iapp1 := newService("iapp1", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 10101}})
	iapp2 := newService("iapp2", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 20202}})
	nodes := []v1.Node{
		*newNode("node0", "0", true, []v1.NodeAddress{
			{"InternalIP", "192.168.0.0"}}),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{"InternalIP", "192.168.0.1"}}),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{"InternalIP", "192.168.0.2"}}),
		*newNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "192.168.0.3"}}),
	}
	extraNode := newNode("node4", "4", false, []v1.NodeAddress{{"InternalIP",
		"192.168.0.4"}})

	addrs := []string{"192.168.0.1", "192.168.0.2"}

	fake := fake.NewSimpleClientset(
		&v1.ConfigMapList{Items: []v1.ConfigMap{*cfgIapp1, *cfgIapp2}},
		&v1.ServiceList{Items: []v1.Service{*iapp1, *iapp2}},
		&v1.NodeList{Items: nodes})
	require.NotNil(fake, "Mock client cannot be nil")

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
	endptStore := newStore(nil)
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfgIapp1,
	}, true, endptStore)
	assert.Equal(1, virtualServers.Count())
	vs, ok := virtualServers.Get(
		serviceKey{"iapp1", 80, "default"}, formatVirtualServerName(cfgIapp1))
	require.True(ok)
	assert.EqualValues(generateExpectedAddrs(10101, addrs),
		vs.VirtualServer.Backend.PoolMemberAddrs)

	// Second ConfigMap ADDED
	ProcessConfigMapUpdate(fake, added, changedObject{
		nil,
		cfgIapp2,
	}, true, endptStore)
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
	ProcessServiceUpdate(fake, added, changedObject{
		nil,
		iapp1}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// Second Service ADDED
	ProcessServiceUpdate(fake, added, changedObject{
		nil,
		iapp2}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// ConfigMap UPDATED
	ProcessConfigMapUpdate(fake, updated, changedObject{
		cfgIapp1,
		cfgIapp1,
	}, true, endptStore)
	assert.Equal(2, virtualServers.Count())

	// Service UPDATED
	ProcessServiceUpdate(fake, updated, changedObject{
		iapp1,
		iapp1}, true, endptStore)
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
	ProcessConfigMapUpdate(fake, deleted, changedObject{
		cfgIapp1,
		nil,
	}, true, endptStore)
	assert.Equal(1, virtualServers.Count())
	assert.Equal(0, virtualServers.CountOf(serviceKey{"iapp1", 80, "default"}),
		"Config map should be removed after delete")
	validateConfig(t, mw, oneIappOneNodeConfig)

	// Service DELETED
	err = fake.Core().Services("default").Delete("iapp2", &v1.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(v1.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(fake, deleted, changedObject{
		iapp2,
		nil}, true, endptStore)
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

	// JSON is valid, but values are invalid
	var configmapFoo string = string(`{
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

	badjson := newConfigMap("badjson", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo,
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

	svcName := "foo"
	emptyIps := []string{}
	readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	notReadyIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5", "10.2.96.6"}
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
	}

	cfgFoo := newConfigMap("foomap", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	foo := newService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)
	fake := fake.NewSimpleClientset(&v1.ServiceList{Items: []v1.Service{*foo}})

	svcStore := newStore(nil)
	svcStore.Add(foo)
	var endptStore cache.Store
	onEndptChange := func(changeType changeType, obj changedObject) {
		ProcessEndpointsUpdate(fake, changeType, obj, svcStore)
	}
	endptStore = newStore(onEndptChange)

	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	goodEndpts := newEndpoints(svcName, "1", namespace, emptyIps, emptyIps,
		endptPorts)

	err := endptStore.Add(goodEndpts)
	require.Nil(err)
	// this is for another service
	badEndpts := newEndpoints("wrongSvc", "1", namespace, []string{"10.2.96.7"},
		[]string{}, endptPorts)
	err = endptStore.Add(badEndpts)
	require.Nil(err)

	r := processConfigMap(fake, added, changedObject{
		nil, cfgFoo}, false, endptStore)
	require.True(r, "Config map should be processed")

	require.Equal(len(svcPorts), virtualServers.Count())
	for _, p := range svcPorts {
		require.Equal(1, virtualServers.CountOf(serviceKey{"foo", p.Port, namespace}))
		vs, ok := virtualServers.Get(
			serviceKey{"foo", p.Port, namespace}, formatVirtualServerName(cfgFoo))
		require.True(ok)
		require.EqualValues([]string{}, vs.VirtualServer.Backend.PoolMemberAddrs)
	}

	validateServiceIps(t, svcName, namespace, svcPorts, []string{})

	// Move it back to ready from not ready and make sure it is re-added
	err = endptStore.Update(newEndpoints(svcName, "2", namespace, readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, readyIps)

	// Remove all endpoints make sure they are removed but virtual server exists
	err = endptStore.Update(newEndpoints(svcName, "3", namespace, emptyIps,
		emptyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, []string{})

	// Move it back to ready from not ready and make sure it is re-added
	err = endptStore.Update(newEndpoints(svcName, "4", namespace, readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, readyIps)
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

	svcName := "foo"
	emptyIps := []string{}
	readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	notReadyIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5", "10.2.96.6"}
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
		newServicePort("port1", 8080),
		newServicePort("port2", 9090),
	}

	cfgFoo := newConfigMap("foomap", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := newConfigMap("foomap8080", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := newConfigMap("foomap9090", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})

	foo := newService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)
	fake := fake.NewSimpleClientset(&v1.ServiceList{Items: []v1.Service{*foo}})

	svcStore := newStore(nil)
	svcStore.Add(foo)
	var endptStore cache.Store
	onEndptChange := func(changeType changeType, obj changedObject) {
		ProcessEndpointsUpdate(fake, changeType, obj, svcStore)
	}
	endptStore = newStore(onEndptChange)

	r := processConfigMap(fake, added, changedObject{
		nil, cfgFoo}, false, endptStore)
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, added, changedObject{
		nil, cfgFoo8080}, false, endptStore)
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, added, changedObject{
		nil, cfgFoo9090}, false, endptStore)
	require.True(r, "Config map should be processed")

	require.Equal(len(svcPorts), virtualServers.Count())
	for _, p := range svcPorts {
		require.Equal(1,
			virtualServers.CountOf(serviceKey{"foo", p.Port, namespace}))
	}

	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	goodEndpts := newEndpoints(svcName, "1", namespace, readyIps, notReadyIps,
		endptPorts)
	err := endptStore.Add(goodEndpts)
	require.Nil(err)
	// this is for another service
	badEndpts := newEndpoints("wrongSvc", "1", namespace, []string{"10.2.96.7"},
		[]string{}, endptPorts)
	err = endptStore.Add(badEndpts)
	require.Nil(err)

	validateServiceIps(t, svcName, namespace, svcPorts, readyIps)

	// Move an endpoint from ready to not ready and make sure it
	// goes away from virtual servers
	notReadyIps = append(notReadyIps, readyIps[len(readyIps)-1])
	readyIps = readyIps[:len(readyIps)-1]
	err = endptStore.Update(newEndpoints(svcName, "2", namespace, readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, readyIps)

	// Move it back to ready from not ready and make sure it is re-added
	readyIps = append(readyIps, notReadyIps[len(notReadyIps)-1])
	notReadyIps = notReadyIps[:len(notReadyIps)-1]
	err = endptStore.Update(newEndpoints(svcName, "3", namespace, readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, readyIps)

	// Remove all endpoints make sure they are removed but virtual server exists
	err = endptStore.Update(newEndpoints(svcName, "4", namespace, emptyIps,
		emptyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, []string{})

	// Move it back to ready from not ready and make sure it is re-added
	err = endptStore.Update(newEndpoints(svcName, "5", namespace, readyIps,
		notReadyIps, endptPorts))
	require.Nil(err)
	validateServiceIps(t, svcName, namespace, svcPorts, readyIps)
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

	svcName := "foo"
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
		newServicePort("port1", 8080),
		newServicePort("port2", 9090),
	}
	svcPodIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endptStore := newStore(nil)

	foo := newService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)
	fake := fake.NewSimpleClientset(&v1.ServiceList{Items: []v1.Service{*foo}})

	onSvcChange := func(changeType changeType, obj changedObject) {
		processService(fake, changeType, obj, false, endptStore)
	}
	svcStore := newStore(onSvcChange)
	svcStore.Add(foo)

	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	err := endptStore.Add(newEndpoints(svcName, "1", namespace, svcPodIps,
		[]string{}, endptPorts))
	require.Nil(err)

	cfgFoo := newConfigMap("foomap", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgFoo8080 := newConfigMap("foomap8080", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgFoo9090 := newConfigMap("foomap9090", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo9090})

	r := processConfigMap(fake, added, changedObject{
		nil, cfgFoo}, false, endptStore)
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, added, changedObject{
		nil, cfgFoo8080}, false, endptStore)
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, added, changedObject{
		nil, cfgFoo9090}, false, endptStore)
	require.True(r, "Config map should be processed")

	require.Equal(len(svcPorts), virtualServers.Count())
	validateServiceIps(t, svcName, namespace, svcPorts, svcPodIps)

	// delete the service and make sure the IPs go away on the VS
	svcStore.Delete(foo)
	require.Equal(len(svcPorts), virtualServers.Count())
	validateServiceIps(t, svcName, namespace, svcPorts, nil)

	// re-add the service
	foo.ObjectMeta.ResourceVersion = "2"
	svcStore.Add(foo)
	require.Equal(len(svcPorts), virtualServers.Count())
	validateServiceIps(t, svcName, namespace, svcPorts, svcPodIps)
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

	svcName := "foo"
	svcPorts := []v1.ServicePort{
		newServicePort("port0", 80),
		newServicePort("port1", 8080),
		newServicePort("port2", 9090),
	}
	svcPodIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endptStore := newStore(nil)
	endptPorts := convertSvcPortsToEndpointPorts(svcPorts)
	err := endptStore.Add(newEndpoints(svcName, "1", namespace, svcPodIps,
		[]string{}, endptPorts))
	require.Nil(err)

	foo := newService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)
	fake := fake.NewSimpleClientset(&v1.ServiceList{Items: []v1.Service{*foo}})

	// no virtual servers yet
	require.Equal(0, virtualServers.Count())

	onCfgChange := func(changeType changeType, obj changedObject) {
		processConfigMap(fake, changeType, obj, false, endptStore)
	}
	cfgStore := newStore(onCfgChange)

	// add a config map
	cfgFoo := newConfigMap("foomap", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})
	cfgStore.Add(cfgFoo)
	require.Equal(1, virtualServers.Count())
	validateServiceIps(t, svcName, namespace, svcPorts[:1], svcPodIps)

	// add another
	cfgFoo8080 := newConfigMap("foomap8080", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgStore.Add(cfgFoo8080)
	require.Equal(2, virtualServers.Count())
	validateServiceIps(t, svcName, namespace, svcPorts[:2], svcPodIps)

	// remove first one
	cfgStore.Delete(cfgFoo)
	require.Equal(1, virtualServers.Count())
	validateServiceIps(t, svcName, namespace, svcPorts[1:2], svcPodIps)
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

	cfgFoo := newConfigMap("foomap", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})
	cfgBar := newConfigMap("barmap", "1", namespace, map[string]string{
		"schema": schemaUrl,
		"data":   configmapBar})

	foo := newService("foo", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
	bar := newService("bar", "1", namespace, v1.ServiceTypeClusterIP, barPorts)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")

	var cfgStore cache.Store
	var endptStore cache.Store
	var svcStore cache.Store

	onCfgChange := func(changeType changeType, obj changedObject) {
		ProcessConfigMapUpdate(fake, changeType, obj, false, endptStore)
	}
	cfgStore = newStore(onCfgChange)

	onEndptChange := func(changeType changeType, obj changedObject) {
		ProcessEndpointsUpdate(fake, changeType, obj, svcStore)
	}
	endptStore = newStore(onEndptChange)

	onSvcChange := func(changeType changeType, obj changedObject) {
		ProcessServiceUpdate(fake, changeType, obj, false, endptStore)
		require.True(ok, "expected changedObject")
		switch changeType {
		case added:
			svc := obj.New.(*v1.Service)
			fSvc, err := fake.Core().Services(namespace).Create(svc)
			require.Nil(err, "Should not fail creating service")
			require.EqualValues(fSvc, svc, "Service should be equal")
		case deleted:
			svc := obj.Old.(*v1.Service)
			err := fake.Core().Services(namespace).Delete(svc.ObjectMeta.Name,
				&v1.DeleteOptions{})
			require.Nil(err, "Should not error deleting service")
		}
	}
	svcStore = newStore(onSvcChange)

	fooEndpts := newEndpoints("foo", "1", namespace, fooIps, barIps,
		convertSvcPortsToEndpointPorts(fooPorts))
	barEndpts := newEndpoints("bar", "1", namespace, barIps, fooIps,
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

	cfgFoo := newConfigMap(
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

	endptStore := newStore(nil)
	r := processConfigMap(
		fake,
		added,
		changedObject{nil, cfgFoo},
		true,
		endptStore,
	)
	require.True(r, "Config map should be processed")

	require.Equal(1, virtualServers.Count())
	require.Equal(1, virtualServers.CountOf(serviceKey{"foo", 80, "default"}),
		"Virtual servers should have an entry",
	)

	foo := newService(
		"foo",
		"1",
		"default",
		"ClusterIP",
		[]v1.ServicePort{{Port: 80}},
	)

	r = processService(
		fake,
		added,
		changedObject{nil, foo},
		true,
		endptStore,
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

	defer virtualServers.Init()

	svcPorts := []v1.ServicePort{
		newServicePort("port80", 80),
	}
	svc := newService("app", "1", "default", v1.ServiceTypeClusterIP, svcPorts)
	fake := fake.NewSimpleClientset(&v1.ServiceList{Items: []v1.Service{*svc}})
	svcStore := newStore(nil)
	svcStore.Add(svc)

	endptStore := newStore(func(change changeType, obj changedObject) {
		ProcessEndpointsUpdate(fake, change, obj, svcStore)
	})

	cfgStore := newStore(func(change changeType, obj changedObject) {
		ProcessConfigMapUpdate(fake, change, obj, false, endptStore)
	})

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
	cfgStore.Add(newConfigMap("cmap-1", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   fmt.Sprintf(vsTemplate, 5, 80),
	}))
	require.Equal(1, virtualServers.Count())
	cfgStore.Update(newConfigMap("cmap-1", "2", "default", map[string]string{
		"schema": schemaUrl,
		"data":   fmt.Sprintf(vsTemplate, 5, 80),
	}))
	require.Equal(1, virtualServers.Count())
	cfgStore.Add(newConfigMap("cmap-2", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   fmt.Sprintf(vsTemplate, 5, 8080),
	}))
	require.Equal(2, virtualServers.Count())
}
