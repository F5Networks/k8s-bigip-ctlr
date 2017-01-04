package virtualServer

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"eventStream"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/1.4/kubernetes/fake"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/unversioned"
	"k8s.io/client-go/1.4/pkg/api/v1"
)

var schemaUrl string = "https://bldr-git.int.lineratesystems.com/velcro/schemas/raw/master/bigip-virtual-server_v0.1.1.json"

var configmapFoo string = string(`{
  "virtualServer": {
    "backend": {
      "serviceName": "foo",
      "servicePort": 80
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
      "iappTableName": "pool__members",
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
      "iappTableName": "pool__members",
      "iappOptions": {
        "description": "iApp 2"
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

var twoSvcsFourPortsThreeNodesConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":80,"nodePort":30001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":8080,"nodePort":38001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"partition":"velcro","balance":"round-robin","mode":"http","virtualAddress":{"bindAddr":"10.128.10.240","port":5051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":9090,"nodePort":39001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"partition":"velcro","balance":"round-robin","mode":"tcp","virtualAddress":{"bindAddr":"10.128.10.200","port":4041}}}}]}`)

var twoSvcsThreeNodesConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":80,"nodePort":30001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}}]}`)

var twoSvcsTwoNodesConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.1","127.0.0.2"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":80,"nodePort":30001,"nodes":["127.0.0.1","127.0.0.2"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}}]}`)

var twoSvcsOneNodeConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":80,"nodePort":30001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051},"sslProfile":{"f5ProfileName":"velcro/testcert"}}}}]}`)

var oneSvcTwoNodesConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}}]}`)

var oneSvcOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":6051}}}}]}`)

var twoIappsThreeNodesConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp1","servicePort":80,"nodePort":10101,"nodes":["192.168.0.1","192.168.0.2","192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 1"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}}}},{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"nodePort":20202,"nodes":["192.168.0.1","192.168.0.2","192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 2"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var twoIappsOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp1","servicePort":80,"nodePort":10101,"nodes":["192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 1"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}}}},{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"nodePort":20202,"nodes":["192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 2"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var oneIappOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"nodePort":20202,"nodes":["192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 2"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monitor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

func TestConfigFilename(t *testing.T) {
	assert := assert.New(t)

	pid := os.Getpid()
	expectedFilename := "/tmp/f5-k8s-controller.config." + strconv.Itoa(pid) + ".json"

	assert.Equal(expectedFilename, OutputFilename)
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

	addresses, err := getNodeAddresses(fake, false)
	require.Nil(t, err, "Should not fail getting addresses")
	assert.EqualValues(t, expectedReturn, addresses,
		"Should receive the correct addresses")

	// test filtering
	expectedInternal := []string{
		"127.0.0.4",
	}

	addresses, err = getNodeAddresses(fake, true)
	require.Nil(t, err, "Should not fail getting internal addresses")
	assert.EqualValues(t, expectedInternal, addresses,
		"Should receive the correct addresses")

	for _, node := range expectedNodes {
		err := fake.Core().Nodes().Delete(node.ObjectMeta.Name,
			&api.DeleteOptions{})
		require.Nil(t, err, "Should not fail deleting node")
	}

	expectedReturn = []string{}
	addresses, err = getNodeAddresses(fake, false)
	require.Nil(t, err, "Should not fail getting empty addresses")
	assert.EqualValues(t, expectedReturn, addresses, "Should get no addresses")
}

func validateFile(t *testing.T, expected string) {
	configFile, err := os.Open(OutputFilename)
	if nil != err {
		assert.Nil(t, err)
		return
	}

	services := outputConfigs{}

	parser := json.NewDecoder(configFile)
	err = parser.Decode(&services)
	if nil != err {
		assert.Nil(t, err)
		return
	}

	// Sort virtual-servers configs for comparison
	sort.Sort(services.Services)

	// Read JSON from exepectedOutput into array of structs
	expectedOutput := outputConfigs{[]*VirtualServerConfig{}}
	err = json.Unmarshal([]byte(expected), &expectedOutput)
	if nil != err {
		assert.Nil(t, err)
		return
	}

	require.True(t, assert.ObjectsAreEqualValues(expectedOutput, services),
		"Config output does not match expected")
}

func TestProcessNodeUpdate(t *testing.T) {
	defer os.Remove(OutputFilename)

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

	ProcessNodeUpdate(fake, false)
	validateFile(t, emptyConfig)
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

	ProcessNodeUpdate(fake, true)
	validateFile(t, emptyConfig)
	require.EqualValues(t, expectedInternal, oldNodes,
		"Should have cached correct node set")

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedInternal, cachedNodes,
		"Cached nodes should be expected set")

	// add some nodes
	_, err := fake.Core().Nodes().Create(newNode("nodeAdd", "nodeAdd", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.6"}}))
	require.Nil(t, err, "Create should not return err")

	_, err = fake.Core().Nodes().Create(newNode("nodeExclude", "nodeExclude",
		true, []v1.NodeAddress{{"InternalIP", "127.0.0.7"}}))

	ProcessNodeUpdate(fake, false)
	validateFile(t, emptyConfig)
	expectedAddSet := append(expectedOgSet, "127.0.0.6")

	require.EqualValues(t, expectedAddSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedAddSet, cachedNodes,
		"Cached nodes should be expected set")

	// make no changes and re-run process
	ProcessNodeUpdate(fake, false)
	validateFile(t, emptyConfig)
	expectedAddSet = append(expectedOgSet, "127.0.0.6")

	require.EqualValues(t, expectedAddSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedAddSet, cachedNodes,
		"Cached nodes should be expected set")

	// remove nodes
	err = fake.Core().Nodes().Delete("node1", &api.DeleteOptions{})
	require.Nil(t, err)
	fake.Core().Nodes().Delete("node2", &api.DeleteOptions{})
	require.Nil(t, err)
	fake.Core().Nodes().Delete("node3", &api.DeleteOptions{})
	require.Nil(t, err)

	expectedDelSet := []string{"127.0.0.6"}

	ProcessNodeUpdate(fake, false)
	validateFile(t, emptyConfig)

	require.EqualValues(t, expectedDelSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedDelSet, cachedNodes,
		"Cached nodes should be expected set")
}

func TestOverwriteAdd(t *testing.T) {
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

	require := require.New(t)

	namespace = "default"

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")

	r := processConfigMap(fake, eventStream.Added,
		eventStream.ChangedObject{nil, cfgFoo})
	require.True(r, "Config map should be processed")

	require.Equal(1, len(virtualServers.m))
	require.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should have entry")
	require.Equal("http",
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Frontend.Mode,
		"Mode should be http")

	cfgFoo = newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFooTcp})

	r = processConfigMap(fake, eventStream.Added,
		eventStream.ChangedObject{nil, cfgFoo})
	require.True(r, "Config map should be processed")

	require.Equal(1, len(virtualServers.m))
	require.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should have new entry")
	require.Equal("tcp",
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Frontend.Mode,
		"Mode should be tcp after overwrite")
}

func TestServiceChangeUpdate(t *testing.T) {
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

	require := require.New(t)

	cfgFoo := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo})

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client cannot be nil")

	r := processConfigMap(fake, eventStream.Added,
		eventStream.ChangedObject{nil, cfgFoo})
	require.True(r, "Config map should be processed")

	require.Equal(1, len(virtualServers.m))
	require.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should have an entry")

	cfgFoo8080 := newConfigMap("foomap", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo8080})

	r = processConfigMap(fake, eventStream.Updated,
		eventStream.ChangedObject{cfgFoo, cfgFoo8080})
	require.True(r, "Config map should be processed")
	require.Contains(virtualServers.m, serviceKey{"foo", 8080, "default"},
		"Virtual servers should have new entry")
	require.NotContains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should have old config removed")
}

func TestServicePortsRemoved(t *testing.T) {
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

	require := require.New(t)

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

	r := processConfigMap(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgFoo})
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgFoo8080})
	require.True(r, "Config map should be processed")

	r = processConfigMap(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgFoo9090})
	require.True(r, "Config map should be processed")

	require.Equal(3, len(virtualServers.m))
	require.Contains(virtualServers.m, serviceKey{"foo", 80, "default"})
	require.Contains(virtualServers.m, serviceKey{"foo", 8080, "default"})
	require.Contains(virtualServers.m, serviceKey{"foo", 9090, "default"})

	// Create a new service with less ports and update
	newFoo := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})

	r = processService(fake, eventStream.Updated, eventStream.ChangedObject{
		foo,
		newFoo})
	require.True(r, "Service should be processed")

	require.Equal(3, len(virtualServers.m))
	require.Contains(virtualServers.m, serviceKey{"foo", 80, "default"})
	require.Contains(virtualServers.m, serviceKey{"foo", 8080, "default"})
	require.Contains(virtualServers.m, serviceKey{"foo", 9090, "default"})

	require.Equal(int32(30001),
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.NodePort,
		"Existing NodePort should be set")
	require.Equal(int32(0),
		virtualServers.m[serviceKey{"foo", 8080, "default"}].VirtualServer.Backend.NodePort,
		"Removed NodePort should be unset")
	require.Equal(int32(0),
		virtualServers.m[serviceKey{"foo", 9090, "default"}].VirtualServer.Backend.NodePort,
		"Removed NodePort should be unset")

	// Re-add port in new service
	newFoo2 := newService("foo", "1", "default", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 20001},
			{Port: 8080, NodePort: 45454}})

	r = processService(fake, eventStream.Updated, eventStream.ChangedObject{
		newFoo,
		newFoo2})
	require.True(r, "Service should be processed")

	require.Equal(3, len(virtualServers.m))
	require.Contains(virtualServers.m, serviceKey{"foo", 80, "default"})
	require.Contains(virtualServers.m, serviceKey{"foo", 8080, "default"})
	require.Contains(virtualServers.m, serviceKey{"foo", 9090, "default"})

	require.Equal(int32(20001),
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.NodePort,
		"Existing NodePort should be set")
	require.Equal(int32(45454),
		virtualServers.m[serviceKey{"foo", 8080, "default"}].VirtualServer.Backend.NodePort,
		"Removed NodePort should be unset")
	require.Equal(int32(0),
		virtualServers.m[serviceKey{"foo", 9090, "default"}].VirtualServer.Backend.NodePort,
		"Removed NodePort should be unset")
}

func TestUpdatesConcurrent(t *testing.T) {
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

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

			ProcessNodeUpdate(fake, false)
		}

		nodeCh <- struct{}{}
	}()

	go func() {
		f, err := fake.Core().ConfigMaps("default").Create(cfgFoo)
		require.Nil(err, "Should not fail creating configmap")
		require.EqualValues(f, cfgFoo, "Maps should be equal")

		ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
			nil,
			cfgFoo,
		})

		b, err := fake.Core().ConfigMaps("default").Create(cfgBar)
		require.Nil(err, "Should not fail creating configmap")
		require.EqualValues(b, cfgBar, "Maps should be equal")

		ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
			nil,
			cfgBar,
		})

		mapCh <- struct{}{}
	}()

	go func() {
		fSvc, err := fake.Core().Services("default").Create(foo)
		require.Nil(err, "Should not fail creating service")
		require.EqualValues(fSvc, foo, "Service should be equal")

		ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
			nil,
			foo})

		bSvc, err := fake.Core().Services("default").Create(bar)
		require.Nil(err, "Should not fail creating service")
		require.EqualValues(bSvc, bar, "Maps should be equal")

		ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
			nil,
			bar})

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

	validateFile(t, twoSvcsTwoNodesConfig)

	go func() {
		err := fake.Core().Nodes().Delete("node1", &api.DeleteOptions{})
		require.Nil(err)
		err = fake.Core().Nodes().Delete("node2", &api.DeleteOptions{})
		require.Nil(err)
		_, err = fake.Core().Nodes().Create(extraNode)
		require.Nil(err)
		ProcessNodeUpdate(fake, false)

		nodeCh <- struct{}{}
	}()

	go func() {
		err := fake.Core().ConfigMaps("default").Delete("foomap",
			&api.DeleteOptions{})
		require.Nil(err, "Should not error deleting map")
		m, _ := fake.Core().ConfigMaps("").List(api.ListOptions{})
		assert.Equal(1, len(m.Items))
		ProcessConfigMapUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
			cfgFoo,
			nil,
		})
		assert.Equal(1, len(virtualServers.m))

		mapCh <- struct{}{}
	}()

	go func() {
		err := fake.Core().Services("default").Delete("foo",
			&api.DeleteOptions{})
		require.Nil(err, "Should not error deleting service")
		s, _ := fake.Core().Services("").List(api.ListOptions{})
		assert.Equal(1, len(s.Items))
		ProcessServiceUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
			foo,
			nil})

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

	validateFile(t, oneSvcTwoNodesConfig)
}

func TestProcessUpdates(t *testing.T) {
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

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

	m, err := fake.Core().ConfigMaps("").List(api.ListOptions{})
	require.Nil(err)
	s, err := fake.Core().Services("").List(api.ListOptions{})
	require.Nil(err)
	n, err := fake.Core().Nodes().List(api.ListOptions{})
	require.Nil(err)

	assert.Equal(2, len(m.Items))
	assert.Equal(2, len(s.Items))
	assert.Equal(3, len(n.Items))

	ProcessNodeUpdate(fake, false)

	// ConfigMap ADDED
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgFoo,
	})
	assert.Equal(1, len(virtualServers.m))
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.Nodes)

	// Second ConfigMap ADDED
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgBar,
	})
	assert.Equal(2, len(virtualServers.m))
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"bar", 80, "default"}].VirtualServer.Backend.Nodes)

	// Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		foo})
	assert.Equal(2, len(virtualServers.m))

	// Second Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		bar})
	assert.Equal(2, len(virtualServers.m))

	// ConfigMap UPDATED
	ProcessConfigMapUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		cfgFoo,
		cfgFoo,
	})
	assert.Equal(2, len(virtualServers.m))

	// Service UPDATED
	ProcessServiceUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		foo,
		foo})
	assert.Equal(2, len(virtualServers.m))

	// ConfigMap ADDED second foo port
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgFoo8080})
	assert.Equal(3, len(virtualServers.m))
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 8080, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"bar", 80, "default"}].VirtualServer.Backend.Nodes)

	// ConfigMap ADDED third foo port
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgFoo9090})
	assert.Equal(4, len(virtualServers.m))
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 9090, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 8080, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"bar", 80, "default"}].VirtualServer.Backend.Nodes)

	// Nodes ADDED
	_, err = fake.Core().Nodes().Create(extraNode)
	require.Nil(err)
	ProcessNodeUpdate(fake, false)
	assert.Equal(4, len(virtualServers.m))
	assert.EqualValues(append(addrs, "127.0.0.3"),
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(append(addrs, "127.0.0.3"),
		virtualServers.m[serviceKey{"bar", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(append(addrs, "127.0.0.3"),
		virtualServers.m[serviceKey{"foo", 8080, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(append(addrs, "127.0.0.3"),
		virtualServers.m[serviceKey{"foo", 9090, "default"}].VirtualServer.Backend.Nodes)
	validateFile(t, twoSvcsFourPortsThreeNodesConfig)

	// ConfigMap DELETED third foo port
	ProcessConfigMapUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		cfgFoo9090,
		nil})
	assert.Equal(3, len(virtualServers.m))
	assert.NotContains(virtualServers.m, serviceKey{"foo", 9090, "default"},
		"Virtual servers should not contain removed port")
	assert.Contains(virtualServers.m, serviceKey{"foo", 8080, "default"},
		"Virtual servers should contain remaining ports")
	assert.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should contain remaining ports")
	assert.Contains(virtualServers.m, serviceKey{"bar", 80, "default"},
		"Virtual servers should contain remaining ports")

	// ConfigMap UPDATED second foo port
	ProcessConfigMapUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		cfgFoo8080,
		cfgFoo8080})
	assert.Equal(3, len(virtualServers.m))
	assert.Contains(virtualServers.m, serviceKey{"foo", 8080, "default"},
		"Virtual servers should contain remaining ports")
	assert.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should contain remaining ports")
	assert.Contains(virtualServers.m, serviceKey{"bar", 80, "default"},
		"Virtual servers should contain remaining ports")

	// ConfigMap DELETED second foo port
	ProcessConfigMapUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		cfgFoo8080,
		nil})
	assert.Equal(2, len(virtualServers.m))
	assert.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should contain remaining ports")
	assert.Contains(virtualServers.m, serviceKey{"bar", 80, "default"},
		"Virtual servers should contain remaining ports")

	// Nodes DELETES
	err = fake.Core().Nodes().Delete("node1", &api.DeleteOptions{})
	require.Nil(err)
	err = fake.Core().Nodes().Delete("node2", &api.DeleteOptions{})
	require.Nil(err)
	ProcessNodeUpdate(fake, false)
	assert.Equal(2, len(virtualServers.m))
	assert.EqualValues([]string{"127.0.0.3"},
		virtualServers.m[serviceKey{"foo", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues([]string{"127.0.0.3"},
		virtualServers.m[serviceKey{"bar", 80, "default"}].VirtualServer.Backend.Nodes)
	validateFile(t, twoSvcsOneNodeConfig)

	// ConfigMap DELETED
	err = fake.Core().ConfigMaps("default").Delete("foomap", &api.DeleteOptions{})
	m, err = fake.Core().ConfigMaps("").List(api.ListOptions{})
	assert.Equal(1, len(m.Items))
	ProcessConfigMapUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		cfgFoo,
		nil,
	})
	assert.Equal(1, len(virtualServers.m))
	assert.NotContains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Config map should be removed after delete")
	validateFile(t, oneSvcOneNodeConfig)

	// Service DELETED
	err = fake.Core().Services("default").Delete("bar", &api.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(api.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		bar,
		nil})
	assert.Equal(1, len(virtualServers.m))
	validateFile(t, emptyConfig)
}

func TestDontCareConfigMap(t *testing.T) {
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

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

	m, err := fake.Core().ConfigMaps("").List(api.ListOptions{})
	require.Nil(err)
	s, err := fake.Core().Services("").List(api.ListOptions{})
	require.Nil(err)

	assert.Equal(1, len(m.Items))
	assert.Equal(1, len(s.Items))

	// ConfigMap ADDED
	assert.Equal(0, len(virtualServers.m))
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfg,
	})
	assert.Equal(0, len(virtualServers.m))
}

func TestConfigMapKeys(t *testing.T) {
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

	require := require.New(t)
	assert := assert.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client should not be nil")

	noschemakey := newConfigMap("noschema", "1", "default", map[string]string{
		"data": "bar"})
	cfg, err := parseVirtualServerConfig(noschemakey)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err, "configmap noschema does not contain schema key",
		"Should receive no schema error")
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		noschemakey,
	})
	require.Equal(0, len(virtualServers.m))

	nodatakey := newConfigMap("nodata", "1", "default", map[string]string{
		"schema": schemaUrl,
	})
	cfg, err = parseVirtualServerConfig(nodatakey)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err, "configmap nodata does not contain data key",
		"Should receive no data error")
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		nodatakey,
	})
	require.Equal(0, len(virtualServers.m))

	badjson := newConfigMap("badjson", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   "///// **invalid json** /////",
	})
	cfg, err = parseVirtualServerConfig(badjson)
	require.Nil(cfg, "Should not have parsed bad configmap")
	require.EqualError(err,
		"invalid character '/' looking for beginning of value")
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		badjson,
	})
	require.Equal(0, len(virtualServers.m))

	extrakeys := newConfigMap("extrakeys", "1", "default", map[string]string{
		"schema": schemaUrl,
		"data":   configmapFoo,
		"key1":   "value1",
		"key2":   "value2",
	})
	cfg, err = parseVirtualServerConfig(extrakeys)
	require.NotNil(cfg, "Config map should parse with extra keys")
	require.Nil(err, "Should not receive errors")
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		extrakeys,
	})
	require.Equal(1, len(virtualServers.m))

	vs, ok := virtualServers.m[serviceKey{"foo", 80, "default"}]
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
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

	require := require.New(t)
	assert := assert.New(t)

	fake := fake.NewSimpleClientset()
	require.NotNil(fake, "Mock client should not be nil")

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

	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil, cfgFoo})
	_, ok := virtualServers.m[serviceKey{"foo", 80, "default"}]
	assert.True(ok, "Config map should be accessible")

	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil, cfgBar})
	_, ok = virtualServers.m[serviceKey{"foo", 80, "wrongnamespace"}]
	assert.False(ok, "Config map should not be added if namespace does not match flag")
	assert.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should contain original config")
	assert.Equal(1, len(virtualServers.m), "There should only be 1 virtual server")

	ProcessConfigMapUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		cfgBar, cfgBar})
	_, ok = virtualServers.m[serviceKey{"foo", 80, "wrongnamespace"}]
	assert.False(ok, "Config map should not be added if namespace does not match flag")
	assert.Contains(virtualServers.m, serviceKey{"foo", 80, "default"},
		"Virtual servers should contain original config")
	assert.Equal(1, len(virtualServers.m), "There should only be 1 virtual server")

	ProcessConfigMapUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		cfgBar, nil})
	_, ok = virtualServers.m[serviceKey{"foo", 80, "wrongnamespace"}]
	assert.False(ok, "Config map should not be deleted if namespace does not match flag")
	_, ok = virtualServers.m[serviceKey{"foo", 80, "default"}]
	assert.True(ok, "Config map should be accessible after delete called on incorrect namespace")

	ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil, servFoo})
	vs, ok := virtualServers.m[serviceKey{"foo", 80, "default"}]
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(37001, vs.VirtualServer.Backend.NodePort, "NodePort should match initial config")

	ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil, servBar})
	_, ok = virtualServers.m[serviceKey{"foo", 80, "wrongnamespace"}]
	assert.False(ok, "Service should not be added if namespace does not match flag")
	vs, ok = virtualServers.m[serviceKey{"foo", 80, "default"}]
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(37001, vs.VirtualServer.Backend.NodePort, "NodePort should match initial config")

	ProcessServiceUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		servBar, servBar})
	_, ok = virtualServers.m[serviceKey{"foo", 80, "wrongnamespace"}]
	assert.False(ok, "Service should not be added if namespace does not match flag")
	vs, ok = virtualServers.m[serviceKey{"foo", 80, "default"}]
	assert.True(ok, "Service should be accessible")
	assert.EqualValues(37001, vs.VirtualServer.Backend.NodePort, "NodePort should match initial config")

	ProcessServiceUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		servBar, nil})
	vs, ok = virtualServers.m[serviceKey{"foo", 80, "default"}]
	assert.True(ok, "Service should not have been deleted")
	assert.EqualValues(37001, vs.VirtualServer.Backend.NodePort, "NodePort should match initial config")
}

func TestProcessUpdatesIApp(t *testing.T) {
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

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

	m, err := fake.Core().ConfigMaps("").List(api.ListOptions{})
	require.Nil(err)
	s, err := fake.Core().Services("").List(api.ListOptions{})
	require.Nil(err)
	n, err := fake.Core().Nodes().List(api.ListOptions{})
	require.Nil(err)

	assert.Equal(2, len(m.Items))
	assert.Equal(2, len(s.Items))
	assert.Equal(4, len(n.Items))

	ProcessNodeUpdate(fake, true)

	// ConfigMap ADDED
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgIapp1,
	})
	assert.Equal(1, len(virtualServers.m))
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"iapp1", 80, "default"}].VirtualServer.Backend.Nodes)

	// Second ConfigMap ADDED
	ProcessConfigMapUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		cfgIapp2,
	})
	assert.Equal(2, len(virtualServers.m))
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"iapp1", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs,
		virtualServers.m[serviceKey{"iapp2", 80, "default"}].VirtualServer.Backend.Nodes)

	// Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		iapp1})
	assert.Equal(2, len(virtualServers.m))

	// Second Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, eventStream.ChangedObject{
		nil,
		iapp2})
	assert.Equal(2, len(virtualServers.m))

	// ConfigMap UPDATED
	ProcessConfigMapUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		cfgIapp1,
		cfgIapp1,
	})
	assert.Equal(2, len(virtualServers.m))

	// Service UPDATED
	ProcessServiceUpdate(fake, eventStream.Updated, eventStream.ChangedObject{
		iapp1,
		iapp1})
	assert.Equal(2, len(virtualServers.m))

	// Nodes ADDED
	_, err = fake.Core().Nodes().Create(extraNode)
	require.Nil(err)
	ProcessNodeUpdate(fake, true)
	assert.Equal(2, len(virtualServers.m))
	assert.EqualValues(append(addrs, "192.168.0.4"),
		virtualServers.m[serviceKey{"iapp1", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues(append(addrs, "192.168.0.4"),
		virtualServers.m[serviceKey{"iapp2", 80, "default"}].VirtualServer.Backend.Nodes)
	validateFile(t, twoIappsThreeNodesConfig)

	// Nodes DELETES
	err = fake.Core().Nodes().Delete("node1", &api.DeleteOptions{})
	require.Nil(err)
	err = fake.Core().Nodes().Delete("node2", &api.DeleteOptions{})
	require.Nil(err)
	ProcessNodeUpdate(fake, true)
	assert.Equal(2, len(virtualServers.m))
	assert.EqualValues([]string{"192.168.0.4"},
		virtualServers.m[serviceKey{"iapp1", 80, "default"}].VirtualServer.Backend.Nodes)
	assert.EqualValues([]string{"192.168.0.4"},
		virtualServers.m[serviceKey{"iapp2", 80, "default"}].VirtualServer.Backend.Nodes)
	validateFile(t, twoIappsOneNodeConfig)

	// ConfigMap DELETED
	err = fake.Core().ConfigMaps("default").Delete("iapp1map",
		&api.DeleteOptions{})
	m, err = fake.Core().ConfigMaps("").List(api.ListOptions{})
	assert.Equal(1, len(m.Items))
	ProcessConfigMapUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		cfgIapp1,
		nil,
	})
	assert.Equal(1, len(virtualServers.m))
	assert.NotContains(virtualServers.m, serviceKey{"iapp1", 80, "default"},
		"Config map should be removed after delete")
	validateFile(t, oneIappOneNodeConfig)

	// Service DELETED
	err = fake.Core().Services("default").Delete("iapp2", &api.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(api.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(fake, eventStream.Deleted, eventStream.ChangedObject{
		iapp2,
		nil})
	assert.Equal(1, len(virtualServers.m))
	validateFile(t, emptyConfig)
}

func TestSchemaValidation(t *testing.T) {
	defer os.Remove(OutputFilename)
	defer func() {
		virtualServers.m = make(map[serviceKey]*VirtualServerConfig)
	}()

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
	cfg, err := parseVirtualServerConfig(badjson)
	require.Nil(cfg, "Should not have parsed bad configmap")
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
