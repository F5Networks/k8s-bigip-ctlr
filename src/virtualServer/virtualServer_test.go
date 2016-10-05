package virtualServer

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"testing"

	"eventStream"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/1.4/kubernetes/fake"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/unversioned"
	"k8s.io/client-go/1.4/pkg/api/v1"
)

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
        "bindAddr": "10.128.10.260",
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
        "monotor__uri": "/",
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
        "monotor__uri": "/",
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

var twoSvcsThreeNodesConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.260","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":80,"nodePort":30001,"nodes":["127.0.0.1","127.0.0.2","127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051}}}}]}`)

var twoSvcsOneNodeConfig string = string(`{"services":[ {"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.260","port":6051}}}},{"virtualServer":{"backend":{"serviceName":"foo","servicePort":80,"nodePort":30001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.240","port":5051}}}}]}`)

var oneSvcOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"bar","servicePort":80,"nodePort":37001,"nodes":["127.0.0.3"]},"frontend":{"balance":"round-robin","mode":"http","partition":"velcro","virtualAddress":{"bindAddr":"10.128.10.260","port":6051}}}}]}`)

var twoIappsThreeNodesConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp1","servicePort":80,"nodePort":10101,"nodes":["192.168.0.1","192.168.0.2","192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 1"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monotor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}}}},{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"nodePort":20202,"nodes":["192.168.0.1","192.168.0.2","192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 2"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monotor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var twoIappsOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp1","servicePort":80,"nodePort":10101,"nodes":["192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 1"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monotor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.1","pool__pool_to_use":"/#create_new#","pool__port":"8080"}}}},{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"nodePort":20202,"nodes":["192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 2"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monotor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

var oneIappOneNodeConfig string = string(`{"services":[{"virtualServer":{"backend":{"serviceName":"iapp2","servicePort":80,"nodePort":20202,"nodes":["192.168.0.4"]},"frontend":{"partition":"velcro","iapp":"/Common/f5.http","iappTableName":"pool__members","iappOptions":{"description":"iApp 2"},"iappVariables":{"monitor__monitor":"/#create_new#","monitor__resposne":"none","monotor__uri":"/","net__client_mode":"wan","net__server_mode":"lan","pool__addr":"127.0.0.2","pool__pool_to_use":"/#create_new#","pool__port":"4430"}}}}]}`)

func TestConfigFilename(t *testing.T) {
	assert := assert.New(t)

	pid := os.Getpid()
	expectedFilename := "/tmp/f5-k8s-controller.config." + strconv.Itoa(pid) + ".json"

	assert.Equal(expectedFilename, OutputFilename)
}

func newConfigMap(id, rv, namespace, key, value string) *v1.ConfigMap {
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
		Data: map[string]string{
			key: value,
		},
	}
}

func newService(id, rv, namespace string, serviceType v1.ServiceType, nodePort int32) *v1.Service {
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
			Ports: []v1.ServicePort{{NodePort: nodePort}},
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
	expectedOutput := outputConfigs{[]VirtualServerConfig{}}
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

func TestProcessUpdates(t *testing.T) {
	defer os.Remove(OutputFilename)

	assert := assert.New(t)
	require := require.New(t)

	// Create a test env with two ConfigMaps, two Services, and three Nodes
	cfgFoo := newConfigMap("foomap", "1", "default", "foomap.json", configmapFoo)
	cfgBar := newConfigMap("barmap", "1", "default", "barmap.json", configmapBar)
	foo := newService("foo", "1", "default", "NodePort", 30001)
	bar := newService("bar", "1", "default", "NodePort", 37001)
	nodes := []v1.Node{
		*newNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"}}),
	}
	extraNode := newNode("node3", "3", false, []v1.NodeAddress{{"ExternalIP", "127.0.0.3"}})

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
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgFoo)
	assert.Equal(1, len(virtualServers))
	assert.EqualValues(addrs, virtualServers["foo"].VirtualServer.Backend.Nodes)

	// Second ConfigMap ADDED
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgBar)
	assert.Equal(2, len(virtualServers))
	assert.EqualValues(addrs, virtualServers["foo"].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs, virtualServers["bar"].VirtualServer.Backend.Nodes)

	// Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, foo)
	assert.Equal(2, len(virtualServers))

	// Second Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, bar)
	assert.Equal(2, len(virtualServers))

	// ConfigMap REPLACED
	cfgs := []interface{}{cfgFoo}
	ProcessConfigMapUpdate(fake, eventStream.Replaced, cfgs)
	assert.Equal(2, len(virtualServers))

	// Service REPLACED
	svcs := []interface{}{foo}
	ProcessServiceUpdate(fake, eventStream.Replaced, svcs)
	assert.Equal(2, len(virtualServers))

	// Nodes ADDED
	_, err = fake.Core().Nodes().Create(extraNode)
	require.Nil(err)
	ProcessNodeUpdate(fake, false)
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgFoo)
	assert.Equal(2, len(virtualServers))
	assert.EqualValues(append(addrs, "127.0.0.3"), virtualServers["foo"].VirtualServer.Backend.Nodes)
	assert.EqualValues(append(addrs, "127.0.0.3"), virtualServers["bar"].VirtualServer.Backend.Nodes)
	validateFile(t, twoSvcsThreeNodesConfig)

	// Nodes DELETES
	err = fake.Core().Nodes().Delete("node1", &api.DeleteOptions{})
	require.Nil(err)
	err = fake.Core().Nodes().Delete("node2", &api.DeleteOptions{})
	require.Nil(err)
	ProcessNodeUpdate(fake, false)
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgFoo)
	assert.Equal(2, len(virtualServers))
	assert.EqualValues([]string{"127.0.0.3"}, virtualServers["foo"].VirtualServer.Backend.Nodes)
	assert.EqualValues([]string{"127.0.0.3"}, virtualServers["bar"].VirtualServer.Backend.Nodes)
	validateFile(t, twoSvcsOneNodeConfig)

	// ConfigMap DELETED
	err = fake.Core().ConfigMaps("default").Delete("foomap", &api.DeleteOptions{})
	m, err = fake.Core().ConfigMaps("").List(api.ListOptions{})
	assert.Equal(1, len(m.Items))
	ProcessConfigMapUpdate(fake, eventStream.Deleted, cfgFoo)
	assert.Equal(1, len(virtualServers))
	assert.EqualValues([]string(nil), virtualServers["foo"].VirtualServer.Backend.Nodes)
	validateFile(t, oneSvcOneNodeConfig)

	// Service DELETED
	err = fake.Core().Services("default").Delete("bar", &api.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(api.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(fake, eventStream.Deleted, bar)
	assert.Equal(1, len(virtualServers))
	validateFile(t, emptyConfig)
}

func TestDontCareConfigMap(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	virtualServers = make(map[string]VirtualServerConfig)

	cfg := newConfigMap("foomap", "1", "default", "foo", "bar")
	svc := newService("foo", "1", "default", "NodePort", 30001)

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
	assert.Equal(0, len(virtualServers))
	ProcessConfigMapUpdate(fake, eventStream.Added, cfg)
	assert.Equal(0, len(virtualServers))
}

func TestProcessUpdatesIApp(t *testing.T) {
	//	defer os.Remove(OutputFilename)

	assert := assert.New(t)
	require := require.New(t)

	// Create a test env with two ConfigMaps, two Services, and three Nodes
	cfgIapp1 := newConfigMap("iapp1map", "1", "default", "iapp1map.json",
		configmapIApp1)
	cfgIapp2 := newConfigMap("iapp2map", "1", "default", "iapp2map.json",
		configmapIApp2)
	iapp1 := newService("iapp1", "1", "default", "NodePort", 10101)
	iapp2 := newService("iapp2", "1", "default", "NodePort", 20202)
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
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgIapp1)
	assert.Equal(1, len(virtualServers))
	assert.EqualValues(addrs, virtualServers["iapp1"].VirtualServer.Backend.Nodes)

	// Second ConfigMap ADDED
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgIapp2)
	assert.Equal(2, len(virtualServers))
	assert.EqualValues(addrs, virtualServers["iapp1"].VirtualServer.Backend.Nodes)
	assert.EqualValues(addrs, virtualServers["iapp2"].VirtualServer.Backend.Nodes)

	// Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, iapp1)
	assert.Equal(2, len(virtualServers))

	// Second Service ADDED
	ProcessServiceUpdate(fake, eventStream.Added, iapp2)
	assert.Equal(2, len(virtualServers))

	// ConfigMap REPLACED
	cfgs := []interface{}{cfgIapp1}
	ProcessConfigMapUpdate(fake, eventStream.Replaced, cfgs)
	assert.Equal(2, len(virtualServers))

	// Service REPLACED
	svcs := []interface{}{iapp1}
	ProcessServiceUpdate(fake, eventStream.Replaced, svcs)
	assert.Equal(2, len(virtualServers))

	// Nodes ADDED
	_, err = fake.Core().Nodes().Create(extraNode)
	require.Nil(err)
	ProcessNodeUpdate(fake, true)
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgIapp1)
	assert.Equal(2, len(virtualServers))
	assert.EqualValues(append(addrs, "192.168.0.4"),
		virtualServers["iapp1"].VirtualServer.Backend.Nodes)
	assert.EqualValues(append(addrs, "192.168.0.4"),
		virtualServers["iapp2"].VirtualServer.Backend.Nodes)
	validateFile(t, twoIappsThreeNodesConfig)

	// Nodes DELETES
	err = fake.Core().Nodes().Delete("node1", &api.DeleteOptions{})
	require.Nil(err)
	err = fake.Core().Nodes().Delete("node2", &api.DeleteOptions{})
	require.Nil(err)
	ProcessNodeUpdate(fake, true)
	ProcessConfigMapUpdate(fake, eventStream.Added, cfgIapp1)
	assert.Equal(2, len(virtualServers))
	assert.EqualValues([]string{"192.168.0.4"},
		virtualServers["iapp1"].VirtualServer.Backend.Nodes)
	assert.EqualValues([]string{"192.168.0.4"},
		virtualServers["iapp2"].VirtualServer.Backend.Nodes)
	validateFile(t, twoIappsOneNodeConfig)

	// ConfigMap DELETED
	err = fake.Core().ConfigMaps("default").Delete("iapp1map",
		&api.DeleteOptions{})
	m, err = fake.Core().ConfigMaps("").List(api.ListOptions{})
	assert.Equal(1, len(m.Items))
	ProcessConfigMapUpdate(fake, eventStream.Deleted, cfgIapp1)
	assert.Equal(1, len(virtualServers))
	assert.EqualValues([]string(nil),
		virtualServers["iapp1"].VirtualServer.Backend.Nodes)
	validateFile(t, oneIappOneNodeConfig)

	// Service DELETED
	err = fake.Core().Services("default").Delete("iapp2", &api.DeleteOptions{})
	require.Nil(err)
	s, err = fake.Core().Services("").List(api.ListOptions{})
	assert.Equal(1, len(s.Items))
	ProcessServiceUpdate(fake, eventStream.Deleted, iapp2)
	assert.Equal(1, len(virtualServers))
	validateFile(t, emptyConfig)
}
