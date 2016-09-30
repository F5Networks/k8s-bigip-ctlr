package virtualServer

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/1.4/kubernetes/fake"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/unversioned"
	"k8s.io/client-go/1.4/pkg/api/v1"
)

func TestConfigFilename(t *testing.T) {
	assert := assert.New(t)

	pid := os.Getpid()
	expectedFilename := "/tmp/f5-k8s-controller.config." + strconv.Itoa(pid) + ".json"

	assert.Equal(expectedFilename, OutputFilename)
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

	addresses, err := getNodeAddresses(fake)
	require.Nil(t, err, "Should not fail getting addresses")
	assert.EqualValues(t, expectedReturn, addresses,
		"Should receive the correct addresses")

	for _, node := range expectedNodes {
		err := fake.Core().Nodes().Delete(node.ObjectMeta.Name,
			&api.DeleteOptions{})
		require.Nil(t, err, "Should not fail deleting node")
	}

	expectedReturn = []string{}
	addresses, err = getNodeAddresses(fake)
	require.Nil(t, err, "Should not fail getting empty addresses")
	assert.EqualValues(t, expectedReturn, addresses, "Should get no addresses")
}

func validateFile(t *testing.T) {
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

	require.EqualValues(t, outputConfigs{[]VirtualServerConfig{}}, services,
		"Should be empty config output")
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

	ProcessNodeUpdate(fake)
	validateFile(t)
	require.EqualValues(t, expectedOgSet, oldNodes,
		"Should have cached correct node set")

	cachedNodes := getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedOgSet, cachedNodes,
		"Cached nodes should be expected set")

	// add some nodes
	_, err := fake.Core().Nodes().Create(newNode("nodeAdd", "nodeAdd", false,
		[]v1.NodeAddress{{"ExternalIP", "127.0.0.6"}}))
	require.Nil(t, err, "Create should not return err")

	_, err = fake.Core().Nodes().Create(newNode("nodeExclude", "nodeExclude",
		true, []v1.NodeAddress{{"InternalIP", "127.0.0.7"}}))

	ProcessNodeUpdate(fake)
	validateFile(t)
	expectedAddSet := append(expectedOgSet, "127.0.0.6")

	require.EqualValues(t, expectedAddSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedAddSet, cachedNodes,
		"Cached nodes should be expected set")

	// make no changes and re-run process
	ProcessNodeUpdate(fake)
	validateFile(t)
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

	ProcessNodeUpdate(fake)
	validateFile(t)

	require.EqualValues(t, expectedDelSet, oldNodes)

	cachedNodes = getNodesFromCache()
	require.EqualValues(t, oldNodes, cachedNodes,
		"Cached nodes should be oldNodes")
	require.EqualValues(t, expectedDelSet, cachedNodes,
		"Cached nodes should be expected set")
}
