/*-
 * Copyright (c) 2017, F5 Networks, Inc.
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

package pollers

import (
	"runtime"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/v1"
)

type nodeData struct {
	Name          string
	Unschedulable bool
	Addresses     []v1.NodeAddress
}

func newNode(
	id string,
	rv string,
	unsched bool,
	addresses []v1.NodeAddress,
) *v1.Node {
	return &v1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
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

func initTestData(t *testing.T) (Poller, []nodeData) {
	addressList := [][]v1.NodeAddress{
		{
			{"ExternalIP", "127.0.0.0"},
		},
		{
			{"ExternalIP", "127.0.0.1"},
			{"InternalIP", "127.1.0.1"},
		},
		{
			{"ExternalIP", "127.0.0.2"},
			{"InternalIP", "127.1.0.2"},
		},
		{
			{"ExternalIP", "127.0.0.3"},
			{"InternalIP", "127.1.0.3"},
		},
		{
			{"InternalIP", "127.0.0.4"},
		},
		{
			{"Hostname", "127.0.0.5"},
		},
	}

	// Existing Node data
	setNodes := []*v1.Node{
		newNode("node0", "0", true, addressList[0]),
		newNode("node1", "1", false, addressList[1]),
		newNode("node2", "2", false, addressList[2]),
		newNode("node3", "3", false, addressList[3]),
		newNode("node4", "4", false, addressList[4]),
		newNode("node5", "5", false, addressList[5]),
	}

	expectedNodes := []nodeData{
		nodeData{
			Name:          "node0",
			Unschedulable: true,
			Addresses:     addressList[0],
		},
		nodeData{
			Name:          "node1",
			Unschedulable: false,
			Addresses:     addressList[1],
		},
		nodeData{
			Name:          "node2",
			Unschedulable: false,
			Addresses:     addressList[2],
		},
		nodeData{
			Name:          "node3",
			Unschedulable: false,
			Addresses:     addressList[3],
		},
		nodeData{
			Name:          "node4",
			Unschedulable: false,
			Addresses:     addressList[4],
		},
		nodeData{
			Name:          "node5",
			Unschedulable: false,
			Addresses:     addressList[5],
		},
	}

	fake := fake.NewSimpleClientset()
	require.NotNil(t, fake, "Mock client cannot be nil")

	for _, setNode := range setNodes {
		node, err := fake.Core().Nodes().Create(setNode)
		assert.Nil(t, err, "Should not fail creating node")
		assert.EqualValues(t, setNode, node, "Nodes should be equal")
	}

	np := NewNodePoller(fake, 1*time.Millisecond)
	require.NotNil(t, np, "Node poller cannot be nil")

	return np, expectedNodes
}

func assertRegister(
	t *testing.T,
	p Poller,
	expectedNodes []nodeData,
	stopped bool,
) {
	called := 0
	err := p.RegisterListener(func(call *int) PollListener {
		var p PollListener = func(obj interface{}, err error) {
			if 0 == *call {
				nl, ok := obj.([]v1.Node)
				require.True(t, ok, "Should be called back with a nodeData")
				assert.Equal(t, 6, len(nl))
				assert.Nil(t, err, "Should not get an error")

				for i, expected := range expectedNodes {
					assert.Equal(t, expected.Name, nl[i].ObjectMeta.Name)
					assert.Equal(t, expected.Unschedulable, nl[i].Spec.Unschedulable)
					assert.Equal(t, expected.Addresses, nl[i].Status.Addresses)
				}
			}
			(*call)++
		}
		return p
	}(&called))
	assert.Nil(t, err)

	runtime.Gosched()
	<-time.After(100 * time.Millisecond)

	assert.Condition(t, func() bool {
		var cond bool
		if false == stopped {
			cond = called > 0
		} else {
			cond = called == 0
		}
		return cond
	}, "Listener should have been called 1 or more times")
}

func TestNodePollerStartStop(t *testing.T) {
	fake := fake.NewSimpleClientset()
	require.NotNil(t, fake, "Mock client cannot be nil")

	np := NewNodePoller(fake, 1*time.Millisecond)
	require.NotNil(t, np, "Node poller cannot be nil")

	err := np.Run()
	assert.Nil(t, err)
	// call run a second time
	err = np.Run()
	assert.NotNil(t, err)

	var called bool
	err = np.RegisterListener(func(obj interface{}, err error) {
		called = true
	})

	<-time.After(100 * time.Millisecond)
	assert.True(t, called)

	err = np.Stop()
	assert.Nil(t, err)

	// after stop called should not be reset to true from a running
	// listener
	<-time.After(100 * time.Millisecond)
	called = false
	assert.False(t, called)

	// call stop a second time
	err = np.Stop()
	assert.NotNil(t, err)
}

func TestNodePoller(t *testing.T) {
	np, expectedNodes := initTestData(t)

	err := np.Run()
	assert.Nil(t, err)

	for _ = range []int{1, 2, 3, 4, 5} {
		// one is the magic number, 1 routine for the NodePoller
		assertRegister(t, np, expectedNodes, false)
	}

	err = np.Stop()
	assert.NoError(t, err)

	assertRegister(t, np, expectedNodes, true)
}

func TestNodePollerSlowReader(t *testing.T) {
	np, expectedNodes := initTestData(t)

	err := np.Run()
	assert.Nil(t, err)

	err = np.RegisterListener(func(obj interface{}, err error) {
		<-time.After(500 * time.Millisecond)
	})

	for _ = range []int{1, 2, 3, 4, 5} {
		// two is the magic number, 1 routine1 for the NodePoller
		// plus the 1 slow reader
		assertRegister(t, np, expectedNodes, false)
	}

	err = np.Stop()
	assert.NoError(t, err)

	assertRegister(t, np, expectedNodes, true)
}

func TestNodePollerConcurrent(t *testing.T) {
	np, expectedNodes := initTestData(t)

	err := np.Run()
	assert.Nil(t, err)

	var wg sync.WaitGroup
	for _ = range []int{0, 1, 2, 3, 4} {
		wg.Add(1)
		go func() {
			// don't test against number of go routines, for this
			// test they are too transitory because of the concurrency
			// routine we're using here
			assertRegister(t, np, expectedNodes, false)
			wg.Done()
		}()
	}

	wg.Wait()
	err = np.Stop()
	assert.NoError(t, err)

	assertRegister(t, np, expectedNodes, true)
}

func TestNodePollerRegisterWhileStopped(t *testing.T) {
	fake := fake.NewSimpleClientset()
	require.NotNil(t, fake, "Mock client cannot be nil")

	np := NewNodePoller(fake, 1*time.Millisecond)
	require.NotNil(t, np, "Node poller cannot be nil")

	calls := []bool{false, false, false, false, false}
	for i := range calls {
		err := np.RegisterListener(func(index int) PollListener {
			var p PollListener = func(obj interface{}, err error) {
				if false == calls[index] {
					calls[index] = true
				}
			}
			return p
		}(i))
		assert.Nil(t, err)
	}

	err := np.Run()
	assert.Nil(t, err)

	runtime.Gosched()
	<-time.After(100 * time.Millisecond)

	for i := range calls {
		assert.True(t, calls[i])
	}

	err = np.Stop()
	<-time.After(100 * time.Millisecond)

	calls = []bool{
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
	}

	for i := range calls[5:] {
		err := np.RegisterListener(func(index int) PollListener {
			var p PollListener = func(obj interface{}, err error) {
				if false == calls[index] {
					calls[index] = true
				}
			}
			return p
		}(i + 5))
		assert.Nil(t, err)
	}

	err = np.Run()
	assert.Nil(t, err)

	runtime.Gosched()
	<-time.After(100 * time.Millisecond)

	for i := range calls {
		assert.True(t, calls[i])
	}

	err = np.Stop()
	assert.NoError(t, err)
}
