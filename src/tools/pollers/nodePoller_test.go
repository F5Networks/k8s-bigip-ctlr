package pollers

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/1.4/kubernetes/fake"
	"k8s.io/client-go/1.4/pkg/api/unversioned"
	"k8s.io/client-go/1.4/pkg/api/v1"
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

func assertGoroutines(
	t *testing.T,
	operation func() error,
	expectedRoutines int,
) {
	ticks := 0
	tickLimit := 100
	ticker := time.NewTicker(100 * time.Millisecond)

	err := operation()
	assert.Nil(t, err)
	runtime.Gosched()

	if expectedRoutines == runtime.NumGoroutine() {
		assert.Equal(t, expectedRoutines, runtime.NumGoroutine())
		return
	}

	for _ = range ticker.C {
		runtime.Gosched()

		if expectedRoutines == runtime.NumGoroutine() {
			break
		}

		ticks++
		if tickLimit == ticks {
			break
		}
	}

	assert.Equal(t, expectedRoutines, runtime.NumGoroutine())
}

func assertRegister(
	t *testing.T,
	p Poller,
	expectedRoutines int,
	expectedNodes []nodeData,
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
		return called > 0
	}, "Listener should have been called 1 or more times")

	if -1 != expectedRoutines {
		assert.Equal(t, expectedRoutines, runtime.NumGoroutine(),
			"Should have started a goroutine for each listeners")
	}
}

func TestNodePollerStartStop(t *testing.T) {
	fake := fake.NewSimpleClientset()
	require.NotNil(t, fake, "Mock client cannot be nil")

	np := NewNodePoller(fake, 1*time.Millisecond)
	require.NotNil(t, np, "Node poller cannot be nil")

	curGoroutines := runtime.NumGoroutine()
	assertGoroutines(t, np.Run, curGoroutines+1)

	// call run a second time
	err := np.Run()
	assert.NotNil(t, err)

	err = np.RegisterListener(func(obj interface{}, err error) {
		// do nothing
	})

	assertGoroutines(t, np.Stop, curGoroutines)

	// call stop a second time
	err = np.Stop()
	assert.NotNil(t, err)
}

func TestNodePoller(t *testing.T) {
	np, expectedNodes := initTestData(t)

	curGoroutines := runtime.NumGoroutine()
	err := np.Run()
	assert.Nil(t, err)

	for _, v := range []int{1, 2, 3, 4, 5} {
		// one is the magic number, 1 routine for the NodePoller
		assertRegister(t, np, curGoroutines+1+v, expectedNodes)
	}

	assertGoroutines(t, np.Stop, curGoroutines)
}

func TestNodePollerSlowReader(t *testing.T) {
	np, expectedNodes := initTestData(t)

	curGoroutines := runtime.NumGoroutine()
	err := np.Run()
	assert.Nil(t, err)

	err = np.RegisterListener(func(obj interface{}, err error) {
		<-time.After(500 * time.Millisecond)
	})

	for _, v := range []int{1, 2, 3, 4, 5} {
		// two is the magic number, 1 routine1 for the NodePoller
		// plus the 1 slow reader
		assertRegister(t, np, curGoroutines+2+v, expectedNodes)
	}

	assertGoroutines(t, np.Stop, curGoroutines)
}

func TestNodePollerConcurrent(t *testing.T) {
	np, expectedNodes := initTestData(t)

	curGoroutines := runtime.NumGoroutine()
	err := np.Run()
	assert.Nil(t, err)

	var wg sync.WaitGroup
	for _, _ = range []int{0, 1, 2, 3, 4} {
		wg.Add(1)
		go func() {
			// don't test against number of go routines, for this
			// test they are too transitory because of the concurrency
			// routine we're using here
			assertRegister(t, np, -1, expectedNodes)
			wg.Done()
		}()
	}

	wg.Wait()
	assertGoroutines(t, np.Stop, curGoroutines)
}

func TestNodePollerRegisterWhileStopped(t *testing.T) {
	fake := fake.NewSimpleClientset()
	require.NotNil(t, fake, "Mock client cannot be nil")

	np := NewNodePoller(fake, 1*time.Millisecond)
	require.NotNil(t, np, "Node poller cannot be nil")

	curGoroutines := runtime.NumGoroutine()

	calls := []bool{false, false, false, false, false}
	for i, _ := range calls {
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

	for i, _ := range calls {
		assert.True(t, calls[i])
	}

	assertGoroutines(t, np.Stop, curGoroutines)

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

	for i, _ := range calls[5:] {
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

	for i, _ := range calls {
		assert.True(t, calls[i])
	}

	assertGoroutines(t, np.Stop, curGoroutines)
}
