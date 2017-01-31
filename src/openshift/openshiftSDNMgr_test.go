package openshift

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/1.4/pkg/api/unversioned"
	"k8s.io/client-go/1.4/pkg/api/v1"
)

const (
	ImmediateFail = iota
	AsyncFail
	Timeout
	Success
)

type MockWriter struct {
	FailStyle    int
	WrittenTimes int
	Name         string
	SdnSection   sdnSection
}

func (mw *MockWriter) GetOutputFilename() string {
	return "mock-file"
}

func (mw *MockWriter) Stop() {
}

func (mw *MockWriter) SendSection(
	name string,
	obj interface{},
) (<-chan struct{}, <-chan error, error) {

	doneCh := make(chan struct{})
	errCh := make(chan error)

	mw.WrittenTimes++

	mw.Name = name
	mw.SdnSection = obj.(sdnSection)

	switch mw.FailStyle {
	case ImmediateFail:
		return nil, nil, fmt.Errorf("immediate test error")
	case AsyncFail:
		go func() {
			errCh <- fmt.Errorf("async test error")
		}()
	case Timeout:
		<-time.After(2 * time.Second)
	case Success:
		go func() {
			doneCh <- struct{}{}
		}()
	}

	return doneCh, errCh, nil
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

func getNodeList() []v1.Node {
	nodes := []v1.Node{
		*newNode("node0", "0", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.0"}}),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.1"}}),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.2"},
			{"InternalIP", "127.1.1.2"}}),
		*newNode("node3", "3", false, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.3"}}),
		*newNode("node4", "4", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.4"}}),
		*newNode("node5", "5", false, []v1.NodeAddress{
			{"Hostname", "127.0.0.5"},
			{"InternalIP", "127.1.1.5"}}),
		*newNode("node6", "6", true, []v1.NodeAddress{
			{"ExternalIP", "127.0.0.6"}}),
		*newNode("node7", "7", false, []v1.NodeAddress{
			{"InternalIP", "127.0.0.7"}}),
		*newNode("node8", "8", false, []v1.NodeAddress{
			{"Hostname", "127.0.0.8"}}),
	}

	return nodes
}

func TestOpenshiftMgrCreate(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    ImmediateFail,
		WrittenTimes: 0,
	}

	osMgr, err := NewOpenshiftSDNMgr("", "vxlan500", true, mock)
	assert.Error(t, err)
	assert.Nil(t, osMgr)

	osMgr, err = NewOpenshiftSDNMgr("gobbledy-goo", "vxlan500", true, mock)
	assert.Error(t, err)
	assert.Nil(t, osMgr)

	osMgr, err = NewOpenshiftSDNMgr("maintain", "", true, mock)
	assert.Error(t, err)
	assert.Nil(t, osMgr)

	osMgr, err = NewOpenshiftSDNMgr("maintain", "vxlan500", true, nil)
	assert.Error(t, err)
	assert.Nil(t, osMgr)

	osMgr, err = NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	assert.NotNil(t, osMgr)
}

func TestOpenshiftMgrNodeUpdateCallFail(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    ImmediateFail,
		WrittenTimes: 0,
	}

	osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(struct{}{}, fmt.Errorf("an error"))
	})
	assert.EqualValues(t, 0, mock.WrittenTimes)
}

func TestOpenshiftNodeUpdateBadData(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    ImmediateFail,
		WrittenTimes: 0,
	}

	osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(struct{}{}, nil)
	})
	assert.EqualValues(t, 0, mock.WrittenTimes)
}

func TestOpenshiftNodeUpdate(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    Success,
		WrittenTimes: 0,
	}

	nodeList := getNodeList()

	osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(nodeList, nil)
	})
	assert.EqualValues(t, 1, mock.WrittenTimes)
	assert.Equal(t, "openshift-sdn", mock.Name)

	expected := sdnSection{
		VxLAN: "vxlan500",
		Nodes: []string{
			"127.1.1.2",
			"127.0.0.4",
			"127.1.1.5",
			"127.0.0.7",
		},
	}

	assert.EqualValues(t, expected, mock.SdnSection)

	osMgr.useNodeInt = false
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(nodeList, nil)
	})
	assert.Equal(t, 2, mock.WrittenTimes)
	assert.Equal(t, "openshift-sdn", mock.Name)

	expected = sdnSection{
		VxLAN: "vxlan500",
		Nodes: []string{
			"127.0.0.1",
			"127.0.0.2",
			"127.0.0.3",
		},
	}

	assert.EqualValues(t, expected, mock.SdnSection)
}

func TestOpenshiftNodeUpdateSendFail(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    ImmediateFail,
		WrittenTimes: 0,
	}

	nodeList := getNodeList()

	osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(nodeList, nil)
	})
	assert.EqualValues(t, 1, mock.WrittenTimes)
}

func TestOpenshiftNodeUpdateSendFailAsync(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    AsyncFail,
		WrittenTimes: 0,
	}

	nodeList := getNodeList()

	osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(nodeList, nil)
	})
	assert.EqualValues(t, 1, mock.WrittenTimes)
}

func TestOpenshiftNodeUpdateSendFailTimeout(t *testing.T) {
	mock := &MockWriter{
		FailStyle:    Timeout,
		WrittenTimes: 0,
	}

	nodeList := getNodeList()

	osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
	assert.NoError(t, err)
	require.NotPanics(t, func() {
		osMgr.ProcessNodeUpdate(nodeList, nil)
	})
	assert.EqualValues(t, 1, mock.WrittenTimes)
}
