/*-
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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
	"context"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	nodeLabel   = "node-role.io.kubernetes.io/node"
	masterLabel = "node-role.io.kubernetes.io/master"
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
	labels map[string]string,
) *v1.Node {
	return &v1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Labels:          labels,
		},
		Spec: v1.NodeSpec{
			Unschedulable: unsched,
		},
		Status: v1.NodeStatus{
			Addresses: addresses,
		},
	}
}

func hasNodeLabel(node *v1.Node, label string) bool {
	if label == "" {
		return true
	}

	_, ok := node.ObjectMeta.Labels[label]

	return ok
}

var _ = Describe("Node Poller Tests", func() {
	initTestData := func(nodeLabelSelector string) (Poller, []nodeData) {
		addressList := [][]v1.NodeAddress{
			{
				{Type: "ExternalIP", Address: "127.0.0.0"},
			},
			{
				{Type: "ExternalIP", Address: "127.0.0.1"},
				{Type: "InternalIP", Address: "127.1.0.1"},
			},
			{
				{Type: "ExternalIP", Address: "127.0.0.2"},
				{Type: "InternalIP", Address: "127.1.0.2"},
			},
			{
				{Type: "ExternalIP", Address: "127.0.0.3"},
				{Type: "InternalIP", Address: "127.1.0.3"},
			},
			{
				{Type: "InternalIP", Address: "127.0.0.4"},
			},
			{
				{Type: "Hostname", Address: "127.0.0.5"},
			},
		}

		masterLabelMap := map[string]string{
			masterLabel: "true",
		}
		nodeLabelMap := map[string]string{
			nodeLabel: "true",
		}

		// Existing Node data
		setNodes := []*v1.Node{
			newNode("node0", "0", true, addressList[0], masterLabelMap),
		}

		for idx := 1; idx < 6; idx++ {
			setNodes = append(setNodes, newNode(fmt.Sprintf("node%d", idx), strconv.Itoa(idx), false, addressList[idx], nodeLabelMap))
		}

		expectedNodes := []nodeData{}
		for _, node := range setNodes {
			if !hasNodeLabel(node, nodeLabelSelector) {
				continue
			}

			expectedNodes = append(expectedNodes, nodeData{
				Name:          node.ObjectMeta.Name,
				Unschedulable: node.Spec.Unschedulable,
				Addresses:     node.Status.Addresses,
			})
		}

		fake := fake.NewSimpleClientset()
		Expect(fake).ToNot(BeNil(), "Mock client cannot be nil.")

		for _, setNode := range setNodes {
			node, err := fake.CoreV1().Nodes().Create(context.TODO(), setNode, metav1.CreateOptions{})
			Expect(err).To(BeNil(), "Should not fail creating node.")
			Expect(node).To(Equal(setNode))
		}

		np := NewNodePoller(fake, 1*time.Millisecond, nodeLabelSelector)
		Expect(np).ToNot(BeNil(), "Node poller cannot be nil.")

		return np, expectedNodes
	}

	assertRegister := func(p Poller, expectedNodes []nodeData, stopped bool, countExpectedNodes int) {
		called := 0
		err := p.RegisterListener(func(call *int) PollListener {
			var p PollListener = func(obj interface{}, err error) {
				if 0 == *call {
					nl, ok := obj.([]v1.Node)
					Expect(ok).To(BeTrue(), "Should be called back with a nodeData.")
					Expect(len(nl)).To(Equal(countExpectedNodes))
					Expect(err).To(BeNil())

					for i, expected := range expectedNodes {
						Expect(nl[i].ObjectMeta.Name).To(Equal(expected.Name))
						Expect(nl[i].Spec.Unschedulable).To(Equal(expected.Unschedulable))
						Expect(nl[i].Status.Addresses).To(Equal(expected.Addresses))
					}
				}
				(*call)++
			}
			return p
		}(&called))
		Expect(err).To(BeNil())

		runtime.Gosched()
		<-time.After(100 * time.Millisecond)

		var cond bool
		if false == stopped {
			cond = called > 0
		} else {
			cond = called == 0
		}

		Expect(cond).To(BeTrue(), "Listener should have been called 1 or more times.")
	}

	It("starts and stops", func() {
		fakeClient := fake.NewSimpleClientset()
		Expect(fakeClient).ToNot(BeNil(), "Mock client cannot be nil.")

		np := NewNodePoller(fakeClient, 1*time.Millisecond, "")
		Expect(np).ToNot(BeNil(), "Node poller cannot be nil.")

		err := np.Run()
		Expect(err).To(BeNil())
		// call run a second time
		err = np.Run()
		Expect(err).ToNot(BeNil())

		var called bool
		err = np.RegisterListener(func(obj interface{}, err error) {
			called = true
		})

		<-time.After(100 * time.Millisecond)
		Expect(called).To(BeTrue())

		err = np.Stop()
		Expect(err).To(BeNil())

		// after stop called should not be reset to true from a running
		// listener
		<-time.After(100 * time.Millisecond)
		called = false
		Expect(called).To(BeFalse())

		// call stop a second time
		err = np.Stop()
		Expect(err).ToNot(BeNil())
	})

	It("polls nodes", func() {
		np, expectedNodes := initTestData("")

		err := np.Run()
		Expect(err).To(BeNil())

		for _ = range []int{1, 2, 3, 4, 5} {
			// one is the magic number, 1 routine for the NodePoller
			assertRegister(np, expectedNodes, false, len(expectedNodes))
		}

		err = np.Stop()
		Expect(err).To(BeNil())

		assertRegister(np, expectedNodes, true, len(expectedNodes))
	})

	It("polls nodes - SlowReader", func() {
		np, expectedNodes := initTestData("")

		err := np.Run()
		Expect(err).To(BeNil())

		err = np.RegisterListener(func(obj interface{}, err error) {
			<-time.After(500 * time.Millisecond)
		})

		for _ = range []int{1, 2, 3, 4, 5} {
			// two is the magic number, 1 routine1 for the NodePoller
			// plus the 1 slow reader
			assertRegister(np, expectedNodes, false, len(expectedNodes))
		}

		err = np.Stop()
		Expect(err).To(BeNil())

		assertRegister(np, expectedNodes, true, len(expectedNodes))
	})

	It("polls nodes concurrently", func() {
		np, expectedNodes := initTestData("")

		err := np.Run()
		Expect(err).To(BeNil())

		var wg sync.WaitGroup
		for _ = range []int{0, 1, 2, 3, 4} {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				// don't test against number of go routines, for this
				// test they are too transitory because of the concurrency
				// routine we're using here
				assertRegister(np, expectedNodes, false, len(expectedNodes))
				wg.Done()
			}()
		}

		wg.Wait()
		err = np.Stop()
		Expect(err).To(BeNil())

		assertRegister(np, expectedNodes, true, len(expectedNodes))
	})

	It("registers properly while stopped", func() {
		fakeClient := fake.NewSimpleClientset()
		Expect(fakeClient).ToNot(BeNil(), "Mock client cannot be nil.")

		np := NewNodePoller(fakeClient, 1*time.Millisecond, "")
		Expect(np).ToNot(BeNil(), "Node poller cannot be nil.")

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
			Expect(err).To(BeNil())
		}

		err := np.Run()
		Expect(err).To(BeNil())

		runtime.Gosched()
		<-time.After(100 * time.Millisecond)

		for i := range calls {
			Expect(calls[i]).To(BeTrue())
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
			err = np.RegisterListener(func(index int) PollListener {
				var p PollListener = func(obj interface{}, err error) {
					if false == calls[index] {
						calls[index] = true
					}
				}
				return p
			}(i + 5))
			Expect(err).To(BeNil())
		}

		err = np.Run()
		Expect(err).To(BeNil())

		runtime.Gosched()
		<-time.After(100 * time.Millisecond)

		for i := range calls {
			Expect(calls[i]).To(BeTrue())
		}

		err = np.Stop()
		Expect(err).To(BeNil())
	})

	It("polls nodes with a nodeLabelSelector ", func() {
		np, expectedNodes := initTestData(nodeLabel)

		err := np.Run()
		Expect(err).To(BeNil())

		var wg sync.WaitGroup
		for _ = range []int{0, 1, 2, 3, 4} {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				// don't test against number of go routines, for this
				// test they are too transitory because of the concurrency
				// routine we're using here
				assertRegister(np, expectedNodes, false, len(expectedNodes))
				wg.Done()
			}()
		}

		wg.Wait()
		err = np.Stop()
		Expect(err).To(BeNil())

		assertRegister(np, expectedNodes, true, len(expectedNodes))
	})
})
