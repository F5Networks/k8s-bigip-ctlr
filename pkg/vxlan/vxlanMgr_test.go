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

package vxlan

import (
	"context"
	"time"

	// appManager is only used because we need the Member type (can't mock it)
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newNode(
	id,
	rv string,
	unsched bool,
	addresses []v1.NodeAddress,
	annotations map[string]string,
) *v1.Node {
	return &v1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Annotations:     annotations,
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
			{Type: "ExternalIP", Address: "127.0.0.0"}}, nil),
		*newNode("node1", "1", false, []v1.NodeAddress{
			{Type: "ExternalIP", Address: "127.0.0.1"}}, nil),
		*newNode("node2", "2", false, []v1.NodeAddress{
			{Type: "ExternalIP", Address: "127.0.0.2"},
			{Type: "InternalIP", Address: "127.1.1.2"}}, nil),
		*newNode("node3", "3", false, []v1.NodeAddress{
			{Type: "ExternalIP", Address: "127.0.0.3"}}, nil),
		*newNode("node4", "4", false, []v1.NodeAddress{
			{Type: "InternalIP", Address: "127.0.0.4"}}, nil),
		*newNode("node5", "5", false, []v1.NodeAddress{
			{Type: "Hostname", Address: "127.0.0.5"},
			{Type: "InternalIP", Address: "127.1.1.5"}}, nil),
		*newNode("node6", "6", true, []v1.NodeAddress{
			{Type: "ExternalIP", Address: "127.0.0.6"}}, nil),
		*newNode("node7", "7", false, []v1.NodeAddress{
			{Type: "InternalIP", Address: "127.0.0.7"}}, nil),
		*newNode("node8", "8", false, []v1.NodeAddress{
			{Type: "Hostname", Address: "127.0.0.8"}}, nil),
	}

	return nodes
}

var _ = Describe("VxlanMgr Tests", func() {
	It("is only created using proper arguments", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		vxMgr, err := NewVxlanMgr("", "vxlan500", "", true, mock, nil)
		Expect(err).To(HaveOccurred())
		Expect(vxMgr).To(BeNil())

		vxMgr, err = NewVxlanMgr("gobbledy-goo", "vxlan500", "", true, mock, nil)
		Expect(err).To(HaveOccurred())
		Expect(vxMgr).To(BeNil())

		vxMgr, err = NewVxlanMgr("maintain", "", "", true, mock, nil)
		Expect(err).To(HaveOccurred())
		Expect(vxMgr).To(BeNil())

		vxMgr, err = NewVxlanMgr("maintain", "vxlan500", "", true, nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(vxMgr).To(BeNil())

		vxMgr, err = NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(vxMgr).ToNot(BeNil())
	})

	It("doesn't panic when node update call fails", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			vxMgr.ProcessNodeUpdate(struct{}{})
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(0))
	})

	It("doesn't panic when giving node update bad data", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			vxMgr.ProcessNodeUpdate(struct{}{})
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(0))
	})

	It("writes fdb records", func() {
		mock := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			vxMgr.ProcessNodeUpdate(nodeList)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))

		mock.Lock()
		Expect(mock.Sections).To(HaveKey("vxlan-fdb"))
		mock.Unlock()

		expected := fdbSection{
			TunnelName: "vxlan500",
			Records: []fdbRecord{
				fdbRecord{
					Name:     "0a:0a:7f:01:01:02",
					Endpoint: "127.1.1.2",
				},
				fdbRecord{
					Name:     "0a:0a:7f:00:00:04",
					Endpoint: "127.0.0.4",
				},
				fdbRecord{
					Name:     "0a:0a:7f:01:01:05",
					Endpoint: "127.1.1.5",
				},
				fdbRecord{
					Name:     "0a:0a:7f:00:00:07",
					Endpoint: "127.0.0.7",
				},
			},
		}

		mock.Lock()
		section, ok := mock.Sections["vxlan-fdb"].(fdbSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		Expect(section).To(Equal(expected))

		vxMgr.useNodeInt = false
		Expect(func() {
			vxMgr.ProcessNodeUpdate(nodeList)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(2))

		mock.Lock()
		Expect(mock.Sections).To(HaveKey("vxlan-fdb"))
		mock.Unlock()

		expected = fdbSection{
			TunnelName: "vxlan500",
			Records: []fdbRecord{
				fdbRecord{
					Name:     "0a:0a:7f:00:00:00",
					Endpoint: "127.0.0.0",
				},
				fdbRecord{
					Name:     "0a:0a:7f:00:00:01",
					Endpoint: "127.0.0.1",
				},
				fdbRecord{
					Name:     "0a:0a:7f:00:00:02",
					Endpoint: "127.0.0.2",
				},
				fdbRecord{
					Name:     "0a:0a:7f:00:00:03",
					Endpoint: "127.0.0.3",
				},
				fdbRecord{
					Name:     "0a:0a:7f:00:00:06",
					Endpoint: "127.0.0.6",
				},
			},
		}

		mock.Lock()
		section, ok = mock.Sections["vxlan-fdb"].(fdbSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		Expect(section).To(Equal(expected))

		// Flannel case
		vxMgr.useNodeInt = true
		annotations := map[string]string{
			"flannel.alpha.coreos.com/backend-data": "{\"VtepMAC\":\"12:ab:34:cd:56:ef\"}",
		}
		flannelNode := *newNode("flannelNode", "9", false,
			[]v1.NodeAddress{{Type: "InternalIP", Address: "127.0.0.10"}}, annotations)

		expected = fdbSection{
			TunnelName: "vxlan500",
			Records: []fdbRecord{
				fdbRecord{
					Name:     "12:ab:34:cd:56:ef",
					Endpoint: "127.0.0.10",
				},
			},
		}

		Expect(func() {
			vxMgr.ProcessNodeUpdate([]v1.Node{flannelNode})
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(3))

		mock.Lock()
		section, ok = mock.Sections["vxlan-fdb"].(fdbSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		Expect(section).To(Equal(expected))
	})

	It("writes fdb records - SendFail", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			vxMgr.ProcessNodeUpdate(nodeList)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))
	})

	It("writes fdb records - SendFailAsync", func() {
		mock := &test.MockWriter{
			FailStyle: test.AsyncFail,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			vxMgr.ProcessNodeUpdate(nodeList)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))
	})

	It("writes fdb records - SendFailTimeout", func() {
		mock := &test.MockWriter{
			FailStyle: test.Timeout,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			vxMgr.ProcessNodeUpdate(nodeList)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))
	})

	It("writes arp entries", func() {
		mock := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		fakeClient := fake.NewSimpleClientset()
		eventChan := make(chan interface{})
		vxMgr, err := NewVxlanMgr("maintain", "vxlan500", "", true, mock, eventChan)
		Expect(err).ToNot(HaveOccurred())
		vxMgr.useNodeInt = true

		annotations := map[string]string{
			"flannel.alpha.coreos.com/backend-data": "{\"VtepMAC\":\"12:ab:34:cd:56:ef\"}",
			"flannel.alpha.coreos.com/public-ip":    "127.0.0.10",
		}
		flannelNode := *newNode("flannelNode", "9", false,
			[]v1.NodeAddress{{Type: "InternalIP", Address: "127.0.0.10"}}, annotations)
		flannelPod := &v1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1",
			},
			Status: v1.PodStatus{
				PodIP:  "1.2.3.4",
				HostIP: "127.0.0.10",
			},
			Spec: v1.PodSpec{
				NodeName: "flannelNode",
			},
		}

		fakeClient.CoreV1().Nodes().Create(context.TODO(), &flannelNode, metav1.CreateOptions{})
		fakeClient.CoreV1().Pods("default").Create(context.TODO(), flannelPod, metav1.CreateOptions{})
		vxMgr.ProcessAppmanagerEvents(fakeClient)
		pod := []resource.Member{
			resource.Member{
				Address: "1.2.3.4",
			},
		}
		eventChan <- pod

		Eventually(func() int {
			return mock.WrittenTimes
		}).Should(Equal(1))
		mock.Lock()
		section, ok := mock.Sections["vxlan-arp"].(arpSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		expected := arpSection{
			Entries: []arpEntry{
				arpEntry{
					Name:    "k8s-1.2.3.4",
					IPAddr:  "1.2.3.4",
					MACAddr: "12:ab:34:cd:56:ef",
				},
			},
		}
		Expect(section).To(Equal(expected))

		// CiliumTunnel
		cilliumPod := flannelPod.DeepCopy()
		vxMgr.ciliumTunnelName = "cliliumTunnel"
		fakeClient.CoreV1().Pods("default").Update(context.TODO(), cilliumPod, metav1.UpdateOptions{})

		pod = []resource.Member{
			resource.Member{
				Address: "1.2.3.4",
			},
		}
		eventChan <- pod

		Eventually(func() int {
			return mock.WrittenTimes
		}).Should(Equal(1))
		mock.Lock()
		section, ok = mock.Sections["vxlan-arp"].(arpSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		expected = arpSection{
			Entries: []arpEntry{
				arpEntry{
					Name:    "k8s-1.2.3.4",
					IPAddr:  "1.2.3.4",
					MACAddr: "12:ab:34:cd:56:ef",
				},
			},
		}
		Expect(section).To(Equal(expected))
		time.Sleep(time.Millisecond * 2)

		// pod name contains cilium
		delete(mock.Sections, "vxlan-arp")
		cilliumPod2 := cilliumPod.DeepCopy()
		cilliumPod2.Name = "test_pod_cilium"
		vxMgr.ciliumTunnelName = ""
		fakeClient.CoreV1().Pods("default").Create(context.TODO(), cilliumPod2, metav1.CreateOptions{})
		cilliumPod2.Status.Phase = "Running"
		fakeClient.CoreV1().Pods("default").Update(context.TODO(), cilliumPod2, metav1.UpdateOptions{})
		eventChan <- pod
		Eventually(func() int {
			return mock.WrittenTimes
		}).Should(Equal(3))
		mock.Lock()
		section, ok = mock.Sections["vxlan-arp"].(arpSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())
		Expect(section).To(Equal(arpSection{}))
	})
})
