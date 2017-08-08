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

package openshift

import (
	"fmt"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"
)

func newNode(id, rv string, unsched bool,
	addresses []v1.NodeAddress) *v1.Node {
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

var _ = Describe("OpenShiftSDNMgr Tests", func() {
	It("is only created using proper arguments", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		osMgr, err := NewOpenshiftSDNMgr("", "vxlan500", true, mock)
		Expect(err).To(HaveOccurred())
		Expect(osMgr).To(BeNil())

		osMgr, err = NewOpenshiftSDNMgr("gobbledy-goo", "vxlan500", true, mock)
		Expect(err).To(HaveOccurred())
		Expect(osMgr).To(BeNil())

		osMgr, err = NewOpenshiftSDNMgr("maintain", "", true, mock)
		Expect(err).To(HaveOccurred())
		Expect(osMgr).To(BeNil())

		osMgr, err = NewOpenshiftSDNMgr("maintain", "vxlan500", true, nil)
		Expect(err).To(HaveOccurred())
		Expect(osMgr).To(BeNil())

		osMgr, err = NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(osMgr).ToNot(BeNil())
	})

	It("doesn't panic when node update call fails", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			osMgr.ProcessNodeUpdate(struct{}{}, fmt.Errorf("an error"))
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(0))
	})

	It("doesn't panic when giving node update bad data", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			osMgr.ProcessNodeUpdate(struct{}{}, nil)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(0))
	})

	It("updates nodes", func() {
		mock := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			osMgr.ProcessNodeUpdate(nodeList, nil)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))

		mock.Lock()
		Expect(mock.Sections).To(HaveKey("openshift-sdn"))
		mock.Unlock()

		expected := sdnSection{
			VxLAN: "vxlan500",
			Nodes: []string{
				"127.1.1.2",
				"127.0.0.4",
				"127.1.1.5",
				"127.0.0.7",
			},
		}

		mock.Lock()
		section, ok := mock.Sections["openshift-sdn"].(sdnSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		Expect(section).To(Equal(expected))

		osMgr.useNodeInt = false
		Expect(func() {
			osMgr.ProcessNodeUpdate(nodeList, nil)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(2))

		mock.Lock()
		Expect(mock.Sections).To(HaveKey("openshift-sdn"))
		mock.Unlock()

		expected = sdnSection{
			VxLAN: "vxlan500",
			Nodes: []string{
				"127.0.0.0",
				"127.0.0.1",
				"127.0.0.2",
				"127.0.0.3",
				"127.0.0.6",
			},
		}

		mock.Lock()
		section, ok = mock.Sections["openshift-sdn"].(sdnSection)
		mock.Unlock()
		Expect(ok).To(BeTrue())

		Expect(section).To(Equal(expected))
	})

	It("updates nodes - SendFail", func() {
		mock := &test.MockWriter{
			FailStyle: test.ImmediateFail,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			osMgr.ProcessNodeUpdate(nodeList, nil)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))
	})

	It("updates nodes - SendFailAsync", func() {
		mock := &test.MockWriter{
			FailStyle: test.AsyncFail,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			osMgr.ProcessNodeUpdate(nodeList, nil)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))
	})

	It("updates nodes - SendFailTimeout", func() {
		mock := &test.MockWriter{
			FailStyle: test.Timeout,
			Sections:  make(map[string]interface{}),
		}

		nodeList := getNodeList()

		osMgr, err := NewOpenshiftSDNMgr("maintain", "vxlan500", true, mock)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			osMgr.ProcessNodeUpdate(nodeList, nil)
		}).ToNot(Panic())
		Expect(mock.WrittenTimes).To(Equal(1))
	})
})
