package crmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

var _ = Describe("Node Poller Handler", func() {
	var mockCRM *mockCRManager

	BeforeEach(func() {
		mockCRM = newMockCRManager()
		mockCRM.Agent = newMockAgent(&test.MockWriter{FailStyle: test.Success})
	})

	AfterEach(func() {
		mockCRM.shutdown()
	})

	It("Setup", func() {
		err := mockCRM.SetupNodePolling(
			30,
			"",
			"maintain",
			"test/vxlan")
		Expect(err).To(BeNil(), "Failed to setup Node Poller")
	})

	It("Nodes", func() {
		nodeAddr1 := v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: "1.2.3.4",
		}
		nodeAddr2 := v1.NodeAddress{
			Type:    v1.NodeExternalIP,
			Address: "1.2.3.5",
		}
		nodeObjs := []v1.Node{
			*test.NewNode("worker1", "1", false,
				[]v1.NodeAddress{nodeAddr1}, nil),
			*test.NewNode("worker2", "1", false,
				[]v1.NodeAddress{nodeAddr2}, nil),
		}

		nodes, err := mockCRM.getNodes(nodeObjs)
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes")
		Expect(err).To(BeNil(), "Failed to get nodes")

		mockCRM.UseNodeInternal = true
		nodeObjs[0].Labels = make(map[string]string)
		nodeObjs[0].Labels["app"] = "test"

		nodes, err = mockCRM.getNodes(nodeObjs)
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes")
		Expect(err).To(BeNil(), "Failed to get nodes")

		mockCRM.oldNodes = nodes

		// Negative case
		nodes, err = mockCRM.getNodes([]interface{}{nodeAddr1, nodeAddr2})
		Expect(nodes).To(BeNil(), "Failed to Validate nodes")
		Expect(err).ToNot(BeNil(), "Failed to Validate nodes")

		nodes = mockCRM.getNodesFromCache()
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes from Cache")

		nodes = mockCRM.getNodesWithLabel("app=test")
		Expect(nodes).ToNot(BeNil(), "Failed to get Nodes with Label")

		nodes = mockCRM.getNodesWithLabel("app")
		Expect(nodes).To(BeNil(), "Failed to Validate Nodes with Label")
	})
})
