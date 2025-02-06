package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
)

var _ = Describe("Node Poller Handler", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		params := Params{
			MultiClusterMode: PrimaryCIS,
			Agent: &Agent{
				PostManager: &PostManager{
					PrimaryClusterHealthProbeParams: PrimaryClusterHealthProbeParams{
						statusRunning: true,
					},
				},
			},
		}
		mockCtlr.multiClusterHandler = NewClusterHandler("", params.MultiClusterMode, &params.Agent.PrimaryClusterHealthProbeParams)
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
		mockCtlr.Agent = newMockAgent(&test.MockWriter{FailStyle: test.Success})
		writer := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		mockCtlr.Agent.ConfigWriter = writer
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = &ClusterConfig{kubeClient: k8sfake.NewSimpleClientset()}
		mockCtlr.multiClusterHandler.ClusterConfigs[""].InformerStore = initInformerStore()
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
	})

	AfterEach(func() {
		mockCtlr.shutdown()
	})

	It("Nodes", func() {
		mockCtlr.setNodeInformer("")
		mockCtlr.UseNodeInternal = true
		nodeAddr1 := v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: "1.2.3.4",
		}
		nodeAddr2 := v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: "1.2.3.5",
		}
		nodeAddr3 := v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: "1.2.3.6",
		}
		nodecondition := v1.NodeCondition{Type: v1.NodeReady, Status: v1.ConditionFalse}
		nodeObjs := []v1.Node{
			*test.NewNode("worker1", "1", false,
				[]v1.NodeAddress{nodeAddr1}, nil, nil),
			*test.NewNode("worker2", "1", false,
				[]v1.NodeAddress{nodeAddr2}, nil, nil),
			*test.NewNode("worker3", "1", false,
				[]v1.NodeAddress{nodeAddr3}, nil, []v1.NodeCondition{nodecondition}),
		}

		for _, node := range nodeObjs {
			mockCtlr.addNode(&node)
		}
		Expect(len(mockCtlr.multiClusterHandler.ClusterConfigs[""].nodeInformer.nodeInformer.GetIndexer().List())).To(Equal(3))
		nodes, err := mockCtlr.getNodes(nodeObjs)
		//verify node with NotReady state not added to node list
		Expect(len(nodes)).To(Equal(2))
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes")
		Expect(err).To(BeNil(), "Failed to get nodes")

		mockCtlr.UseNodeInternal = true
		nodeObjs[0].Labels = make(map[string]string)
		nodeObjs[0].Labels["app"] = "test"

		nodes, err = mockCtlr.getNodes(nodeObjs)
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes")
		Expect(err).To(BeNil(), "Failed to get nodes")

		mockCtlr.multiClusterHandler.ClusterConfigs[""].oldNodes = nodes

		// Negative case
		nodes, err = mockCtlr.getNodes([]interface{}{nodeAddr1, nodeAddr2})
		Expect(nodes).To(BeNil(), "Failed to Validate nodes")
		Expect(err).ToNot(BeNil(), "Failed to Validate nodes")

		nodes = mockCtlr.getNodesFromCache("")
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes from Cache")

		nodes = mockCtlr.getNodesWithLabel("app=test", "")
		Expect(nodes).ToNot(BeNil(), "Failed to get Nodes with Label")

		nodes = mockCtlr.getNodesWithLabel("app", "")
		Expect(nodes).To(BeNil(), "Failed to Validate Nodes with Label")
	})

	It("Nodes Update processing", func() {
		mockCtlr.setNodeInformer("")
		mockCtlr.UseNodeInternal = true
		namespace := "default"
		mockCtlr.multiClusterHandler.ClusterConfigs[""].namespaces = make(map[string]struct{})
		mockCtlr.multiClusterHandler.ClusterConfigs[""].namespaces[namespace] = struct{}{}
		mockCtlr.addNamespacedInformers(namespace, false, "")
		mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")

		// Static routes with Node taints
		nodeAddr1 := v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: "10.244.1.1",
		}
		nodeObjs := []v1.Node{
			*test.NewNode("worker1", "1", false,
				[]v1.NodeAddress{nodeAddr1}, nil, nil),
		}
		for _, node := range nodeObjs {
			mockCtlr.addNode(&node)
		}
		mockCtlr.StaticRoutingMode = true
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok := mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))
		// Nodes without taints, CNI flannel, no podCIDR
		for i, _ := range nodeObjs {
			nodeObjs[i].Spec.Taints = []v1.Taint{}
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// Nodes without taints, CNI flannel, with podCIDR, InternalNodeIP
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Spec.PodCIDR = "10.244.0.0/28"
			nodeObjs[i].Status.Addresses = []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "1.2.3.4"},
			}
			mockCtlr.updateStatusNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		expectedRouteSection := routeSection{
			Entries: []routeConfig{
				{
					Name:    "k8s-worker1-1.2.3.4",
					Network: "10.244.0.0/28",
					Gateway: "1.2.3.4",
				},
			},
		}
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(expectedRouteSection))

		// OrchestrationCNI = OVN_K8S no OVN annotation on node
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// OrchestrationCNI = OVN_K8S with incorrect OVN annotation on node
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations = make(map[string]string)
			nodeObjs[i].Annotations["k8s.ovn.org/node-subnets"] = "{\"invalid\":\"invalid\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))
		// OrchestrationCNI = OVN_K8S with correct OVN annotation k8s.ovn.org/node-subnets on node with interface but no k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations = make(map[string]string)
			nodeObjs[i].Annotations["k8s.ovn.org/node-subnets"] = "{\"default\":[\"10.244.0.0/28\"]}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// OrchestrationCNI = OVN_K8S with correct OVN annotation k8s.ovn.org/node-subnets on node but no k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations = make(map[string]string)
			nodeObjs[i].Annotations["k8s.ovn.org/node-subnets"] = "{\"default\":\"10.244.0.0/28\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// OrchestrationCNI = OVN_K8S with StaticRouteNodeCIDR and invalid OVN annotation k8s.ovn.org/host-cidrss on node but no k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["k8s.ovn.org/host-cidrs"] = "{\"default\":\"10.244.0.0/28\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// OrchestrationCNI = OVN_K8S with correct OVN annotation on node invalid k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = ""
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["k8s.ovn.org/node-primary-ifaddr"] = "{\"invalid\":\"invalid\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// OrchestrationCNI = OVN_K8S with correct OVN annotation on node valid k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["k8s.ovn.org/node-primary-ifaddr"] = "{\"ipv4\":\"10.244.0.0/28\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		expectedRouteSection = routeSection{
			Entries: []routeConfig{
				{
					Name:    "k8s-worker1-10.244.0.0",
					Network: "10.244.0.0/28",
					Gateway: "10.244.0.0",
				},
			},
		}
		Expect(mockWriter.Sections["static-routes"]).To(Equal(expectedRouteSection))
		// OrchestrationCNI = ovn_k8s and invalid hostaddresses annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["k8s.ovn.org/host-addresses"] = "{\"default\":\"10.244.0.0/28\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))
		// OrchestrationCNI = ovn_k8s and node network CIDR
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["k8s.ovn.org/host-addresses"] = "[\"10.244.0.0\"]"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		expectedRouteSection = routeSection{
			Entries: []routeConfig{
				{
					Name:    "k8s-worker1-10.244.0.0",
					Network: "10.244.0.0/28",
					Gateway: "10.244.0.0",
				},
			},
		}
		Expect(mockWriter.Sections["static-routes"]).To(Equal(expectedRouteSection))
		// set valid hostcidrs annoation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			delete(nodeObjs[i].Annotations, "k8s.ovn.org/host-addresses")
			nodeObjs[i].Annotations["k8s.ovn.org/host-cidrs"] = "[\"10.244.0.0/28\"]"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		expectedRouteSection = routeSection{
			Entries: []routeConfig{
				{
					Name:    "k8s-worker1-10.244.0.0",
					Network: "10.244.0.0/28",
					Gateway: "10.244.0.0",
				},
			},
		}
		Expect(mockWriter.Sections["static-routes"]).To(Equal(expectedRouteSection))
		// OrchestrationCNI = CILIUM_K8S with no valid cilium-k8s annotation
		mockCtlr.OrchestrationCNI = CILIUM_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(routeSection{}))

		// OrchestrationCNI = CILIUM_K8S with network.cilium.io/ipv4-pod-cidr annotation
		mockCtlr.OrchestrationCNI = CILIUM_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["network.cilium.io/ipv4-pod-cidr"] = "10.244.0.0/28"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		expectedRouteSection = routeSection{
			Entries: []routeConfig{
				{
					Name:    "k8s-worker1-1.2.3.4",
					Network: "10.244.0.0/28",
					Gateway: "1.2.3.4",
				},
			},
		}
		Expect(mockWriter.Sections["static-routes"]).To(Equal(expectedRouteSection))

		// OrchestrationCNI = CILIUM_K8S with io.cilium.network.ipv4-pod-cidr annotation
		mockCtlr.OrchestrationCNI = CILIUM_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			delete(nodeObjs[i].Annotations, "network.cilium.io/ipv4-pod-cidr")
			nodeObjs[i].Annotations["io.cilium.network.ipv4-pod-cidr"] = "10.244.0.0/28"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		mockWriter, ok = mockCtlr.Agent.ConfigWriter.(*test.MockWriter)
		Expect(ok).To(Equal(true))
		Expect(len(mockWriter.Sections)).To(Equal(1))
		Expect(mockWriter.Sections["static-routes"]).To(Equal(expectedRouteSection))
		mockCtlr.resourceQueue.ShutDown()

	})

	//TODO fix this unit testcase for new node-update logic
	//Describe("Processes CIS monitored resources on node update", func() {
	//	BeforeEach(func() {
	//		namespace := ""
	//		mockCtlr.kubeCRClient = crdfake.NewSimpleClientset()
	//		mockCtlr.kubeClient = k8sfake.NewSimpleClientset()
	//		mockCtlr.mode = CustomResourceMode
	//		mockCtlr.PoolMemberType = NodePort
	//		mockCtlr.crInformers = make(map[string]*CRInformer)
	//		mockCtlr.comInformers = make(map[string]*CommonInformer)
	//		_ = mockCtlr.addNamespacedInformers("", false)
	//		mockCtlr.resources = NewResourceStore()
	//		mockCtlr.crInformers[""].ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
	//			mockCtlr.kubeCRClient,
	//			namespace,
	//			0,
	//			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	//			func(options *metav1.ListOptions) {
	//				options.LabelSelector = mockCtlr.nativeResourceSelector.String()
	//			},
	//		)
	//		mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
	//			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")
	//
	//	})
	//
	//	AfterEach(func() {
	//		mockCtlr.resourceQueue.ShutDown()
	//	})
	//
	//	It("Processes IngressLinks on node update", func() {
	//		// Create IngressLink struct
	//		meta := metav1.ObjectMeta{
	//			Name:      "il1",
	//			Namespace: "nginx-ingress",
	//		}
	//		typeMeta := metav1.TypeMeta{
	//			Kind: IngressLink,
	//		}
	//		ingressLink := &cisapiv1.IngressLink{
	//			ObjectMeta: meta,
	//			TypeMeta:   typeMeta,
	//			Spec: cisapiv1.IngressLinkSpec{
	//				Host:                 "abc.com",
	//				VirtualServerAddress: "10.11.12.13",
	//			},
	//		}
	//		vs := &cisapiv1.VirtualServer{
	//			ObjectMeta: meta,
	//			TypeMeta:   typeMeta,
	//			Spec: cisapiv1.VirtualServerSpec{
	//				Host:                 "abc.com",
	//				VirtualServerAddress: "10.11.12.13",
	//			},
	//		}
	//		vs.ObjectMeta.Namespace = "default"
	//		ts := &cisapiv1.TransportServer{
	//			ObjectMeta: meta,
	//			TypeMeta:   typeMeta,
	//			Spec: cisapiv1.TransportServerSpec{
	//				Host:                 "abc.com",
	//				VirtualServerAddress: "10.11.12.13",
	//			},
	//		}
	//		ts.ObjectMeta.Namespace = "default"
	//
	//		// Add ingressLink resource to informer store
	//		err := mockCtlr.crInformers[""].ilInformer.GetStore().Add(ingressLink)
	//		Expect(err).To(BeNil(), "Failed to add ingressLink resource to informer store")
	//
	//		// Add k8s node resources
	//		nodeAddr1 := v1.NodeAddress{
	//			Type:    v1.NodeInternalIP,
	//			Address: "1.2.3.4",
	//		}
	//		nodeAddr2 := v1.NodeAddress{
	//			Type:    v1.NodeExternalIP,
	//			Address: "1.2.3.5",
	//		}
	//		nodeAddr3 := v1.NodeAddress{
	//			Type:    v1.NodeExternalIP,
	//			Address: "1.2.3.6",
	//		}
	//		nodeObjs := []v1.Node{
	//			*test.NewNode("worker1", "1", false,
	//				[]v1.NodeAddress{nodeAddr1}, nil),
	//			*test.NewNode("worker2", "1", false,
	//				[]v1.NodeAddress{nodeAddr2}, nil),
	//		}
	//		mockCtlr.oldNodes, err = mockCtlr.getNodes(nodeObjs)
	//		Expect(err).To(BeNil(), "Failed to get a list of node addresses")
	//
	//		// Add the new K8S node and verify
	//		nodeObjs = append(nodeObjs, *test.NewNode("worker3", "1", false,
	//			[]v1.NodeAddress{nodeAddr3}, nil))
	//		tempNodeObjs := nodeObjs
	//
	//		mockCtlr.ProcessNodeUpdate(nil, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(0))
	//		mockCtlr.initState = true
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(0))
	//		mockCtlr.ProcessNodeUpdate(nil, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(0))
	//		mockCtlr.initState = false
	//		nodeObjs = tempNodeObjs
	//		mockCtlr.oldNodes = nil
	//		// Process Node update and verify that ingressLink is added to the resource queue for processing
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"IngressLink not added to resource queue for processing")
	//		key, _ := mockCtlr.resourceQueue.Get()
	//		rKey := key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(ingressLink.Name),
	//			"IngressLink not added to resource queue for processing")
	//		mockCtlr.crInformers[""].ilInformer.GetStore().Delete(ingressLink)
	//
	//		nodeObjs = nodeObjs[:len(nodeObjs)-1]
	//		err = mockCtlr.crInformers[""].vsInformer.GetStore().Add(vs)
	//		Expect(err).To(BeNil(), "Failed to add Virtual Server resource to informer store")
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"Virtual Server not added to resource queue for processing")
	//		key, _ = mockCtlr.resourceQueue.Get()
	//		rKey = key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(vs.Name), "Virtual Server not added to resource queue for processing")
	//		mockCtlr.crInformers[""].vsInformer.GetStore().Delete(vs)
	//
	//		nodeObjs = nodeObjs[:len(nodeObjs)-1]
	//		err = mockCtlr.crInformers[""].tsInformer.GetStore().Add(ts)
	//		Expect(err).To(BeNil(), "Failed to add Transport Server resource to informer store")
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"Transport Server not added to resource queue for processing")
	//		key, _ = mockCtlr.resourceQueue.Get()
	//		rKey = key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(ts.Name), "Transport Server not added to resource queue for processing")
	//		mockCtlr.crInformers[""].tsInformer.GetStore().Delete(ts)
	//
	//		nodeObjs = tempNodeObjs
	//		delete(mockCtlr.crInformers, "")
	//		mockCtlr.namespaces = map[string]bool{"nginx-ingress": true, "default": true}
	//
	//		mockCtlr.crInformers["default"] = mockCtlr.newNamespacedCustomResourceInformerForCluster("default")
	//		mockCtlr.crInformers["nginx-ingress"] = mockCtlr.newNamespacedCustomResourceInformerForCluster("nginx-ingress")
	//		mockCtlr.crInformers["nginx-ingress"].ilInformer.GetStore().Add(ingressLink)
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"IngressLink not added to resource queue for processing")
	//		key, _ = mockCtlr.resourceQueue.Get()
	//		rKey = key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(ingressLink.Name),
	//			"IngressLink not added to resource queue for processing")
	//		mockCtlr.crInformers["nginx-ingress"].ilInformer.GetStore().Delete(ingressLink)
	//
	//		mockCtlr.crInformers["default"].vsInformer.GetStore().Add(vs)
	//		nodeObjs = nodeObjs[:len(nodeObjs)-1]
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"Virtual Server not added to resource queue for processing")
	//		key, _ = mockCtlr.resourceQueue.Get()
	//		rKey = key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(vs.Name), "Virtual Server not added to resource queue for processing")
	//		mockCtlr.crInformers["default"].vsInformer.GetStore().Delete(vs)
	//
	//		mockCtlr.crInformers["default"].tsInformer.GetStore().Add(ts)
	//		nodeObjs = nodeObjs[:len(nodeObjs)-1]
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"Transport Server not added to resource queue for processing")
	//		key, _ = mockCtlr.resourceQueue.Get()
	//		rKey = key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(ts.Name), "Transport Server not added to resource queue for processing")
	//		mockCtlr.crInformers["default"].tsInformer.GetStore().Delete(ts)
	//
	//		mockCtlr.crInformers = make(map[string]*CRInformer)
	//		_ = mockCtlr.addNamespacedInformers("", false)
	//		mockCtlr.crInformers[""].ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
	//			mockCtlr.kubeCRClient,
	//			"",
	//			0,
	//			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	//			func(options *metav1.ListOptions) {
	//				options.LabelSelector = mockCtlr.nativeResourceSelector.String()
	//			},
	//		)
	//		nodeObjs = tempNodeObjs
	//		mockCtlr.PoolMemberType = NodePort
	//		mockCtlr.crInformers[""].ilInformer.GetStore().Add(ingressLink)
	//		// Delete a K8S node and verify
	//		nodeObjs = nodeObjs[:len(nodeObjs)-1]
	//		// Process Node update and verify that ingressLink is added to the resource queue for processing
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
	//			"IngressLink not added to resource queue for processing")
	//		key, _ = mockCtlr.resourceQueue.Get()
	//		rKey = key.(*rqKey)
	//		Expect(rKey.rscName).To(Equal(ingressLink.Name),
	//			"IngressLink not added to resource queue for processing")
	//
	//		// Verify that ingressLink isn't added to the resource queue for processing if no node is added/deleted
	//		// Process Node update and verify
	//		mockCtlr.ProcessNodeUpdate(nodeObjs, "")
	//		Expect(mockCtlr.resourceQueue.Len()).To(Equal(0),
	//			"IngressLink should not be added to resource queue for processing")
	//	})
	//})
})
