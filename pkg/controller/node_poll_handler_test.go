package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/networkmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	"sync"
)

var _ = Describe("Node Poller Handler", func() {
	var mockCtlr *mockController
	var networkManager *networkmanager.NetworkManager
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.comInformers = make(map[string]*CommonInformer)
		mockCtlr.crInformers = make(map[string]*CRInformer)
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
		mockCtlr.multiClusterNodeInformers = make(map[string]*NodeInformer)
		mockCtlr.multiClusterNodeInformers[""] = &NodeInformer{}
	})

	AfterEach(func() {
		mockCtlr.shutdown()
	})

	It("Nodes", func() {
		nodeInf := mockCtlr.getNodeInformer("")
		mockCtlr.multiClusterNodeInformers[""] = &nodeInf
		mockCtlr.addNodeEventUpdateHandler(&nodeInf)
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
		Expect(len(nodeInf.nodeInformer.GetIndexer().List())).To(Equal(3))
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

		mockCtlr.multiClusterNodeInformers[""].oldNodes = nodes
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
		nodeInf := mockCtlr.getNodeInformer("")
		mockCtlr.multiClusterNodeInformers[""] = &nodeInf
		mockCtlr.addNodeEventUpdateHandler(&nodeInf)
		mockCtlr.UseNodeInternal = true
		namespace := "default"
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces[namespace] = true
		mockCtlr.addNamespacedInformers(namespace, false)
		networkManager = networkmanager.NewNetworkManager(mockCtlr.CMTokenManager, "")
		networkManager.DeviceMap["10.8.3.11"] = "dummy-id"
		networkManager.L3ForwardStore.InstanceStaticRoutes["dummy-id"] = networkmanager.StaticRouteMap{}
		mockCtlr.networkManager = networkManager
		mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")
		mockCtlr.requestMap = &requestMap{sync.RWMutex{}, make(map[cisapiv1.BigIpConfig]requestMeta)}
		rMeta := requestMeta{
			partitionMap: make(map[string]map[string]string),
		}
		rMeta.partitionMap[DEFAULT_PARTITION] = make(map[string]string)
		mockCtlr.requestMap.requestMap[cisapiv1.BigIpConfig{
			BigIpLabel:       "bigip1",
			BigIpAddress:     "10.8.3.11",
			DefaultPartition: DEFAULT_PARTITION,
		}] = rMeta
		// Static routes with Node taints, CNI flannel, no podCIDR
		nodeAddr1 := v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: "10.244.1.1",
		}
		nodeObjs := []v1.Node{
			*test.NewNode("worker1", "1", false,
				[]v1.NodeAddress{nodeAddr1}, []v1.Taint{
					{Key: "node-role.kubernetes.io/master", Effect: "NoSchedule"},
				},
				nil),
		}
		for _, node := range nodeObjs {
			mockCtlr.addNode(&node)
		}
		mockCtlr.StaticRoutingMode = true
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// Nodes without taints, CNI flannel, no podCIDR
		for i, _ := range nodeObjs {
			nodeObjs[i].Spec.Taints = []v1.Taint{}
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

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
		Expect(len(networkManager.NetworkChan)).To(Equal(1))
		req, ok := <-networkManager.NetworkChan
		Expect(ok).To(Equal(true))
		Expect(req.Action).To(Equal(networkmanager.Create))
		l3Forward := req.NetworkConfig.(networkmanager.L3Forward)
		Expect(l3Forward.Name).To(ContainSubstring("worker1"))
		Expect(l3Forward.Config.Gateway).To(Equal("1.2.3.4"))

		// OrchestrationCNI = OVN_K8S no OVN annotation on node
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))
		// OrchestrationCNI = OVN_K8S with incorrect OVN annotation on node
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations = make(map[string]string)
			nodeObjs[i].Annotations["k8s.ovn.org/node-subnets"] = "{\"invalid\":\"invalid\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		//TODO add logic to test the below
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// OrchestrationCNI = OVN_K8S with correct OVN annotation k8s.ovn.org/node-subnets on node but no k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations = make(map[string]string)
			nodeObjs[i].Annotations["k8s.ovn.org/node-subnets"] = "{\"default\":\"10.244.0.0/28\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// OrchestrationCNI = OVN_K8S with correct OVN annotation on node invalid k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["k8s.ovn.org/node-primary-ifaddr"] = "{\"invalid\":\"invalid\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		//TODO add logic to test the below
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// OrchestrationCNI = OVN_K8S with correct OVN annotation on node valid k8s.ovn.org/node-primary-ifaddr annotation
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations[OVNK8sNodeIPAnnotation] = "{\"ipv4\":\"10.244.0.0/28\"}"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		//TODO add logic to test the below
		Expect(len(networkManager.NetworkChan)).To(Equal(1))
		req, ok = <-networkManager.NetworkChan
		Expect(ok).To(Equal(true))
		Expect(req.Action).To(Equal(networkmanager.Create))
		l3Forward = req.NetworkConfig.(networkmanager.L3Forward)
		Expect(l3Forward.Name).To(ContainSubstring("worker1"))
		Expect(l3Forward.Config.Gateway).To(Equal("10.244.0.0"))

		// OrchestrationCNI = ovn_k8s and node network CIDR
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations[OVNK8sNodeIPAnnotation2] = "[\"10.244.0.10\"]"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(1))
		req, ok = <-networkManager.NetworkChan
		Expect(ok).To(Equal(true))
		Expect(req.Action).To(Equal(networkmanager.Create))
		l3Forward = req.NetworkConfig.(networkmanager.L3Forward)
		Expect(l3Forward.Name).To(ContainSubstring("worker1"))
		Expect(l3Forward.Config.Gateway).To(Equal("10.244.0.10"))

		// OrchestrationCNI = ovn_k8s without annotations
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			delete(nodeObjs[i].Annotations, OVNK8sNodeIPAnnotation2)
			delete(nodeObjs[i].Annotations, OVNK8sNodeIPAnnotation)
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// OrchestrationCNI = ovn_k8s and valid node network CIDRs
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			delete(nodeObjs[i].Annotations, OVNK8sNodeIPAnnotation2)
			nodeObjs[i].Annotations[OvnK8sNodeIPAnnotation3] = "[\"10.244.0.12/28\"]"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(1))
		req, ok = <-networkManager.NetworkChan
		Expect(ok).To(Equal(true))
		Expect(req.Action).To(Equal(networkmanager.Create))
		l3Forward = req.NetworkConfig.(networkmanager.L3Forward)
		Expect(l3Forward.Name).To(ContainSubstring("worker1"))
		Expect(l3Forward.Config.Gateway).To(Equal("10.244.0.12"))

		// OrchestrationCNI = ovn_k8s and node network CIDRs with invalid ip
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations[OvnK8sNodeIPAnnotation3] = "[\"1.2.3.4/28\"]"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// OrchestrationCNI = ovn_k8s and invalid node network CIDRs
		mockCtlr.OrchestrationCNI = OVN_K8S
		mockCtlr.UseNodeInternal = true
		mockCtlr.StaticRouteNodeCIDR = "10.244.0.0/28"
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations[OvnK8sNodeIPAnnotation3] = "[{\"ipv4\":\"10.244.0.11/28\"}]"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(0))

		// OrchestrationCNI = CILIUM_Static with no valid cilium-k8s annotation
		mockCtlr.OrchestrationCNI = CILIUM
		mockCtlr.UseNodeInternal = true
		mockCtlr.SetupNodeProcessing("")
		//TODO add logic to test the below
		Expect(len(networkManager.NetworkChan)).To(Equal(0))
		// OrchestrationCNI = CILIUM_Static with network.cilium.io/ipv4-pod-cidr annotation
		mockCtlr.OrchestrationCNI = CILIUM
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			nodeObjs[i].Annotations["network.cilium.io/ipv4-pod-cidr"] = "10.244.0.0/28"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(1))
		req, ok = <-networkManager.NetworkChan
		Expect(ok).To(Equal(true))
		Expect(req.Action).To(Equal(networkmanager.Create))
		l3Forward = req.NetworkConfig.(networkmanager.L3Forward)
		Expect(l3Forward.Name).To(ContainSubstring("worker1"))
		Expect(l3Forward.Config.Gateway).To(Equal("1.2.3.4"))

		// OrchestrationCNI = CILIUM_Static with io.cilium.network.ipv4-pod-cidr annotation
		mockCtlr.OrchestrationCNI = CILIUM
		mockCtlr.UseNodeInternal = true
		for i, _ := range nodeObjs {
			delete(nodeObjs[i].Annotations, "network.cilium.io/ipv4-pod-cidr")
			nodeObjs[i].Annotations["io.cilium.network.ipv4-pod-cidr"] = "10.244.0.0/28"
			mockCtlr.updateNode(&nodeObjs[i], namespace)
		}
		mockCtlr.SetupNodeProcessing("")
		Expect(len(networkManager.NetworkChan)).To(Equal(1))
		req, ok = <-networkManager.NetworkChan
		Expect(ok).To(Equal(true))
		Expect(req.Action).To(Equal(networkmanager.Create))
		l3Forward = req.NetworkConfig.(networkmanager.L3Forward)
		Expect(l3Forward.Name).To(ContainSubstring("worker1"))
		Expect(l3Forward.Config.Gateway).To(Equal("1.2.3.4"))
		mockCtlr.resourceQueue.ShutDown()
	})

	//Describe("Processes CIS monitored resources on node update", func() {
	//	BeforeEach(func() {
	//		mockCtlr.clientsets.KubeCRClient = crdfake.NewSimpleClientset()
	//		mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
	//		mockCtlr.PoolMemberType = NodePort
	//		mockCtlr.crInformers = make(map[string]*CRInformer)
	//		mockCtlr.comInformers = make(map[string]*CommonInformer)
	//		mockCtlr.managedResources.ManageCustomResources = true
	//		mockCtlr.resourceSelectorConfig.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
	//		mockCtlr.crInformers[""] = mockCtlr.newNamespacedCustomResourceInformer("")
	//		mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
	//			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")
	//		mockCtlr.resources = NewResourceStore()
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
	//				[]v1.NodeAddress{nodeAddr1}, nil, nil),
	//			*test.NewNode("worker2", "1", false,
	//				[]v1.NodeAddress{nodeAddr2}, nil, nil),
	//		}
	//		// Add the new K8S node and verify
	//		nodeObjs = append(nodeObjs, *test.NewNode("worker3", "1", false,
	//			[]v1.NodeAddress{nodeAddr3}, nil, nil))
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
	//		mockCtlr.crInformers["default"] = mockCtlr.newNamespacedCustomResourceInformer("default")
	//		mockCtlr.crInformers["nginx-ingress"] = mockCtlr.newNamespacedCustomResourceInformer("nginx-ingress")
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
	//			mockCtlr.clientsets.KubeCRClient,
	//			"",
	//			0,
	//			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	//			func(options *metav1.ListOptions) {
	//				options.LabelSelector = mockCtlr.resourceSelectorConfig.nativeResourceSelector.String()
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
