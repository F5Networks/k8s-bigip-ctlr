package controller

import (
	"errors"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned/fake"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/informers/externalversions/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var _ = Describe("Node Poller Handler", func() {
	var mockCtlr *mockController

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.Agent = newMockAgent(&test.MockWriter{FailStyle: test.Success})
	})

	AfterEach(func() {
		mockCtlr.shutdown()
	})

	It("Setup", func() {
		err := mockCtlr.SetupNodePolling(
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

		nodes, err := mockCtlr.getNodes(nodeObjs)
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes")
		Expect(err).To(BeNil(), "Failed to get nodes")

		mockCtlr.UseNodeInternal = true
		nodeObjs[0].Labels = make(map[string]string)
		nodeObjs[0].Labels["app"] = "test"

		nodes, err = mockCtlr.getNodes(nodeObjs)
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes")
		Expect(err).To(BeNil(), "Failed to get nodes")

		mockCtlr.oldNodes = nodes

		// Negative case
		nodes, err = mockCtlr.getNodes([]interface{}{nodeAddr1, nodeAddr2})
		Expect(nodes).To(BeNil(), "Failed to Validate nodes")
		Expect(err).ToNot(BeNil(), "Failed to Validate nodes")

		nodes = mockCtlr.getNodesFromCache()
		Expect(nodes).ToNot(BeNil(), "Failed to get nodes from Cache")

		nodes = mockCtlr.getNodesWithLabel("app=test")
		Expect(nodes).ToNot(BeNil(), "Failed to get Nodes with Label")

		nodes = mockCtlr.getNodesWithLabel("app")
		Expect(nodes).To(BeNil(), "Failed to Validate Nodes with Label")
	})

	Describe("Processes CIS monitored resources on node update", func() {
		BeforeEach(func() {
			namespace := ""
			mockCtlr.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.mode = CustomResourceMode
			mockCtlr.PoolMemberType = NodePort
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			_ = mockCtlr.addNamespacedInformers("", false)
			mockCtlr.resources = NewResourceStore()
			mockCtlr.crInformers[""].ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
				mockCtlr.kubeCRClient,
				namespace,
				0,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				func(options *metav1.ListOptions) {
					options.LabelSelector = mockCtlr.nativeResourceSelector.String()
				},
			)
			mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
				workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")

		})

		AfterEach(func() {
			mockCtlr.resourceQueue.ShutDown()
		})

		It("Processes IngressLinks on node update", func() {
			// Create IngressLink struct
			meta := metav1.ObjectMeta{
				Name:      "il1",
				Namespace: "nginx-ingress",
			}
			typeMeta := metav1.TypeMeta{
				Kind: IngressLink,
			}
			ingressLink := &cisapiv1.IngressLink{
				ObjectMeta: meta,
				TypeMeta:   typeMeta,
				Spec: cisapiv1.IngressLinkSpec{
					Host:                 "abc.com",
					VirtualServerAddress: "10.11.12.13",
				},
			}
			vs := &cisapiv1.VirtualServer{
				ObjectMeta: meta,
				TypeMeta:   typeMeta,
				Spec: cisapiv1.VirtualServerSpec{
					Host:                 "abc.com",
					VirtualServerAddress: "10.11.12.13",
				},
			}
			vs.ObjectMeta.Namespace = "default"
			ts := &cisapiv1.TransportServer{
				ObjectMeta: meta,
				TypeMeta:   typeMeta,
				Spec: cisapiv1.TransportServerSpec{
					Host:                 "abc.com",
					VirtualServerAddress: "10.11.12.13",
				},
			}
			ts.ObjectMeta.Namespace = "default"

			// Add ingressLink resource to informer store
			err := mockCtlr.crInformers[""].ilInformer.GetStore().Add(ingressLink)
			Expect(err).To(BeNil(), "Failed to add ingressLink resource to informer store")

			// Add k8s node resources
			nodeAddr1 := v1.NodeAddress{
				Type:    v1.NodeInternalIP,
				Address: "1.2.3.4",
			}
			nodeAddr2 := v1.NodeAddress{
				Type:    v1.NodeExternalIP,
				Address: "1.2.3.5",
			}
			nodeAddr3 := v1.NodeAddress{
				Type:    v1.NodeExternalIP,
				Address: "1.2.3.6",
			}
			nodeObjs := []v1.Node{
				*test.NewNode("worker1", "1", false,
					[]v1.NodeAddress{nodeAddr1}, nil),
				*test.NewNode("worker2", "1", false,
					[]v1.NodeAddress{nodeAddr2}, nil),
			}
			mockCtlr.oldNodes, err = mockCtlr.getNodes(nodeObjs)
			Expect(err).To(BeNil(), "Failed to get a list of node addresses")

			// Add the new K8S node and verify
			nodeObjs = append(nodeObjs, *test.NewNode("worker3", "1", false,
				[]v1.NodeAddress{nodeAddr3}, nil))
			tempNodeObjs := nodeObjs

			mockCtlr.ProcessNodeUpdate(nil, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(0))
			mockCtlr.initState = true
			mockCtlr.ProcessNodeUpdate(nodeObjs, errors.New("error"))
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(0))
			mockCtlr.ProcessNodeUpdate(nil, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(0))
			mockCtlr.initState = false
			nodeObjs = tempNodeObjs
			mockCtlr.oldNodes = nil
			// Process Node update and verify that ingressLink is added to the resource queue for processing
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"IngressLink not added to resource queue for processing")
			key, _ := mockCtlr.resourceQueue.Get()
			rKey := key.(*rqKey)
			Expect(rKey.rscName).To(Equal(ingressLink.Name),
				"IngressLink not added to resource queue for processing")
			mockCtlr.crInformers[""].ilInformer.GetStore().Delete(ingressLink)

			nodeObjs = nodeObjs[:len(nodeObjs)-1]
			err = mockCtlr.crInformers[""].vsInformer.GetStore().Add(vs)
			Expect(err).To(BeNil(), "Failed to add Virtual Server resource to informer store")
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"Virtual Server not added to resource queue for processing")
			key, _ = mockCtlr.resourceQueue.Get()
			rKey = key.(*rqKey)
			Expect(rKey.rscName).To(Equal(vs.Name), "Virtual Server not added to resource queue for processing")
			mockCtlr.crInformers[""].vsInformer.GetStore().Delete(vs)

			nodeObjs = nodeObjs[:len(nodeObjs)-1]
			err = mockCtlr.crInformers[""].tsInformer.GetStore().Add(ts)
			Expect(err).To(BeNil(), "Failed to add Transport Server resource to informer store")
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"Transport Server not added to resource queue for processing")
			key, _ = mockCtlr.resourceQueue.Get()
			rKey = key.(*rqKey)
			Expect(rKey.rscName).To(Equal(ts.Name), "Transport Server not added to resource queue for processing")
			mockCtlr.crInformers[""].tsInformer.GetStore().Delete(ts)

			nodeObjs = tempNodeObjs
			delete(mockCtlr.crInformers, "")
			mockCtlr.namespaces = map[string]bool{"nginx-ingress": true, "default": true}

			mockCtlr.crInformers["default"] = mockCtlr.newNamespacedCustomResourceInformer("default")
			mockCtlr.crInformers["nginx-ingress"] = mockCtlr.newNamespacedCustomResourceInformer("nginx-ingress")
			mockCtlr.crInformers["nginx-ingress"].ilInformer.GetStore().Add(ingressLink)
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"IngressLink not added to resource queue for processing")
			key, _ = mockCtlr.resourceQueue.Get()
			rKey = key.(*rqKey)
			Expect(rKey.rscName).To(Equal(ingressLink.Name),
				"IngressLink not added to resource queue for processing")
			mockCtlr.crInformers["nginx-ingress"].ilInformer.GetStore().Delete(ingressLink)

			mockCtlr.crInformers["default"].vsInformer.GetStore().Add(vs)
			nodeObjs = nodeObjs[:len(nodeObjs)-1]
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"Virtual Server not added to resource queue for processing")
			key, _ = mockCtlr.resourceQueue.Get()
			rKey = key.(*rqKey)
			Expect(rKey.rscName).To(Equal(vs.Name), "Virtual Server not added to resource queue for processing")
			mockCtlr.crInformers["default"].vsInformer.GetStore().Delete(vs)

			mockCtlr.crInformers["default"].tsInformer.GetStore().Add(ts)
			nodeObjs = nodeObjs[:len(nodeObjs)-1]
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"Transport Server not added to resource queue for processing")
			key, _ = mockCtlr.resourceQueue.Get()
			rKey = key.(*rqKey)
			Expect(rKey.rscName).To(Equal(ts.Name), "Transport Server not added to resource queue for processing")
			mockCtlr.crInformers["default"].tsInformer.GetStore().Delete(ts)

			mockCtlr.crInformers = make(map[string]*CRInformer)
			_ = mockCtlr.addNamespacedInformers("", false)
			mockCtlr.crInformers[""].ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
				mockCtlr.kubeCRClient,
				"",
				0,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				func(options *metav1.ListOptions) {
					options.LabelSelector = mockCtlr.nativeResourceSelector.String()
				},
			)
			nodeObjs = tempNodeObjs
			mockCtlr.PoolMemberType = NodePort
			mockCtlr.crInformers[""].ilInformer.GetStore().Add(ingressLink)
			// Delete a K8S node and verify
			nodeObjs = nodeObjs[:len(nodeObjs)-1]
			// Process Node update and verify that ingressLink is added to the resource queue for processing
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1),
				"IngressLink not added to resource queue for processing")
			key, _ = mockCtlr.resourceQueue.Get()
			rKey = key.(*rqKey)
			Expect(rKey.rscName).To(Equal(ingressLink.Name),
				"IngressLink not added to resource queue for processing")

			// Verify that ingressLink isn't added to the resource queue for processing if no node is added/deleted
			// Process Node update and verify
			mockCtlr.ProcessNodeUpdate(nodeObjs, nil)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(0),
				"IngressLink should not be added to resource queue for processing")
		})
	})
})
