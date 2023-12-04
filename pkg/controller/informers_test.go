package controller

import (
	"container/list"
	"context"
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sync"
)

var _ = Describe("Informers Tests", func() {
	var mockCtlr *mockController
	namespace := "default"

	BeforeEach(func() {
		mockCtlr = newMockController()
	})

	Describe("Custom Resource Informers", func() {
		BeforeEach(func() {
			mockCtlr.managedResources.ManageCustomResources = true
			mockCtlr.namespaces = make(map[string]bool)
			mockCtlr.namespaces["default"] = true
			mockCtlr.clientsets.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.clientsets.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.nsInformers = make(map[string]*NSInformer)
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			mockCtlr.resourceSelectorConfig.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		})
		It("Resource Informers", func() {
			err := mockCtlr.addNamespacedInformers(namespace, false)
			Expect(err).To(BeNil(), "Informers Creation Failed")

			crInf, found := mockCtlr.getNamespacedCRInformer(namespace)
			Expect(crInf).ToNot(BeNil(), "Finding Informer Failed")
			Expect(found).To(BeTrue(), "Finding Informer Failed")
		})

		It("Namespace Informer", func() {
			namespaceSelector, err := createLabelSelector("app=test")
			Expect(namespaceSelector).ToNot(BeNil(), "Failed to Create Label Selector")
			Expect(err).To(BeNil(), "Failed to Create Label Selector")
			err = mockCtlr.createNamespaceLabeledInformer("app=test")
			Expect(err).To(BeNil(), "Failed to Create Namespace Informer")
		})
	})

	Describe("Custom Resource Queueing", func() {
		BeforeEach(func() {
			mockCtlr.managedResources.ManageCustomResources = true
			mockCtlr.namespaces = make(map[string]bool)
			mockCtlr.namespaces["default"] = true
			mockCtlr.clientsets.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.clientsets.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.nsInformers = make(map[string]*NSInformer)
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			mockCtlr.resourceSelectorConfig.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
			mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
				workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")
			mockCtlr.resources = NewResourceStore()
			mockCtlr.resources.ltmConfig = make(map[string]*PartitionConfig, 0)
			mockCtlr.requestQueue = &requestQueue{sync.Mutex{}, list.New()}
			mockCtlr.bigIpMap = make(BigIpMap)
			mockCtlr.bigIpMap[cisapiv1.BigIpConfig{BigIpLabel: "bigip1", DefaultPartition: "test"}] = BigIpResourceConfig{}
		})
		AfterEach(func() {
			mockCtlr.resourceQueue.ShutDown()
		})
		It("VirtualServer", func() {
			vs := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "1.2.3.4",
				})
			mockCtlr.enqueueVirtualServer(vs)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New VS  Failed")

			newVS := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "1.2.3.5",
					Partition:            "dev",
				})
			zero := 0
			partition := mockCtlr.getPartitionForBIGIP("")
			mockCtlr.resources.ltmConfig[partition] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			mockCtlr.enqueueUpdatedVirtualServer(vs, newVS)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")
			Expect(*mockCtlr.resources.ltmConfig[partition].Priority).To(BeEquivalentTo(1), "Priority Not Updated")
			delete(mockCtlr.resources.ltmConfig, partition)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")

			mockCtlr.enqueueDeletedVirtualServer(newVS)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted VS  Failed")

			// Check if correct event in set while enqueuing vs
			// Create updated VS CR
			updatedVS1 := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "1.2.3.5",
					Partition:            "dev",
					SNAT:                 "none",
				})
			mockCtlr.enqueueUpdatedVirtualServer(newVS, updatedVS1)
			// With a change of snat in VS CR, an update event should be enqueued
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")
			rKey := key.(*rqKey)
			Expect(rKey).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(rKey.event).To(Equal(Update), "Incorrect event set")

			// When VirtualServerAddress is updated then it should enqueue both delete & create events
			updatedVS2 := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "5.6.7.8",
					SNAT:                 "none",
				})
			mockCtlr.enqueueUpdatedVirtualServer(updatedVS1, updatedVS2)
			key, quit = mockCtlr.resourceQueue.Get()
			// Delete event
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")
			rKey = key.(*rqKey)
			Expect(rKey).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(rKey.event).To(Equal(Delete), "Incorrect event set")
			// Create event
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")
			rKey = key.(*rqKey)
			Expect(rKey).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(rKey.event).To(Equal(Create), "Incorrect event set")

			mockCtlr.enqueueVirtualServer(vs)
			Expect(mockCtlr.processResources()).To(Equal(true))

			// Verify VS status update event is not queued for processing
			updatedStatusVS := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "5.6.7.8",
					SNAT:                 "none",
				})
			updatedStatusVS.Status.StatusOk = "OK"
			mockCtlr.enqueueUpdatedVirtualServer(updatedVS2, updatedStatusVS)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(0), "VS status update should be skipped")

			// Verify VS Label update event is queued for processing
			updatedLabelVS := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "5.6.7.8",
					SNAT:                 "none",
				})
			labels := make(map[string]string)
			labels["f5cr"] = "false"
			updatedLabelVS.Labels = labels
			mockCtlr.enqueueUpdatedVirtualServer(updatedStatusVS, updatedLabelVS)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(1), "VS label update should not be skipped")
		})

		It("TLS Profile", func() {
			tlsp := test.NewTLSProfile(
				"SampleTLS",
				namespace,
				cisapiv1.TLSProfileSpec{
					Hosts: []string{"test.com", "prod.com"},
					TLS: cisapiv1.TLS{
						Termination: "edge",
						ClientSSL:   "2359qhfniqlur89phuf;rhfi",
					},
				})
			mockCtlr.enqueueTLSProfile(tlsp, Create)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue TLS Failed")
			Expect(quit).To(BeFalse(), "Enqueue TLS  Failed")

			mockCtlr.enqueueTLSProfile(tlsp, Create)
			Expect(mockCtlr.processResources()).To(Equal(true))
		})

		It("TransportServer", func() {
			ts := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					SNAT:                 "auto",
					VirtualServerAddress: "1.2.3.4",
				})
			mockCtlr.enqueueTransportServer(ts)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New TS  Failed")

			newTS := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					SNAT:                 "auto",
					VirtualServerAddress: "1.2.3.5",
				})
			mockCtlr.enqueueUpdatedTransportServer(ts, newTS)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated TS  Failed")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated TS  Failed")

			mockCtlr.enqueueDeletedTransportServer(newTS)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted TS  Failed")

			mockCtlr.enqueueTransportServer(ts)
			Expect(mockCtlr.processResources()).To(Equal(true))
			tsWithPartition := newTS.DeepCopy()
			tsWithPartition.Spec.Partition = "dev"
			zero := 0
			partition := mockCtlr.getPartitionForBIGIP("")
			mockCtlr.resources.ltmConfig[partition] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			mockCtlr.enqueueUpdatedTransportServer(newTS, tsWithPartition)
			Expect(*mockCtlr.resources.ltmConfig[partition].Priority).To(BeEquivalentTo(1), "Priority Not Updated")

			// Verify TS status update event is not queued for processing
			queueLen := mockCtlr.resourceQueue.Len()
			updatedStatusTS := tsWithPartition.DeepCopy()
			updatedStatusTS.Status.StatusOk = "Ok"
			mockCtlr.enqueueUpdatedTransportServer(tsWithPartition, updatedStatusTS)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(queueLen), "TS status update should be skipped")

			// Verify TS Label update event is queued for processing
			updatedLabelTS := updatedStatusTS.DeepCopy()
			labels := make(map[string]string)
			labels["f5cr"] = "false"
			updatedLabelTS.Labels = labels
			mockCtlr.enqueueUpdatedTransportServer(updatedStatusTS, updatedLabelTS)
			Expect(mockCtlr.resourceQueue.Len()).To(Equal(queueLen+1), "TS label update should not be skipped")

		})

		It("IngressLink", func() {
			label1 := make(map[string]string)
			label1["app"] = "ingresslink"

			selctor := &metav1.LabelSelector{
				MatchLabels: label1,
			}

			iRules := []string{"dummyiRule"}
			il := test.NewIngressLink(
				"SampleIL",
				namespace,
				"1",
				cisapiv1.IngressLinkSpec{
					VirtualServerAddress: "1.2.3.4",
					Selector:             selctor,
					IRules:               iRules,
				},
			)
			mockCtlr.enqueueIngressLink(il)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue New IL  Failed")

			newIL := test.NewIngressLink(
				"SampleIL",
				namespace,
				"1",
				cisapiv1.IngressLinkSpec{
					VirtualServerAddress: "1.2.3.5",
					Selector:             selctor,
					IRules:               iRules,
				},
			)
			mockCtlr.enqueueUpdatedIngressLink(il, newIL)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IL  Failed")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IL  Failed")

			mockCtlr.enqueueDeletedIngressLink(newIL)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted IL  Failed")

			mockCtlr.enqueueIngressLink(il)
			Expect(mockCtlr.processResources()).To(Equal(true))

			ilWithPartition := newIL.DeepCopy()
			ilWithPartition.Spec.Partition = "dev"
			zero := 0
			partition := mockCtlr.getPartitionForBIGIP("")
			mockCtlr.resources.ltmConfig[partition] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
			mockCtlr.enqueueUpdatedIngressLink(newIL, ilWithPartition)
			Expect(*mockCtlr.resources.ltmConfig[partition].Priority).To(BeEquivalentTo(1), "Priority Not Updated")

		})

		It("ExternalDNS", func() {
			edns := test.NewExternalDNS(
				"SampleEDNS",
				namespace,
				cisapiv1.ExternalDNSSpec{
					DomainName:        "test.com",
					LoadBalanceMethod: "round-robin",
				})
			mockCtlr.enqueueExternalDNS(edns)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New EDNS  Failed")

			newEDNS := test.NewExternalDNS(
				"SampleEDNS",
				namespace,
				cisapiv1.ExternalDNSSpec{
					DomainName:        "prod.com",
					LoadBalanceMethod: "round-robin",
				})
			mockCtlr.enqueueUpdatedExternalDNS(edns, newEDNS)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated EDNS  Failed")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated EDNS  Failed")

			mockCtlr.enqueueDeletedExternalDNS(newEDNS)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted EDNS  Failed")

			mockCtlr.TeemData = &teem.TeemsData{
				ResourceType: teem.ResourceTypes{
					RouteGroups:  make(map[string]int),
					NativeRoutes: make(map[string]int),
					ExternalDNS:  make(map[string]int),
				},
			}
			mockCtlr.AgentMap["bigip1"] = &RequestHandler{
				PostManager: &PostManager{
					postChan: make(chan agentConfig, 1),
					PostParams: PostParams{
						CMURL: "10.10.10.1",
					},
				},
			}

			mockCtlr.requestQueue = &requestQueue{sync.Mutex{}, list.New()}

			mockCtlr.enqueueExternalDNS(edns)
			Expect(mockCtlr.processResources()).To(Equal(true))
		})

		It("Policy", func() {
			plc := test.NewPolicy(
				"SamplePolicy",
				namespace,
				cisapiv1.PolicySpec{})
			mockCtlr.enqueuePolicy(plc, Create)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Policy Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Policy  Failed")

			newPlc := test.NewPolicy(
				"SamplePolicy2",
				namespace,
				cisapiv1.PolicySpec{})
			mockCtlr.enqueueDeletedPolicy(newPlc)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Policy Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Policy  Failed")

			mockCtlr.enqueuePolicy(plc, Create)
			Expect(mockCtlr.processResources()).To(Equal(true))
		})
		It("Primary Cluster Down Event", func() {
			mockCtlr.enqueuePrimaryClusterProbeEvent()
			key, _ := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Primary cluster event key not enqueued")
		})

		It("Service", func() {
			// setting teem data
			mockCtlr.TeemData = &teem.TeemsData{
				ResourceType: teem.ResourceTypes{
					IPAMSvcLB:   make(map[string]int),
					IngressLink: make(map[string]int),
				},
			}
			svc := test.NewService(
				"SampleSVC",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				nil,
			)
			mockCtlr.enqueueService(svc, "")
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Service  Failed")

			newSVC := test.NewService(
				"SampleSVC",
				"2",
				namespace,
				v1.ServiceTypeNodePort,
				nil,
			)
			mockCtlr.enqueueUpdatedService(svc, newSVC, "")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Service  Failed")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Service  Failed")

			mockCtlr.enqueueDeletedService(newSVC, "")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted Service  Failed")

			mockCtlr.enqueueService(svc, "")
			Expect(mockCtlr.processResources()).To(Equal(true))

			svc.Name = "kube-dns"
			mockCtlr.enqueueDeletedService(svc, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Service")

			mockCtlr.enqueueUpdatedService(svc, svc, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Service")

			mockCtlr.enqueueService(svc, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Service")
		})

		It("Endpoints", func() {
			eps := test.NewEndpoints(
				"SampleSVC",
				"1",
				"worker1",
				namespace,
				[]string{"10.20.30.40"},
				nil,
				[]v1.EndpointPort{
					{
						Name: "port1",
						Port: 80,
					},
				},
			)
			mockCtlr.enqueueEndpoints(eps, Create, "")
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Endpoints Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Endpoints  Failed")

			mockCtlr.enqueueEndpoints(eps, Create, "")
			Expect(mockCtlr.processResources()).To(Equal(true))

			eps.Name = "kube-dns"
			mockCtlr.enqueueEndpoints(eps, Create, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Endpoint")
		})

		It("Pod", func() {
			label1 := make(map[string]string)
			label1["app"] = "sampleSVC"
			pod := test.NewPod(
				"SampleSVC",
				namespace,
				80,
				label1,
			)
			mockCtlr.enqueuePod(pod, "")
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Pod Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Pod Failed")

			mockCtlr.enqueueDeletedPod(pod, "")
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted Pod Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted Pod Failed")

			mockCtlr.enqueuePod(pod, "")
			Expect(mockCtlr.processResources()).To(Equal(true))

			pod.Labels["app"] = "kube-dns"
			mockCtlr.enqueuePod(pod, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Pod")
			// Verify CIS handles DeletedFinalStateUnknown pod object
			mockCtlr.enqueueDeletedPod(cache.DeletedFinalStateUnknown{Key: pod.Namespace + "/" + pod.Name, Obj: pod}, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Pod")

			// Verify CIS handles DeletedFinalStateUnknown pod object in case it doesn't have any pod Obj referenced
			mockCtlr.enqueueDeletedPod(cache.DeletedFinalStateUnknown{Key: pod.Namespace + "/" + pod.Name, Obj: nil}, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Pod")

			// Verify CIS handles scenarios when unexpected objects are received in pod deletion event
			mockCtlr.enqueueDeletedPod(nil, "")
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Invalid Pod")

		})

		It("Secret", func() {
			secret := test.NewSecret(
				"SampleSecret",
				namespace,
				"testcert",
				"testkey",
			)
			mockCtlr.enqueueSecret(secret, Create)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Secret Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Secret Failed")

			mockCtlr.enqueueSecret(secret, Create)
			Expect(mockCtlr.processResources()).To(Equal(true))
		})

		It("Namespace", func() {
			labels := make(map[string]string)
			labels["app"] = "test"
			ns := test.NewNamespace(
				"SampleNS",
				"1",
				labels,
			)
			mockCtlr.enqueueNamespace(ns)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Namespace Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Namespace  Failed")

			mockCtlr.enqueueDeletedNamespace(ns)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted Namespace Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted Namespace  Failed")

			//mockCtlr.enqueueNamespace(ns)
			//Expect(mockCtlr.processResources()).To(Equal(true))
		})

		It("IPAM", func() {
			mockCtlr.ipamCR = "default/SampleIPAM"

			hostSpec := &ficV1.HostSpec{
				Host:      "test.com",
				IPAMLabel: "test",
			}
			ipam := test.NewIPAM(
				"SampleIPAM",
				namespace,
				ficV1.IPAMSpec{
					HostSpecs: []*ficV1.HostSpec{hostSpec},
				},
				ficV1.IPAMStatus{},
			)
			mockCtlr.enqueueIPAM(ipam)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue New IPAM  Failed")

			ipSpec := &ficV1.IPSpec{
				Host:      "test.com",
				IPAMLabel: "test",
				IP:        "1.2.3.4",
			}
			newIPAM := test.NewIPAM(
				"SampleIPAM",
				namespace,
				ficV1.IPAMSpec{
					HostSpecs: []*ficV1.HostSpec{hostSpec},
				},
				ficV1.IPAMStatus{
					IPStatus: []*ficV1.IPSpec{ipSpec},
				},
			)
			mockCtlr.enqueueUpdatedIPAM(ipam, newIPAM)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IPAM  Failed")

			mockCtlr.enqueueDeletedIPAM(newIPAM)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted IPAM  Failed")

			mockCtlr.enqueueIPAM(ipam)
			Expect(mockCtlr.processResources()).To(Equal(true))

			newIPAM.Namespace = "test"
			mockCtlr.enqueueDeletedIPAM(newIPAM)
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Enqueue Deleted IPAM Failed")
			mockCtlr.enqueueIPAM(newIPAM)
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Enqueue Deleted IPAM Failed")
			mockCtlr.enqueueUpdatedIPAM(newIPAM, newIPAM)
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Enqueue Deleted IPAM Failed")
			Expect(mockCtlr.getEventHandlerForIPAM()).ToNot(BeNil())
		})
	})

	Describe("Common Resource Informers", func() {
		BeforeEach(func() {
			mockCtlr.managedResources.ManageRoutes = true
			mockCtlr.namespaces = make(map[string]bool)
			mockCtlr.namespaces["default"] = true
			mockCtlr.clientsets.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.clientsets.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.nrInformers = make(map[string]*NRInformer)
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
			mockCtlr.resources = NewResourceStore()
		})
		It("Resource Informers", func() {
			err := mockCtlr.addNamespacedInformers(namespace, false)
			Expect(err).To(BeNil(), "Informers Creation Failed")
			comInf, found := mockCtlr.getNamespacedCommonInformer(namespace)
			Expect(comInf).ToNot(BeNil(), "Finding Informer Failed")
			Expect(found).To(BeTrue(), "Finding Informer Failed")
			mockCtlr.comInformers[""] = mockCtlr.newNamespacedCommonResourceInformer("")
			comInf, found = mockCtlr.getNamespacedCommonInformer(namespace)
			Expect(comInf).ToNot(BeNil(), "Finding Informer Failed")
			Expect(found).To(BeTrue(), "Finding Informer Failed")
			nsObj := v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			mockCtlr.clientsets.kubeClient.CoreV1().Namespaces().Create(context.TODO(), &nsObj, metav1.CreateOptions{})
			ns := mockCtlr.getWatchingNamespaces()
			Expect(ns).ToNot(BeNil())
			mockCtlr.nrInformers[""] = mockCtlr.newNamespacedNativeResourceInformer("")
			nrInr, found := mockCtlr.getNamespacedNativeInformer(namespace)
			Expect(nrInr).ToNot(BeNil(), "Finding Informer Failed")
			Expect(found).To(BeTrue(), "Finding Informer Failed")
		})
	})

	Describe("Native Resource Queueing", func() {
		BeforeEach(func() {
			mockCtlr.managedResources.ManageRoutes = true
			mockCtlr.namespaces = make(map[string]bool)
			mockCtlr.namespaces["default"] = true
			mockCtlr.clientsets.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.clientsets.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.nrInformers = make(map[string]*NRInformer)
			mockCtlr.comInformers = make(map[string]*CommonInformer)
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
			mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
				workqueue.DefaultControllerRateLimiter(), "native-resource-controller")
			mockCtlr.resources = NewResourceStore()
		})
		AfterEach(func() {
			mockCtlr.resourceQueue.ShutDown()
		})

		It("Route", func() {
			rt := test.NewRoute(
				"sampleroute",
				"v1",
				namespace,
				routeapi.RouteSpec{
					Host: "foo.com",
					Path: "bar",
				},
				nil)
			mockCtlr.enqueueRoute(rt, Create)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Route Failed")
			Expect(quit).To(BeFalse(), "Enqueue Route  Failed")

			mockCtlr.enqueueRoute(rt, Create)
			Expect(mockCtlr.processResources()).To(Equal(true))

			rtNew := rt.DeepCopy()
			mockCtlr.enqueueUpdatedRoute(rt, rtNew)
			Expect(mockCtlr.resourceQueue.Len()).To(BeEquivalentTo(0), "Duplicate Route Enqueued")

			rtNew.Spec.Host = "foo1.com"
			mockCtlr.enqueueUpdatedRoute(rt, rtNew)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Update Route Failed")
			Expect(quit).To(BeFalse(), "Enqueue Update Route  Failed")
			//mockCtlr.enqueueDeletedRoute(rt)
			//key, quit = mockCtlr.resourceQueue.Get()
			//Expect(key).ToNot(BeNil(), "Enqueue Route Failed")
			//Expect(quit).To(BeFalse(), "Enqueue Route  Failed")
		})

		It("Global ConfigCR", func() {
			configCRName := "sampleConfigCR"
			mockCtlr.CISConfigCRKey = namespace + "/" + configCRName
			configCR := test.NewConfigCR(
				configCRName,
				namespace,
				cisapiv1.DeployConfigSpec{},
			)
			mockCtlr.enqueueConfigCR(configCR, Create)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Global ConfigCR Failed")
			Expect(quit).To(BeFalse(), "Enqueue Global ConfigCR  Failed")
			updatedConfigCR := test.NewConfigCR(
				configCRName,
				namespace,
				cisapiv1.DeployConfigSpec{
					ExtendedSpec: cisapiv1.ExtendedSpec{
						HAMode: StandAloneCIS,
					},
				},
			)
			mockCtlr.enqueueUpdatedConfigCR(configCR, updatedConfigCR)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Global ConfigCR Failed")
			Expect(quit).To(BeFalse(), "Enqueue Global ConfigCR  Failed")

			mockCtlr.enqueueConfigCR(configCR, Delete)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Delete Global ConfigCR Failed")
			Expect(quit).To(BeFalse(), "Enqueue Delete Global ConfigCR  Failed")

			mockCtlr.enqueueDeletedConfigCR(configCR)
			key, quit = mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Delete Global ConfigCR Failed")
		})

		It("Local ConfigCR", func() {
			configCR := test.NewConfigCR(
				"sampleConfigCR",
				namespace,
				cisapiv1.DeployConfigSpec{},
			)
			configCR.SetLabels(map[string]string{
				"f5nr": "true",
			})
			mockCtlr.enqueueConfigCR(configCR, Update)
			key, quit := mockCtlr.resourceQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Local ConfigCR Failed")
			Expect(quit).To(BeFalse(), "Enqueue Local ConfigCR  Failed")
		})

	})

})
