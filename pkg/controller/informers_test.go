package controller

import (
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned/fake"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
)

var _ = Describe("Informers Tests", func() {
	var mockCtlr *mockController
	namespace := "default"

	BeforeEach(func() {
		mockCtlr = newMockController()
	})

	Describe("Informers", func() {
		BeforeEach(func() {
			mockCtlr.namespaces = make(map[string]bool)
			mockCtlr.namespaces["default"] = true
			mockCtlr.kubeCRClient = crdfake.NewSimpleClientset()
			mockCtlr.kubeClient = k8sfake.NewSimpleClientset()
			mockCtlr.crInformers = make(map[string]*CRInformer)
			mockCtlr.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		})
		It("Resource Informers", func() {
			err := mockCtlr.addNamespacedInformer(namespace)
			Expect(err).To(BeNil(), "Informers Creation Failed")

			crInf, found := mockCtlr.getNamespacedInformer(namespace)
			Expect(crInf).ToNot(BeNil(), "Finding Informer Failed")
			Expect(found).To(BeTrue(), "Finding Informer Failed")
		})

		It("Namespace Informer", func() {
			namespaceSelector, err := createLabelSelector("app=test")
			Expect(namespaceSelector).ToNot(BeNil(), "Failed to Create Label Selector")
			Expect(err).To(BeNil(), "Failed to Create Label Selector")

			err = mockCtlr.createNamespaceLabeledInformer(namespaceSelector)
			Expect(err).To(BeNil(), "Failed to Create Namespace Informer")
		})
	})

	Describe("Queueing", func() {
		BeforeEach(func() {
			mockCtlr.rscQueue = workqueue.NewNamedRateLimitingQueue(
				workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")

		})
		AfterEach(func() {
			mockCtlr.rscQueue.ShutDown()
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
			key, quit := mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New VS  Failed")

			newVS := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "1.2.3.5",
				})
			mockCtlr.enqueueUpdatedVirtualServer(vs, newVS)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")

			mockCtlr.enqueueDeletedVirtualServer(newVS)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted VS  Failed")
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
			mockCtlr.enqueueTLSServer(tlsp)
			key, quit := mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue TLS Failed")
			Expect(quit).To(BeFalse(), "Enqueue TLS  Failed")
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
			key, quit := mockCtlr.rscQueue.Get()
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
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated TS  Failed")
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated TS  Failed")

			mockCtlr.enqueueDeletedTransportServer(newTS)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted TS  Failed")
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
			key, quit := mockCtlr.rscQueue.Get()
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
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IL  Failed")
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IL  Failed")

			mockCtlr.enqueueDeletedIngressLink(newIL)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted IL  Failed")
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
			key, quit := mockCtlr.rscQueue.Get()
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
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated EDNS  Failed")
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated EDNS  Failed")

			mockCtlr.enqueueDeletedExternalDNS(newEDNS)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted EDNS  Failed")
		})

		It("Service", func() {
			svc := test.NewService(
				"SampleSVC",
				"1",
				namespace,
				v1.ServiceTypeLoadBalancer,
				nil,
			)
			mockCtlr.enqueueService(svc)
			key, quit := mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Service  Failed")

			newSVC := test.NewService(
				"SampleSVC",
				"2",
				namespace,
				v1.ServiceTypeNodePort,
				nil,
			)
			mockCtlr.enqueueUpdatedService(svc, newSVC)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Service  Failed")
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Service  Failed")

			mockCtlr.enqueueDeletedService(newSVC)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted Service  Failed")
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
			mockCtlr.enqueueEndpoints(eps)
			key, quit := mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Endpoints Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Endpoints  Failed")
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
			mockCtlr.enqueuePod(pod)
			key, quit := mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Pod Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Pod Failed")
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
			key, quit := mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Namespace Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Namespace  Failed")

			mockCtlr.enqueueDeletedNamespace(ns)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted Namespace Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted Namespace  Failed")
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
			key, quit := mockCtlr.rscQueue.Get()
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
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IPAM  Failed")

			mockCtlr.enqueueDeletedIPAM(newIPAM)
			key, quit = mockCtlr.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted IPAM  Failed")
		})
	})
})
