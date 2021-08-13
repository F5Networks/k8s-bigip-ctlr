package crmanager

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
	var mockCRM *mockCRManager
	namespace := "default"

	BeforeEach(func() {
		mockCRM = newMockCRManager()
	})

	Describe("Informers", func() {
		BeforeEach(func() {
			mockCRM.namespaces = make(map[string]bool)
			mockCRM.namespaces["default"] = true
			mockCRM.kubeCRClient = crdfake.NewSimpleClientset()
			mockCRM.kubeClient = k8sfake.NewSimpleClientset()
			mockCRM.crInformers = make(map[string]*CRInformer)
			mockCRM.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		})
		It("Resource Informers", func() {
			err := mockCRM.addNamespacedInformer(namespace)
			Expect(err).To(BeNil(), "Informers Creation Failed")

			crInf, found := mockCRM.getNamespacedInformer(namespace)
			Expect(crInf).ToNot(BeNil(), "Finding Informer Failed")
			Expect(found).To(BeTrue(), "Finding Informer Failed")
		})

		It("Namespace Informer", func() {
			namespaceSelector, err := createLabelSelector("app=test")
			Expect(namespaceSelector).ToNot(BeNil(), "Failed to Create Label Selector")
			Expect(err).To(BeNil(), "Failed to Create Label Selector")

			err = mockCRM.createNamespaceLabeledInformer(namespaceSelector)
			Expect(err).To(BeNil(), "Failed to Create Namespace Informer")
		})
	})

	Describe("Queueing", func() {
		BeforeEach(func() {
			mockCRM.rscQueue = workqueue.NewNamedRateLimitingQueue(
				workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")

		})
		AfterEach(func() {
			mockCRM.rscQueue.ShutDown()
		})
		It("VirtualServer", func() {
			vs := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "1.2.3.4",
				})
			mockCRM.enqueueVirtualServer(vs)
			key, quit := mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New VS  Failed")

			newVS := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.com",
					VirtualServerAddress: "1.2.3.5",
				})
			mockCRM.enqueueUpdatedVirtualServer(vs, newVS)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated VS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated VS  Failed")

			mockCRM.enqueueDeletedVirtualServer(newVS)
			key, quit = mockCRM.rscQueue.Get()
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
			mockCRM.enqueueTLSServer(tlsp)
			key, quit := mockCRM.rscQueue.Get()
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
			mockCRM.enqueueTransportServer(ts)
			key, quit := mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New TS  Failed")

			newTS := test.NewTransportServer(
				"SampleTS",
				namespace,
				cisapiv1.TransportServerSpec{
					SNAT:                 "auto",
					VirtualServerAddress: "1.2.3.5",
				})
			mockCRM.enqueueUpdatedTransportServer(ts, newTS)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated TS  Failed")
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated TS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated TS  Failed")

			mockCRM.enqueueDeletedTransportServer(newTS)
			key, quit = mockCRM.rscQueue.Get()
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
			mockCRM.enqueueIngressLink(il)
			key, quit := mockCRM.rscQueue.Get()
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
			mockCRM.enqueueUpdatedIngressLink(il, newIL)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IL  Failed")
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IL Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IL  Failed")

			mockCRM.enqueueDeletedIngressLink(newIL)
			key, quit = mockCRM.rscQueue.Get()
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
			mockCRM.enqueueExternalDNS(edns)
			key, quit := mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue New EDNS  Failed")

			newEDNS := test.NewExternalDNS(
				"SampleEDNS",
				namespace,
				cisapiv1.ExternalDNSSpec{
					DomainName:        "prod.com",
					LoadBalanceMethod: "round-robin",
				})
			mockCRM.enqueueUpdatedExternalDNS(edns, newEDNS)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated EDNS  Failed")
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated EDNS Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated EDNS  Failed")

			mockCRM.enqueueDeletedExternalDNS(newEDNS)
			key, quit = mockCRM.rscQueue.Get()
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
			mockCRM.enqueueService(svc)
			key, quit := mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Service  Failed")

			newSVC := test.NewService(
				"SampleSVC",
				"2",
				namespace,
				v1.ServiceTypeNodePort,
				nil,
			)
			mockCRM.enqueueUpdatedService(svc, newSVC)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Service  Failed")
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated Service Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated Service  Failed")

			mockCRM.enqueueDeletedService(newSVC)
			key, quit = mockCRM.rscQueue.Get()
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
			mockCRM.enqueueEndpoints(eps)
			key, quit := mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Endpoints Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Endpoints  Failed")
		})

		It("Namespace", func() {
			labels := make(map[string]string)
			labels["app"] = "test"
			ns := test.NewNamespace(
				"SampleNS",
				"1",
				labels,
			)
			mockCRM.enqueueNamespace(ns)
			key, quit := mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue New Namespace Failed")
			Expect(quit).To(BeFalse(), "Enqueue New Namespace  Failed")

			mockCRM.enqueueDeletedNamespace(ns)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted Namespace Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted Namespace  Failed")
		})

		It("IPAM", func() {
			mockCRM.ipamCR = "default/SampleIPAM"

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
			mockCRM.enqueueIPAM(ipam)
			key, quit := mockCRM.rscQueue.Get()
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
			mockCRM.enqueueUpdatedIPAM(ipam, newIPAM)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Updated IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue Updated IPAM  Failed")

			mockCRM.enqueueDeletedIPAM(newIPAM)
			key, quit = mockCRM.rscQueue.Get()
			Expect(key).ToNot(BeNil(), "Enqueue Deleted IPAM Failed")
			Expect(quit).To(BeFalse(), "Enqueue Deleted IPAM  Failed")
		})
	})
})
