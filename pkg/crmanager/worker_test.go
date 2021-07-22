package crmanager

import (
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned/fake"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"reflect"
	"sort"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Worker Tests", func() {
	var mockCRM *mockCRManager
	var vrt1 *cisapiv1.VirtualServer
	var svc1 *v1.Service
	namespace := "default"

	BeforeEach(func() {
		mockCRM = newMockCRManager()
		svc1 = test.NewService(
			"svc1",
			"1",
			namespace,
			v1.ServiceTypeClusterIP,
			[]v1.ServicePort{
				{
					Port: 80,
					Name: "port0",
				},
			},
		)

		vrt1 = test.NewVirtualServer(
			"SampleVS",
			namespace,
			cisapiv1.VirtualServerSpec{
				Host:                   "test.com",
				VirtualServerAddress:   "1.2.3.4",
				IPAMLabel:              "",
				VirtualServerName:      "",
				VirtualServerHTTPPort:  0,
				VirtualServerHTTPSPort: 0,
				Pools: []cisapiv1.Pool{
					cisapiv1.Pool{
						Path:    "/path",
						Service: "svc1",
					},
				},
				TLSProfileName:   "",
				HTTPTraffic:      "",
				SNAT:             "",
				WAF:              "",
				RewriteAppRoot:   "",
				AllowVLANs:       nil,
				IRules:           nil,
				ServiceIPAddress: nil,
			})
		mockCRM.kubeCRClient = crdfake.NewSimpleClientset(vrt1)
		mockCRM.kubeClient = k8sfake.NewSimpleClientset(svc1)
		mockCRM.crInformers = make(map[string]*CRInformer)
		mockCRM.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		_ = mockCRM.addNamespacedInformer("default")
		mockCRM.resources = NewResources()
		mockCRM.crInformers["default"].vsInformer = cisinfv1.NewFilteredVirtualServerInformer(
			mockCRM.kubeCRClient,
			namespace,
			0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(options *metav1.ListOptions) {
				options.LabelSelector = mockCRM.resourceSelector.String()
			},
		)
	})

	Describe("Validating Ingress link functions", func() {
		var namespace string
		BeforeEach(func() {
			namespace = "nginx-ingress"
		})

		It("Validating filterIngressLinkForService filters the correct ingresslink resource", func() {
			fooPorts := []v1.ServicePort{
				{
					Port: 8080,
					Name: "port0",
				},
			}
			foo := test.NewService("foo", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
			label1 := make(map[string]string)
			label2 := make(map[string]string)
			label1["app"] = "ingresslink"
			label2["app"] = "dummy"
			foo.ObjectMeta.Labels = label1
			var (
				selctor = &metav1.LabelSelector{
					MatchLabels: label1,
				}
			)
			var iRules []string
			IngressLink1 := test.NewIngressLink("ingresslink1", namespace, "1",
				cisapiv1.IngressLinkSpec{
					VirtualServerAddress: "",
					Selector:             selctor,
					IRules:               iRules,
				})
			IngressLink2 := test.NewIngressLink("ingresslink2", "dummy", "1",
				cisapiv1.IngressLinkSpec{
					VirtualServerAddress: "",
					Selector:             selctor,
					IRules:               iRules,
				})
			var IngressLinks []*cisapiv1.IngressLink
			IngressLinks = append(IngressLinks, IngressLink1, IngressLink2)
			ingresslinksForService := filterIngressLinkForService(IngressLinks, foo)
			Expect(ingresslinksForService[0]).To(Equal(IngressLink1), "Should return the Ingresslink1 object")
		})
		It("Validating service are sorted properly", func() {
			fooPorts := []v1.ServicePort{
				{
					Port: 8080,
					Name: "port0",
				},
			}
			foo := test.NewService("foo", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
			bar := test.NewService("bar", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
			bar.ObjectMeta.CreationTimestamp = metav1.NewTime(time.Now())
			time.Sleep(10 * time.Millisecond)
			foo.ObjectMeta.CreationTimestamp = metav1.NewTime(time.Now())
			var services Services
			services = append(services, *foo, *bar)
			sort.Sort(services)
			Expect(services[0].Name).To(Equal("bar"), "Should return the service name as bar")
		})
	})

	Describe("IPAM", func() {
		BeforeEach(func() {
			mockCRM.Agent = &Agent{
				PostManager: &PostManager{
					PostParams: PostParams{
						BIGIPURL: "10.10.10.1",
					},
				},
			}
			mockCRM.ipamCli = ipammachinery.NewFakeIPAMClient(nil, nil, nil)
		})

		It("Create IPAM Custom Resource", func() {
			err := mockCRM.createIPAMResource()
			Expect(err).To(BeNil(), "Failed to Create IPAM Custom Resource")
			err = mockCRM.createIPAMResource()
			Expect(err).To(BeNil(), "Failed to Create IPAM Custom Resource")

		})

		It("Get IPAM Resource", func() {
			_ = mockCRM.createIPAMResource()
			ipamCR := mockCRM.getIPAMCR()
			Expect(ipamCR).NotTo(BeNil(), "Failed to GET IPAM")
			mockCRM.ipamCR = mockCRM.ipamCR + "invalid"
			ipamCR = mockCRM.getIPAMCR()
			Expect(ipamCR).To(BeNil(), "Failed to GET IPAM")
			mockCRM.ipamCR = mockCRM.ipamCR + "/invalid"
			ipamCR = mockCRM.getIPAMCR()
			Expect(ipamCR).To(BeNil(), "Failed to GET IPAM")
		})

		It("Request IP Address", func() {

			testSpec := make(map[string]string)
			testSpec["host"] = "foo.com"
			testSpec["key"] = "ns/name"

			for sp, val := range testSpec {
				_ = mockCRM.createIPAMResource()
				var key, host, errHint string
				if sp == "host" {
					host = val
					key = ""
					errHint = "Host: "
				} else {
					key = val
					host = ""
					errHint = "Key: "
				}

				ip := mockCRM.requestIP("test", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				ipamCR := mockCRM.getIPAMCR()
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(1), errHint+"Invalid number of Host Specs")
				Expect(ipamCR.Spec.HostSpecs[0].IPAMLabel).To(Equal("test"), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Host).To(Equal(host), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Key).To(Equal(key), errHint+"IPAM Request Failed")

				ip = mockCRM.requestIP("", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				newIPAMCR := mockCRM.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")

				ip = mockCRM.requestIP("test", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				newIPAMCR = mockCRM.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")

				ip = mockCRM.requestIP("test", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				newIPAMCR = mockCRM.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")

				ipamCR.Status.IPStatus = []*ficV1.IPSpec{
					{
						IPAMLabel: "test",
						Host:      host,
						IP:        "10.10.10.1",
						Key:       key,
					},
				}
				ipamCR, _ = mockCRM.ipamCli.Update(ipamCR)
				ip = mockCRM.requestIP("test", host, key)
				Expect(ip).To(Equal("10.10.10.1"), errHint+"Invalid IP")
				ipamCR = mockCRM.getIPAMCR()
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(1), errHint+"Invalid number of Host Specs")
				Expect(ipamCR.Spec.HostSpecs[0].IPAMLabel).To(Equal("test"), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Host).To(Equal(host), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Key).To(Equal(key), errHint+"IPAM Request Failed")

				ip = mockCRM.requestIP("dev", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				ipamCR = mockCRM.getIPAMCR()
				// TODO: The expected number of Specs is 1. After the bug gest fixed update this to 1 from 2.
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(2), errHint+"Invalid number of Host Specs")

				ip = mockCRM.requestIP("test", "", "")
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				newIPAMCR = mockCRM.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")
			}
		})

		It("Release IP Addresss", func() {
			testSpec := make(map[string]string)
			testSpec["host"] = "foo.com"
			testSpec["key"] = "ns/name"

			for sp, val := range testSpec {
				_ = mockCRM.createIPAMResource()
				var key, host, errHint string
				if sp == "host" {
					host = val
					key = ""
					errHint = "Host: "
				} else {
					key = val
					host = ""
					errHint = "Key: "
				}

				ip := mockCRM.releaseIP("", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Unexpected IP address released")

				ipamCR := mockCRM.getIPAMCR()
				ipamCR.Spec.HostSpecs = []*ficV1.HostSpec{
					{
						IPAMLabel: "test",
						Host:      host,
						Key:       key,
					},
				}
				ipamCR.Status.IPStatus = []*ficV1.IPSpec{
					{
						IPAMLabel: "test",
						Host:      host,
						IP:        "10.10.10.1",
						Key:       key,
					},
				}
				ipamCR, _ = mockCRM.ipamCli.Update(ipamCR)

				ip = mockCRM.releaseIP("test", host, key)
				ipamCR = mockCRM.getIPAMCR()
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(0), errHint+"IP Address Not released")
				Expect(ip).To(Equal("10.10.10.1"), errHint+"Wrong IP Address released")
			}
		})
	})
})
