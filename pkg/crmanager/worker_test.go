package crmanager

import (
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned/fake"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
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
})
