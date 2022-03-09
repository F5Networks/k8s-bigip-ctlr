package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned/fake"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	apm "github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/teem"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Worker Tests", func() {
	var mockCtlr *mockController
	var vrt1 *cisapiv1.VirtualServer
	var svc1 *v1.Service
	namespace := "default"

	BeforeEach(func() {
		mockCtlr = newMockController()
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
		mockCtlr.kubeCRClient = crdfake.NewSimpleClientset(vrt1)
		mockCtlr.kubeClient = k8sfake.NewSimpleClientset(svc1)
		mockCtlr.crInformers = make(map[string]*CRInformer)
		mockCtlr.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		_ = mockCtlr.addNamespacedInformer("default")
		mockCtlr.resources = NewResourceStore()
		mockCtlr.crInformers["default"].vsInformer = cisinfv1.NewFilteredVirtualServerInformer(
			mockCtlr.kubeCRClient,
			namespace,
			0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(options *metav1.ListOptions) {
				options.LabelSelector = mockCtlr.resourceSelector.String()
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
		DEFAULT_PARTITION = "Test"
		BeforeEach(func() {
			mockCtlr.Agent = &Agent{
				PostManager: &PostManager{
					PostParams: PostParams{
						BIGIPURL: "10.10.10.1",
					},
				},
			}
			mockCtlr.ipamCli = ipammachinery.NewFakeIPAMClient(nil, nil, nil)
		})

		It("Create IPAM Custom Resource", func() {
			err := mockCtlr.createIPAMResource()
			Expect(err).To(BeNil(), "Failed to Create IPAM Custom Resource")
			err = mockCtlr.createIPAMResource()
			Expect(err).To(BeNil(), "Failed to Create IPAM Custom Resource")

		})

		It("Get IPAM Resource", func() {
			_ = mockCtlr.createIPAMResource()
			ipamCR := mockCtlr.getIPAMCR()
			Expect(ipamCR).NotTo(BeNil(), "Failed to GET IPAM")
			mockCtlr.ipamCR = mockCtlr.ipamCR + "invalid"
			ipamCR = mockCtlr.getIPAMCR()
			Expect(ipamCR).To(BeNil(), "Failed to GET IPAM")
			mockCtlr.ipamCR = mockCtlr.ipamCR + "/invalid"
			ipamCR = mockCtlr.getIPAMCR()
			Expect(ipamCR).To(BeNil(), "Failed to GET IPAM")
		})

		It("Request IP Address", func() {

			testSpec := make(map[string]string)
			testSpec["host"] = "foo.com"
			testSpec["key"] = "ns/name"

			for sp, val := range testSpec {
				_ = mockCtlr.createIPAMResource()
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

				ip, status := mockCtlr.requestIP("test", host, key)
				Expect(status).To(Equal(Requested), errHint+"Failed to Request IP")
				Expect(ip).To(BeEmpty(), errHint+"IP available even before requesting")
				ipamCR := mockCtlr.getIPAMCR()
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(1), errHint+"Invalid number of Host Specs")
				Expect(ipamCR.Spec.HostSpecs[0].IPAMLabel).To(Equal("test"), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Host).To(Equal(host), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Key).To(Equal(key), errHint+"IPAM Request Failed")

				ip, status = mockCtlr.requestIP("", host, key)
				Expect(status).To(Equal(InvalidInput), errHint+"Failed to validate invalid input")
				Expect(ip).To(BeEmpty(), errHint+"Failed to validate invalid input")
				newIPAMCR := mockCtlr.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")

				ip, status = mockCtlr.requestIP("test", host, key)
				Expect(status).To(Equal(Requested), errHint+"Wrong status")
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				newIPAMCR = mockCtlr.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")

				ipamCR.Status.IPStatus = []*ficV1.IPSpec{
					{
						IPAMLabel: "test",
						Host:      host,
						IP:        "10.10.10.1",
						Key:       key,
					},
				}
				ipamCR, _ = mockCtlr.ipamCli.Update(ipamCR)
				ip, status = mockCtlr.requestIP("test", host, key)
				Expect(ip).To(Equal("10.10.10.1"), errHint+"Invalid IP")
				Expect(status).To(Equal(Allocated), "Failed to fetch Allocated IP")
				ipamCR = mockCtlr.getIPAMCR()
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(1), errHint+"Invalid number of Host Specs")
				Expect(ipamCR.Spec.HostSpecs[0].IPAMLabel).To(Equal("test"), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Host).To(Equal(host), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Key).To(Equal(key), errHint+"IPAM Request Failed")

				ip, status = mockCtlr.requestIP("dev", host, key)
				Expect(status).To(Equal(Requested), "Failed to Request IP")
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				ipamCR = mockCtlr.getIPAMCR()
				// TODO: The expected number of Specs is 1. After the bug gets fixed update this to 1 from 2.
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(2), errHint+"Invalid number of Host Specs")
				Expect(ipamCR.Spec.HostSpecs[0].Host).To(Equal(host), errHint+"IPAM Request Failed")
				Expect(ipamCR.Spec.HostSpecs[0].Key).To(Equal(key), errHint+"IPAM Request Failed")

				ip, status = mockCtlr.requestIP("test", "", "")
				Expect(status).To(Equal(InvalidInput), errHint+"Failed to validate invalid input")
				Expect(ip).To(BeEmpty(), errHint+"Invalid IP")
				newIPAMCR = mockCtlr.getIPAMCR()
				Expect(reflect.DeepEqual(ipamCR, newIPAMCR)).To(BeTrue(), errHint+"IPAM CR should not be updated")

				ipamCR.Spec.HostSpecs = []*ficV1.HostSpec{}
				ipamCR.Status.IPStatus = []*ficV1.IPSpec{
					{
						IPAMLabel: "old",
						Host:      host,
						IP:        "10.10.10.2",
						Key:       key,
					},
				}
				ipamCR, _ = mockCtlr.ipamCli.Update(ipamCR)

				ip, status = mockCtlr.requestIP("old", host, key)
				Expect(ip).To(Equal(""), errHint+"Invalid IP")
				Expect(status).To(Equal(NotRequested), "Failed to identify Stale status")
			}
		})

		It("Release IP Addresss", func() {
			testSpec := make(map[string]string)
			testSpec["host"] = "foo.com"
			testSpec["key"] = "ns/name"

			for sp, val := range testSpec {
				_ = mockCtlr.createIPAMResource()
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

				ip := mockCtlr.releaseIP("", host, key)
				Expect(ip).To(BeEmpty(), errHint+"Unexpected IP address released")

				ipamCR := mockCtlr.getIPAMCR()
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
				ipamCR, _ = mockCtlr.ipamCli.Update(ipamCR)

				ip = mockCtlr.releaseIP("test", host, key)
				ipamCR = mockCtlr.getIPAMCR()
				Expect(len(ipamCR.Spec.HostSpecs)).To(Equal(0), errHint+"IP Address Not released")
				Expect(ip).To(Equal("10.10.10.1"), errHint+"Wrong IP Address released")
			}
		})

		It("IPAM Label", func() {
			vrt2 := test.NewVirtualServer(
				"SampleVS2",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.Pool{
						cisapiv1.Pool{
							Path:    "/path",
							Service: "svc1",
						},
					},
				})
			vrt3 := test.NewVirtualServer(
				"SampleVS3",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.Pool{
						cisapiv1.Pool{
							Path:    "/path2",
							Service: "svc2",
						},
					},
				})
			label := getIPAMLabel([]*cisapiv1.VirtualServer{vrt2, vrt3})
			Expect(label).To(BeEmpty())
			vrt3.Spec.IPAMLabel = "test"
			label = getIPAMLabel([]*cisapiv1.VirtualServer{vrt2, vrt3})
			Expect(label).To(Equal("test"))
		})
	})

	Describe("Filtering and Validation", func() {
		It("Filter VS for Service", func() {
			ns := "temp"
			svc := test.NewService("svc", "1", ns, v1.ServiceTypeClusterIP, nil)
			vrt2 := test.NewVirtualServer(
				"SampleVS2",
				ns,
				cisapiv1.VirtualServerSpec{
					Host:                 "test2.com",
					VirtualServerAddress: "1.2.3.5",
					Pools: []cisapiv1.Pool{
						cisapiv1.Pool{
							Path:    "/path",
							Service: "svc",
						},
					},
				})
			vrt3 := test.NewVirtualServer(
				"SampleVS",
				ns,
				cisapiv1.VirtualServerSpec{
					Host:                 "test3.com",
					VirtualServerAddress: "1.2.3.6",
					Pools: []cisapiv1.Pool{
						cisapiv1.Pool{
							Path:    "/path",
							Service: "svc",
						},
					},
				})
			res := filterVirtualServersForService([]*cisapiv1.VirtualServer{vrt1, vrt2, vrt3}, svc)
			Expect(len(res)).To(Equal(2), "Wrong list of Virtual Servers")
			Expect(res[0]).To(Equal(vrt2), "Wrong list of Virtual Servers")
			Expect(res[1]).To(Equal(vrt3), "Wrong list of Virtual Servers")
		})
		It("Filter TS for Service", func() {
			ns := "temp"
			svc := test.NewService("svc", "1", ns, v1.ServiceTypeClusterIP, nil)

			ts1 := test.NewTransportServer(
				"SampleTS1",
				namespace,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.Pool{
						Path:    "/path",
						Service: "svc",
					},
				},
			)
			ts2 := test.NewTransportServer(
				"SampleTS1",
				ns,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.Pool{
						Path:    "/path",
						Service: "svc",
					},
				},
			)
			ts3 := test.NewTransportServer(
				"SampleTS1",
				ns,
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.Pool{
						Path:    "/path",
						Service: "svc1",
					},
				},
			)

			res := filterTransportServersForService([]*cisapiv1.TransportServer{ts1, ts2, ts3}, svc)
			Expect(len(res)).To(Equal(1), "Wrong list of Transport Servers")
			Expect(res[0]).To(Equal(ts2), "Wrong list of Transport Servers")
		})

		It("Filter VS for TLSProfile", func() {
			tlsProf := test.NewTLSProfile("sampleTLS", namespace, cisapiv1.TLSProfileSpec{
				Hosts: []string{"test2.com"},
			})
			vrt2 := test.NewVirtualServer(
				"SampleVS2",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test2.com",
					VirtualServerAddress: "1.2.3.5",
					TLSProfileName:       "sampleTLS",
				})
			vrt3 := test.NewVirtualServer(
				"SampleVS",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test2.com",
					VirtualServerAddress: "1.2.3.5",
					TLSProfileName:       "sampleTLS",
				})
			res := getVirtualServersForTLSProfile([]*cisapiv1.VirtualServer{vrt1, vrt2, vrt3}, tlsProf)
			Expect(len(res)).To(Equal(2), "Wrong list of Virtual Servers")
			Expect(res[0]).To(Equal(vrt2), "Wrong list of Virtual Servers")
			Expect(res[1]).To(Equal(vrt3), "Wrong list of Virtual Servers")
		})

		It("VS Handling HTTP", func() {
			Expect(doesVSHandleHTTP(vrt1)).To(BeTrue(), "HTTP VS in invalid")
			vrt1.Spec.TLSProfileName = "TLSProf"
			Expect(doesVSHandleHTTP(vrt1)).To(BeFalse(), "HTTPS VS in invalid")
			vrt1.Spec.HTTPTraffic = TLSAllowInsecure
			Expect(doesVSHandleHTTP(vrt1)).To(BeTrue(), "HTTPS VS in invalid")
		})

		Describe("Filter Associated VirtualServers", func() {
			var vrt2, vrt3, vrt4 *cisapiv1.VirtualServer
			BeforeEach(func() {
				vrt2 = test.NewVirtualServer(
					"SampleVS2",
					namespace,
					cisapiv1.VirtualServerSpec{
						Host:                 "test2.com",
						VirtualServerAddress: "1.2.3.5",
						Pools: []cisapiv1.Pool{
							cisapiv1.Pool{
								Path:    "/path",
								Service: "svc",
							},
						},
					})
				vrt3 = test.NewVirtualServer(
					"SampleVS3",
					namespace,
					cisapiv1.VirtualServerSpec{
						Host:                 "test2.com",
						VirtualServerAddress: "1.2.3.5",
						Pools: []cisapiv1.Pool{
							cisapiv1.Pool{
								Path:    "/path3",
								Service: "svc",
							},
						},
					})
				vrt4 = test.NewVirtualServer(
					"SampleVS4",
					namespace,
					cisapiv1.VirtualServerSpec{
						Host:                 "test2.com",
						VirtualServerAddress: "1.2.3.5",
						Pools: []cisapiv1.Pool{
							cisapiv1.Pool{
								Path:    "/path4",
								Service: "svc",
							},
						},
					})
			})
			It("Duplicate Paths", func() {
				vrt3.Spec.Pools[0].Path = "/path"
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
			})

			It("Unassociated VS", func() {
				vrt4.Spec.Host = "new.com"
				vrt4.Spec.VirtualServerAddress = "1.2.3.6"
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt4},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
			})

			It("Unique Paths", func() {
				//vrt3.Spec.Pools[0].Path = "/path3"
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					false)
				Expect(len(virts)).To(Equal(2), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
				Expect(virts[1].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
			})

			It("Deletion", func() {
				//vrt3.Spec.Pools[0].Path = "/path3"
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					true)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
			})

			It("Absence of HostName of Unassociated VS", func() {
				vrt3.Spec.Host = ""
				//vrt3.Spec.Pools[0].Path = "/path3"
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
			})

			It("Absence of HostName of Associated VS", func() {
				vrt3.Spec.Host = ""
				//vrt3.Spec.Pools[0].Path = "/path3"
				vrt4.Spec.Host = ""

				virts := mockCtlr.getAssociatedVirtualServers(vrt3,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(2), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
				Expect(virts[1].Name).To(Equal("SampleVS4"), "Wrong Virtual Server")
			})

			It("UnAssociated VS 2", func() {
				vrt3.Spec.Host = ""
				//vrt3.Spec.Pools[0].Path = "/path3"
				vrt4.Spec.Host = ""
				vrt4.Spec.VirtualServerAddress = "1.2.3.6"

				virts := mockCtlr.getAssociatedVirtualServers(vrt3,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
			})

			It("Virtuals with same Host, but different Virtual Address", func() {
				vrt4.Spec.Host = "test2.com"
				vrt4.Spec.VirtualServerAddress = "1.2.3.6"

				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt4},
					false)
				Expect(virts).To(BeNil(), "Wrong Number of Virtual Servers")
			})

			It("HostGroup", func() {
				vrt2.Spec.HostGroup = "test"
				vrt3.Spec.HostGroup = "test"
				vrt3.Spec.Host = "test3.com"

				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(2), "Wrong number of Virtual Servers")
				Expect(virts[0].Spec.Host).To(Equal("test2.com"), "Wrong Virtual Server Host")
				Expect(virts[1].Spec.Host).To(Equal("test3.com"), "Wrong Virtual Server Host")
			})

			It("Host Group with IP Address Only specified once", func() {
				vrt2.Spec.HostGroup = "test"
				vrt3.Spec.HostGroup = "test"
				vrt3.Spec.Host = "test3.com"
				vrt3.Spec.VirtualServerAddress = ""

				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)

				Expect(len(virts)).To(Equal(2), "Wrong number of Virtual Servers")
				Expect(virts[0].Spec.Host).To(Equal("test2.com"), "Wrong Virtual Server Host")
				Expect(virts[1].Spec.Host).To(Equal("test3.com"), "Wrong Virtual Server Host")
			})

			It("HostGroup with wrong custom port", func() {
				vrt2.Spec.HostGroup = "test"
				vrt2.Spec.VirtualServerHTTPPort = 8080

				vrt3.Spec.HostGroup = "test"
				vrt3.Spec.Host = "test3.com"
				vrt3.Spec.VirtualServerHTTPPort = 8081

				vrt4.Spec.HostGroup = "test"
				vrt4.Spec.Host = "test4.com"
				vrt4.Spec.VirtualServerHTTPPort = 8080

				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(2), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
				Expect(virts[1].Name).To(Equal("SampleVS4"), "Wrong Virtual Server")
			})

			It("Unique Paths: same path but with different host names", func() {
				vrt2.Spec.HostGroup = "test"
				vrt2.Spec.Pools[0].Path = "/path"

				vrt3.Spec.HostGroup = "test"
				vrt3.Spec.Host = "test3.com"
				vrt3.Spec.Pools[0].Path = "/path"

				vrt4.Spec.HostGroup = "test"
				vrt4.Spec.Host = "test4.com"
				vrt4.Spec.Pools[0].Path = "/path"

				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(3), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
				Expect(virts[1].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
				Expect(virts[2].Name).To(Equal("SampleVS4"), "Wrong Virtual Server")
			})

			It("IPAM Label", func() {
				mockCtlr.ipamCli = &ipammachinery.IPAMClient{}
				vrt2.Spec.IPAMLabel = "test"
				vrt3.Spec.IPAMLabel = "test"
				vrt4.Spec.IPAMLabel = "test"
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(3), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
				Expect(virts[1].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
				Expect(virts[2].Name).To(Equal("SampleVS4"), "Wrong Virtual Server")
			})

			It("IPAM Label: Absence in a virtualServer", func() {
				mockCtlr.ipamCli = &ipammachinery.IPAMClient{}
				vrt2.Spec.IPAMLabel = "test"
				vrt3.Spec.IPAMLabel = "test"
				vrt4.Spec.IPAMLabel = ""
				virts := mockCtlr.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(0), "Wrong number of Virtual Servers")
			})
			It("IPAM Label in a virtualServer with empty host", func() {
				mockCtlr.ipamCli = &ipammachinery.IPAMClient{}
				vrt4.Spec.IPAMLabel = "test"
				vrt4.Spec.Host = ""
				virts := mockCtlr.getAssociatedVirtualServers(vrt4,
					[]*cisapiv1.VirtualServer{vrt4},
					false)
				Expect(len(virts)).To(Equal(0), "Wrong number of Virtual Servers")
			})
		})
	})
	Describe("Endpoints", func() {
		BeforeEach(func() {
			mockCtlr.oldNodes = []Node{
				{
					Name: "worker1",
					Addr: "10.10.10.1",
					Labels: map[string]string{
						"worker": "true",
					},
				},
				{
					Name: "worker2",
					Addr: "10.10.10.2",
					Labels: map[string]string{
						"worker": "true",
					},
				},
				{
					Name: "master",
					Addr: "10.10.10.3",
				},
			}
		})

		It("NodePort", func() {
			var nodePort int32 = 30000
			members := []PoolMember{
				{
					Address: "10.10.10.1",
					Port:    nodePort,
					Session: "user-enabled",
				},
				{
					Address: "10.10.10.2",
					Port:    nodePort,
					Session: "user-enabled",
				},
				{
					Address: "10.10.10.3",
					Port:    nodePort,
					Session: "user-enabled",
				},
			}

			mems := mockCtlr.getEndpointsForNodePort(nodePort, "")
			Expect(mems).To(Equal(members), "Wrong set of Endpoints for NodePort")
			mems = mockCtlr.getEndpointsForNodePort(nodePort, "worker=true")
			Expect(mems).To(Equal(members[:2]), "Wrong set of Endpoints for NodePort")
			mems = mockCtlr.getEndpointsForNodePort(nodePort, "invalid label")
			Expect(len(mems)).To(Equal(0), "Wrong set of Endpoints for NodePort")
		})

	})

	Describe("Processing Resources", func() {
		It("Processing ServiceTypeLoadBalancer", func() {
			// Service when IPAM is not available
			_ = mockCtlr.processLBServices(svc1, false)
			Expect(len(mockCtlr.resources.rsMap)).To(Equal(0), "Resource Config should be empty")

			mockCtlr.Agent = &Agent{
				PostManager: &PostManager{
					PostParams: PostParams{
						BIGIPURL: "10.10.10.1",
					},
				},
			}
			mockCtlr.ipamCli = ipammachinery.NewFakeIPAMClient(nil, nil, nil)
			mockCtlr.eventNotifier = apm.NewEventNotifier(nil)

			svc1.Spec.Type = v1.ServiceTypeLoadBalancer

			mockCtlr.resources.Init()

			// Service Without annotation
			_ = mockCtlr.processLBServices(svc1, false)
			Expect(len(mockCtlr.resources.rsMap)).To(Equal(0), "Resource Config should be empty")

			svc1.Annotations = make(map[string]string)
			svc1.Annotations[LBServiceIPAMLabelAnnotation] = "test"

			svc1, _ = mockCtlr.kubeClient.CoreV1().Services(svc1.ObjectMeta.Namespace).UpdateStatus(context.TODO(), svc1, metav1.UpdateOptions{})

			_ = mockCtlr.processLBServices(svc1, false)
			Expect(len(mockCtlr.resources.rsMap)).To(Equal(0), "Resource Config should be empty")

			_ = mockCtlr.createIPAMResource()
			ipamCR := mockCtlr.getIPAMCR()

			ipamCR.Spec.HostSpecs = []*ficV1.HostSpec{
				{
					IPAMLabel: "test",
					Host:      "",
					Key:       svc1.Namespace + "/" + svc1.Name + "_svc",
				},
			}

			ipamCR.Status.IPStatus = []*ficV1.IPSpec{
				{
					IPAMLabel: "test",
					Host:      "",
					IP:        "10.10.10.1",
					Key:       svc1.Namespace + "/" + svc1.Name + "_svc",
				},
			}
			ipamCR, _ = mockCtlr.ipamCli.Update(ipamCR)

			_ = mockCtlr.processLBServices(svc1, false)
			Expect(len(mockCtlr.resources.rsMap)).To(Equal(1), "Invalid Resource Configs")

			_ = mockCtlr.processLBServices(svc1, true)
			Expect(len(mockCtlr.resources.rsMap)).To(Equal(0), "Invalid Resource Configs")

			Expect(len(svc1.Status.LoadBalancer.Ingress)).To(Equal(1))
			mockCtlr.eraseLBServiceIngressStatus(svc1)
			Expect(len(svc1.Status.LoadBalancer.Ingress)).To(Equal(0))
		})

		It("Processing External DNS", func() {
			mockCtlr.resources.Init()
			mockCtlr.TeemData = &teem.TeemsData{
				ResourceType: teem.ResourceTypes{
					ExternalDNS: make(map[string]int),
				},
			}

			newEDNS := test.NewExternalDNS(
				"SampleEDNS",
				namespace,
				cisapiv1.ExternalDNSSpec{
					DomainName: "test.com",
					Pools: []cisapiv1.DNSPool{
						{
							DataServerName: "DataServer",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 10,
								Timeout:  10,
							},
						},
					},
				})

			mockCtlr.processExternalDNS(newEDNS, false)
			Expect(len(mockCtlr.resources.dnsConfig)).To(Equal(1))
			Expect(len(mockCtlr.resources.dnsConfig["test.com"].Pools)).To(Equal(1))
			Expect(len(mockCtlr.resources.dnsConfig["test.com"].Pools[0].Members)).To(Equal(0))

			mockCtlr.resources.rsMap["SampleVS"] = &ResourceConfig{
				MetaData: metaData{
					hosts: []string{"test.com"},
				},
			}
			mockCtlr.processExternalDNS(newEDNS, false)
			Expect(len(mockCtlr.resources.dnsConfig)).To(Equal(1))
			Expect(len(mockCtlr.resources.dnsConfig["test.com"].Pools)).To(Equal(1))
			Expect(len(mockCtlr.resources.dnsConfig["test.com"].Pools[0].Members)).To(Equal(1))

			mockCtlr.processExternalDNS(newEDNS, true)
			Expect(len(mockCtlr.resources.dnsConfig)).To(Equal(0))
		})
	})

	It("get node port", func() {
		svc1.Spec.Ports[0].NodePort = 30000
		np := getNodeport(svc1, 80)
		Expect(int(np)).To(Equal(30000))
	})

	Describe("Test NodeportLocal", func() {
		var nplsvc *v1.Service
		var selectors map[string]string
		BeforeEach(func() {
			mockCtlr.PoolMemberType = NodePortLocal
			selectors = make(map[string]string)
			selectors["app"] = "npl"
			nplsvc = test.NewServicewithselectors(
				"svcnpl",
				"1",
				namespace,
				selectors,
				v1.ServiceTypeClusterIP,
				[]v1.ServicePort{
					{
						Port: 8080,
						Name: "port0",
					},
				},
			)
			ann := make(map[string]string)
			ann[NPLSvcAnnotation] = "true"
			nplsvc.Annotations = ann
		})
		It("NodePortLocal", func() {
			pod1 := test.NewPod("pod1", namespace, 8080, selectors)
			ann := make(map[string]string)
			ann[NPLPodAnnotation] = "[{\"podPort\":8080,\"nodeIP\":\"10.10.10.1\",\"nodePort\":40000}]"
			pod1.Annotations = ann
			pod2 := test.NewPod("pod2", namespace, 8080, selectors)
			ann2 := make(map[string]string)
			ann2[NPLPodAnnotation] = "[{\"podPort\":8080,\"nodeIP\":\"10.10.10.1\",\"nodePort\":40001}]"
			pod2.Annotations = ann2
			mockCtlr.resources.Init()
			mockCtlr.processPod(pod1, false)
			mockCtlr.processPod(pod2, false)
			var val1 NPLAnnoations
			var val2 NPLAnnoations
			json.Unmarshal([]byte(pod1.Annotations[NPLPodAnnotation]), &val1)
			json.Unmarshal([]byte(pod2.Annotations[NPLPodAnnotation]), &val2)
			//verify npl store populated
			Expect(mockCtlr.resources.nplStore[namespace+"/"+pod1.Name]).To(Equal(val1))
			Expect(mockCtlr.resources.nplStore[namespace+"/"+pod2.Name]).To(Equal(val2))
		})

	})
})
