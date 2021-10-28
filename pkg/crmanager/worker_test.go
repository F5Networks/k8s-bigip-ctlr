package crmanager

import (
	"context"
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned/fake"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	apm "github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/teem"
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
				Firewall:         "",
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
		DEFAULT_PARTITION = "Test"
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
				virts := mockCRM.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
			})

			It("Unassociated VS", func() {
				vrt4.Spec.Host = "new.com"
				vrt4.Spec.VirtualServerAddress = "1.2.3.6"
				virts := mockCRM.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt4},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
			})

			It("Unique Paths", func() {
				//vrt3.Spec.Pools[0].Path = "/path3"
				virts := mockCRM.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					false)
				Expect(len(virts)).To(Equal(2), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
				Expect(virts[1].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
			})

			It("Deletion", func() {
				//vrt3.Spec.Pools[0].Path = "/path3"
				virts := mockCRM.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					true)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
			})

			It("Absence of HostName of Unassociated VS", func() {
				vrt3.Spec.Host = ""
				//vrt3.Spec.Pools[0].Path = "/path3"
				virts := mockCRM.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt3},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS2"), "Wrong Virtual Server")
			})

			It("Absence of HostName of Associated VS", func() {
				vrt3.Spec.Host = ""
				//vrt3.Spec.Pools[0].Path = "/path3"
				vrt4.Spec.Host = ""

				virts := mockCRM.getAssociatedVirtualServers(vrt3,
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

				virts := mockCRM.getAssociatedVirtualServers(vrt3,
					[]*cisapiv1.VirtualServer{vrt2, vrt3, vrt4},
					false)
				Expect(len(virts)).To(Equal(1), "Wrong number of Virtual Servers")
				Expect(virts[0].Name).To(Equal("SampleVS3"), "Wrong Virtual Server")
			})

			It("Virtuals with same Host, but different Virtual Address", func() {
				vrt4.Spec.Host = "test2.com"
				vrt4.Spec.VirtualServerAddress = "1.2.3.6"

				virts := mockCRM.getAssociatedVirtualServers(vrt2,
					[]*cisapiv1.VirtualServer{vrt2, vrt4},
					false)
				Expect(virts).To(BeNil(), "Wrong Number of Virtual Servers")
			})
		})
	})
	Describe("Endpoints", func() {
		BeforeEach(func() {
			mockCRM.oldNodes = []Node{
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
			members := []Member{
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

			mems := mockCRM.getEndpointsForNodePort(nodePort, "")
			Expect(mems).To(Equal(members), "Wrong set of Endpoints for NodePort")
			mems = mockCRM.getEndpointsForNodePort(nodePort, "worker=true")
			Expect(mems).To(Equal(members[:2]), "Wrong set of Endpoints for NodePort")
			mems = mockCRM.getEndpointsForNodePort(nodePort, "invalid label")
			Expect(len(mems)).To(Equal(0), "Wrong set of Endpoints for NodePort")
		})

		It("Cluster", func() {
			ports := []v1.EndpointPort{
				{
					Name: "http",
					Port: 80,
				},
				{
					Name: "https",
					Port: 443,
				},
			}

			members := []Member{
				{
					Address: "11.11.11.1",
					Port:    80,
					Session: "user-enabled",
				},
				{
					Address: "11.11.11.2",
					Port:    80,
					Session: "user-enabled",
				},
				{
					Address: "11.11.12.1",
					Port:    80,
					Session: "user-enabled",
				},
				{
					Address: "11.11.12.2",
					Port:    80,
					Session: "user-enabled",
				},
			}

			eps := test.NewEndpoints("svc1", "1", "worker1", namespace,
				[]string{"11.11.11.1", "11.11.11.2"}, nil, ports)
			epsTemp := test.NewEndpoints("svc1", "1", "worker2", namespace,
				[]string{"11.11.12.1", "11.11.12.2"}, nil, ports)
			eps.Subsets = append(eps.Subsets, epsTemp.Subsets...)

			mems := mockCRM.getEndpointsForCluster("http", eps, 80, "13.13.13.1")
			Expect(mems).To(Equal(members), "Wrong set of Endpoints for Cluster")

			mems = mockCRM.getEndpointsForCluster("http", nil, 80, "13.13.13.1")
			Expect(len(mems)).To(Equal(0), "Wrong set of Endpoints for Cluster")
		})
	})

	Describe("Processing Resources", func() {
		It("Processing ServiceTypeLoadBalancer", func() {
			// Service when IPAM is not available
			_ = mockCRM.processLBServices(svc1, false)
			Expect(len(mockCRM.resources.rsMap)).To(Equal(0), "Resource Config should be empty")

			mockCRM.Agent = &Agent{
				PostManager: &PostManager{
					PostParams: PostParams{
						BIGIPURL: "10.10.10.1",
					},
				},
			}
			mockCRM.ipamCli = ipammachinery.NewFakeIPAMClient(nil, nil, nil)
			mockCRM.eventNotifier = apm.NewEventNotifier(nil)

			svc1.Spec.Type = v1.ServiceTypeLoadBalancer

			mockCRM.resources.Init()

			// Service Without annotation
			_ = mockCRM.processLBServices(svc1, false)
			Expect(len(mockCRM.resources.rsMap)).To(Equal(0), "Resource Config should be empty")

			svc1.Annotations = make(map[string]string)
			svc1.Annotations[LBServiceIPAMLabelAnnotation] = "test"

			svc1, _ = mockCRM.kubeClient.CoreV1().Services(svc1.ObjectMeta.Namespace).UpdateStatus(context.TODO(), svc1, metav1.UpdateOptions{})

			_ = mockCRM.processLBServices(svc1, false)
			Expect(len(mockCRM.resources.rsMap)).To(Equal(0), "Resource Config should be empty")

			_ = mockCRM.createIPAMResource()
			ipamCR := mockCRM.getIPAMCR()

			ipamCR.Status.IPStatus = []*ficV1.IPSpec{
				{
					IPAMLabel: "test",
					Host:      "",
					IP:        "10.10.10.1",
					Key:       svc1.Namespace + "/" + svc1.Name + "_svc",
				},
			}
			ipamCR, _ = mockCRM.ipamCli.Update(ipamCR)

			_ = mockCRM.processLBServices(svc1, false)
			Expect(len(mockCRM.resources.rsMap)).To(Equal(1), "Invalid Resource Configs")

			_ = mockCRM.processLBServices(svc1, true)
			Expect(len(mockCRM.resources.rsMap)).To(Equal(0), "Invalid Resource Configs")

			Expect(len(svc1.Status.LoadBalancer.Ingress)).To(Equal(1))
			mockCRM.eraseLBServiceIngressStatus(svc1)
			Expect(len(svc1.Status.LoadBalancer.Ingress)).To(Equal(0))
		})

		It("Processing External DNS", func() {
			mockCRM.resources.Init()
			mockCRM.TeemData = &teem.TeemsData{
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
							Name:           "DNSPool",
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

			mockCRM.processExternalDNS(newEDNS, false)
			Expect(len(mockCRM.resources.dnsConfig)).To(Equal(1))
			Expect(len(mockCRM.resources.dnsConfig["test.com"].Pools)).To(Equal(1))
			Expect(len(mockCRM.resources.dnsConfig["test.com"].Pools[0].Members)).To(Equal(0))

			mockCRM.resources.rsMap["SampleVS"] = &ResourceConfig{
				MetaData: metaData{
					hosts: []string{"test.com"},
				},
			}
			mockCRM.processExternalDNS(newEDNS, false)
			Expect(len(mockCRM.resources.dnsConfig)).To(Equal(1))
			Expect(len(mockCRM.resources.dnsConfig["test.com"].Pools)).To(Equal(1))
			Expect(len(mockCRM.resources.dnsConfig["test.com"].Pools[0].Members)).To(Equal(1))

			mockCRM.processExternalDNS(newEDNS, true)
			Expect(len(mockCRM.resources.dnsConfig)).To(Equal(0))
		})
	})

	It("get node port", func() {
		svc1.Spec.Ports[0].NodePort = 30000
		np := getNodeport(svc1, 80)
		Expect(int(np)).To(Equal(30000))
	})
})
