package controller

import (
	"context"
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"time"
)

var _ = Describe("Routes", func() {
	var mockCtlr *mockController
	var bigipConfig cisapiv1.BigIpConfig
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.managedResources.ManageRoutes = true
		mockCtlr.CISConfigCRKey = "kube-system/global-cm"
		mockCtlr.clientsets.RouteClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces["default"] = true
		mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.nrInformers = make(map[string]*NRInformer)
		mockCtlr.comInformers = make(map[string]*CommonInformer)
		mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.comInformers["test"] = mockCtlr.newNamespacedCommonResourceInformer("test")
		mockCtlr.comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default")
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
				ExternalDNS:  make(map[string]int),
			},
		}
		bigIpKey := cisapiv1.BigIpConfig{BigIpAddress: "10.8.3.11", BigIpLabel: "bigip1"}
		mockCtlr.RequestHandler.PostManagers.PostManagerMap[bigIpKey] = &PostManager{
			tokenManager: mockCtlr.CMTokenManager,
			PostParams:   PostParams{},
		}
		bigipConfig = cisapiv1.BigIpConfig{
			BigIpLabel:       "bigip1",
			BigIpAddress:     "10.8.0.5",
			DefaultPartition: "test",
		}
		mockCtlr.bigIpConfigMap[bigipConfig] = BigIpResourceConfig{ltmConfig: make(LTMConfig), gtmConfig: make(GTMConfig)}
	})

	Describe("Routes", func() {
		var rt *routeapi.Route
		var ns string
		BeforeEach(func() {
			ns = "default"
			rt = test.NewRoute(
				"sampleroute",
				"v1",
				ns,
				routeapi.RouteSpec{
					Host: "foo.com",
					Path: "/bar",
					To: routeapi.RouteTargetReference{
						Name: "samplesvc",
					},
				},
				nil,
			)
		})

		It("Base Route", func() {
			var override = false
			mockCtlr.resources.extdSpecMap[ns] = &extendedParsedSpec{
				override: override,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "samplevs",
					VServerAddr:   "10.10.10.10",
					AllowOverride: "false",
				},
			}
			err := mockCtlr.processRoutes(ns, false)
			Expect(err).To(BeNil(), "Failed to process routes")
		})
		It("Passthrough Route", func() {
			var override = false
			mockCtlr.resources.extdSpecMap[ns] = &extendedParsedSpec{
				override: override,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "samplevs",
					VServerAddr:   "10.10.10.10",
					AllowOverride: "False",
				},
				namespaces: []string{ns},
				partition:  "test",
			}
			tlsConfig := &routeapi.TLSConfig{}
			tlsConfig.Termination = TLSPassthrough
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: tlsConfig,
			}
			route1 := test.NewRoute("route1", "1", ns, spec1, nil)
			mockCtlr.addRoute(route1)
			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
				{Port: 8080, NodePort: 38001},
				{Port: 9090, NodePort: 39001}}
			foo := test.NewService("foo", "1", ns, "NodePort", fooPorts)
			mockCtlr.addService(foo)
			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", ns, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			mockCtlr.resources.invertedNamespaceLabelMap[ns] = ns

			err := mockCtlr.processRoutes(ns, false)
			mapKey := NameRef{
				Name:      getRSCfgResName("samplevs_443", PassthroughHostsDgName),
				Partition: "test",
			}
			Expect(err).To(BeNil(), "Failed to process routes")
			Expect(len(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["samplevs_443"].Policies)).To(BeEquivalentTo(0), "Policy should not be created for passthrough route")
			dg, ok := mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["samplevs_443"].IntDgMap[mapKey]
			Expect(ok).To(BeTrue(), "datagroup should be created for passthrough route")
			Expect(dg[ns].Records[0].Name).To(BeEquivalentTo("foo.com"), "Invalid vsHostname in datagroup")
			Expect(dg[ns].Records[0].Data).To(BeEquivalentTo("foo_80_default"), "Invalid vsHostname in datagroup")
		})

		It("Route Admit Status", func() {
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
			}
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			mockCtlr.addRoute(route1)
			rskey := fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			mockCtlr.updateRouteAdmitStatus(rskey, "", "", v1.ConditionTrue)
			route := mockCtlr.fetchRoute(rskey)
			Expect(route.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionTrue), "Incorrect route admit status")
			// Update the status for route with duplicate host path
			mockCtlr.updateRouteAdmitStatus(rskey, "HostAlreadyClaimed", "Testing", v1.ConditionFalse)
			route = mockCtlr.fetchRoute(rskey)
			Expect(route.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("HostAlreadyClaimed"), "Incorrect route admit reason")
			Expect(route.Status.Ingress[0].Conditions[0].Message).To(BeEquivalentTo("Testing"), "Incorrect route admit message")
			//fetch invalid route
			Expect(mockCtlr.fetchRoute(fmt.Sprintf("%v-invalid", rskey))).To(BeNil(), "We should not be able to fetch the route")

		})
		It("Erase All Route Admit Status", func() {
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
			}
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			route1.ObjectMeta.Labels = map[string]string{
				"pro": "asb",
			}
			mockCtlr.addRoute(route1)
			mockCtlr.namespaces = map[string]bool{
				"test": true,
			}
			rskey := fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			mockCtlr.updateRouteAdmitStatus(rskey, "Route Admitted", "", v1.ConditionTrue)
			route := mockCtlr.fetchRoute(rskey)
			Expect(len(route1.Status.Ingress)).To(BeEquivalentTo(1), "Incorrect route admit status")
			mockCtlr.clientsets.RouteClientV1.Routes("default").Create(context.TODO(), route1, metav1.CreateOptions{})
			mockCtlr.resourceSelectorConfig.RouteLabel = " pro in (pro) "
			mockCtlr.processedHostPath.processedHostPathMap["foo.com/foo"] = route1.ObjectMeta.CreationTimestamp
			mockCtlr.eraseAllRouteAdmitStatus()
			route = mockCtlr.fetchRoute(rskey)
			Expect(len(route.Status.Ingress)).To(BeEquivalentTo(0), "Incorrect route admit status")
		})
		It("Check Valid Route", func() {
			var configCR *cisapiv1.DeployConfig
			configSpec := cisapiv1.DeployConfigSpec{}
			crName := "escm"
			crNamespace := "system"
			mockCtlr.CISConfigCRKey = crNamespace + "/" + crName

			extConfig := `
{
    "baseRouteSpec": {
        "tlsCipher": {
            "tlsVersion": 1.2
        }
    },
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
		`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configSpec.ExtendedSpec = es
			configCR = test.NewConfigCR(
				crName,
				crNamespace,
				configSpec)
			_, _ = mockCtlr.processConfigCR(configCR, false)

			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: TLSReencrypt,
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
			}
			spec3 := routeapi.RouteSpec{
				Host: "default.com",
				Path: "/test",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: TLSEdge,
					Certificate: "-----BEGIN CERTIFICATE-----\nMIIC+DCCAeCgAwIBAgIQIBIcC6PuJQEHwwI0Hv5QmTANBgkqhkiG9w0BAQsFADAS\nMRAwDgYDVQQKEwdBY21lIENvMB4XDTIyMTIyMjA5MjE0OFoXDTIzMTIyMjA5MjE0\nOFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAN0NWXsUvGYBV9uo2Iuz3gnovyk3W7p8AA4I8eRUFaWV1EYaxFpsGmdN\nrQgdVJ6w+POSykbDuZynYJyBjC11dJmfTaXffLaUSrJfu+a0QaeWIpt+XxzO4SKQ\nunUSh5Z9w4P45G8VKF7E67wFVN0ni10FLAfBUjYVsQpPagpkH8OdnYCsymCzVSWi\nYETZZ+Hbaih9flRgBQOsoUyNBSkCdJ2wEkZ/0p9+tYwZp1Xvp/Neu3TTsezpu7lE\nbTp0RLQNqfLHWiMV9BSAQRbXAvtvky3J42iy+ec24JyQPtiD85u8Pp/+ssV0ZL9l\nc5KoDEuAvf4NPFWu270gYyQljKcTbB8CAwEAAaNKMEgwDgYDVR0PAQH/BAQDAgWg\nMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwEwYDVR0RBAwwCoII\ndGVzdC5jb20wDQYJKoZIhvcNAQELBQADggEBAI9VUdpVmfx+WUEejREa+plEjCIV\ns+d7v66ddyU4B+Zer1y4RgoWaVq5pywPPjBNJuz6NfwSvBCmuMUd1LUoF5tQFkqb\nVa85Aq6ODbwIMoQ53kTG9vLbT78qESrbukaW9v+axdD9/DIXZJtdwvLvHAVpelRi\n7z48Lxk1GTe7dM3ixKQrU4hz656kH3kXSnD79metOkJA6BAXsqL2XonIhNkCkQVV\n38IHDNkzk228d97ebLu+EhLlkjFgFQEnXusK1amrGJrRDli72pY01yxzGI1caKG5\nN6I8MEIqYI/POwbYWENqONF22pzw/OIs4T1a3jjUqEFugnELcTtx/xRLmOI=\n-----END CERTIFICATE-----\n",
					Key:         "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDdDVl7FLxmAVfb\nqNiLs94J6L8pN1u6fAAOCPHkVBWlldRGGsRabBpnTa0IHVSesPjzkspGw7mcp2Cc\ngYwtdXSZn02l33y2lEqyX7vmtEGnliKbfl8czuEikLp1EoeWfcOD+ORvFShexOu8\nBVTdJ4tdBSwHwVI2FbEKT2oKZB/DnZ2ArMpgs1UlomBE2Wfh22oofX5UYAUDrKFM\njQUpAnSdsBJGf9KffrWMGadV76fzXrt007Hs6bu5RG06dES0Danyx1ojFfQUgEEW\n1wL7b5MtyeNosvnnNuCckD7Yg/ObvD6f/rLFdGS/ZXOSqAxLgL3+DTxVrtu9IGMk\nJYynE2wfAgMBAAECggEAf8l91vcvylAweB1twaUjUNsp1yvXbUDNz09Adtxc/zJU\nWoqSxCsGQH3Y7331Mx/fav+Ky8nN/U+NPCxv2r+xvjUncCJ4OBwV6nQJbd76rWTP\ncNBnL4IxCAheodsqYsclRZ+WftjeU5rHJBR48Lgxin6462rImdeEVw99n7At5Kig\nGZmGNXnk6jgvoNU1YJZxSMWQQwKtrfJxXry5a90SfjiviGseuBPsgbrMxEPaeqlQ\nGAMi4nIVRmijL56vbbuuudZm+6dpOnbGzzF6J4M5Nrfr/qJF7ClwXjcMeb6lESIo\n5pmGl3QwSGQYeflFexP3ydvQdUwN5rLbtCexPC2CsQKBgQDxLPn8pIU7WuFiTuOp\n1o7/25v7ijPydIRBjjVeA7E7+mbq9FllkT4CW+HtP7zCCjdScuXhKjuPRrST4fsZ\nZex2nUYfc586s/W95b4QMKtXcJd1MMMWOK2/ZGN/6L5zLPupDrhyWHw91biFZG8h\nSFgn7G2zS/+09gJTglpdj3gClQKBgQDqo7f+kZiXGFvP4kcOWNgnOJOpdqzG/zeD\nuVP2Y6Q8mi7GhkiYhdlrl6Ibh9X0qjFMKMKy827jbUPSGaj5tIT8iXyFT4KVaqZQ\n7r2cMyCqbznKfWlyMyspaVEDa910+VwC2hYQvahTQzfdQqFp6JfiLqCdQtiNDGLf\nbvUOHk4a4wKBgHDLo0NowrMm5wBuewXExm6djE9RrMf5fJ2YYBdPTMYLb7T1gRYC\nnujFhl3KkIKD+qnB+QedE+wHmo8Lgr+3LqevGMu+7LqszgL5fzHdQVWM4Bk8LBGp\ngoFf9zUsal49rJm9u8Am6DyXR0yD04HSbwCFEC1qHvbIk//wmEjnv64dAoGANBbW\nYPBHlLt2nmbYaWn1ync36LYM0zyTQW3iIt+p9T4xRidHdHy6cLU/6qa0K9Wgjgy6\ndGmwY1K9bKX/qjeWEk4fU6T8E1mSxILLmyKKjOuWQ8qlnxGW8mGL95t5lV9KOuPZ\nZCwGcz2H6FnDZbSaCz9YrrDJTD7EsF98jX7SzgsCgYBQv5yi7aGxH6OcrAJPQH4v\n1fZo7mFbqp0WoUMpwuWKNOHZuZoF0EU/bllMZT7AipxVhso+hUC+rDEO7H36TAyc\nTUJbdxtlIC1JmJTmeBOWh3i3Htu8A97DLUNTqNikNyKyGWjy7eC0ncG3+CGG91wA\nky9KxzxszaIez6kIUCY7xQ==\n-----END PRIVATE KEY-----\n",
				},
			}
			spec4 := routeapi.RouteSpec{
				Host: "test.com",
				Path: "/",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: TLSReencrypt},
			}
			annotations := make(map[string]string)
			annotations[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			route1 := test.NewRoute("route1", "1", "default", spec1, annotations)
			route2 := test.NewRoute("route2", "1", "test", spec1, nil)
			route3 := test.NewRoute("route3", "1", "default", spec2, nil)
			route4 := test.NewRoute("route4", "1", "default", spec3, nil)
			route5 := test.NewRoute("route5", "1", "default", spec4, nil)
			mockCtlr.addRoute(route1)
			mockCtlr.addRoute(route2)
			mockCtlr.addRoute(route3)
			mockCtlr.addRoute(route4)
			_, _ = mockCtlr.processConfigCR(configCR, false)
			mockCtlr.addRoute(route5)
			mockCtlr.clientsets.RouteClientV1.Routes("default").Create(context.TODO(), route1, metav1.CreateOptions{})
			mockCtlr.clientsets.RouteClientV1.Routes("default").Create(context.TODO(), route2, metav1.CreateOptions{})
			mockCtlr.clientsets.RouteClientV1.Routes("default").Create(context.TODO(), route3, metav1.CreateOptions{})
			mockCtlr.clientsets.RouteClientV1.Routes("default").Create(context.TODO(), route4, metav1.CreateOptions{})
			mockCtlr.clientsets.RouteClientV1.Routes("default").Create(context.TODO(), route5, metav1.CreateOptions{})
			rskey1 := fmt.Sprintf("%v/%v", route1.Namespace, route1.Name)
			rskey2 := fmt.Sprintf("%v/%v", route2.Namespace, route2.Name)
			Expect(mockCtlr.checkValidRoute(route1, rgPlcSSLProfiles{})).To(BeFalse())
			mockCtlr.processedHostPath.processedHostPathMap[route1.Spec.Host+route1.Spec.Path] = route1.ObjectMeta.CreationTimestamp
			Expect(mockCtlr.checkValidRoute(route2, rgPlcSSLProfiles{})).To(BeFalse())
			Expect(mockCtlr.checkValidRoute(route3, rgPlcSSLProfiles{})).To(BeFalse())
			Expect(mockCtlr.checkValidRoute(route4, rgPlcSSLProfiles{})).To(BeFalse())
			mockCtlr.resources.baseRouteConfig.DefaultTLS = cisapiv1.DefaultSSLProfile{Reference: BIGIP}
			Expect(mockCtlr.checkValidRoute(route5, rgPlcSSLProfiles{})).To(BeFalse())
			mockCtlr.resources.baseRouteConfig.DefaultTLS = cisapiv1.DefaultSSLProfile{Reference: BIGIP, ClientSSL: "/Common/clientSSL"}
			Expect(mockCtlr.checkValidRoute(route5, rgPlcSSLProfiles{})).To(BeFalse())
			mockCtlr.resources.baseRouteConfig.DefaultTLS = cisapiv1.DefaultSSLProfile{}
			Expect(mockCtlr.checkValidRoute(route5, rgPlcSSLProfiles{})).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			route1 = mockCtlr.fetchRoute(rskey1)
			route2 = mockCtlr.fetchRoute(rskey2)
			Expect(route1.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route2.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route1.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route2.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route1.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("ExtendedValidationFailed"), "Incorrect route admit reason")
			Expect(route2.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("HostAlreadyClaimed"), "incorrect the route admit reason")
			// Check valid route with app root annotation
			annotations[F5VsAppRootAnnotation] = ""
			spec6 := routeapi.RouteSpec{
				Host: "test.com",
				Path: "/",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
			}
			route6 := test.NewRoute("route6", "1", "default", spec6, annotations)
			mockCtlr.addRoute(route6)
			Expect(mockCtlr.checkValidRoute(route6, rgPlcSSLProfiles{})).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			rskey6 := fmt.Sprintf("%v/%v", route6.Namespace, route6.Name)
			route6 = mockCtlr.fetchRoute(rskey6)
			Expect(route6.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route6.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route6.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("InvalidAnnotation"), "Incorrect route admit reason")
			annotations[F5VsAppRootAnnotation] = "/foo"
			spec7 := routeapi.RouteSpec{
				Host: "test.com",
				Path: "/test",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
			}
			route7 := test.NewRoute("route7", "1", "default", spec7, annotations)
			mockCtlr.addRoute(route7)
			Expect(mockCtlr.checkValidRoute(route7, rgPlcSSLProfiles{})).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			rskey7 := fmt.Sprintf("%v/%v", route7.Namespace, route7.Name)
			route7 = mockCtlr.fetchRoute(rskey7)
			Expect(route7.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route7.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route7.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("InvalidAnnotation"), "Incorrect route admit reason")

			// Check valid route with WAF annotation
			wafAnnotation := make(map[string]string)
			wafAnnotation[F5VsWAFPolicy] = ""
			spec8 := routeapi.RouteSpec{
				Host: "test.com",
				Path: "/",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
			}
			route8 := test.NewRoute("route8", "1", "default", spec8, wafAnnotation)
			mockCtlr.addRoute(route8)
			Expect(mockCtlr.checkValidRoute(route8, rgPlcSSLProfiles{})).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			rskey8 := fmt.Sprintf("%v/%v", route8.Namespace, route8.Name)
			route8 = mockCtlr.fetchRoute(rskey8)
			Expect(route8.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route8.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route8.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("InvalidAnnotation"), "Incorrect route admit reason")

			// Check valid route with AllowSourceRange annotation
			sourceRangeAnnotation := make(map[string]string)
			sourceRangeAnnotation[F5VsAllowSourceRangeAnnotation] = ""
			spec9 := routeapi.RouteSpec{
				Host: "test.com",
				Path: "/",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
			}
			route9 := test.NewRoute("route9", "1", "default", spec9, sourceRangeAnnotation)
			mockCtlr.addRoute(route9)
			Expect(mockCtlr.checkValidRoute(route9, rgPlcSSLProfiles{})).To(BeFalse())
			time.Sleep(100 * time.Millisecond)
			rskey9 := fmt.Sprintf("%v/%v", route9.Namespace, route9.Name)
			route9 = mockCtlr.fetchRoute(rskey9)
			Expect(route9.Status.Ingress[0].RouterName).To(BeEquivalentTo(F5RouterName), "Incorrect router name")
			Expect(route9.Status.Ingress[0].Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse), "Incorrect route admit status")
			Expect(route9.Status.Ingress[0].Conditions[0].Reason).To(BeEquivalentTo("InvalidAnnotation"), "Incorrect route admit reason")

		})
		/*It("Check GSLB Support for Routes", func() {
					var configCR *cisapiv1.DeployConfig
					configSpec := cisapiv1.DeployConfigSpec{}
					crName := "escm"
					crNamespace := "kube-system"
					mockCtlr.CISConfigCRKey = crNamespace + "/" + crName
					extConfig := `
		{
		    "baseRouteSpec": {
		        "tlsCipher": {
		            "tlsVersion": 1.2
		        }
		    },
		    "extendedRouteSpec": [
		        {
		            "namespace": "default",
		            "vserverAddr": "10.8.3.11",
		            "vserverName": "nextgenroutes",
		            "allowOverride": true
		        },
		        {
		            "namespace": "test",
		            "vserverAddr": "10.8.3.12",
		            "allowOverride": true,
		            "bigIpPartition": "dev"
		        }
		    ]
		}
		`
					es := cisapiv1.ExtendedSpec{}
					//log.Debugf("GCM: %v", cm.Data)
					_ = json.Unmarshal([]byte(extConfig), &es)
					configSpec.ExtendedSpec = es
					configSpec.BigIpConfig = []cisapiv1.BigIpConfig{bigIpConfig}
					configCR = test.NewConfigCR(
						crName,
						crNamespace,
						configSpec)
					err, isProcessed := mockCtlr.processConfigCR(configCR, false)
					Expect(err).To(BeNil())
					Expect(isProcessed).To(BeTrue())

					namespace1 := "default"
					namespace2 := "test"
					spec1 := routeapi.RouteSpec{
						Host: "pytest-foo-1.com",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "foo",
						},
						TLS: &routeapi.TLSConfig{Termination: "edge"},
					}
					spec2 := routeapi.RouteSpec{
						Host: "pytest-bar-1.com",
						To: routeapi.RouteTargetReference{
							Kind: "Service",
							Name: "bar",
						},
						TLS: &routeapi.TLSConfig{Termination: "edge"},
					}
					fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
						{Port: 8080, NodePort: 38001},
						{Port: 9090, NodePort: 39001}}
					foo := test.NewService("foo", "1", namespace1, "NodePort", fooPorts)
					mockCtlr.addService(foo)
					fooIps := []string{"10.1.1.1"}
					fooEndpts := test.NewEndpoints(
						"foo", "1", "node0", namespace1, fooIps, []string{},
						convertSvcPortsToEndpointPorts(fooPorts))
					mockCtlr.addEndpoints(fooEndpts)

					//Add new Route
					annotation1 := make(map[string]string)
					annotation1[F5ServerSslProfileAnnotation] = "/Common/serverssl"
					annotation1[F5ClientSslProfileAnnotation] = "/Common/clientssl"
					route1 := test.NewRoute("route1", "1", namespace1, spec1, annotation1)
					mockCtlr.addRoute(route1)
					mockCtlr.resources.invertedNamespaceLabelMap[namespace1] = namespace1
					err = mockCtlr.processRoutes(namespace1, false)

					bar := test.NewService("bar", "1", namespace2, "NodePort", fooPorts)
					mockCtlr.addService(bar)
					barIPs := []string{"10.1.1.1"}
					barEndpts := test.NewEndpoints(
						"bar", "1", "node0", namespace2, barIPs, []string{},
						convertSvcPortsToEndpointPorts(fooPorts))
					mockCtlr.addEndpoints(barEndpts)

					//Add new Route
					annotation2 := make(map[string]string)
					annotation2[F5ServerSslProfileAnnotation] = "/Common/serverssl"
					annotation2[F5ClientSslProfileAnnotation] = "/Common/clientssl"
					route2 := test.NewRoute("route2", "1", namespace2, spec2, annotation2)
					mockCtlr.addRoute(route2)
					mockCtlr.resources.invertedNamespaceLabelMap[namespace2] = namespace2
					err = mockCtlr.processRoutes(namespace2, false)

					newEDNS := test.NewExternalDNS(
						"SampleEDNS",
						"default",
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
					//Process ENDS with non-matching domain
					mockCtlr.addEDNS(newEDNS)
					mockCtlr.processExternalDNS(newEDNS, false)
					gtmConfig := mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					DEFAULT_GTM_PARTITION = DEFAULT_GTM_PARTITION + "_gtm"
					Expect(len(gtmConfig)).To(Equal(1))
					Expect(len(gtmConfig["test.com"].Pools)).To(Equal(1))
					// No pool member should be present
					Expect(len(gtmConfig["test.com"].Pools[0].Members)).To(Equal(0))

					//delete EDNS
					mockCtlr.deleteEDNS(newEDNS)
					mockCtlr.processExternalDNS(newEDNS, true)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(0))

					// Modify EDNS with matching domain and create again
					mockCtlr.addEDNS(newEDNS)
					newEDNS.Spec.DomainName = "pytest-foo-1.com"
					mockCtlr.processExternalDNS(newEDNS, false)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(1))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					// Pool member should be present
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools[0].Members)).To(Equal(1))

					// Delete domain matching route
					mockCtlr.deleteRoute(route1)
					mockCtlr.deleteHostPathMapEntry(route1)
					mockCtlr.processRoutes(namespace1, false)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(1))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					// No pool member should be present
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools[0].Members)).To(Equal(0))

					// Recreate route
					mockCtlr.addRoute(route1)
					mockCtlr.resources.invertedNamespaceLabelMap[namespace1] = namespace1
					err = mockCtlr.processRoutes(namespace1, false)
					Expect(len(gtmConfig)).To(Equal(1))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools[0].Members)).To(Equal(1))

					//Update route host
					route1.Spec.Host = "pytest-foo-2.com"
					mockCtlr.updateRoute(route1)
					var key string
					if route1.Spec.Path == "/" || len(route1.Spec.Path) == 0 {
						key = route1.Spec.Host + "/"
					} else {
						key = route1.Spec.Host + route1.Spec.Path
					}
					mockCtlr.updateHostPathMap(route1.ObjectMeta.CreationTimestamp, key)
					err = mockCtlr.processRoutes(namespace1, false)
					Expect(len(gtmConfig)).To(Equal(1))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					// There should be no pool members
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools[0].Members)).To(Equal(0))

					//Reset host
					route1.Spec.Host = "pytest-foo-1.com"
					mockCtlr.updateRoute(route1)
					err = mockCtlr.processRoutes(namespace1, false)

					barEDNS := test.NewExternalDNS(
						"barEDNS",
						"default",
						cisapiv1.ExternalDNSSpec{
							DomainName: "pytest-bar-1.com",
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
					//Test with 2nd route with bigIpPartition
					mockCtlr.addEDNS(barEDNS)
					mockCtlr.processExternalDNS(barEDNS, false)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(2))
					Expect(len(gtmConfig["pytest-bar-1.com"].Pools)).To(Equal(1))
					Expect(len(gtmConfig["pytest-bar-1.com"].Pools[0].Members)).To(Equal(1))
					Expect(strings.Contains(gtmConfig["pytest-bar-1.com"].Pools[0].Members[0], "routes_10.8_3_12_dev"))

					mockCtlr.deleteEDNS(barEDNS)
					mockCtlr.processExternalDNS(barEDNS, true)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(1))

					//Remove route group
					extConfig = `
		{
		    "baseRouteSpec": {
		        "tlsCipher": {
		            "tlsVersion": 1.2
		        }
		    },
		    "extendedRouteSpec": [
		        {
		            "namespace": "test",
		            "vserverAddr": "10.8.3.12",
		            "allowOverride": true
		        }
		    ]
		}
		`
					es = cisapiv1.ExtendedSpec{}
					_ = json.Unmarshal([]byte(extConfig), &es)
					configCR.Spec.ExtendedSpec = es
					err, isProcessed = mockCtlr.processConfigCR(configCR, false)
					Expect(err).To(BeNil())
					Expect(isProcessed).To(BeTrue())

					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(1))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					//No pool members should present
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools[0].Members)).To(Equal(0))

					// EDNS with Monitor type other than http/https
					barEDNS.Spec.Pools[0].Monitor.Type = "tcp"
					mockCtlr.addEDNS(barEDNS)
					mockCtlr.processExternalDNS(barEDNS, false)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(2))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					Expect(len(gtmConfig["pytest-bar-1.com"].Pools[0].Members)).To(Equal(1))
					Expect(strings.Contains(gtmConfig["pytest-bar-1.com"].Pools[0].Members[0], "routes_10.8_3_12_dev"))
					Expect(gtmConfig["pytest-bar-1.com"].Pools[0].Monitors[0].Type).To(Equal(barEDNS.Spec.Pools[0].Monitor.Type))

					// EDNS with monitors
					barEDNS.Spec.Pools[0].Monitors = []cisapiv1.Monitor{
						cisapiv1.Monitor{
							Type:     "http",
							Interval: 10,
							Timeout:  10,
						},
					}
					mockCtlr.addEDNS(barEDNS)
					mockCtlr.processExternalDNS(barEDNS, false)
					gtmConfig = mockCtlr.resources.bigIpConfigMap[bigIpConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs
					Expect(len(gtmConfig)).To(Equal(2))
					Expect(len(gtmConfig["pytest-foo-1.com"].Pools)).To(Equal(1))
					Expect(len(gtmConfig["pytest-bar-1.com"].Pools[0].Members)).To(Equal(1))
					Expect(strings.Contains(gtmConfig["pytest-bar-1.com"].Pools[0].Members[0], "routes_10.8_3_12_dev"))
					Expect(gtmConfig["pytest-bar-1.com"].Pools[0].Monitors[0].Type).To(Equal(barEDNS.Spec.Pools[0].Monitors[0].Type))

				})*/
		It("Check Host-Path Map functions", func() {
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			route1 := test.NewRoute("route1", "1", "default", spec1, nil)
			mockCtlr.addRoute(route1)
			// test hostpathMap update function
			oldURI := route1.Spec.Host + route1.Spec.Path
			route1.Spec.Path = "/test"
			newURI := route1.Spec.Host + route1.Spec.Path
			mockCtlr.updateRoute(route1)
			mockCtlr.updateHostPathMap(route1.ObjectMeta.CreationTimestamp, route1.Spec.Host+route1.Spec.Path)
			_, found := mockCtlr.processedHostPath.processedHostPathMap[oldURI]
			Expect(found).To(BeFalse())
			_, found = mockCtlr.processedHostPath.processedHostPathMap[newURI]
			Expect(found).To(BeTrue())
			Expect(len(mockCtlr.processedHostPath.processedHostPathMap)).To(BeEquivalentTo(1))
			mockCtlr.deleteRoute(route1)
		})
		It("Checks whether Forwarding policy is added correctly", func() {
			routeGroup := "default"
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			spec3 := routeapi.RouteSpec{
				Host: "baz.com",
				Path: "/baz",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "baz",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}
			route1 := test.NewRoute("route1", "1", routeGroup, spec1, nil)
			route2 := test.NewRoute("route2", "1", routeGroup, spec2, nil)
			route3 := test.NewRoute("route3", "1", routeGroup, spec3, nil)

			// Resource Config for unsecured virtual server
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_80"
			rsCfg.MetaData.Protocol = HTTP
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTP_PORT)
			// Portstruct for unsecured virtual server
			ps := portStruct{HTTP, DEFAULT_HTTP_PORT}
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = ""
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).To(BeNil())
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = "None"
			route1.Spec.TLS.InsecureEdgeTerminationPolicy = routeapi.InsecureEdgeTerminationPolicyNone
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).To(BeNil())
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = "Allow"
			route1.Spec.TLS.InsecureEdgeTerminationPolicy = routeapi.InsecureEdgeTerminationPolicyAllow
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))
			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = ""
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route2, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))
			Expect(rsCfg.Policies[0].Rules[0].FullURI).To(Equal("foo.com/foo"))

			// HTTP virtual server, secured route, InsecureEdgeTerminationPolicy = ""
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route3, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))

			// ResourceConfig for secured virtual server
			rsCfg = &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_443"
			rsCfg.MetaData.Protocol = HTTPS
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTPS_PORT)
			// Portstruct for secured virtual server
			ps.protocol = HTTPS
			ps.port = DEFAULT_HTTPS_PORT
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(1))
			Expect(rsCfg.Policies[0].Rules[0].FullURI).To(Equal("foo.com/foo"))
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route2, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(2))
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route3, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(rsCfg.Policies).NotTo(BeNil())
			Expect(len(rsCfg.Policies)).To(Equal(1))
			Expect(len(rsCfg.Policies[0].Rules)).To(Equal(3))
			// Check Rules are in sorted order
			Expect(rsCfg.Policies[0].Rules[0].FullURI).To(Equal("bar.com/bar"))
			Expect(rsCfg.Policies[0].Rules[1].FullURI).To(Equal("baz.com/baz"))
			Expect(rsCfg.Policies[0].Rules[2].FullURI).To(Equal("foo.com/foo"))

		})

		It("Check Route A/B Deploy", func() {
			routeGroup := "default"

			mockCtlr.resources.extdSpecMap[routeGroup] = &extendedParsedSpec{
				override: true,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "nextgenroutes",
					VServerAddr:   "10.10.10.10",
					AllowOverride: "False",
				},
				namespaces: []string{routeGroup},
				partition:  "test",
			}

			spec1 := routeapi.RouteSpec{
				Host: "pytest-foo-1.com",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "reencrypt",
					Certificate:              " -----BEGIN CERTIFICATE-----\n      MIIDDjCCAfYCCQCgR208hrCAozANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJV\n      UzELMAkGA1UECAwCQ08xDDAKBgNVBAcMA0JETzELMAkGA1UECwwCY2ExCzAJBgNV\n      BAoMAkY1MB4XDTIyMTAxODA4MDg0NVoXDTIyMTAyMTA4MDg0NVowUDELMAkGA1UE\n      BhMCVVMxCzAJBgNVBAgMAkNPMQwwCgYDVQQHDANCRE8xCzAJBgNVBAoMAkY1MRkw\n      FwYDVQQDDBBweXRlc3QtZm9vLTEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n      MIIBCgKCAQEAy3IHmdvGjR/fSti25e4YKpotbwkG/WOcOkXk+IwJuu14c/4dsDM1\n      7IayBOWuyhxvQUTyIpmNNqkb1PJ1cY1+6eIdecXdFhUPZtKylxE6NhqWtxpYn1jU\n      byiH1iqKS899MjbQ9GUrfBy/SZxwEkupq/WJcdvbtuYClUgMXqAcLpDQFZoPCWn9\n      qkFj3BubkQp2trO+2K4VGURTNixDcSZs+GoTpZQSS1E6KFAFWu8T9WgnWODWZi1D\n      OGoYb0+rgso9qi1FgPNSPbEqgi82917rUobC8qK8TweXL0xq4rgpAv3Ypsc4Mhbx\n      cm9Gh1QflH+MDI3eqYhN9F5oMQYYeH3HKwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB\n      AQCvmFvTHeY5x0MMYR99DmkxwgTKE5yRgUs5X276quCUL/XJezOmLXYmWeuKy3U8\n      Z4L1zkGj4saH9ysZ1PwhHgrBIIfJpsMMFyvA8CHlO0bCBk4q/5vLAGDlsVj6UXx4\n      VZupUmJbapBXIM20WSqDeM6PVlbsBO1t8tJPV+NOYOS+M8muXlotivKUrB2zwggS\n      7+VMgWgJ6Rq4+uPVL+LOYUEY31pUkhUFnxdw9iSwuLiFIT6B9QtwVydXqe82X6KM\n      ncH6TIRTYXmTXy9CU3YqJWGl6E4Bybr6Uzlkyoo1CEKDetbwBrgrEwr8Cs8i/K4C\n      rTbQUqAOMjosET4jarlY9/t0\n      -----END CERTIFICATE-----",
					DestinationCACertificate: " -----BEGIN CERTIFICATE-----\n      MIIDVzCCAj+gAwIBAgIJAPl2S8PFsPkeMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNV\n      BAYTAlVTMQswCQYDVQQIDAJDTzEMMAoGA1UEBwwDQkRPMQswCQYDVQQLDAJjYTEL\n      MAkGA1UECgwCRjUwHhcNMjIwOTIzMTYxMzMxWhcNMjMwOTIzMTYxMzMxWjBCMQsw\n      CQYDVQQGEwJVUzELMAkGA1UECAwCQ08xDDAKBgNVBAcMA0JETzELMAkGA1UECwwC\n      Y2ExCzAJBgNVBAoMAkY1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n      0luQ/n3iC/3kA3RAYveM1hpXsOThcyzb8xT8QoL58i+J2P/pGl+8Ho2HHS+4+jbG\n      7iJ5m46yflLWSLXqSVtvIuEgXDFr8bkLGhuUYZfMQyprzSUN+QNM6EtHsrXSeJGE\n      /qOSOPPm7M2eJoS+DDhiAaTiOAAd2iUJ4bCrsc4RBRuZaXx4Gxcmdk5fqwt5Urqc\n      iNDteplu3UJ4TibP/dTkqEqZ7o6E2kUxzIBjtZqG09cqrygX/ayZYYjuFzl6Ksyp\n      5dUC0TZ2RZwfd7564xBOdCAKcHDgbm7ygP8MMJa2olj04f0d5hikJcFAxVhWePzL\n      BxpDjXNfv6shzshL0StXJQIDAQABo1AwTjAdBgNVHQ4EFgQUdGNL5SrEZp+ukaR/\n      lIken7t1um4wHwYDVR0jBBgwFoAUdGNL5SrEZp+ukaR/lIken7t1um4wDAYDVR0T\n      BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAaO8ZWa/94FvAW8ZcSLooEchWw98G\n      7IK4+nzLo+b4GEKhV9ALH0Cz6+UUW3+9v56kdHTIgDOR7lF5lPyzPTEh4PgpiX8M\n      rmtzqEM3CBJEGNuAaSk4vxNCTVX3vLBqMG53VmWFPuqHqoa46VIV/HzSQVBjJu6x\n      JfjKRDEvsgGSSrv6W/x5getsjIO0SQuuMVH4IJuD3oQWvf5WfYZMf+53ToHSRncy\n      2kiQtgbsxK/KWDix9TM+hhkILFvU/CmpTTweD8hNpCOvF5GLs9lhMVBFc+HJBVtZ\n      qfVuJiZMiyIyaGbxefgz60QgCBuLcyaAVafRH7rSRr43DNP0Pm2k4figzg==\n      -----END CERTIFICATE-----",
					Key:                      "-----BEGIN RSA PRIVATE KEY-----\n      MIIEpAIBAAKCAQEAy3IHmdvGjR/fSti25e4YKpotbwkG/WOcOkXk+IwJuu14c/4d\n      sDM17IayBOWuyhxvQUTyIpmNNqkb1PJ1cY1+6eIdecXdFhUPZtKylxE6NhqWtxpY\n      n1jUbyiH1iqKS899MjbQ9GUrfBy/SZxwEkupq/WJcdvbtuYClUgMXqAcLpDQFZoP\n      CWn9qkFj3BubkQp2trO+2K4VGURTNixDcSZs+GoTpZQSS1E6KFAFWu8T9WgnWODW\n      Zi1DOGoYb0+rgso9qi1FgPNSPbEqgi82917rUobC8qK8TweXL0xq4rgpAv3Ypsc4\n      Mhbxcm9Gh1QflH+MDI3eqYhN9F5oMQYYeH3HKwIDAQABAoIBACLPujk7f/f58i1O\n      c81YNk5j305Wjxmgh8T43Lsiyy9vHuNKIi5aNOnqCmAIJSZ0Qx05/OyqtZ0axqZj\n      bnElswe2JzEFCFWU+POxLdnnmrxTRGLEYVGy03bJyqR81vkt4dBLzOlkvlIYYSrp\n      V8vponjIJOKUqj3bkamVkHhIkUnuM2lXdC30VcWBU5m9S6SuwjNFOLzhrIucXATA\n      vvKH+Bw6tGKI5yE8PkSyW8BCnFg24AF2UQq1k8XvjnT3CTVeCxEZUp+HOt1Y2F25\n      AhqE0viC2KeJtG0y34QKhbxq5gtUljbNCaKUkKJlO4Hu+bGVrZGPmAIEMPwMgX9u\n      JaH2w/ECgYEA63XUA243qlMESfasD2BbIxyO6Wqk47CGZvfj6N66pFQO075Vv3dO\n      IY1ENT/Cd73XE9zxr/9RQ4BG42pWL1/3g1jcpAa+iW2SK1YxaCe3SwSQY+EWuGsY\n      XmhahZ/V7aD5PH4v+ewOG1r6WF5ugwoaaEvn/9/f3At4TszX9/acWbcCgYEA3TFD\n      blSk+iFWjXnYzTTgS+5ZVt2c3Ix4iEY1pCRpcMsCbqx0BiqjXUCtHBDNQ5+LxlyD\n      wLMjcQGGIyfSlLxuXQONRRfo2PZjcYe7JvxsX/FrXTvFi0n+i9o2HM38nH2Un40Z\n      cpr/fpcpvC8kFD20jo/nt8J8OdZT9fZ5WIa2Di0CgYBQQW8sZCrxES7LDxsCerNV\n      umwzvzfIq+iDvEagnxo63LPZFG0hv8aPxRjUlZDxQ3HFwW9Xr8zBFz4SUbJin3E8\n      AdPizLGxIfnKb6yTdcYR+dJFWPlnjolV1HfWR+6g+lc5eUFdDEqapF3kNPuyCoWJ\n      uyWun14sIHS3Vzbdu9767QKBgQDQiTB0pXLAq4upaFYA6bgJflZWMitAN2Mvv1m1\n      Per2vz60zvu4EJziPya1zhVnitTBl9lTZNCmKvSm0lWTiq9WHBIlMOyDGJAaqgfF\n      MriOH9LEHKUatBE7EuhvcbiWZUMoxWNXjFASrjtXwu3181L2ETA6LC7obGvN+ajf\n      0Gl1pQKBgQCAzIzP5ab8vvqwHVhDN+mWfG3vvN3tCI2rL4zv5boO20MqVTxu9i7o\n      e7Zro8EKG/HNmt7hF46vq2OJa5QUpNf6a1II4dRsbbBoFUzGinm41TUENkeMumTU\n      XsGWrknaI+J90tmvkM8rSI1Qjcw1zHUWTyd7blDj/snjb/Qg4v57yw==\n      -----END RSA PRIVATE KEY-----"},
			}
			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
				{Port: 8080, NodePort: 38001},
				{Port: 9090, NodePort: 39001}}
			foo := test.NewService("foo", "1", routeGroup, "NodePort", fooPorts)
			mockCtlr.addService(foo)
			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", routeGroup, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			//Domain Based Route
			annotation1 := make(map[string]string)
			annotation1[F5ServerSslProfileAnnotation] = "/Common/serverssl"
			annotation1[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			annotation1[PodConcurrentConnectionsAnnotation] = "5"
			route1 := test.NewRoute("route1", "1", routeGroup, spec1, annotation1)

			mockCtlr.addRoute(route1)
			mockCtlr.resources.invertedNamespaceLabelMap[routeGroup] = routeGroup
			err := mockCtlr.processRoutes(routeGroup, false)
			parition := mockCtlr.resources.extdSpecMap[routeGroup].partition
			vsName := frameRouteVSName(mockCtlr.resources.extdSpecMap[routeGroup].global.VServerName, mockCtlr.resources.extdSpecMap[routeGroup].global.VServerAddr, portStruct{protocol: "https", port: 443})
			Expect(err).To(BeNil())
			Expect(len(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig[parition].ResourceMap[vsName].IRulesMap) == 1).To(BeTrue())
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap[vsName].Pools[0].ConnectionLimit).
				To(Equal(int32(5)), "pod concurrent connections not processed")

			var alternateBackend []routeapi.RouteTargetReference
			weight := new(int32)
			*weight = 50
			alternateBackend = append(alternateBackend, routeapi.RouteTargetReference{Kind: "Service",
				Name: "foo", Weight: weight})

			spec1.AlternateBackends = alternateBackend
			//Domain based route with alternate backend
			route2 := test.NewRoute("route2", "1", routeGroup, spec1, annotation1)

			mockCtlr.addRoute(route2)
			mockCtlr.resources.invertedNamespaceLabelMap[routeGroup] = routeGroup
			err = mockCtlr.processRoutes(routeGroup, false)
			Expect(err).To(BeNil())
			Expect(len(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig[parition].ResourceMap[vsName].IRulesMap) == 1).To(BeTrue())

			spec2 := routeapi.RouteSpec{
				Host: "pytest-foo-1.com",
				Path: "/first",
				To: routeapi.RouteTargetReference{
					Kind:   "Service",
					Name:   "foo",
					Weight: weight,
				},
				AlternateBackends: alternateBackend,
				TLS: &routeapi.TLSConfig{Termination: "reencrypt",
					Certificate:              " -----BEGIN CERTIFICATE-----\n      MIIDDjCCAfYCCQCgR208hrCAozANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJV\n      UzELMAkGA1UECAwCQ08xDDAKBgNVBAcMA0JETzELMAkGA1UECwwCY2ExCzAJBgNV\n      BAoMAkY1MB4XDTIyMTAxODA4MDg0NVoXDTIyMTAyMTA4MDg0NVowUDELMAkGA1UE\n      BhMCVVMxCzAJBgNVBAgMAkNPMQwwCgYDVQQHDANCRE8xCzAJBgNVBAoMAkY1MRkw\n      FwYDVQQDDBBweXRlc3QtZm9vLTEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n      MIIBCgKCAQEAy3IHmdvGjR/fSti25e4YKpotbwkG/WOcOkXk+IwJuu14c/4dsDM1\n      7IayBOWuyhxvQUTyIpmNNqkb1PJ1cY1+6eIdecXdFhUPZtKylxE6NhqWtxpYn1jU\n      byiH1iqKS899MjbQ9GUrfBy/SZxwEkupq/WJcdvbtuYClUgMXqAcLpDQFZoPCWn9\n      qkFj3BubkQp2trO+2K4VGURTNixDcSZs+GoTpZQSS1E6KFAFWu8T9WgnWODWZi1D\n      OGoYb0+rgso9qi1FgPNSPbEqgi82917rUobC8qK8TweXL0xq4rgpAv3Ypsc4Mhbx\n      cm9Gh1QflH+MDI3eqYhN9F5oMQYYeH3HKwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB\n      AQCvmFvTHeY5x0MMYR99DmkxwgTKE5yRgUs5X276quCUL/XJezOmLXYmWeuKy3U8\n      Z4L1zkGj4saH9ysZ1PwhHgrBIIfJpsMMFyvA8CHlO0bCBk4q/5vLAGDlsVj6UXx4\n      VZupUmJbapBXIM20WSqDeM6PVlbsBO1t8tJPV+NOYOS+M8muXlotivKUrB2zwggS\n      7+VMgWgJ6Rq4+uPVL+LOYUEY31pUkhUFnxdw9iSwuLiFIT6B9QtwVydXqe82X6KM\n      ncH6TIRTYXmTXy9CU3YqJWGl6E4Bybr6Uzlkyoo1CEKDetbwBrgrEwr8Cs8i/K4C\n      rTbQUqAOMjosET4jarlY9/t0\n      -----END CERTIFICATE-----",
					DestinationCACertificate: " -----BEGIN CERTIFICATE-----\n      MIIDVzCCAj+gAwIBAgIJAPl2S8PFsPkeMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNV\n      BAYTAlVTMQswCQYDVQQIDAJDTzEMMAoGA1UEBwwDQkRPMQswCQYDVQQLDAJjYTEL\n      MAkGA1UECgwCRjUwHhcNMjIwOTIzMTYxMzMxWhcNMjMwOTIzMTYxMzMxWjBCMQsw\n      CQYDVQQGEwJVUzELMAkGA1UECAwCQ08xDDAKBgNVBAcMA0JETzELMAkGA1UECwwC\n      Y2ExCzAJBgNVBAoMAkY1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n      0luQ/n3iC/3kA3RAYveM1hpXsOThcyzb8xT8QoL58i+J2P/pGl+8Ho2HHS+4+jbG\n      7iJ5m46yflLWSLXqSVtvIuEgXDFr8bkLGhuUYZfMQyprzSUN+QNM6EtHsrXSeJGE\n      /qOSOPPm7M2eJoS+DDhiAaTiOAAd2iUJ4bCrsc4RBRuZaXx4Gxcmdk5fqwt5Urqc\n      iNDteplu3UJ4TibP/dTkqEqZ7o6E2kUxzIBjtZqG09cqrygX/ayZYYjuFzl6Ksyp\n      5dUC0TZ2RZwfd7564xBOdCAKcHDgbm7ygP8MMJa2olj04f0d5hikJcFAxVhWePzL\n      BxpDjXNfv6shzshL0StXJQIDAQABo1AwTjAdBgNVHQ4EFgQUdGNL5SrEZp+ukaR/\n      lIken7t1um4wHwYDVR0jBBgwFoAUdGNL5SrEZp+ukaR/lIken7t1um4wDAYDVR0T\n      BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAaO8ZWa/94FvAW8ZcSLooEchWw98G\n      7IK4+nzLo+b4GEKhV9ALH0Cz6+UUW3+9v56kdHTIgDOR7lF5lPyzPTEh4PgpiX8M\n      rmtzqEM3CBJEGNuAaSk4vxNCTVX3vLBqMG53VmWFPuqHqoa46VIV/HzSQVBjJu6x\n      JfjKRDEvsgGSSrv6W/x5getsjIO0SQuuMVH4IJuD3oQWvf5WfYZMf+53ToHSRncy\n      2kiQtgbsxK/KWDix9TM+hhkILFvU/CmpTTweD8hNpCOvF5GLs9lhMVBFc+HJBVtZ\n      qfVuJiZMiyIyaGbxefgz60QgCBuLcyaAVafRH7rSRr43DNP0Pm2k4figzg==\n      -----END CERTIFICATE-----",
					Key:                      "-----BEGIN RSA PRIVATE KEY-----\n      MIIEpAIBAAKCAQEAy3IHmdvGjR/fSti25e4YKpotbwkG/WOcOkXk+IwJuu14c/4d\n      sDM17IayBOWuyhxvQUTyIpmNNqkb1PJ1cY1+6eIdecXdFhUPZtKylxE6NhqWtxpY\n      n1jUbyiH1iqKS899MjbQ9GUrfBy/SZxwEkupq/WJcdvbtuYClUgMXqAcLpDQFZoP\n      CWn9qkFj3BubkQp2trO+2K4VGURTNixDcSZs+GoTpZQSS1E6KFAFWu8T9WgnWODW\n      Zi1DOGoYb0+rgso9qi1FgPNSPbEqgi82917rUobC8qK8TweXL0xq4rgpAv3Ypsc4\n      Mhbxcm9Gh1QflH+MDI3eqYhN9F5oMQYYeH3HKwIDAQABAoIBACLPujk7f/f58i1O\n      c81YNk5j305Wjxmgh8T43Lsiyy9vHuNKIi5aNOnqCmAIJSZ0Qx05/OyqtZ0axqZj\n      bnElswe2JzEFCFWU+POxLdnnmrxTRGLEYVGy03bJyqR81vkt4dBLzOlkvlIYYSrp\n      V8vponjIJOKUqj3bkamVkHhIkUnuM2lXdC30VcWBU5m9S6SuwjNFOLzhrIucXATA\n      vvKH+Bw6tGKI5yE8PkSyW8BCnFg24AF2UQq1k8XvjnT3CTVeCxEZUp+HOt1Y2F25\n      AhqE0viC2KeJtG0y34QKhbxq5gtUljbNCaKUkKJlO4Hu+bGVrZGPmAIEMPwMgX9u\n      JaH2w/ECgYEA63XUA243qlMESfasD2BbIxyO6Wqk47CGZvfj6N66pFQO075Vv3dO\n      IY1ENT/Cd73XE9zxr/9RQ4BG42pWL1/3g1jcpAa+iW2SK1YxaCe3SwSQY+EWuGsY\n      XmhahZ/V7aD5PH4v+ewOG1r6WF5ugwoaaEvn/9/f3At4TszX9/acWbcCgYEA3TFD\n      blSk+iFWjXnYzTTgS+5ZVt2c3Ix4iEY1pCRpcMsCbqx0BiqjXUCtHBDNQ5+LxlyD\n      wLMjcQGGIyfSlLxuXQONRRfo2PZjcYe7JvxsX/FrXTvFi0n+i9o2HM38nH2Un40Z\n      cpr/fpcpvC8kFD20jo/nt8J8OdZT9fZ5WIa2Di0CgYBQQW8sZCrxES7LDxsCerNV\n      umwzvzfIq+iDvEagnxo63LPZFG0hv8aPxRjUlZDxQ3HFwW9Xr8zBFz4SUbJin3E8\n      AdPizLGxIfnKb6yTdcYR+dJFWPlnjolV1HfWR+6g+lc5eUFdDEqapF3kNPuyCoWJ\n      uyWun14sIHS3Vzbdu9767QKBgQDQiTB0pXLAq4upaFYA6bgJflZWMitAN2Mvv1m1\n      Per2vz60zvu4EJziPya1zhVnitTBl9lTZNCmKvSm0lWTiq9WHBIlMOyDGJAaqgfF\n      MriOH9LEHKUatBE7EuhvcbiWZUMoxWNXjFASrjtXwu3181L2ETA6LC7obGvN+ajf\n      0Gl1pQKBgQCAzIzP5ab8vvqwHVhDN+mWfG3vvN3tCI2rL4zv5boO20MqVTxu9i7o\n      e7Zro8EKG/HNmt7hF46vq2OJa5QUpNf6a1II4dRsbbBoFUzGinm41TUENkeMumTU\n      XsGWrknaI+J90tmvkM8rSI1Qjcw1zHUWTyd7blDj/snjb/Qg4v57yw==\n      -----END RSA PRIVATE KEY-----"},
			}

			route3 := test.NewRoute("route3", "1", routeGroup, spec2, annotation1)
			mockCtlr.addRoute(route3)
			err = mockCtlr.processRoutes(routeGroup, false)
			Expect(err).To(BeNil())

			abPathIRule := getRSCfgResName(vsName, ABPathIRuleName)
			Expect(len(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap[vsName].IRulesMap) == 2).To(BeTrue())
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap[vsName].IRulesMap[NameRef{abPathIRule, parition}].Name == abPathIRule).To(BeTrue())

		})

		It("Check Route TLS", func() {

			annotation1 := make(map[string]string)
			annotation1[F5ServerSslProfileAnnotation] = "/Common/serverssl"
			annotation1[F5ClientSslProfileAnnotation] = "/Common/clientssl"

			clientSSLAnnotation := make(map[string]string)
			clientSSLAnnotation[F5ClientSslProfileAnnotation] = "/Common/clientssl"

			serverSSLAnnotation := make(map[string]string)
			serverSSLAnnotation[F5ServerSslProfileAnnotation] = "/Common/serverssl"

			extdSpec := &cisapiv1.ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				AllowOverride: "0",
			}

			//with no tls defined
			extdSpec1 := &cisapiv1.ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				AllowOverride: "0",
			}

			// with only client tls defined
			extdSpec2 := &cisapiv1.ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				AllowOverride: "0",
			}

			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge"},
			}

			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: "reencrypt"},
			}

			routeGroup := "default"

			route1 := test.NewRoute("route1", "1", routeGroup, spec1, annotation1)
			route2 := test.NewRoute("route2", "2", routeGroup, spec2, annotation1)
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_443"
			rsCfg.MetaData.Protocol = HTTPS
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTPS_PORT)
			ps := portStruct{HTTP, DEFAULT_HTTP_PORT}
			// Portstruct for secured virtual server
			ps.protocol = HTTPS
			ps.port = DEFAULT_HTTPS_PORT
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
			clientSSLs := []string{"\\Common\\clientssl"}
			sslProfiles := rgPlcSSLProfiles{
				clientSSLs: clientSSLs,
			}

			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
				{Port: 8080, NodePort: 38001},
				{Port: 9090, NodePort: 39001}}
			foo := test.NewService("bar", "1", routeGroup, "NodePort", fooPorts)
			mockCtlr.addService(foo)
			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", routeGroup, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			route3 := test.NewRoute("route1", "1", routeGroup, spec2, nil)
			mockCtlr.addRoute(route3)
			// server ssl profile missing in policy. invalid route
			Expect(mockCtlr.checkValidRoute(route3, sslProfiles)).To(BeFalse())
			sslProfiles.serverSSLs = []string{"\\Common\\plc-serverssl"}
			//  valid route
			Expect(mockCtlr.checkValidRoute(route3, sslProfiles)).To(BeTrue())
			sslProfiles.clientSSLs = []string{}
			// server client profile missing in policy and no profile annotations invalid route
			Expect(mockCtlr.checkValidRoute(route3, sslProfiles)).To(BeFalse())
			annotations := make(map[string]string)
			annotations[F5ServerSslProfileAnnotation] = "/Common/serverssl"
			annotations[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			route3.Annotations = annotations
			// with annotations added route should get processed
			Expect(mockCtlr.checkValidRoute(route3, sslProfiles)).To(BeTrue())
			delete(annotations, F5ServerSslProfileAnnotation)
			// invalid
			Expect(mockCtlr.checkValidRoute(route3, sslProfiles)).To(BeFalse())
			sslProfiles.clientSSLs = []string{"\\Common\\plc-clientssl"}
			// with ssl profile added route should get processed
			Expect(mockCtlr.checkValidRoute(route3, sslProfiles)).To(BeTrue())
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 443}, ps)).To(BeNil())

			checkSSLProfiles := func(profiles ProfileRefs, profile string, ctxt string) bool {
				for _, v := range profiles {
					if v.Name == profile && v.Context == ctxt {
						return true
					}
				}
				return false
			}

			// missing client ssl profile
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route3,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{clientSSLs: []string{"\\Common\\plc-serverssl"}})).To(BeFalse())

			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route3,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				sslProfiles)).To(BeTrue())
			Expect(checkSSLProfiles(rsCfg.Virtual.Profiles, "\\Common\\plc-serverssl", "serverside")).To(BeTrue())
			Expect(checkSSLProfiles(rsCfg.Virtual.Profiles, "\\Common\\plc-clientssl", "clientside")).To(BeTrue())

			annotations[F5ServerSslProfileAnnotation] = "/Common/serverssl"
			annotations[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			route3.Annotations = annotations
			rsCfg.Virtual.Profiles = ProfileRefs{}
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route3,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeTrue())
			Expect(checkSSLProfiles(rsCfg.Virtual.Profiles, "\\Common\\serverssl", "serverside")).To(BeFalse())
			Expect(checkSSLProfiles(rsCfg.Virtual.Profiles, "\\Common\\clientssl", "clientside")).To(BeFalse())

			//for edge route, and big ip reference in global config map - It should pass
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route1,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeTrue())

			//for edge route and global config map without client ssl profile - It should fail
			route1.Annotations = serverSSLAnnotation
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route1,
				extdSpec1.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeFalse())

			//for re-encrypt route, and big ip reference in global config map - It should pass
			route2.Annotations = annotation1
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route2,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeTrue())

			//for re encrypt route and global config map without server ssl profile - It should fail
			route2.Annotations = clientSSLAnnotation
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route2,
				extdSpec2.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeFalse())
		})

		It("Verify NextGenRoutes K8S Secret as TLS certs", func() {
			mockCtlr.resources = &ResourceStore{
				supplementContextCache: supplementContextCache{
					baseRouteConfig: cisapiv1.BaseRouteConfig{
						TLSCipher: cisapiv1.TLSCipher{
							TLSVersion:  "1.2",
							Ciphers:     "DEFAULT",
							CipherGroup: "/Common/f5-default",
						},
						DefaultTLS:              cisapiv1.DefaultSSLProfile{},
						DefaultRouteGroupConfig: cisapiv1.DefaultRouteGroupConfig{},
					},
				},
			}
			mockCtlr.resources.poolMemCache = make(PoolMemberCache)
			namespace := "default"
			data := make(map[string][]byte)
			data["tls.key"] = []byte{}
			data["tls.crt"] = []byte{}
			clientssl := &v1.Secret{
				TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "clientssl", Namespace: namespace},
				Data:       data,
			}
			serverssl := &v1.Secret{
				TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "serverssl", Namespace: namespace},
				Data:       data,
			}
			mockCtlr.comInformers["default"].secretsInformer.GetStore().Add(clientssl)
			mockCtlr.comInformers["default"].secretsInformer.GetStore().Add(serverssl)

			annotation1 := make(map[string]string)
			annotation1[F5ServerSslProfileAnnotation] = "serverssl"
			annotation1[F5ClientSslProfileAnnotation] = "clientssl"

			clientSSLAnnotation := make(map[string]string)
			clientSSLAnnotation[F5ClientSslProfileAnnotation] = "clientssl"

			serverSSLAnnotation := make(map[string]string)
			serverSSLAnnotation[F5ServerSslProfileAnnotation] = "serverssl"

			extdSpec := &cisapiv1.ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				AllowOverride: "0",
			}

			//with no tls defined
			extdSpec1 := &cisapiv1.ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				AllowOverride: "0",
			}

			// with only client tls defined
			extdSpec2 := &cisapiv1.ExtendedRouteGroupSpec{
				VServerName:   "defaultServer",
				VServerAddr:   "10.8.3.11",
				AllowOverride: "0",
			}

			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge"},
			}

			spec2 := routeapi.RouteSpec{
				Host: "bar.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				TLS: &routeapi.TLSConfig{Termination: "reencrypt"},
			}

			routeGroup := "default"

			route1 := test.NewRoute("route1", "1", routeGroup, spec1, annotation1)
			route2 := test.NewRoute("route2", "2", routeGroup, spec2, annotation1)
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_443"
			rsCfg.MetaData.Protocol = HTTPS
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTPS_PORT)
			ps := portStruct{HTTP, DEFAULT_HTTP_PORT}
			// Portstruct for secured virtual server
			ps.protocol = HTTPS
			ps.port = DEFAULT_HTTPS_PORT
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
			rsCfg.customProfiles = make(map[SecretKey]CustomProfile)
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 443}, ps)).To(BeNil())

			//for edge route, and k8s secret as TLS certs in global config map - It should pass
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route1,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeTrue())

			//for edge route and global config map without client ssl profile - It should fail
			route1.Annotations = serverSSLAnnotation
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route1,
				extdSpec1.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeFalse())

			//for re-encrypt route, and k8s secret as TLS certs in global config map - It should pass
			route2.Annotations = annotation1
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route2,
				extdSpec.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeTrue())

			//for re encrypt route and global config map without server ssl profile - It should fail
			route2.Annotations = clientSSLAnnotation
			Expect(mockCtlr.handleRouteTLS(
				rsCfg,
				route2,
				extdSpec2.VServerAddr,
				intstr.IntOrString{IntVal: 443},
				rgPlcSSLProfiles{})).To(BeFalse())

			// Verify that getRouteGroupForSecret fetches the z routeGroup on k8s secret update
			// Prepare extdSpecMap that holds all the
			mockCtlr.resources.extdSpecMap = make(map[string]*extendedParsedSpec)
			mockCtlr.resources.extdSpecMap[routeGroup] = &extendedParsedSpec{
				global: &cisapiv1.ExtendedRouteGroupSpec{VServerName: "default"},
			}
			mockCtlr.resources.extdSpecMap["test1"] = &extendedParsedSpec{
				global: &cisapiv1.ExtendedRouteGroupSpec{VServerName: "test1"},
			}
			mockCtlr.resources.extdSpecMap["test2"] = &extendedParsedSpec{
				global: &cisapiv1.ExtendedRouteGroupSpec{VServerName: "test2"},
			}
			// Prepare invertedNamespaceLabelMap that maps namespaces to routeGroup
			mockCtlr.resources.invertedNamespaceLabelMap = make(map[string]string)
			mockCtlr.resources.invertedNamespaceLabelMap[routeGroup] = routeGroup
			mockCtlr.resources.invertedNamespaceLabelMap["test2"] = routeGroup
			mockCtlr.resources.invertedNamespaceLabelMap["test1"] = "test1"
			// get routeGroup clientssl secret which belongs to default namespace
			Expect(mockCtlr.getRouteGroupForSecret(clientssl)).To(Equal(routeGroup))
			// get routeGroup clientssl secret which belongs to test3 namespace
			Expect(mockCtlr.getRouteGroupForSecret(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "clientssl",
				Namespace: "test3"}})).To(Equal(""))
			// Needs to be handled
			// get routeGroup clientssl1 secret which belongs to default namespace
			//Expect(mockCtlr.getRouteGroupForSecret(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "clientssl1",
			//	Namespace: "default"}})).To(Equal(""))

		})
		It("Verify Routes with Different scenarios", func() {
			ports := []portStruct{
				{
					protocol: "http",
					port:     DEFAULT_HTTP_PORT,
				},
			}
			secureRoute := *rt
			secureRoute.Spec.TLS = &routeapi.TLSConfig{}
			secureRoute.Spec.TLS.Termination = TLSReencrypt
			secureRoute.Spec.TLS.InsecureEdgeTerminationPolicy = routeapi.InsecureEdgeTerminationPolicyAllow

			mockCtlr.addRoute(rt)
			rsKey := fmt.Sprintf("%v/%v", "test1", rt.Name)
			route := mockCtlr.fetchRoute(rsKey)
			//Invalid Namespace
			Expect(route).To(BeNil())

			rsKey = fmt.Sprintf("%v/%v", "test", "")
			route = mockCtlr.fetchRoute(rsKey)
			Expect(route).To(BeNil())

			rsKey = fmt.Sprintf("%v/%v", rt.Namespace, rt.Name)
			route = mockCtlr.fetchRoute(rsKey)
			Expect(route).ToNot(BeNil())
			Expect(mockCtlr.GetHostFromHostPath(rt.Spec.Host)).To(Equal("foo.com"))
			Expect(isPassthroughRoute(rt)).To(BeFalse())
			Expect(doRoutesHandleHTTP([]*routeapi.Route{rt})).To(BeTrue())
			Expect(doRoutesHandleHTTP([]*routeapi.Route{&secureRoute})).To(BeTrue())
			secureRoute.Namespace = "test1"
			mockCtlr.getServicePort(&secureRoute)

			// Invalid Route Key
			mockCtlr.eraseRouteAdmitStatus("test")
			// Invalid Route Key
			mockCtlr.updateRouteAdmitStatus("test", "", "", v1.ConditionTrue)
			Expect(getVirtualPortsForRoutes([]*routeapi.Route{rt})).To(Equal(ports))
			secureRoute.Namespace = "test"
			mockCtlr.getServicePort(&secureRoute)

			rt.Spec.Port = &routeapi.RoutePort{TargetPort: intstr.IntOrString{StrVal: "http"}}
			mockCtlr.getServicePort(rt)
		})

		It("Verify Routes with WAF", func() {
			var override = false
			mockCtlr.resources.extdSpecMap[ns] = &extendedParsedSpec{
				override: override,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "samplevs",
					VServerAddr:   "10.10.10.10",
					AllowOverride: "False",
				},
				namespaces: []string{ns},
				partition:  "test",
			}
			tlsConfig := &routeapi.TLSConfig{}
			tlsConfig.Termination = TLSEdge
			annotation1 := make(map[string]string)
			annotation1[F5VsWAFPolicy] = "/Common/WAF_Policy1"
			annotation1[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: tlsConfig,
			}

			spec2 := routeapi.RouteSpec{
				Host: "foo2.com",
				Path: "/foo2",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
			}
			route1 := test.NewRoute("route1", "1", ns, spec1, annotation1)
			mockCtlr.addRoute(route1)

			route2 := test.NewRoute("route2", "1", ns, spec2, nil)
			mockCtlr.addRoute(route2)

			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
				{Port: 8080, NodePort: 38001},
				{Port: 9090, NodePort: 39001}}
			foo := test.NewService("foo", "1", ns, "NodePort", fooPorts)
			mockCtlr.addService(foo)
			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", ns, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			mockCtlr.resources.invertedNamespaceLabelMap[ns] = ns

			err := mockCtlr.processRoutes(ns, false)
			Expect(err).To(BeNil(), "Failed to process routes")
			Expect(len(mockCtlr.Controller.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["samplevs_443"].Policies)).
				To(BeNumerically(">", 0), "Policy should not be empty")
			createdPolicies := mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["samplevs_443"].Policies

			checkWAFRules := func(policies Policies) bool {
				defaultWAFDisableRule := false
				for _, policy := range createdPolicies {
					for _, rule := range policy.Rules {
						if rule.Name == "openshift_route_waf_disable" {
							defaultWAFDisableRule = true
						}
						wafRule := false
						for _, action := range rule.Actions {
							if action.WAF {
								wafRule = true
							}
						}
						if !wafRule {
							return false
						}
					}
				}
				return defaultWAFDisableRule
			}
			Expect(checkWAFRules(createdPolicies)).To(BeTrue(), "WAF should be added in rules")
		})

	})

	Describe("Extended Spec ConfigCR", func() {
		var configCR *cisapiv1.DeployConfig
		configSpec := cisapiv1.DeployConfigSpec{}
		BeforeEach(func() {
			crName := "escm"
			crNamespace := "system"
			mockCtlr.CISConfigCRKey = crNamespace + "/" + crName
			configCR = test.NewConfigCR(
				crName,
				crNamespace,
				configSpec)
		})

		It("Extended Route Spec Global", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			extConfig = `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": "invalid"
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok = mockCtlr.processConfigCR(configCR, false)
			Expect(err).ToNot(BeNil(), "invalid allowOverride value")
			Expect(ok).To(BeFalse())

			extConfig = `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true,
            "vserverName": "newroutes"
        }
    ]
}
`
			es = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok = mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended Route Spec Allow local", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			var localConfigCR *cisapiv1.DeployConfig
			var localConfigSpec cisapiv1.DeployConfigSpec
			localExtConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.110",
            "vserverName": "nextgenroutes"
        }
    ]
}
`
			localEs := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigSpec.ExtendedSpec = localEs
			localConfigCR = test.NewConfigCR(
				"localESCR",
				"default",
				localConfigSpec)
			err, ok = mockCtlr.processConfigCR(localConfigCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended Route Spec Do not Allow local", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": false
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": false
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			var localConfigCR *cisapiv1.DeployConfig
			var localConfigSpec cisapiv1.DeployConfigSpec
			localExtConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.110",
            "vserverName": "nextgenroutes"
        }
    ]
}
`
			localEs := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigSpec.ExtendedSpec = localEs
			localConfigCR = test.NewConfigCR(
				"localESCR",
				"default",
				localConfigSpec)
			err, ok = mockCtlr.processConfigCR(localConfigCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended Route Spec Allow local Update with out spec change", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			var localConfigCR *cisapiv1.DeployConfig
			var localConfigSpec cisapiv1.DeployConfigSpec
			localExtConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.110",
            "vserverName": "nextgenroutes"
        }
    ]
}
`
			localEs := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigSpec.ExtendedSpec = localEs
			localConfigCR = test.NewConfigCR(
				"localESCR",
				"default",
				localConfigSpec)

			err, ok = mockCtlr.processConfigCR(localConfigCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			localExtConfig = `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverName": "nextgenroutes",
            "vserverAddr": "10.8.3.110"
        }
    ]
}
`
			localEs = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigCR.Spec.ExtendedSpec = localEs
			err, ok = mockCtlr.processConfigCR(localConfigCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Extended local Route Spec pickup alternate DeployConfig CR when latest gets deleted", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			namespace := "default"
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			var localConfigCR1 *cisapiv1.DeployConfig
			var localConfigSpec cisapiv1.DeployConfigSpec
			localExtConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.110",
            "vserverName": "nextgenroutes"
        }
    ]
}
`
			localEs := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigSpec.ExtendedSpec = localEs
			localConfigCR1 = test.NewConfigCR(
				"localESCR",
				"default",
				localConfigSpec)
			localExtConfig = `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.110",
            "vserverName": "newvs"
        }
    ]
}
`
			localEs = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigSpec.ExtendedSpec = localEs
			localConfigCR2 := test.NewConfigCR(
				"localESCR2",
				"default",
				localConfigSpec)
			localExtConfig = `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.110",
            "vserverName": "newlatest"
        }
    ]
}
`
			localEs = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(localExtConfig), &localEs)
			localConfigSpec.ExtendedSpec = localEs
			localConfigCR3 := test.NewConfigCR(
				"localESCR3",
				"default",
				localConfigSpec)

			_ = mockCtlr.comInformers[namespace].configCRInformer.GetIndexer().Add(localConfigCR1)
			_ = mockCtlr.comInformers[namespace].configCRInformer.GetIndexer().Add(localConfigCR2)
			_ = mockCtlr.comInformers[namespace].configCRInformer.GetIndexer().Add(localConfigCR3)
			err, ok = mockCtlr.processConfigCR(localConfigCR3, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			Expect(mockCtlr.resources.extdSpecMap[namespace].local.VServerName).To(Equal("newlatest"), "Spec from wrong DeployConfig CR")

			_ = mockCtlr.comInformers[namespace].configCRInformer.GetIndexer().Delete(localConfigCR3)
			err, ok = mockCtlr.processConfigCR(localConfigCR3, true)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Operational Specs on DeployConfig CR Create/Update/Delete events", func() {
			cachedExtdSpecMap := make(map[string]*extendedParsedSpec)
			newExtdSpecMap := make(map[string]*extendedParsedSpec)

			newExtdSpecMap["default"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "defaultServer",
					VServerAddr:   "10.8.3.11",
					AllowOverride: "0",
				},
			}
			newExtdSpecMap["new"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "newServer",
					VServerAddr:   "10.8.3.12",
					AllowOverride: "f",
				},
			}
			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs := getOperationalExtendedConfigCRSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(BeZero())
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(Equal(2))

			cachedExtdSpecMap["default"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "defaultServer",
					VServerAddr:   "10.8.3.11",
					AllowOverride: "false",
				},
			}
			cachedExtdSpecMap["new"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "newServer",
					VServerAddr:   "10.8.3.12",
					AllowOverride: "FALSE",
				},
			}

			newExtdSpecMap["default"].global.Policy = "test/policy1"
			newExtdSpecMap["new"].global.Policy = "test/policy1"

			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigCRSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(BeZero())
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(Equal(2))
			Expect(len(createdSpecs)).To(BeZero())

			newExtdSpecMap["default"].global.VServerName = "defaultServer1"
			newExtdSpecMap["new"].global.VServerName = "newServer1"

			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigCRSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(BeZero())
			Expect(len(modifiedSpecs)).To(Equal(2))
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(BeZero())

			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigCRSpecs(
				cachedExtdSpecMap, newExtdSpecMap, true,
			)
			Expect(len(deletedSpecs)).To(Equal(2))
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(BeZero())

			delete(newExtdSpecMap, "new")
			newExtdSpecMap["default"] = &extendedParsedSpec{
				override: false,
				local:    nil,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "defaultServer",
					VServerAddr:   "10.8.3.11",
					AllowOverride: "false",
				},
			}
			deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs = getOperationalExtendedConfigCRSpecs(
				cachedExtdSpecMap, newExtdSpecMap, false,
			)
			Expect(len(deletedSpecs)).To(Equal(1))
			Expect(len(modifiedSpecs)).To(BeZero())
			Expect(len(updatedSpecs)).To(BeZero())
			Expect(len(createdSpecs)).To(BeZero())
		})

		It("Global ConfigCR with base route config", func() {
			extConfig := `
{
    "baseRouteSpec": {
        "tlsCipher": {
            "tlsVersion": 1.2
        }
    },
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        },
        {
            "namespace": "new",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			extConfig = `
{
    "baseRouteSpec": {
        "tlsCipher": {
            "tlsVersion": 1.3
        }
    },
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        }
    ]
}
`
			es = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			configCR.Spec.BigIpConfig = []cisapiv1.BigIpConfig{bigipConfig}
			err, ok = mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			routeGroup := "default"

			mockCtlr.resources.extdSpecMap[routeGroup] = &extendedParsedSpec{
				override: false,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "nextgenroutes",
					VServerAddr:   "10.10.10.10",
					AllowOverride: "False",
				},
				namespaces: []string{routeGroup},
				partition:  "test",
			}

			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "reencrypt"},
			}
			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001},
				{Port: 8080, NodePort: 38001},
				{Port: 9090, NodePort: 39001}}
			foo := test.NewService("foo", "1", routeGroup, "NodePort", fooPorts)
			mockCtlr.addService(foo)
			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", routeGroup, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			annotations := make(map[string]string)
			annotations["virtual-server.f5.com/balance"] = "least-connections-node"
			annotations[F5ServerSslProfileAnnotation] = "/Common/serverssl"
			annotations[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			annotations[F5VsAppRootAnnotation] = "/foo"
			route1 := test.NewRoute("route1", "1", routeGroup, spec1, annotations)
			mockCtlr.addRoute(route1)
			mockCtlr.resources.invertedNamespaceLabelMap[routeGroup] = routeGroup
			err = mockCtlr.processRoutes(routeGroup, false)

			Expect(err).To(BeNil())
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["nextgenroutes_443"].Pools[0].Balance == "least-connections-node").To(BeTrue())
			Expect(len(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["nextgenroutes_443"].Policies[0].Rules) == 3).To(BeTrue())

			extConfig = `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        }
    ]
}
`
			es = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok = mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})

		It("Verify autoMonitor Options", func() {
			// Verify autoMonitor defaults to readiness-probe when invalid value is provided
			extConfig := `
{
    "baseRouteSpec": {
        "autoMonitor": "invalid-automonitor"
    },
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			configCR.Spec.BigIpConfig = []cisapiv1.BigIpConfig{}
			bigipConfig := cisapiv1.BigIpConfig{
				BigIpLabel:       "bigip1",
				DefaultPartition: "default",
			}
			configCR.Spec.BigIpConfig = append(configCR.Spec.BigIpConfig, bigipConfig)
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
			Expect(mockCtlr.resources.baseRouteConfig.AutoMonitor).To(Equal(None))

			// Verify autoMonitor is set to service-endpoint
			extConfig = `
{
    "baseRouteSpec": {
        "autoMonitor": "service-endpoint"
    },
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        }
    ]
}
`
			es = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err, ok = mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			routeGroup := "default"

			mockCtlr.resources.extdSpecMap[routeGroup] = &extendedParsedSpec{
				override: false,
				global: &cisapiv1.ExtendedRouteGroupSpec{
					VServerName:   "nextgenroutes",
					VServerAddr:   "10.8.3.11",
					AllowOverride: "True",
				},
				namespaces: []string{routeGroup},
				partition:  "test",
			}

			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge"},
			}
			fooPorts := []v1.ServicePort{{Port: 80, NodePort: 30001}}
			foo := test.NewService("foo", "1", routeGroup, "NodePort", fooPorts)
			mockCtlr.addService(foo)

			fooIps := []string{"10.1.1.1"}
			fooEndpts := test.NewEndpoints(
				"foo", "1", "node0", routeGroup, fooIps, []string{},
				convertSvcPortsToEndpointPorts(fooPorts))
			mockCtlr.addEndpoints(fooEndpts)
			annotations := make(map[string]string)
			annotations[F5ClientSslProfileAnnotation] = "/Common/clientssl"
			route1 := test.NewRoute("route1", "1", routeGroup, spec1, annotations)
			mockCtlr.addRoute(route1)
			mockCtlr.resources.invertedNamespaceLabelMap[routeGroup] = routeGroup
			err = mockCtlr.processRoutes(routeGroup, false)
			Expect(err).To(BeNil())
			zero := 0
			expectedDefaultTCPMonitor := Monitor{
				Name:        "foo_80_default_monitor",
				Interval:    5,
				Timeout:     16,
				Type:        "tcp",
				Partition:   "test",
				TimeUntilUp: &zero,
			}
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["nextgenroutes_443"].Pools[0].MonitorNames[0].Name).To(Equal("foo_80_default_monitor"))
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig["test"].ResourceMap["nextgenroutes_443"].Monitors[0]).To(Equal(expectedDefaultTCPMonitor))

			// Verify autoMonitorTimeout
			extConfig = `
{
    "baseRouteSpec": {
        "autoMonitor": "service-endpoint",
        "autoMonitorTimeout": 50
    },
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true
        }
    ]
}
`
			es = cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			configCR.Spec.BigIpConfig = []cisapiv1.BigIpConfig{}
			Config := cisapiv1.BigIpConfig{
				BigIpLabel:       "bigip1",
				DefaultPartition: "default",
			}
			configCR.Spec.BigIpConfig = append(configCR.Spec.BigIpConfig, Config)
			err, ok = mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())

			err = mockCtlr.processRoutes(routeGroup, false)
			Expect(err).To(BeNil())
			expectedDefaultTCPMonitor = Monitor{
				Name:        "foo_80_default_monitor",
				Timeout:     50,
				Type:        "tcp",
				Partition:   "default",
				TimeUntilUp: &zero,
			}
			partition := mockCtlr.getPartitionForBIGIP("")
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig[partition].ResourceMap["nextgenroutes_443"].Pools[0].MonitorNames[0].Name).To(Equal("foo_80_default_monitor"))
			Expect(mockCtlr.resources.bigIpMap[bigipConfig].ltmConfig[partition].ResourceMap["nextgenroutes_443"].Monitors[0]).To(Equal(expectedDefaultTCPMonitor))

		})
	})
})

var _ = Describe("With NamespaceLabel parameter in deployment", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.managedResources.ManageRoutes = true
		mockCtlr.clientsets.RouteClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces["default"] = true
		mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.nrInformers = make(map[string]*NRInformer)
		mockCtlr.comInformers = make(map[string]*CommonInformer)
		mockCtlr.nsInformers = make(map[string]*NSInformer)
		mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.comInformers["test"] = mockCtlr.newNamespacedCommonResourceInformer("test")
		mockCtlr.comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default")
		mockCtlr.resourceSelectorConfig.NamespaceLabel = "environment=dev"
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
			},
		}
	})
	Describe("Extended Spec ConfigCR", func() {
		var configCR *cisapiv1.DeployConfig
		configSpec := cisapiv1.DeployConfigSpec{}
		BeforeEach(func() {
			crName := "escm"
			crNamespace := "system"
			mockCtlr.CISConfigCRKey = crNamespace + "/" + crName
			bigIpKey := cisapiv1.BigIpConfig{BigIpAddress: "10.8.3.11", BigIpLabel: "bigip1"}
			mockCtlr.RequestHandler.PostManagers.PostManagerMap[bigIpKey] = &PostManager{
				tokenManager: mockCtlr.CMTokenManager,
				PostParams:   PostParams{},
			}
			configCR = test.NewConfigCR(
				crName,
				crNamespace,
				configSpec)
		})

		It("namespace and namespaceLabel combination", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true,
            "bigIpPartition": "foo"
        },
        {
            "namespaceLabel": "bar=true",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err := mockCtlr.setNamespaceLabelMode(configCR)
			Expect(err).To(MatchError(fmt.Sprintf("can not specify both namespace and namespace-label in DeployConfig CR %v/%v", configCR.Namespace, configCR.Name)))
		})
		It("with namespaceLabel only", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespaceLabel": "foo=true",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true,
            "bigIpPartition": "foo"
        },
        {
            "namespaceLabel": "bar=true",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			mockCtlr.namespaceLabelMode = true
			err, ok := mockCtlr.processConfigCR(configCR, false)
			Expect(err).To(BeNil())
			Expect(ok).To(BeTrue())
		})
	})
})

var _ = Describe("Without NamespaceLabel parameter in deployment", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.managedResources.ManageRoutes = true
	})
	Describe("Extended Spec ConfigCR", func() {
		var configCR *cisapiv1.DeployConfig
		configSpec := cisapiv1.DeployConfigSpec{}
		BeforeEach(func() {
			crName := "escm"
			crNamespace := "system"
			mockCtlr.CISConfigCRKey = crNamespace + "/" + crName
			configCR = test.NewConfigCR(
				crName,

				crNamespace,
				configSpec)
		})
		It("namespaceLabel only without namespace-label deployment parameter", func() {
			extConfig := `
{
    "extendedRouteSpec": [
        {
            "namespaceLabel": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true,
            "bigIpPartition": "foo"
        },
        {
            "namespaceLabel": "bar=true",
            "vserverAddr": "10.8.3.12",
            "allowOverride": true
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			err := mockCtlr.setNamespaceLabelMode(configCR)
			Expect(err).To(MatchError("--namespace-label deployment parameter is required with namespace-label in DeployConfig CR"))
		})
	})
})

var _ = Describe("Multi Cluster with Routes", func() {
	var mockCtlr *mockController
	var sct1, sct2, sct3, sct4 *v1.Secret
	var configCR *cisapiv1.DeployConfig
	configSpec := cisapiv1.DeployConfigSpec{}

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.managedResources.ManageRoutes = true
		mockCtlr.CISConfigCRKey = "kube-system/global-cm"
		mockCtlr.clientsets.RouteClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces["default"] = true
		mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.nrInformers = make(map[string]*NRInformer)
		mockCtlr.comInformers = make(map[string]*CommonInformer)
		mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.comInformers["test"] = mockCtlr.newNamespacedCommonResourceInformer("test")
		mockCtlr.comInformers[""] = mockCtlr.newNamespacedCommonResourceInformer("")
		mockCtlr.comInformers["kube-system"] = mockCtlr.newNamespacedCommonResourceInformer("kube-system")
		mockCtlr.comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default")
		mockCtlr.multiClusterPoolInformers = make(map[string]map[string]*MultiClusterPoolInformer)
		mockCtlr.multiClusterPoolInformers["cluster3"] = make(map[string]*MultiClusterPoolInformer)
		mockCtlr.multiClusterNodeInformers = make(map[string]*NodeInformer)
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
		mockCtlr.clusterRatio = make(map[string]*int)
		mockCtlr.clusterAdminState = make(map[string]cisapiv1.AdminState)
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
				ExternalDNS:  make(map[string]int),
			},
		}
		bigIpKey := cisapiv1.BigIpConfig{BigIpAddress: "10.8.3.11", BigIpLabel: "bigip1"}
		mockCtlr.RequestHandler.PostManagers.PostManagerMap[bigIpKey] = &PostManager{
			tokenManager: mockCtlr.CMTokenManager,
			PostParams:   PostParams{},
		}

		crName := "ecm"
		crNamespace := "kube-system"
		mockCtlr.CISConfigCRKey = crNamespace + "/" + crName
		mockCtlr.resources = NewResourceStore()
		extConfig := `
{
    "highAvailabilityCIS": {
        "primaryEndPoint": "http://10.145.72.114:8001",
        "probeInterval": 30,
        "retryInterval": 3,
        "primaryCluster": {
            "clusterName": "cluster1",
            "secret": "default/kubeconfig1"
        },
        "secondaryCluster": {
            "clusterName": "cluster2",
            "secret": "default/kubeconfig2"
        }
    },
    "externalClustersConfig": [
        {
            "clusterName": "cluster3",
            "secret": "default/kubeconfig3"
        },
        {
            "clusterName": "cluster4",
            "secret": "default/kubeconfig4"
        }
    ],
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true,
            "policyCR": "default/policy"
        }
    ]
}
`
		es := cisapiv1.ExtendedSpec{}
		_ = json.Unmarshal([]byte(extConfig), &es)
		configSpec.ExtendedSpec = es
		configCR = test.NewConfigCR(
			crName,
			crNamespace,
			configSpec)
		sct1 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		sct2 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig1", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		sct3 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig2", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		sct4 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig3", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		mockCtlr.addSecret(sct1)
		mockCtlr.addSecret(sct2)
		mockCtlr.addSecret(sct3)
		mockCtlr.addSecret(sct4)
		mockCtlr.addConfigCR(configCR)
		mockCtlr.initState = false
		mockCtlr.clusterRatio = make(map[string]*int)

	})

	Describe("Process Routes with multi cluster config", func() {

		var route1 *routeapi.Route
		var rsCfg *ResourceConfig
		var ps portStruct
		BeforeEach(func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			routeGroup := "default"
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{Termination: "edge",
					Certificate:                   "",
					Key:                           "",
					InsecureEdgeTerminationPolicy: "",
					DestinationCACertificate:      "",
				},
			}

			route1 = test.NewRoute("route1", "1", routeGroup, spec1, nil)
			route1.Annotations = make(map[string]string)
			ps = portStruct{HTTP, DEFAULT_HTTP_PORT}
			// Resource Config for unsecured virtual server
			// ResourceConfig for secured virtual server
			rsCfg = &ResourceConfig{}
			rsCfg.Virtual.Partition = routeGroup
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = "newroutes_443"
			rsCfg.MetaData.Protocol = HTTPS
			rsCfg.Virtual.SetVirtualAddress("10.8.3.11", DEFAULT_HTTPS_PORT)
			// Portstruct for secured virtual server
			ps.protocol = HTTPS
			ps.port = DEFAULT_HTTPS_PORT
		})

		It("Process Route with multi cluster annotation without multicluster config", func() {
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(1))
		})

		It("Process Route with multi cluster annotation with multicluster config", func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			mockCtlr.processGlobalDeployConfigCR()
			restClient := mockCtlr.multiClusterConfigs.ClusterConfigs["cluster3"].KubeClient.CoreV1().RESTClient()
			clusterName := "cluster3"
			// Setup informers with namespaces which are watched by CIS
			for namespace := range mockCtlr.namespaces {
				// add common informers  in all modes
				if _, found := mockCtlr.multiClusterPoolInformers[clusterName]; !found {
					mockCtlr.multiClusterPoolInformers[clusterName] = make(map[string]*MultiClusterPoolInformer)
				}
				if _, found := mockCtlr.multiClusterPoolInformers[clusterName][namespace]; !found {
					poolInfr := mockCtlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClient)
					mockCtlr.addMultiClusterPoolEventHandlers(poolInfr)
					mockCtlr.multiClusterPoolInformers[clusterName][namespace] = poolInfr
				}
			}

			//check with multi cluster service annotation
			route1.Annotations["virtual-server.f5.com/multiClusterServices"] = `[{"clusterName": "cluster3", "serviceName":"svc", "namespace": "default", "port": "8080" },
{"clusterName": "cluster3", "serviceName":"svc1", "namespace": "default", "port": "8081" }]`
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(2))

			resourceKey := resourceRef{
				kind:      Route,
				namespace: route1.Namespace,
				name:      route1.Name,
			}

			one := 1
			mockCtlr.clusterRatio["cluster1"] = &one
			two := 2
			mockCtlr.clusterRatio["cluster2"] = &two
			three := 3
			mockCtlr.clusterRatio["cluster3"] = &three
			var weight int32 = 10
			route1.Spec.To.Weight = &weight
			mockCtlr.haModeType = Ratio

			//remove annotation and check
			delete(route1.Annotations, "virtual-server.f5.com/multiClusterServices")
			mockCtlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			// for local cluster service mapping must be present
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(0))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(3))

			route1.Annotations["virtual-server.f5.com/multiClusterServices"] = `[{"clusterName": "cluster3", "serviceName":"svc1", "namespace": "default", "port": "8081" }]`
			mockCtlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(3))

		})

		It("Process Route with multi cluster annotation and cluster AdminState in multicluster config", func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			extConfig := `
{
    "highAvailabilityCIS": {
        "primaryEndPoint": "http://10.145.72.114:8001",
        "probeInterval": 30,
        "retryInterval": 3,
        "primaryCluster": {
            "clusterName": "cluster1",
            "secret": "default/kubeconfig1"
        },
        "secondaryCluster": {
            "clusterName": "cluster2",
            "secret": "default/kubeconfig2",
            "adminState": "disable"
        }
    },
    "externalClustersConfig": [
        {
            "clusterName": "cluster3",
            "secret": "default/kubeconfig3",
            "adminState": "offline"
        },
        {
            "clusterName": "cluster4",
            "secret": "default/kubeconfig4",
            "adminState": "enable"
        }
    ],
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true,
            "policyCR": "default/policy"
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			mockCtlr.updateConfigCR(configCR)
			mockCtlr.processGlobalDeployConfigCR()
			Expect(len(mockCtlr.clusterAdminState)).To(Equal(3))
			Expect(mockCtlr.clusterAdminState[""]).To(Equal(clustermanager.Enable))
			Expect(mockCtlr.clusterAdminState["cluster2"]).To(Equal(clustermanager.Disable))
			Expect(mockCtlr.clusterAdminState["cluster3"]).To(Equal(clustermanager.Offline))
		})

		It("Process Route in multiCluster active-active mode with correct pool name", func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			extConfig := `
{
    "mode": "active-active",
    "highAvailabilityCIS": {
        "primaryEndPoint": "http://10.145.72.114:8001",
        "probeInterval": 30,
        "retryInterval": 3,
        "primaryCluster": {
            "clusterName": "cluster1",
            "secret": "default/kubeconfig1"
        },
        "secondaryCluster": {
            "clusterName": "cluster2",
            "secret": "default/kubeconfig2"
        }
    },
    "externalClustersConfig": [
        {
            "clusterName": "cluster3",
            "secret": "default/kubeconfig3"
        },
        {
            "clusterName": "cluster4",
            "secret": "default/kubeconfig4"
        }
    ],
    "extendedRouteSpec": [
        {
            "namespace": "default",
            "vserverAddr": "10.8.3.11",
            "vserverName": "nextgenroutes",
            "allowOverride": true,
            "policyCR": "default/policy"
        }
    ]
}
`
			es := cisapiv1.ExtendedSpec{}
			_ = json.Unmarshal([]byte(extConfig), &es)
			configCR.Spec.ExtendedSpec = es
			mockCtlr.updateConfigCR(configCR)
			mockCtlr.processGlobalDeployConfigCR()
			Expect(mockCtlr.prepareResourceConfigFromRoute(rsCfg, route1, intstr.IntOrString{IntVal: 80}, ps)).To(BeNil())
			Expect(len(rsCfg.Pools)).To(Equal(1))
			Expect(rsCfg.Pools[0].Name).To(Equal("foo_80_default"), "Pool name in multiCluster active-active mode is incorrect")
		})

	})
})

var _ = Describe("Multi Cluster with CRD", func() {
	var mockCtlr *mockController
	var sct1, sct2, sct3, sct4 *v1.Secret
	var configCR *cisapiv1.DeployConfig
	configSpec := cisapiv1.DeployConfigSpec{}

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = clustermanager.NewMultiClusterConfig()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.managedResources.ManageCustomResources = true
		mockCtlr.CISConfigCRKey = "kube-system/global-cm"
		mockCtlr.clientsets.RouteClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.namespaces = make(map[string]bool)
		mockCtlr.namespaces["default"] = true
		mockCtlr.clientsets.KubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.nrInformers = make(map[string]*NRInformer)
		mockCtlr.comInformers = make(map[string]*CommonInformer)
		mockCtlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.comInformers["test"] = mockCtlr.newNamespacedCommonResourceInformer("test")
		mockCtlr.comInformers[""] = mockCtlr.newNamespacedCommonResourceInformer("")
		mockCtlr.comInformers["kube-system"] = mockCtlr.newNamespacedCommonResourceInformer("kube-system")
		mockCtlr.comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default")
		mockCtlr.multiClusterPoolInformers = make(map[string]map[string]*MultiClusterPoolInformer)
		mockCtlr.multiClusterPoolInformers["cluster3"] = make(map[string]*MultiClusterPoolInformer)
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
		mockCtlr.clusterRatio = make(map[string]*int)
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
				ExternalDNS:  make(map[string]int),
			},
		}
		bigIpKey := cisapiv1.BigIpConfig{BigIpAddress: "10.8.3.11", BigIpLabel: "bigip1"}
		mockCtlr.RequestHandler.PostManagers.PostManagerMap[bigIpKey] = &PostManager{
			tokenManager: mockCtlr.CMTokenManager,
			PostParams:   PostParams{},
		}
		crName := "ecm"
		crNamespace := "kube-system"
		mockCtlr.CISConfigCRKey = crNamespace + "/" + crName
		mockCtlr.resources = NewResourceStore()

		extConfig := `
{
    "highAvailabilityCIS": {
        "primaryEndPoint": "http://10.145.72.114:8001",
        "probeInterval": 30,
        "retryInterval": 3,
        "primaryCluster": {
            "clusterName": "cluster1",
            "secret": "default/kubeconfig1"
        },
        "secondaryCluster": {
            "clusterName": "cluster2",
            "secret": "default/kubeconfig2"
        }
    },
    "externalClustersConfig": [
        {
            "clusterName": "cluster3",
            "secret": "default/kubeconfig3"
        },
        {
            "clusterName": "cluster4",
            "secret": "default/kubeconfig4"
        }
    ]
}
`
		es := cisapiv1.ExtendedSpec{}
		_ = json.Unmarshal([]byte(extConfig), &es)
		configSpec.ExtendedSpec = es
		configCR = test.NewConfigCR(
			crName,
			crNamespace,
			configSpec)

		sct1 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		sct2 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig1", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		sct3 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig2", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		sct4 = &v1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "kubeconfig3", Namespace: "default"},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    server: https://0.0.0.0:80\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes\n  name: kubernetes@kubernetes\ncurrent-context: kubernetes@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lJV0MrTFZDazFmNFF3RFFZSktvWklodmNOQVFFTEJRQXdOakVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TQXdIZ1lEVlFRREV4ZGhaRzFwYmkxcmRXSmxZMjl1Wm1sbkxYTnBaMjVsY2pBZQpGdzB5TXpBeE1USXdOekV6TkRCYUZ3MHpNekF4TURrd056RXpOREZhTURBeEZ6QVZCZ05WQkFvVERuTjVjM1JsCmJUcHRZWE4wWlhKek1SVXdFd1lEVlFRREV3eHplWE4wWlcwNllXUnRhVzR3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURMeDlhRlowcDU2dmM1YWIwZzlQSXZFVU9tWkh6ODg3bm1CWDRZSFJBOAphZHhnZ1NtNWVYdVlzRjFBZ28rRE1WZnlCRjJvWFc5K0w3K2VWdVdyVzRkS3dNc1diUExJc0tKSFpzeE5qQ1Q0CjVUWE0wemtXZGRiZUdaNnU5OFZpM3Q5amhIVWpGRFA2YzRlR1pXTVlNWHY0elZJL0VrNnlWTWUxaFpzR2J6ZGsKcmgweGUxai9UK3pzVXl2TkZMekEyMjIxVlk2VmN1Nk1INjczM1p6MjZPTnR4akNBSm5lWFY2KzZiODNqL25JbgpqNWFJVzJIMzJrckowUWN6WStsQlpIM2s5cmZJMUdtK3NzV3FHdnQzWUpXRTN0Vi9DMm5RTGRJb1BSaTBBekd5CmJwcUR6Qi9kM2dkZ0d2eW43NUFBVkZwcEwzU1p5MGg2aVEveHhtenhPalhYQWdNQkFBR2pmekI5TUE0R0ExVWQKRHdFQi93UUVBd0lGb0RBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVApBUUgvQkFJd0FEQWRCZ05WSFE0RUZnUVU2OW1vcXJlNzZ4MFVLeUo2cElYWVF3aW5kTEl3SHdZRFZSMGpCQmd3CkZvQVUyTThzV3RsSkEzVzR3VzNCbWd5Mk1ya0oweEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtHdi9rMSsKYytoay8rLzdWU1Y4Z2tjYzMrRm5qNktmWGpQNTBKZ0hDVjFubFhaOS9TZC9LdHdoVjZ4VE00a0IrdDNtY240NgprNWI3TTZMOWpSWVBhZFpHcVFUbEh4RUwrd1MwUiticmtqTlYwb2RQZmVIWVVaMTVCc2JzRWJZNml4UHpPU3p0CkpJUWkvbzFYZXVDRUMzSG5YTG5wUFZUc3EyNm44UXNRM3QrUzErSDRJdlFTWjZSRys2ZEowM2lIUUJMY1pKSVMKUHpSbGxxN01icnRWdUIzVHpqb08vNGR0eUp2Yi8yLzFuSkZ4Wnd4cTZERlNVRU90RGxZOGdDWEMyRFJOcXdtQQp4UExoSUhuWFN6YjlqT1l0eG1McklaWE8vRU5FVnJDMHhOMFZpSThQRU5Md3czTHlhT2RoQ0xoZG1Yc0hlbkU0CmxSa0tTZ3hPSWFLUjNvTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeThmV2hXZEtlZXIzT1dtOUlQVHlMeEZEcG1SOC9QTzU1Z1YrR0IwUVBHbmNZSUVwCnVYbDdtTEJkUUlLUGd6Rlg4Z1JkcUYxdmZpKy9ubGJscTF1SFNzRExGbXp5eUxDaVIyYk1UWXdrK09VMXpOTTUKRm5YVzNobWVydmZGWXQ3Zlk0UjFJeFF6K25PSGhtVmpHREY3K00xU1B4Sk9zbFRIdFlXYkJtODNaSzRkTVh0WQovMC9zN0ZNcnpSUzh3TnR0dFZXT2xYTHVqQit1OTkyYzl1ampiY1l3Z0NaM2wxZXZ1bS9ONC81eUo0K1dpRnRoCjk5cEt5ZEVITTJQcFFXUjk1UGEzeU5ScHZyTEZxaHI3ZDJDVmhON1Zmd3RwMEMzU0tEMFl0QU14c202YWc4d2YKM2Q0SFlCcjhwKytRQUZSYWFTOTBtY3RJZW9rUDhjWnM4VG8xMXdJREFRQUJBb0lCQUNaSWJLeXpNdktraWIxbgpkL2h4Qys1N3Q5SFNud2lHWVM0dGFmcnR1dGNlckNBVkk5bU1VUVBtWGg1NGFLMmszM2pBQ1RoUUZWb0hibUE0Cnd2em1QUXgyRzdFaTFwbU5WVzlFaUswbzN1bERabEFNZm5VUnZrUUxYQnhTditwTEpIeDFyZXZoSjhLdFlaQ0cKQzQvSC9CcEp1R0hROXFmWjlZck1oc3MycVpsb0puZ2piNytmUnQwS1g5ck44VXVDajN2bDlBWW9jWDF6VmZKdwpYR1hjMkJjR2pTdHlQNnQ4cnQyeGZ0bmgrQUN1TVc4VlBWaVRsQkdXZWVEZndiNHBIa1B2UlhtQUR3ZU5xeVFNCkVhSGJkL1pJSWZ2QmNFTVQ2b0RValAzeWhkeTk4UTdTVHMxTEZUN0dOamhRemt6blNwNjhWUU45aWNWVklaOU0KcCtDMkJFRUNnWUVBMllLK0J2S1ozK2lUN2h5cCtJdTV5eXZsYXE1bHBGcTVZbnlPVjlaNTV0MjNSdjRWeHgwdgpqQVlCTUFlT0RVOGNYR05EMkJnUTFHM0o3eFlWbnE2NXFBR0VYYzFJNWlONXlmTE1iWDZ2SnlFQnlJN0Q2Q0pvCjEwL2tWdU53MUVIRWlBVG9CSFE1ZkJ3RHNyUW1tWXdCcy9POWIwNHVpQ1E1bnZPUUNmN0l6VTBDZ1lFQTc5Y2UKOXluWFdjWlhWNGZnSGxXbmVsQnZwSkRMUW1zdnF3S1VxS0xSMWc2c0x5bnFpRVVBMVhtS0lvZ1dNbzRpQWlUMApCQU95azdIT29kdm1SZlZxTSs3UEpCSmlsVDhqVFlWQklRK0t6Vlc0OHVpT2MzSWgyVS9Ndmhwd0JQWW9YeFNIClZuam9NVHlJb1UvMVo1MUxBaWR6OEZjSmJmQXpCTWRhLzdJY3piTUNnWUVBMGY4cFNmbmxWOGpyTVlPWkVtNk0KTlR5dkpQMDFBcVhZdjk0emExaVZuckJHcDVMZUlidnEwTXhuVHlDc0krdFNIVngwL3VmVkw5TERtRUlCSTQvYgpqUG5SK3VJY1ZKekJrNWtIaDFzODdaRXZjSnR0UnV3WnZtN1NySlN2dFMyOStmaUtyT290S2NhK1IwVW8weXZaCjVRd1l3NkoreUUvNUZaNWZYVmNRTlMwQ2dZRUFoZXgyY3dkZkk5Y1g0RjJUN1B4aE4zQ0Exc0N2YnhnUkZ3bXEKM3Z1RDltWmRDVHo3cERuN3ZEaFF4UFYraDU1TUtTeGZRWHFiRmRPOGtTOE1SMVpCaGx3OE9HVTN2U1R6WG84aApEZ2Z5dHJPK1FZMVFOZkN1Sy8xZVUyekp6a3R4d1ozaDhJdzFBNEZNdmQ2N0pxOXpPZkd6MEttWkwxVm45NndtCkNROTQrL2NDZ1lFQWkrRzU1TENEOU9HTGpXL2h1Ulp0SThvOFhJM0I0eld6UWFzMGNxd0F5ZWdSRENxMm9mQmIKZjYvcm96OGsyOENVd0tLb0pWejJGMDVQaUJHZTJCdVBNUWJwaFRrQVgwQ3dyZENTQzB4eGNwSjZpMFZaOXdVRwpiWS8rV29Rb3dnYnI5SlhSS3NySXNudmRBdTZnNFZxM1BSTzNZdnBoNkxVR3hUemEvQXVyTzFBPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n"),
			},
		}
		mockCtlr.addSecret(sct1)
		mockCtlr.addSecret(sct2)
		mockCtlr.addSecret(sct3)
		mockCtlr.addSecret(sct4)
		mockCtlr.addConfigCR(configCR)
		mockCtlr.initState = false
		mockCtlr.clusterRatio = make(map[string]*int)
		mockCtlr.clusterAdminState = make(map[string]cisapiv1.AdminState)
	})

	Describe("Process CRD with multi cluster config", func() {
		var rsCfg *ResourceConfig
		BeforeEach(func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			mockCtlr.processGlobalDeployConfigCR()
		})
		It("Process VS with multi cluster config", func() {
			one := 1
			mockCtlr.clusterRatio["cluster1"] = &one
			two := 2
			mockCtlr.clusterRatio["cluster2"] = &two
			three := 3
			mockCtlr.clusterRatio["cluster3"] = &three
			rsCfg = &ResourceConfig{}
			rsCfg.MetaData.ResourceType = VirtualServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)
			weight1 := int32(70)
			weight2 := int32(30)
			vs := test.NewVirtualServer(
				"SampleVS",
				"default",
				cisapiv1.VirtualServerSpec{
					Host: "test.com",
					Pools: []cisapiv1.VSPool{
						{
							Path:             "/foo",
							Service:          "svc1",
							ServiceNamespace: "test",
							Monitor: cisapiv1.Monitor{
								Type:     "http",
								Send:     "GET /health",
								Interval: 15,
								Timeout:  10,
							},
							Weight: &weight1,
							AlternateBackends: []cisapiv1.AlternateBackend{
								{
									Service:          "svc1-b",
									ServiceNamespace: "test2",
									Weight:           &weight2,
								},
							},
							MultiClusterServices: []cisapiv1.MultiClusterServiceReference{
								{
									ClusterName: "cluster3",
									Namespace:   "default",
									SvcName:     "test",
									ServicePort: intstr.IntOrString{IntVal: 80},
								},
							},
						},
					},
				},
			)
			restClient := mockCtlr.multiClusterConfigs.ClusterConfigs["cluster3"].KubeClient.CoreV1().RESTClient()
			clusterName := "cluster3"
			// Setup informers with namespaces which are watched by CIS
			for namespace := range mockCtlr.namespaces {
				// add common informers  in all modes
				if _, found := mockCtlr.multiClusterPoolInformers[clusterName]; !found {
					mockCtlr.multiClusterPoolInformers[clusterName] = make(map[string]*MultiClusterPoolInformer)
				}
				if _, found := mockCtlr.multiClusterPoolInformers[clusterName][namespace]; !found {
					poolInfr := mockCtlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClient)
					mockCtlr.addMultiClusterPoolEventHandlers(poolInfr)
					mockCtlr.multiClusterPoolInformers[clusterName][namespace] = poolInfr
				}
			}
			mockCtlr.haModeType = Ratio
			mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(3))

			// Verify that distinct health monitors are created for all pools in ratio mode
			expectedHealthMonitors := make(map[string]struct{})
			expectedHealthMonitors = map[string]struct{}{
				"svc1_test_test_com_foo_cluster1":    struct{}{},
				"svc1_test_test_com_foo_cluster2":    struct{}{},
				"svc1_b_test2_test_com_foo_cluster1": struct{}{},
				"svc1_b_test2_test_com_foo_cluster2": struct{}{},
				"test_default_test_com_foo_cluster3": struct{}{},
			}
			for _, hm := range rsCfg.Monitors {
				_, ok := expectedHealthMonitors[hm.Name]
				Expect(ok).To(Equal(true), "Expected health monitor %s not found while using "+
					"ratio mode", hm.Name)
			}
			resourceKey := resourceRef{
				kind:      VirtualServer,
				namespace: vs.Namespace,
				name:      vs.Name,
			}

			vs.Spec.Pools[0].MultiClusterServices = []cisapiv1.MultiClusterServiceReference{}
			mockCtlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
			mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			// for local cluster service mapping must be present
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(0))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(3))

			vs.Spec.Pools[0].MultiClusterServices = []cisapiv1.MultiClusterServiceReference{
				{
					ClusterName: "cluster3",
					Namespace:   "default",
					SvcName:     "test",
					ServicePort: intstr.IntOrString{IntVal: 80},
				},
			}
			mockCtlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
			mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(3))
		})

		It("Process TS with multi cluster config", func() {

			one := 1
			mockCtlr.clusterRatio["cluster1"] = &one
			two := 2
			mockCtlr.clusterRatio["cluster2"] = &two
			three := 3
			mockCtlr.clusterRatio["cluster3"] = &three
			rsCfg = &ResourceConfig{}
			rsCfg.MetaData.ResourceType = TransportServer
			rsCfg.Virtual.Enabled = true
			rsCfg.Virtual.Name = formatCustomVirtualServerName("My_VS", 80)
			rsCfg.IntDgMap = make(InternalDataGroupMap)
			rsCfg.IRulesMap = make(IRulesMap)

			ts := test.NewTransportServer(
				"SampleTS",
				"default",
				cisapiv1.TransportServerSpec{
					Pool: cisapiv1.TSPool{
						Service:          "svc1",
						ServicePort:      intstr.IntOrString{IntVal: 80},
						ServiceNamespace: "test",
						Monitor: cisapiv1.Monitor{
							Type:     "tcp",
							Timeout:  10,
							Interval: 10,
						},
						MultiClusterServices: []cisapiv1.MultiClusterServiceReference{
							{
								ClusterName: "cluster3",
								Namespace:   "default",
								SvcName:     "svc",
								ServicePort: intstr.IntOrString{IntVal: 80},
							},
						},
					},
				},
			)
			restClient := mockCtlr.multiClusterConfigs.ClusterConfigs["cluster3"].KubeClient.CoreV1().RESTClient()
			clusterName := "cluster3"
			// Setup informers with namespaces which are watched by CIS
			for namespace := range mockCtlr.namespaces {
				// add common informers  in all modes
				if _, found := mockCtlr.multiClusterPoolInformers[clusterName]; !found {
					mockCtlr.multiClusterPoolInformers[clusterName] = make(map[string]*MultiClusterPoolInformer)
				}
				if _, found := mockCtlr.multiClusterPoolInformers[clusterName][namespace]; !found {
					poolInfr := mockCtlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClient)
					mockCtlr.addMultiClusterPoolEventHandlers(poolInfr)
					mockCtlr.multiClusterPoolInformers[clusterName][namespace] = poolInfr
				}
			}
			mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(2))

			resourceKey := resourceRef{
				kind:      TransportServer,
				namespace: ts.Namespace,
				name:      ts.Name,
			}

			ts.Spec.Pool.MultiClusterServices = []cisapiv1.MultiClusterServiceReference{}
			mockCtlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
			mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			// for local cluster service mapping must be present
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(0))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(2))

			ts.Spec.Pool.MultiClusterServices = []cisapiv1.MultiClusterServiceReference{
				{
					ClusterName: "cluster3",
					Namespace:   "default",
					SvcName:     "test",
					ServicePort: intstr.IntOrString{IntVal: 80},
				},
			}
			mockCtlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
			mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap[""])).To(Equal(2))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap["cluster3"])).To(Equal(1))
			Expect(len(mockCtlr.multiClusterResources.clusterSvcMap)).To(Equal(2))

		})
	})

})

var _ = Describe("processRouteConfigFromLocalConfigCR", func() {
	var (
		mockCtlr    *mockController
		es          cisapiv1.ExtendedSpec
		isDelete    bool
		namespace   string
		err         error
		retryNeeded bool
	)

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.resources = NewResourceStore()
		es = cisapiv1.ExtendedSpec{
			ExtendedRouteGroupConfigs: []cisapiv1.ExtendedRouteGroupConfig{
				{
					Namespace: "test-namespace",
					ExtendedRouteGroupSpec: cisapiv1.ExtendedRouteGroupSpec{
						VServerName: "vserver1",
					},
				},
			},
		}
		isDelete = false
		namespace = "test-namespace"
	})

	Describe("processRouteConfigFromLocalConfigCR", func() {
		Context("when namespace mismatch occurs", func() {
			It("should return an error and true", func() {
				namespace = "invalid-namespace"
				err, retryNeeded = mockCtlr.processRouteConfigFromLocalConfigCR(es, isDelete, namespace)
				Expect(err).To(HaveOccurred())
				Expect(retryNeeded).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring("Invalid Extended Route Spec Block in DeployConfig CR"))
			})
		})

		Context("when RouteGroup is not found", func() {
			It("should return an error and true", func() {
				err, retryNeeded = mockCtlr.processRouteConfigFromLocalConfigCR(es, isDelete, namespace)
				Expect(err).To(HaveOccurred())
				Expect(retryNeeded).To(BeTrue())
				Expect(err.Error()).To(Equal("RouteGroup not found"))
			})
		})

		Context("when deleting and override is not enabled", func() {
			It("should set local to nil and return nil and true", func() {
				mockCtlr.resources.extdSpecMap[namespace] = &extendedParsedSpec{
					override: false,
					local:    &es.ExtendedRouteGroupConfigs[0].ExtendedRouteGroupSpec,
				}
				mockCtlr.resources.invertedNamespaceLabelMap[namespace] = "test-namespace"
				isDelete = true
				err, retryNeeded = mockCtlr.processRouteConfigFromLocalConfigCR(es, isDelete, namespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(retryNeeded).To(BeTrue())
				Expect(mockCtlr.resources.extdSpecMap[namespace].local).To(BeNil())
			})
		})

		Context("when creating and spec is local and global is not equal", func() {
			It("should set local to ExtendedRouteGroupSpec and return nil and true", func() {
				mockCtlr.resources.extdSpecMap[namespace] = &extendedParsedSpec{
					override: false,
					global: &cisapiv1.ExtendedRouteGroupSpec{
						VServerName: "vserver-global",
					},
				}
				mockCtlr.resources.invertedNamespaceLabelMap[namespace] = "test-namespace"
				err, retryNeeded = mockCtlr.processRouteConfigFromLocalConfigCR(es, isDelete, namespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(retryNeeded).To(BeTrue())
				Expect(mockCtlr.resources.extdSpecMap[namespace].local).To(Equal(&es.ExtendedRouteGroupConfigs[0].ExtendedRouteGroupSpec))
			})
		})

		Context("when updating and spec.local is not equal to ExtendedRouteGroupSpec", func() {
			It("should set local to ExtendedRouteGroupSpec and return nil and true", func() {
				mockCtlr.resources.extdSpecMap[namespace] = &extendedParsedSpec{
					local: &cisapiv1.ExtendedRouteGroupSpec{
						VServerName: "vserver-old",
					},
				}
				mockCtlr.resources.invertedNamespaceLabelMap[namespace] = "test-namespace"
				err, retryNeeded = mockCtlr.processRouteConfigFromLocalConfigCR(es, isDelete, namespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(retryNeeded).To(BeTrue())
				Expect(mockCtlr.resources.extdSpecMap[namespace].local).To(Equal(&es.ExtendedRouteGroupConfigs[0].ExtendedRouteGroupSpec))
			})
		})
	})
})
