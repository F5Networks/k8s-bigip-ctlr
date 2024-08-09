package appmanager

import (
	"context"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Test AgentResponseHandler", func() {
	Context("Using Mock Manager", func() {
		var mockMgr *mockAppManager
		var mw *test.MockWriter
		BeforeEach(func() {
			RegisterBigIPSchemaTypes()

			mw = &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}

			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			mockMgr = newMockAppManager(&Params{
				KubeClient:             fakeClient,
				restClient:             test.CreateFakeHTTPClient(),
				RouteClientV1:          fakeRouteClient.NewSimpleClientset().RouteV1(),
				ProcessAgentLabels:     func(m map[string]string, n, ns string) bool { return true },
				IsNodePort:             true,
				broadcasterFunc:        NewFakeEventBroadcaster,
				ManageConfigMaps:       true,
				ManageIngress:          true,
				ManageIngressClassOnly: false,
				IngressClass:           "f5",
			})

			mockMgr.appMgr.AgentCIS, _ = agent.CreateAgent(agent.CCCLAgent)
			mockMgr.appMgr.AgentCIS.Init(&cccl.Params{ConfigWriter: mw})
		})
		AfterEach(func() {
			mockMgr.shutdown()
		})
		It("Test updateRouteAdmitStatusAll", func() {
			mockMgr.appMgr.processedResources = make(map[string]bool)
			mockMgr.appMgr.processedResources["routes_test/route1"] = true
			namespace := "test"
			selector, err := labels.Parse(resource.DefaultConfigMapLabel)
			Expect(err).To(BeNil())
			//diff ns
			mockMgr.appMgr.AddNamespace("test2", selector, 0)
			mockMgr.appMgr.updateRouteAdmitStatusAll()
			updatedRoute, err := mockMgr.appMgr.routeClientV1.Routes(namespace).Get(context.TODO(), "route1", metav1.GetOptions{})
			Expect(err).NotTo(BeNil())
			Expect(updatedRoute).To(BeNil())

			//correct ns
			mockMgr.appMgr.AddNamespace(namespace, selector, 0)
			//create route
			spec1 := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
			}
			route1 := test.NewRoute("route1", "1", namespace, spec1, nil)
			route1.Status = routeapi.RouteStatus{
				Ingress: []routeapi.RouteIngress{
					routeapi.RouteIngress{
						Host:       "abc.com",
						RouterName: F5RouterName,
						Conditions: []routeapi.RouteIngressCondition{
							routeapi.RouteIngressCondition{Status: "False"},
						}},
				},
			}
			route2 := &routeapi.Route{
				ObjectMeta: metav1.ObjectMeta{Name: "route2", Namespace: namespace},
				Spec:       routeapi.RouteSpec{Path: "/", Host: "abc.com"},
			}
			mockMgr.appMgr.appInformers[namespace].routeInformer.GetStore().Add(route1)
			// Routev1client add routes
			mockMgr.appMgr.routeClientV1.Routes(namespace).Create(context.TODO(), route1, metav1.CreateOptions{})
			mockMgr.appMgr.routeClientV1.Routes(namespace).Create(context.TODO(), route2, metav1.CreateOptions{})
			mockMgr.appMgr.updateRouteAdmitStatusAll()
			updatedRoute, err = mockMgr.appMgr.routeClientV1.Routes(namespace).Get(context.TODO(), "route1", metav1.GetOptions{})
			Expect(err).To(BeNil())
			Expect(updatedRoute).NotTo(BeNil())
			Expect(updatedRoute.Status).NotTo(BeNil())
			Expect(len(updatedRoute.Status.Ingress)).NotTo(BeZero())
			Expect(len(updatedRoute.Status.Ingress[0].Conditions)).NotTo(BeZero())
			Expect(updatedRoute.Status.Ingress[0].Conditions[0].Status).To(Equal(v1.ConditionTrue))
		})
	})
})
