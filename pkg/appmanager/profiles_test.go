/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"

	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("AppManager Profile Tests", func() {
	Describe("Using Mock Manager", func() {
		var mockMgr *mockAppManager
		var mw *test.MockWriter
		var namespace string
		BeforeEach(func() {
			RegisterBigIPSchemaTypes()

			mw = &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			mockMgr = newMockAppManager(&Params{
				KubeClient: fakeClient,
				//ConfigWriter:           mw,
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
			namespace = "default"
			mockMgr.appMgr.routeConfig = RouteConfig{
				HttpVs:  "ose-vserver",
				HttpsVs: "https-ose-vserver",
			}
			mockMgr.appMgr.AgentCIS, _ = agent.CreateAgent(agent.CCCLAgent)
			mockMgr.appMgr.AgentCIS.Init(&cccl.Params{ConfigWriter: mw})
			err := mockMgr.startNonLabelMode([]string{namespace})
			Expect(err).To(BeNil())
		})
		AfterEach(func() {
			mockMgr.shutdown()
		})

		It("uses annotated profiles for Routes", func() {
			spec := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				TLS: &routeapi.TLSConfig{
					Termination:              "reencrypt",
					Certificate:              cert,
					Key:                      key,
					DestinationCACertificate: destCACert,
				},
			}
			route := test.NewRoute("route", "1", namespace, spec,
				map[string]string{
					F5ClientSslProfileAnnotation: "Common/client",
					F5ServerSslProfileAnnotation: "Common/server",
				})
			r := mockMgr.addRoute(route)
			Expect(r).To(BeTrue(), "Route resource should be processed.")

			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 443, NodePort: 37001}})
			mockMgr.addService(fooSvc)

			resources := mockMgr.resources()
			rs, ok := resources.Get(
				ServiceKey{ServiceName: "foo", ServicePort: 443, Namespace: namespace}, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Route should be accessible.")
			Expect(rs).ToNot(BeNil(), "Route should be object.")

			Expect(rs.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Partition: "Common",
					Name:      "client",
					Context:   CustomProfileClient,
					Namespace: namespace,
				}))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(
				ProfileRef{
					Partition: "velcro",
					Name:      "/openshift_route_default_route-client-ssl",
					Context:   CustomProfileClient,
				}))
			pRef := ProfileRef{
				Name:      "server",
				Partition: "Common",
				Context:   CustomProfileServer,
				Namespace: namespace,
			}
			Expect(rs.Virtual.Profiles).To(ContainElement(pRef))
			customPRef := ProfileRef{
				Name:      "openshift_route_default_route-server-ssl",
				Partition: "velcro",
				Context:   CustomProfileServer,
				Namespace: namespace,
			}
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(customPRef))

			// Remove profiles
			delete(route.Annotations, F5ClientSslProfileAnnotation)
			delete(route.Annotations, F5ServerSslProfileAnnotation)
			mockMgr.updateRoute(route)

			rs, _ = resources.Get(
				ServiceKey{ServiceName: "foo", ServicePort: 443, Namespace: namespace}, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(
				ProfileRef{
					Partition: "Common",
					Name:      "client",
					Context:   CustomProfileClient,
				}))
			Expect(rs.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Partition: "velcro",
					Name:      "openshift_route_default_route-client-ssl",
					Context:   CustomProfileClient,
					Namespace: namespace,
				}))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(pRef))
			Expect(rs.Virtual.Profiles).To(ContainElement(customPRef))

			// Re-add the profiles
			route.Annotations[F5ClientSslProfileAnnotation] = "Common/newClient"
			route.Annotations[F5ServerSslProfileAnnotation] = "Common/newServer"
			mockMgr.updateRoute(route)

			rs, _ = resources.Get(
				ServiceKey{ServiceName: "foo", ServicePort: 443, Namespace: namespace}, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(rs.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Partition: "Common",
					Name:      "newClient",
					Context:   CustomProfileClient,
					Namespace: namespace,
				}))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(
				ProfileRef{
					Partition: "velcro",
					Name:      "openshift_route_default_route-client-ssl",
					Context:   CustomProfileClient,
					Namespace: namespace,
				}))
			pRef = ProfileRef{
				Name:      "newServer",
				Partition: "Common",
				Context:   CustomProfileServer,
				Namespace: namespace,
			}
			Expect(rs.Virtual.Profiles).To(ContainElement(pRef))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(customPRef))
		})
	})
})
