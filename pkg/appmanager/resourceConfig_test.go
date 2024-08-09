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
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Resource Config Tests", func() {
	Context("resource configuration", func() {
		var mockMgr *mockAppManager
		BeforeEach(func() {
			mockMgr = newMockAppManager(&Params{})
			mockMgr.appMgr.AgentCIS, _ = agent.CreateAgent(agent.CCCLAgent)
			mockMgr.appMgr.AgentCIS.Init(&cccl.Params{})
		})

		It("properly configures route resources", func() {
			namespace := "default"
			spec := routeapi.RouteSpec{
				Host: "foobar.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "foo",
				},
				Port: &routeapi.RoutePort{
					TargetPort: intstr.FromInt(80),
				},
				TLS: &routeapi.TLSConfig{
					Termination: "edge",
					Certificate: "cert",
					Key:         "key",
				},
			}
			route := test.NewRoute("route", "1", namespace, spec, nil)
			ps := portStruct{
				protocol: "https",
				port:     443,
			}
			rc := RouteConfig{
				HttpVs:  "ose-vserver",
				HttpsVs: "https-ose-vserver",
			}
			svcFwdRulesMap := NewServiceFwdRuleMap()
			cfg, _, _ := mockMgr.appMgr.createRSConfigFromRoute(
				route, GetRouteCanonicalServiceName(route),
				&Resources{}, rc, ps, nil, svcFwdRulesMap, "test-snat-pool")
			Expect(cfg.Virtual.Name).To(Equal("https-ose-vserver"))
			Expect(cfg.Virtual.SourceAddrTranslation).To(Equal(SourceAddrTranslation{
				Type: "snat",
				Pool: "test-snat-pool",
			}))
			Expect(cfg.Pools[0].Name).To(Equal("openshift_default_foo"))
			Expect(cfg.Pools[0].ServiceName).To(Equal("foo"))
			Expect(cfg.Pools[0].ServicePort).To(Equal(int32(80)))
			Expect(cfg.Policies[0].Name).To(Equal("openshift_secure_routes"))
			Expect(cfg.Policies[0].Rules[0].Name).To(Equal("openshift_route_default_route"))

			spec = routeapi.RouteSpec{
				Host: "foobar.com",
				Path: "/foo",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: "bar",
				},
				Port: &routeapi.RoutePort{
					TargetPort: intstr.FromInt(80),
				},
			}
			route2 := test.NewRoute("route2", "1", namespace, spec, nil)
			ps = portStruct{
				protocol: "http",
				port:     80,
			}
			cfg, _, _ = mockMgr.appMgr.createRSConfigFromRoute(
				route2, GetRouteCanonicalServiceName(route2),
				&Resources{}, rc, ps, nil, svcFwdRulesMap, "")
			Expect(cfg.Virtual.Name).To(Equal("ose-vserver"))
			Expect(cfg.Pools[0].Name).To(Equal("openshift_default_bar"))
			Expect(cfg.Pools[0].ServiceName).To(Equal("bar"))
			Expect(cfg.Pools[0].ServicePort).To(Equal(int32(80)))
			Expect(cfg.Policies[0].Name).To(Equal("openshift_insecure_routes"))
			Expect(cfg.Policies[0].Rules[0].Name).To(Equal("openshift_route_default_route2"))
		})
	})
})
