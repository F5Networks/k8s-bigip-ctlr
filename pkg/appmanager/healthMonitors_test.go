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
	. "github.com/onsi/gomega/gstruct"
	routeapi "github.com/openshift/api/route/v1"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Health Monitor Tests", func() {
	var mockMgr *mockAppManager
	var mw *test.MockWriter
	var namespace string
	BeforeEach(func() {
		mw = &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		fakeClient := fake.NewClientset()
		Expect(fakeClient).ToNot(BeNil())

		mockMgr = newMockAppManager(&Params{
			KubeClient: fakeClient,
			//ConfigWriter:           mw,
			restClient:             test.CreateFakeHTTPClient(),
			RouteClientV1:          fakeRouteClient.NewSimpleClientset().RouteV1(),
			IsNodePort:             true,
			ManageIngress:          true,
			broadcasterFunc:        NewFakeEventBroadcaster,
			ManageIngressClassOnly: false,
			IngressClass:           "f5",
		})
		mockMgr.appMgr.AgentCIS, _ = agent.CreateAgent(agent.CCCLAgent)
		mockMgr.appMgr.AgentCIS.Init(&cccl.Params{ConfigWriter: mw})
		namespace = "default"
		err := mockMgr.startNonLabelMode([]string{namespace})
		Expect(err).To(BeNil())
	})
	AfterEach(func() {
		mockMgr.shutdown()
	})

	checkSingleServiceHealthMonitor := func(
		rc *ResourceConfig,
		svcName string,
		svcPort int,
		expectSuccess bool,
	) {
		Expect(len(rc.Pools)).To(BeNumerically(">", 0))
		poolNdx := -1
		for i, pool := range rc.Pools {
			if pool.Partition == rc.GetPartition() &&
				pool.ServiceName == svcName &&
				pool.ServicePort == int32(svcPort) {
				poolNdx = i
			}
		}
		Expect(poolNdx).ToNot(Equal(-1))
		monitorFound := false
		if expectSuccess {
			Expect(len(rc.Pools[poolNdx].MonitorNames)).To(Equal(1))
			partition, monitorName := SplitBigipPath(
				rc.Pools[poolNdx].MonitorNames[0], false)
			for _, monitor := range rc.Monitors {
				if monitor.Partition == partition && monitor.Name == monitorName {
					monitorFound = true
				}
			}
			Expect(monitorFound).To(BeTrue())
		} else {
			Expect(len(rc.Pools[poolNdx].MonitorNames)).To(Equal(0))
			partition := rc.Pools[poolNdx].Name
			poolName := rc.Pools[poolNdx].Name
			for _, monitor := range rc.Monitors {
				if monitor.Partition == partition && monitor.Name == poolName {
					monitorFound = true
				}
			}
			Expect(monitorFound).To(BeFalse())
		}
	}

	Context("health monitor properties", func() {
		It("confirms http health Monitor properties", func() {
			hm := Monitor{}
			hm.Name = "svc"
			hm.Partition = "f5"
			hm.Interval = 10
			hm.Type = "http"
			hm.Send = "GET / HTTP/1.0"
			hm.Recv = "Hello from"
			hm.Timeout = 5

			Expect(hm).To(MatchAllFields(Fields{
				"Name":       Equal("svc"),
				"Partition":  Equal("f5"),
				"Interval":   Equal(10),
				"Type":       Equal("http"),
				"Send":       Equal("GET / HTTP/1.0"),
				"Recv":       Equal("Hello from"),
				"Timeout":    Equal(5),
				"SslProfile": Equal(""),
			}))
		})

		It("confirms https health Monitor properties", func() {
			hm := Monitor{}
			hm.Name = "svc"
			hm.Partition = "f5"
			hm.Interval = 10
			hm.Type = "https"
			hm.Send = "GET / HTTP/1.0"
			hm.Recv = "Hello from"
			hm.Timeout = 5
			Expect(hm).To(MatchAllFields(Fields{
				"Name":       Equal("svc"),
				"Partition":  Equal("f5"),
				"Interval":   Equal(10),
				"Type":       Equal("https"),
				"Send":       Equal("GET / HTTP/1.0"),
				"Recv":       Equal("Hello from"),
				"Timeout":    Equal(5),
				"SslProfile": Equal(""),
			}))
		})

		It("confirms ConfigMapMonitor properties", func() {
			cmm := ConfigMapMonitor{}
			cmm.Name = "svc"
			cmm.Partition = "f5"
			cmm.Interval = 10
			cmm.Protocol = "http"
			cmm.Send = "GET / HTTP/1.0"
			cmm.Recv = "Hello from"
			cmm.Timeout = 5

			Expect(cmm).To(MatchAllFields(Fields{
				"Name":      Equal("svc"),
				"Partition": Equal("f5"),
				"Interval":  Equal(10),
				"Protocol":  Equal("http"),
				"Send":      Equal("GET / HTTP/1.0"),
				"Recv":      Equal("Hello from"),
				"Timeout":   Equal(5),
			}))
		})

		It("confirms AnnotationHealthMonitor properties", func() {
			ahm := AnnotationHealthMonitor{}
			ahm.Path = "/foo"
			ahm.Interval = 10
			ahm.Send = "GET / HTTP/1.0"
			ahm.Recv = "Hello from"
			ahm.Timeout = 5
			ahm.Type = "http"

			Expect(ahm).To(MatchAllFields(Fields{
				"Path":       Equal("/foo"),
				"Interval":   Equal(10),
				"Send":       Equal("GET / HTTP/1.0"),
				"Recv":       Equal("Hello from"),
				"Timeout":    Equal(5),
				"Type":       Equal("http"),
				"SslProfile": Equal(""),
			}))
		})

	})

	Context("route health monitors", func() {
		BeforeEach(func() {
			mockMgr.appMgr.routeConfig = RouteConfig{
				HttpVs:  "ose-vserver",
				HttpsVs: "https-ose-vserver",
			}
		})

		It("configures route health monitors", func() {
			svcName := "svc1"
			svcPort := 8080
			spec := routeapi.RouteSpec{
				Host: "foo.com",
				Path: "/bar",
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: svcName,
				},
				Port: &routeapi.RoutePort{
					TargetPort: intstr.FromInt(svcPort),
				},
				TLS: &routeapi.TLSConfig{
					Termination: "edge",
					Certificate: cert,
					Key:         key,
				},
			}
			route := test.NewRoute("route", "1", namespace, spec,
				map[string]string{
					HealthMonitorAnnotation: `[
					{
						"path":     "svc1/",
						"send":     "HTTP GET /test1",
						"recv":     "Hello from",
						"interval": 5,
						"timeout":  10
					}
				]`,
				})
			svcKey := ServiceKey{
				Namespace:   namespace,
				ServiceName: svcName,
				ServicePort: int32(svcPort),
			}

			svcPorts := []v1.ServicePort{newServicePort(svcName, int32(svcPort))}
			fooSvc := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP,
				svcPorts)

			r := mockMgr.addRoute(route)
			Expect(r).To(BeTrue(), "Route resource should be processed.")

			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))

			// The first test uses an explicit server name
			vsCfgFoo, found := resources.Get(svcKey, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)

			// The second test uses a wildcard host name
			route.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"path":     "*/foo",
				"send":     "HTTP GET /test2",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateRoute(route)
			Expect(r).To(BeTrue(), "Route resource should be processed.")
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)

			// The third test omits the host part of the path
			route.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"path":     "/",
				"send":     "HTTP GET /test3",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateRoute(route)
			Expect(r).To(BeTrue(), "Route resource should be processed.")
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)

			// The fourth test omits the path entirely (error case)
			route.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"send":     "HTTP GET /test3",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateRoute(route)
			Expect(r).To(BeTrue(), "Route resource should be processed.")
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: "https-ose-vserver", Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, false)
		})
	})
})
