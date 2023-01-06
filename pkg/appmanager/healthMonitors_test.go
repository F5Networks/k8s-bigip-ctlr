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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	routeapi "github.com/openshift/api/route/v1"

	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
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
		fakeClient := fake.NewSimpleClientset()
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
	// TODO remove the tests for "ingress health monitors" once v1beta1.Ingress is deprecated in k8s 1.22
	Context("ingress health monitors", func() {
		It("configures single service ingress health checks", func() {
			svcName := "svc1"
			svcPort := 8080
			spec := v1beta1.IngressSpec{
				Backend: &v1beta1.IngressBackend{
					ServiceName: svcName,
					ServicePort: intstr.FromInt(svcPort),
				},
			}
			ing := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsHttpPortAnnotation:  "443",
					HealthMonitorAnnotation: `[
						{
							"path":     "svc1/",
							"send":     "HTTP GET /test1",
							"interval": 5,
							"timeout":  10
						}
					]`,
				})
			emptyIps := []string{}
			svcKey := ServiceKey{
				Namespace:   namespace,
				ServiceName: svcName,
				ServicePort: int32(svcPort),
			}

			svcPorts := []v1.ServicePort{newServicePort(svcName, int32(svcPort))}
			fooSvc := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP,
				svcPorts)
			readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts := test.NewEndpoints(svcName, "1", "node0", namespace,
				readyIps, emptyIps, convertSvcPortsToEndpointPorts(svcPorts))

			r := mockMgr.addIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))

			// The first test uses an explicit server name
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			vsCfgFoo, found := resources.Get(svcKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)

			// The second test uses a wildcard host name
			ing.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"path":     "*/foo",
				"send":     "HTTP GET /test2",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)

			// The third test omits the host part of the path
			ing.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"path":     "/",
				"send":     "HTTP GET /test3",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)

			// The fourth test omits the path entirely (error case)
			ing.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"send":     "HTTP GET /test3",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, false)

			// SSLPROFILE The third test omits the host part of the path
			ing.ObjectMeta.Annotations[HealthMonitorAnnotation] = `[
			{
				"path":     "/",
				"type":     "https",
				"send":     "HTTPS GET /test4",
				"sslProfile": "/Common/serverssl",
				"interval": 5,
				"timeout":  10
			}]`
			r = mockMgr.updateIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, true)
			Expect(vsCfgFoo.Monitors[0].SslProfile).To(Equal("/Common/serverssl"))
		})

		checkMultiServiceHealthMonitor := func(
			rc *ResourceConfig,
			svcName string,
			svcPort int,
			expectSuccess bool,
		) {
			Expect(len(rc.Policies)).To(BeNumerically(">", 0))
			Expect(len(rc.Pools)).To(BeNumerically(">", 0))
			policyNdx := -1
			for i, pol := range rc.Policies {
				if pol.Name == rc.Virtual.Name &&
					pol.Partition == rc.GetPartition() {
					policyNdx = i
					break
				}
			}
			Expect(policyNdx).ToNot(Equal(-1))

			poolNdx := -1
			for i, pool := range rc.Pools {
				if pool.Partition == rc.GetPartition() &&
					pool.ServiceName == svcName &&
					pool.ServicePort == int32(svcPort) {
					poolNdx = i
				}
			}
			Expect(poolNdx).ToNot(Equal(-1))
			fullPoolName := JoinBigipPath(
				rc.Pools[poolNdx].Partition, rc.Pools[poolNdx].Name)
			actionFound := false
			for _, rule := range rc.Policies[policyNdx].Rules {
				for _, action := range rule.Actions {
					if action.Pool == fullPoolName {
						actionFound = true
						Expect(action.Forward).To(BeTrue())
						Expect(action.Pool).To(Equal(fullPoolName))
					}
				}
			}
			Expect(actionFound).To(BeTrue())

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

		It("configures multi service ingress health checks", func() {
			host1Name := "svc1.bar.com"
			svc1Name := "svc1"
			svc1Port := 8080
			svc1Path := "/foo"
			host2Name := "svc2.bar.com"
			svc2Name := "svc2"
			svc2Port := 9090
			svc2Path := "/bar"
			svc3Name := "svc3"
			svc3Port := 8888
			svc3Path := "/baz"
			spec := v1beta1.IngressSpec{
				Rules: []v1beta1.IngressRule{
					{
						Host: host1Name,
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Path: svc1Path,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc1Name,
											ServicePort: intstr.FromInt(svc1Port),
										},
									},
								},
							},
						},
					}, {
						Host: host2Name,
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Path: svc2Path,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc2Name,
											ServicePort: intstr.FromInt(svc2Port),
										},
									}, {
										Path: svc3Path,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc3Name,
											ServicePort: intstr.FromInt(svc3Port),
										},
									},
								},
							},
						},
					},
				},
			}
			ing := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					IngressSslRedirect:      "true",
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsHttpPortAnnotation:  "443",
					HealthMonitorAnnotation: `[
					{
						"path":     "svc2.bar.com/bar",
						"send":     "HTTP GET /health/bar",
						"interval": 5,
						"timeout":  5
					}, {
						"path":     "svc2.bar.com/baz",
						"send":     "HTTP GET /health/baz",
						"interval": 5,
						"timeout":  5
					}, {
						"path":     "svc1.bar.com/foo",
						"send":     "HTTP GET /health/foo",
						"interval": 5,
						"timeout":  10
					}
				]`,
				})
			emptyIps := []string{}

			svc1Ports := []v1.ServicePort{newServicePort(svc1Name, int32(svc1Port))}
			fooSvc := test.NewService(svc1Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc1Ports)
			ready1Ips := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts1 := test.NewEndpoints(svc1Name, "1", "node0", namespace,
				ready1Ips, emptyIps, convertSvcPortsToEndpointPorts(svc1Ports))

			r := mockMgr.addIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts1)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))

			svc1Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc1Name,
				ServicePort: int32(svc1Port),
			}
			Expect(resources.CountOf(svc1Key)).To(Equal(1))
			vsCfgFoo, found := resources.Get(svc1Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())

			svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
			barSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc2Ports)
			ready2Ips := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
			endpts2 := test.NewEndpoints(svc2Name, "1", "node1", namespace,
				ready2Ips, emptyIps, convertSvcPortsToEndpointPorts(svc2Ports))

			r = mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts2)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			Expect(resources.PoolCount()).To(Equal(2))

			svc2Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc2Name,
				ServicePort: int32(svc2Port),
			}
			Expect(resources.CountOf(svc2Key)).To(Equal(1))
			vsCfgBar, found := resources.Get(svc2Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBar).ToNot(BeNil())

			svc3Ports := []v1.ServicePort{newServicePort(svc3Name, int32(svc3Port))}
			bazSvc := test.NewService(svc3Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc3Ports)
			ready3Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
			endpts3 := test.NewEndpoints(svc3Name, "1", "node2", namespace,
				ready3Ips, emptyIps, convertSvcPortsToEndpointPorts(svc3Ports))

			r = mockMgr.addService(bazSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts3)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			Expect(resources.PoolCount()).To(Equal(3))

			svc3Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc3Name,
				ServicePort: int32(svc3Port),
			}
			Expect(resources.CountOf(svc3Key)).To(Equal(1))
			vsCfgBaz, found := resources.Get(svc3Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBaz).ToNot(BeNil())

			checkMultiServiceHealthMonitor(vsCfgFoo, svc1Name, svc1Port, true)
			checkMultiServiceHealthMonitor(vsCfgBar, svc2Name, svc2Port, true)
			checkMultiServiceHealthMonitor(vsCfgBaz, svc3Name, svc3Port, true)
		})

		It("configures multi service ingress health checks with no path", func() {
			host1Name := "foo.bar.com"
			svc1aName := "nginx"
			svc1aPort := 80
			svc1aPath := "/foo"
			svc1bName := "nginx2"
			svc1bPort := 80
			svc1bPath := "/bar"
			host2Name := "bar.foo.com"
			svc2Name := "nginx3"
			svc2Port := 80
			spec := v1beta1.IngressSpec{
				Rules: []v1beta1.IngressRule{
					{
						Host: host1Name,
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Path: svc1aPath,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc1aName,
											ServicePort: intstr.FromInt(svc1aPort),
										},
									}, {
										Path: svc1bPath,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc1bName,
											ServicePort: intstr.FromInt(svc1bPort),
										},
									},
								},
							},
						},
					}, {
						Host: host2Name,
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Backend: v1beta1.IngressBackend{
											ServiceName: svc2Name,
											ServicePort: intstr.FromInt(svc2Port),
										},
									},
								},
							},
						},
					},
				},
			}
			ing := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					F5VsBindAddrAnnotation:  "172.16.3.2",
					F5VsPartitionAnnotation: "velcro",
					HealthMonitorAnnotation: `[
					{
						"path":     "foo.bar.com/foo",
						"send":     "HTTP GET /health/foo",
						"interval": 5,
						"timeout":  10
					}, {
						"path":     "foo.bar.com/bar",
						"send":     "HTTP GET /health/bar",
						"interval": 5,
						"timeout":  10
					}, {
						"path":     "bar.foo.com/",
						"send":     "HTTP GET /health",
						"interval": 5,
						"timeout":  10
					}
				]`,
				})
			emptyIps := []string{}

			svc1aPorts := []v1.ServicePort{newServicePort(svc1aName, int32(svc1aPort))}
			fooSvc := test.NewService(svc1aName, "1", namespace, v1.ServiceTypeClusterIP,
				svc1aPorts)
			ready1aIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts1a := test.NewEndpoints(svc1aName, "1", "node0", namespace,
				ready1aIps, emptyIps, convertSvcPortsToEndpointPorts(svc1aPorts))

			r := mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts1a)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")

			svc1bPorts := []v1.ServicePort{newServicePort(svc1bName, int32(svc1bPort))}
			barSvc := test.NewService(svc1bName, "1", namespace, v1.ServiceTypeClusterIP,
				svc1bPorts)
			ready1bIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
			endpts1b := test.NewEndpoints(svc1bName, "1", "node1", namespace,
				ready1bIps, emptyIps, convertSvcPortsToEndpointPorts(svc1bPorts))

			r = mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts1b)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")

			svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
			bazSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc2Ports)
			ready2Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
			endpts2 := test.NewEndpoints(svc2Name, "1", "node2", namespace,
				ready2Ips, emptyIps, convertSvcPortsToEndpointPorts(svc2Ports))

			r = mockMgr.addService(bazSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts2)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")

			r = mockMgr.addIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(3))

			svc1aKey := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc1aName,
				ServicePort: int32(svc1aPort),
			}
			Expect(resources.CountOf(svc1aKey)).To(Equal(1))
			vsCfgFoo, found := resources.Get(svc1aKey, NameRef{Name: FormatIngressVSName("172.16.3.2", 80), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())

			svc1bKey := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc1bName,
				ServicePort: int32(svc1bPort),
			}
			Expect(resources.CountOf(svc1bKey)).To(Equal(1))
			vsCfgBar, found := resources.Get(svc1bKey, NameRef{Name: FormatIngressVSName("172.16.3.2", 80), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBar).ToNot(BeNil())

			svc2Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc2Name,
				ServicePort: int32(svc2Port),
			}
			Expect(resources.CountOf(svc2Key)).To(Equal(1))
			vsCfgBaz, found := resources.Get(svc2Key, NameRef{Name: FormatIngressVSName("172.16.3.2", 80), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBaz).ToNot(BeNil())

			checkMultiServiceHealthMonitor(vsCfgFoo, svc1aName, svc1aPort, true)
			checkMultiServiceHealthMonitor(vsCfgBar, svc1bName, svc1bPort, true)
			checkMultiServiceHealthMonitor(vsCfgBaz, svc2Name, svc2Port, true)
		})

		It("configures multi service ingress with one health check", func() {
			host1Name := "foo.bar.com"
			svc1aName := "nginx"
			svc1aPort := 80
			svc1aPath := "/foo"
			svc1bName := "nginx2"
			svc1bPort := 80
			svc1bPath := "/bar"
			host2Name := "svc2.bar.com"
			svc2Name := "nginx3"
			svc2Port := 80
			spec := v1beta1.IngressSpec{
				Rules: []v1beta1.IngressRule{
					{
						Host: host1Name,
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Path: svc1aPath,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc1aName,
											ServicePort: intstr.FromInt(svc1aPort),
										},
									}, {
										Path: svc1bPath,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc1bName,
											ServicePort: intstr.FromInt(svc1bPort),
										},
									},
								},
							},
						},
					}, {
						Host: host2Name,
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Backend: v1beta1.IngressBackend{
											ServiceName: svc2Name,
											ServicePort: intstr.FromInt(svc2Port),
										},
									},
								},
							},
						},
					},
				},
			}
			ing := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					IngressSslRedirect:      "true",
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsHttpPortAnnotation:  "443",
					HealthMonitorAnnotation: `[
					{
						"path":     "foo.bar.com/foo",
						"send":     "HTTP GET /health/foo",
						"interval": 5,
						"timeout":  5
					}
				]`,
				})
			emptyIps := []string{}

			svc1aPorts := []v1.ServicePort{newServicePort(svc1aName, int32(svc1aPort))}
			fooSvc := test.NewService(svc1aName, "1", namespace, v1.ServiceTypeClusterIP,
				svc1aPorts)
			ready1aIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts1a := test.NewEndpoints(svc1aName, "1", "node0", namespace,
				ready1aIps, emptyIps, convertSvcPortsToEndpointPorts(svc1aPorts))

			r := mockMgr.addIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts1a)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))

			svc1aKey := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc1aName,
				ServicePort: int32(svc1aPort),
			}
			Expect(resources.CountOf(svc1aKey)).To(Equal(1))
			vsCfgFoo, found := resources.Get(svc1aKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())

			svc1bPorts := []v1.ServicePort{newServicePort(svc1bName, int32(svc1bPort))}
			barSvc := test.NewService(svc1bName, "1", namespace, v1.ServiceTypeClusterIP,
				svc1bPorts)
			ready1bIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
			endpts1b := test.NewEndpoints(svc1bName, "1", "node1", namespace,
				ready1bIps, emptyIps, convertSvcPortsToEndpointPorts(svc1bPorts))

			r = mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts1b)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			Expect(resources.PoolCount()).To(Equal(2))

			svc1bKey := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc1bName,
				ServicePort: int32(svc1bPort),
			}
			Expect(resources.CountOf(svc1bKey)).To(Equal(1))
			vsCfgBar, found := resources.Get(svc1bKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBar).ToNot(BeNil())

			svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
			bazSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc2Ports)
			ready2Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
			endpts2 := test.NewEndpoints(svc2Name, "1", "node0", namespace,
				ready2Ips, emptyIps, convertSvcPortsToEndpointPorts(svc2Ports))

			r = mockMgr.addService(bazSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts2)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			Expect(resources.PoolCount()).To(Equal(3))

			svc2Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc2Name,
				ServicePort: int32(svc2Port),
			}
			Expect(resources.CountOf(svc2Key)).To(Equal(1))
			vsCfgBaz, found := resources.Get(svc2Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBaz).ToNot(BeNil())

			checkMultiServiceHealthMonitor(vsCfgFoo, svc1aName, svc1aPort, true)
			checkMultiServiceHealthMonitor(vsCfgBar, svc1bName, svc1bPort, false)
			checkMultiServiceHealthMonitor(vsCfgBaz, svc2Name, svc2Port, false)
		})

		It("configures multi service ingress health checks with no host", func() {
			svc1Name := "svc1"
			svc1Port := 8080
			svc1Path := "/foo"
			svc2Name := "svc2"
			svc2Port := 9090
			svc2Path := "/bar"
			svc3Name := "svc3"
			svc3Port := 8888
			svc3Path := "/baz"
			spec := v1beta1.IngressSpec{
				Rules: []v1beta1.IngressRule{
					{
						IngressRuleValue: v1beta1.IngressRuleValue{
							HTTP: &v1beta1.HTTPIngressRuleValue{
								Paths: []v1beta1.HTTPIngressPath{
									{
										Path: svc1Path,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc1Name,
											ServicePort: intstr.FromInt(svc1Port),
										},
									}, {
										Path: svc2Path,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc2Name,
											ServicePort: intstr.FromInt(svc2Port),
										},
									}, {
										Path: svc3Path,
										Backend: v1beta1.IngressBackend{
											ServiceName: svc3Name,
											ServicePort: intstr.FromInt(svc3Port),
										},
									},
								},
							},
						},
					},
				},
			}
			ing := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					IngressSslRedirect:      "true",
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsHttpPortAnnotation:  "443",
					HealthMonitorAnnotation: `[
					{
						"path":     "*/bar",
						"send":     "HTTP GET /health/bar",
						"interval": 5,
						"timeout":  5
					}, {
						"path":     "*/baz",
						"send":     "HTTP GET /health/baz",
						"interval": 5,
						"timeout":  7
					}, {
						"path":     "*/foo",
						"send":     "HTTP GET /health/foo",
						"interval": 5,
						"timeout":  10
					}
				]`,
				})
			emptyIps := []string{}

			svc1Ports := []v1.ServicePort{newServicePort(svc1Name, int32(svc1Port))}
			fooSvc := test.NewService(svc1Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc1Ports)
			ready1Ips := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts1 := test.NewEndpoints(svc1Name, "1", "node0", namespace,
				ready1Ips, emptyIps, convertSvcPortsToEndpointPorts(svc1Ports))

			r := mockMgr.addIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts1)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))

			svc1Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc1Name,
				ServicePort: int32(svc1Port),
			}
			Expect(resources.CountOf(svc1Key)).To(Equal(1))
			vsCfgFoo, found := resources.Get(svc1Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())

			svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
			barSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc2Ports)
			ready2Ips := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
			endpts2 := test.NewEndpoints(svc2Name, "1", "node1", namespace,
				ready2Ips, emptyIps, convertSvcPortsToEndpointPorts(svc2Ports))

			r = mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts2)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			Expect(resources.PoolCount()).To(Equal(2))

			svc2Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc2Name,
				ServicePort: int32(svc2Port),
			}
			Expect(resources.CountOf(svc2Key)).To(Equal(1))
			vsCfgBar, found := resources.Get(svc2Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBar).ToNot(BeNil())

			svc3Ports := []v1.ServicePort{newServicePort(svc3Name, int32(svc3Port))}
			bazSvc := test.NewService(svc3Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc3Ports)
			ready3Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
			endpts3 := test.NewEndpoints(svc3Name, "1", "node2", namespace,
				ready3Ips, emptyIps, convertSvcPortsToEndpointPorts(svc3Ports))

			r = mockMgr.addService(bazSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts3)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			Expect(resources.PoolCount()).To(Equal(3))

			svc3Key := ServiceKey{
				Namespace:   namespace,
				ServiceName: svc3Name,
				ServicePort: int32(svc3Port),
			}
			Expect(resources.CountOf(svc3Key)).To(Equal(1))
			vsCfgBaz, found := resources.Get(svc3Key, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgBaz).ToNot(BeNil())

			checkMultiServiceHealthMonitor(vsCfgFoo, svc1Name, svc1Port, true)
			checkMultiServiceHealthMonitor(vsCfgBar, svc2Name, svc2Port, true)
			checkMultiServiceHealthMonitor(vsCfgBaz, svc3Name, svc3Port, true)
		})
		It("Removes unused health monitors", func() {
			rcfg := &ResourceConfig{}
			//rcfg.Monitors = make([]Monitor, 0)
			//rcfg.Pools = make([]Pool, 0)
			rcfg.Pools = []Pool{
				Pool{Name: "svc1", Partition: "test", MonitorNames: []string{"/test/hm1", "/test/hm2"}},
				Pool{Name: "svc2", Partition: "test", MonitorNames: []string{"/test/hm3", "/test/hm4"}},
			}
			rcfg.Monitors = []Monitor{
				Monitor{Name: "hm0", Partition: "test"},
				Monitor{Name: "hm1", Partition: "test"},
				Monitor{Name: "hm2", Partition: "test"},
				Monitor{Name: "hm3", Partition: "test"},
				Monitor{Name: "hm4", Partition: "test"},
				Monitor{Name: "hm5", Partition: "test"},
			}
			expectedMonitors := Monitors([]Monitor{
				Monitor{Name: "hm1", Partition: "test"},
				Monitor{Name: "hm2", Partition: "test"},
				Monitor{Name: "hm3", Partition: "test"},
				Monitor{Name: "hm4", Partition: "test"},
			})
			RemoveUnusedHealthMonitors(rcfg)
			Expect(rcfg.Monitors).To(Equal(expectedMonitors))
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
