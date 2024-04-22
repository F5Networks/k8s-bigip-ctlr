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
	"context"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var IngressClassName = "f5"
var _ = Describe("V1 Ingress Tests", func() {
	var mockMgr *mockAppManager
	var mw *test.MockWriter
	var namespace string
	var ingClass *netv1.IngressClass
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
		ingClass = &netv1.IngressClass{TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1",
			Kind: "IngressClass"},
			ObjectMeta: metav1.ObjectMeta{Name: IngressClassName},
			Spec:       netv1.IngressClassSpec{Controller: CISControllerName},
		}
		mockMgr.appMgr.kubeClient.NetworkingV1().IngressClasses().Create(context.TODO(), ingClass, metav1.CreateOptions{})
		mockMgr.appMgr.AgentCIS, _ = agent.CreateAgent(agent.CCCLAgent)
		mockMgr.appMgr.AgentCIS.Init(&cccl.Params{ConfigWriter: mw})
		namespace = "default"
		err := mockMgr.startNonLabelMode([]string{namespace})
		appInf, _ := mockMgr.appMgr.getNamespaceInformer(namespace)
		appInf.ingClassInformer.GetStore().Add(ingClass)
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
	Context("SSL profiles ", func() {
		It("creates ssl profiles from Secrets", func() {
			mockMgr.appMgr.useSecrets = true
			// Create a secret
			secret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret1",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"tls.crt": []byte("testcert"),
					"tls.key": []byte("testkey"),
				},
			}
			//_, err := mockMgr.appMgr.kubeClient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
			err := mockMgr.appMgr.appInformers[namespace].secretInformer.GetStore().Add(secret)
			Expect(err).To(BeNil())

			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				TLS: []netv1.IngressTLS{
					{
						SecretName: secret.ObjectMeta.Name,
					},
				},
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			// Test for Ingress
			ingress := NewV1Ingress("ingress", "1", namespace, spec,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
				})
			// This should create a custom profile from the ingress secret.
			mockMgr.addV1Ingress(ingress)
			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 443, NodePort: 37001}})
			mockMgr.addService(fooSvc)

			customProfiles := mockMgr.customProfiles()
			Expect(len(customProfiles)).To(Equal(2))

			// This should remove the custom profile.
			mockMgr.deleteV1Ingress(ingress)
			resources := mockMgr.resources()
			Expect(len(resources.RsMap)).To(Equal(0))
			Expect(len(customProfiles)).To(Equal(0))
		})

	})
	Context("properly configures RS Config", func() {
		It("properly configures ingress resources", func() {
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			ingress := NewV1Ingress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
				})
			ps := portStruct{
				protocol: "http",
				port:     80,
			}
			cfg, _ := mockMgr.appMgr.createRSConfigFromV1Ingress(
				ingress, &Resources{}, namespace, nil, ps, "", "test-snat-pool")
			Expect(cfg.Pools[0].Balance).To(Equal("round-robin"))
			Expect(cfg.Virtual.Partition).To(Equal("velcro"))
			Expect(cfg.Virtual.VirtualAddress.BindAddr).To(Equal("1.2.3.4"))
			Expect(cfg.Virtual.VirtualAddress.Port).To(Equal(int32(80)))
			Expect(cfg.Virtual.SourceAddrTranslation).To(Equal(SourceAddrTranslation{
				Type: "snat",
				Pool: "test-snat-pool",
			}))

			ingress = NewV1Ingress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsHttpPortAnnotation:  "100",
					F5VsBalanceAnnotation:   "foobar",
					K8sIngressClass:         "f5",
				})
			ps = portStruct{
				protocol: "http",
				port:     100,
			}
			cfg, _ = mockMgr.appMgr.createRSConfigFromV1Ingress(
				ingress, &Resources{}, namespace, nil, ps, "", "")
			Expect(cfg.Pools[0].Balance).To(Equal("foobar"))
			Expect(cfg.Virtual.VirtualAddress.Port).To(Equal(int32(100)))

			ingress = NewV1Ingress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					K8sIngressClass: "notf5",
				})
			cfg, _ = mockMgr.appMgr.createRSConfigFromV1Ingress(
				ingress, &Resources{}, namespace, nil, ps, "", "")
			Expect(cfg).To(BeNil())

			// Use controller default IP
			defaultIng := NewV1Ingress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "controller-default",
					F5VsPartitionAnnotation: "velcro",
				})
			cfg, _ = mockMgr.appMgr.createRSConfigFromV1Ingress(
				defaultIng, &Resources{}, namespace, nil, ps, "5.6.7.8", "")
			Expect(cfg.Virtual.VirtualAddress.BindAddr).To(Equal("5.6.7.8"))
		})
		It("Verifies that ingress belonging to ingress class that cis doesn't manage isn't processed", func() {
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			ingress := NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
				})

			expectedSvcQKey := []*serviceQueueKey{
				{
					Namespace:    "default",
					ServiceName:  "foo",
					ResourceKind: "ingresses",
					ResourceName: "ingress1",
				},
			}
			tf, svcQKey := mockMgr.appMgr.checkV1Ingress(ingress)
			Expect(tf).To(Equal(true))
			Expect(svcQKey).To(Equal(expectedSvcQKey))
			// Attach a different ingress class to the ingress that cis doesn't manage and verify that CIS skips
			// processing it
			ingClassName := "f5-no-watch"
			ingress.Spec.IngressClassName = &ingClassName
			tf, svcQKey = mockMgr.appMgr.checkV1Ingress(ingress)
			Expect(tf).To(Equal(false))
			Expect(svcQKey).To(BeNil())
		})
	})

	Context("V1 ingress health monitors", func() {
		It("configures single service ingress health checks", func() {
			svcName := "svc1"
			svcPort := 8080
			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: svcName, Port: netv1.ServiceBackendPort{Number: int32(svcPort)}},
				},
			}
			ing := NewV1Ingress("ingress", "1", namespace, spec,
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

			r := mockMgr.addV1Ingress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			// enqueue ingress and check the queue length
			mockMgr.appMgr.enqueueIngress(ing, OprTypeCreate)
			Expect(mockMgr.appMgr.vsQueue.Len()).To(Equal(1))
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
			r = mockMgr.updateV1Ingress(ing)
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
			r = mockMgr.updateV1Ingress(ing)
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
			r = mockMgr.updateV1Ingress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			vsCfgFoo, found = resources.Get(svcKey, NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(found).To(BeTrue())
			Expect(vsCfgFoo).ToNot(BeNil())
			checkSingleServiceHealthMonitor(vsCfgFoo, svcName, svcPort, false)
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
			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						Host: host1Name,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: svc1Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1Name, Port: netv1.ServiceBackendPort{Number: int32(svc1Port)}},
										},
									},
								},
							},
						},
					}, {
						Host: host2Name,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: svc2Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc2Name, Port: netv1.ServiceBackendPort{Number: int32(svc2Port)}},
										},
									}, {
										Path: svc3Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc3Name, Port: netv1.ServiceBackendPort{Number: int32(svc3Port)}},
										},
									},
								},
							},
						},
					},
				},
			}
			ing := NewV1Ingress("ingress", "1", namespace, spec,
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

			r := mockMgr.addV1Ingress(ing)
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
			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						Host: host1Name,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: svc1aPath,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1aName, Port: netv1.ServiceBackendPort{Number: int32(svc1aPort)}},
										},
									}, {
										Path: svc1bPath,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1bName, Port: netv1.ServiceBackendPort{Number: int32(svc1bPort)}},
										},
									},
								},
							},
						},
					}, {
						Host: host2Name,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc2Name, Port: netv1.ServiceBackendPort{Number: int32(svc2Port)}},
										},
									},
								},
							},
						},
					},
				},
			}
			ing := NewV1Ingress("ingress", "1", namespace, spec,
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

			r = mockMgr.addV1Ingress(ing)
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
			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						Host: host1Name,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: svc1aPath,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1aName, Port: netv1.ServiceBackendPort{Number: int32(svc1aPort)}},
										},
									}, {
										Path: svc1bPath,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1bName, Port: netv1.ServiceBackendPort{Number: int32(svc1bPort)}},
										},
									},
								},
							},
						},
					}, {
						Host: host2Name,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc2Name, Port: netv1.ServiceBackendPort{Number: int32(svc2Port)}},
										},
									},
								},
							},
						},
					},
				},
			}
			ing := NewV1Ingress("ingress", "1", namespace, spec,
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

			r := mockMgr.addV1Ingress(ing)
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
			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: svc1Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1Name, Port: netv1.ServiceBackendPort{Number: int32(svc1Port)}},
										},
									}, {
										Path: svc2Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc2Name, Port: netv1.ServiceBackendPort{Number: int32(svc2Port)}},
										},
									}, {
										Path: svc3Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc3Name, Port: netv1.ServiceBackendPort{Number: int32(svc3Port)}},
										},
									},
								},
							},
						},
					},
				},
			}
			ing := NewV1Ingress("ingress", "1", namespace, spec,
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

			r := mockMgr.addV1Ingress(ing)
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
	})
	Context(" Test V1 Ingress annotations ", func() {
		It("doesn't deactivate a multi-service config unnecessarily", func() {
			err := mockMgr.startNonLabelMode([]string{namespace})
			Expect(err).To(BeNil())
			mockMgr.appMgr.useNodeInternal = true
			mockMgr.appMgr.WatchedNS = WatchedNamespaces{Namespaces: []string{namespace}}
			_ = mockMgr.appMgr.AddNodeInformer(0)
			mockMgr.appMgr.startAndSyncNodeInformer()
			// Ingress first
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{Host: "host1",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
									{Path: "/bar",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
								},
							},
						},
					},
				},
			}
			// Create Node so we get endpoints
			node := test.NewNode("node1", "1", false,
				[]v1.NodeAddress{{Type: "InternalIP", Address: "127.0.0.1"}}, []v1.Taint{}, nil)
			mockMgr.addNode(node, namespace)
			Expect(len(mockMgr.appMgr.nodeInformer.nodeInformer.GetIndexer().List())).To(Equal(1))

			// Create the services
			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37001}})
			r := mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			barSvc := test.NewService("bar", "2", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}})
			r = mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")

			// Create the Ingress
			ing := NewV1Ingress("ingress", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
				})
			r = mockMgr.addV1Ingress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			resources := mockMgr.resources()

			deleteServices := func() {
				rs, ok := resources.Get(
					ServiceKey{ServiceName: "foo", ServicePort: 80, Namespace: "default"}, NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())

				// Delete one service, config should still be active
				mockMgr.deleteService(fooSvc)
				rs, ok = resources.Get(
					ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"}, NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
				Expect(ok).To(BeTrue())
				Expect(rs.MetaData.Active).To(BeTrue())

				// Delete final service, config should go inactive
				mockMgr.deleteService(barSvc)
				rs, ok = resources.Get(
					ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"}, NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
				Expect(ok).To(BeFalse())
			}
			deleteServices()
		})

		It("configure whitelist annotation on Ingress", func() {
			var found *Condition

			// Multi-service Ingress
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{Host: "host1",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
									{Path: "/bar",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
								},
							},
						},
					},
				},
			}
			barSvc := test.NewService(
				"bar",
				"2", namespace,
				"NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}})
			r := mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")

			ingress3 := NewV1Ingress(
				"ingress",
				"2",
				namespace,
				ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:             "1.2.3.4",
					F5VsPartitionAnnotation:            "velcro",
					F5VsWhitelistSourceRangeAnnotation: "1.2.3.4/32,2.2.2.0/24",
				})
			ingress4 := NewV1Ingress(
				"ingress",
				"2",
				namespace,
				ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "2.2.2.2",
					F5VsPartitionAnnotation: "velcro",
				})
			r = mockMgr.addV1Ingress(ingress3)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			resources := mockMgr.resources()

			rs, ok := resources.Get(
				ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Ingress should be accessible.")
			Expect(rs).ToNot(BeNil(), "Ingress should be object.")
			Expect(rs.MetaData.Active).To(BeTrue())

			// Check to see that the condition
			Expect(len(rs.Policies)).To(Equal(1))
			Expect(len(rs.Policies[0].Rules)).To(Equal(1))

			// Check to see if there are three conditions.
			//
			// One condition for the /foo rule
			// One condition for the /bar condition
			// One condition for the whitelist entry
			//
			// as defined in ingressConfig above.
			Expect(len(rs.Policies[0].Rules[0].Conditions)).To(Equal(3))
			for _, x := range rs.Policies[0].Rules[0].Conditions {
				if x.Tcp == true {
					found = x
				}
			}
			Expect(found).NotTo(BeNil())
			Expect(found.Values).Should(ConsistOf("1.2.3.4/32", "2.2.2.0/24"))

			mockMgr.deleteV1Ingress(ingress3)
			r = mockMgr.addV1Ingress(ingress4)

			resources = mockMgr.resources()
			rs, ok = resources.Get(
				ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("2.2.2.2", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Ingress should be accessible.")
			Expect(len(rs.Policies[0].Rules[0].Conditions)).To(Equal(2))

			found = nil
			for _, x := range rs.Policies[0].Rules[0].Conditions {
				if x.Tcp == true {
					found = x
				}
			}
			Expect(found).To(BeNil())
		})
		It("configure allow source range annotation on Ingress", func() {
			var found *Condition

			// Multi-service Ingress
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{Host: "host1",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
									{Path: "/bar",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
								},
							},
						},
					},
				},
			}
			barSvc := test.NewService(
				"bar",
				"2", namespace,
				"NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}})
			r := mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")

			ingress3 := NewV1Ingress(
				"ingress",
				"2",
				namespace,
				ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:         "1.2.3.4",
					F5VsPartitionAnnotation:        "velcro",
					F5VsAllowSourceRangeAnnotation: "1.2.3.4/32,2.2.2.0/24",
				})
			ingress4 := NewV1Ingress(
				"ingress",
				"2",
				namespace,
				ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "2.2.2.2",
					F5VsPartitionAnnotation: "velcro",
				})
			r = mockMgr.addV1Ingress(ingress3)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			resources := mockMgr.resources()

			rs, ok := resources.Get(
				ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Ingress should be accessible.")
			Expect(rs).ToNot(BeNil(), "Ingress should be object.")
			Expect(rs.MetaData.Active).To(BeTrue())

			// Check to see that the condition
			Expect(len(rs.Policies)).To(Equal(1))
			Expect(len(rs.Policies[0].Rules)).To(Equal(1))

			// Check to see if there are three conditions.
			//
			// One condition for the /foo rule
			// One condition for the /bar condition
			// One condition for the whitelist entry
			//
			// as defined in ingressConfig above.
			Expect(len(rs.Policies[0].Rules[0].Conditions)).To(Equal(3))
			for _, x := range rs.Policies[0].Rules[0].Conditions {
				if x.Tcp == true {
					found = x
				}
			}
			Expect(found).NotTo(BeNil())
			Expect(found.Values).Should(ConsistOf("1.2.3.4/32", "2.2.2.0/24"))

			mockMgr.deleteV1Ingress(ingress3)
			r = mockMgr.addV1Ingress(ingress4)

			resources = mockMgr.resources()
			rs, ok = resources.Get(
				ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("2.2.2.2", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Ingress should be accessible.")
			Expect(len(rs.Policies[0].Rules[0].Conditions)).To(Equal(2))

			found = nil
			for _, x := range rs.Policies[0].Rules[0].Conditions {
				if x.Tcp == true {
					found = x
				}
			}
			Expect(found).To(BeNil())
		})
		It("check translate server address annotation on Ingress", func() {
			svcName := "svc1"
			svcPort := 8080

			spec := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: svcName, Port: netv1.ServiceBackendPort{Number: int32(svcPort)}},
				},
			}
			ing := NewV1Ingress("ingress", "1", namespace, spec,
				map[string]string{
					F5VsBindAddrAnnotation: "1.2.3.4",
					F5VsHttpPortAnnotation: "443",
				})

			emptyIps := []string{}

			svcPorts := []v1.ServicePort{newServicePort(svcName, int32(svcPort))}
			fooSvc := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP,
				svcPorts)
			readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts := test.NewEndpoints(svcName, "1", "node0", namespace,
				readyIps, emptyIps, convertSvcPortsToEndpointPorts(svcPorts))

			r := mockMgr.addV1Ingress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")

			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))

			rs, _ := resources.Get(
				ServiceKey{ServiceName: svcName, ServicePort: 8080, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(rs.Virtual.TranslateServerAddress).To(Equal("enabled"))

			ing.ObjectMeta.Annotations[F5VSTranslateServerAddress] = "false"
			r = mockMgr.updateV1Ingress(ing)
			rs, _ = resources.Get(
				ServiceKey{ServiceName: svcName, ServicePort: 8080, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(rs.Virtual.TranslateServerAddress).To(Equal("disabled"))

			ing.ObjectMeta.Annotations[F5VSTranslateServerAddress] = "true"
			r = mockMgr.updateV1Ingress(ing)
			rs, _ = resources.Get(
				ServiceKey{ServiceName: svcName, ServicePort: 8080, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 443), Partition: DEFAULT_PARTITION})
			Expect(rs.Virtual.TranslateServerAddress).To(Equal("enabled"))
		})

		It("configure whitelist annotation, extra spaces, on Ingress", func() {
			var found *Condition

			// Multi-service Ingress
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						Host: "host1",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
									{
										Path: "/bar",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
								},
							},
						},
					},
				},
			}
			barSvc := test.NewService(
				"bar",
				"2", namespace,
				"NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}})
			r := mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")

			ingress3 := NewV1Ingress(
				"ingress",
				"2",
				namespace,
				ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:             "1.2.3.4",
					F5VsPartitionAnnotation:            "velcro",
					F5VsWhitelistSourceRangeAnnotation: "10.10.10.0/24, 192.168.0.0/16, 172.16.0.0/18",
				})
			r = mockMgr.addV1Ingress(ingress3)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			resources := mockMgr.resources()

			rs, ok := resources.Get(
				ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Ingress should be accessible.")
			Expect(rs).ToNot(BeNil(), "Ingress should be object.")
			Expect(rs.MetaData.Active).To(BeTrue())

			// Check to see that the condition
			Expect(len(rs.Policies)).To(Equal(1))
			Expect(len(rs.Policies[0].Rules)).To(Equal(1))

			// Check to see if there are three conditions.
			//
			// One condition for the /foo rule
			// One condition for the /bar condition
			// One condition for the whitelist entry
			//
			// as defined in ingressConfig above.
			Expect(len(rs.Policies[0].Rules[0].Conditions)).To(Equal(3))
			for _, x := range rs.Policies[0].Rules[0].Conditions {
				if x.Tcp == true {
					found = x
				}
			}
			Expect(found).NotTo(BeNil())
			Expect(found.Values).Should(ConsistOf("10.10.10.0/24", "192.168.0.0/16", "172.16.0.0/18"))
		})

		It("configure allow source ange annotation, extra spaces, on Ingress", func() {
			var found *Condition

			// Multi-service Ingress
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						Host: "host1",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
									{
										Path: "/bar",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
								},
							},
						},
					},
				},
			}
			barSvc := test.NewService(
				"bar",
				"2", namespace,
				"NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}})
			r := mockMgr.addService(barSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")

			ingress3 := NewV1Ingress(
				"ingress",
				"2",
				namespace,
				ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:         "1.2.3.4",
					F5VsPartitionAnnotation:        "velcro",
					F5VsAllowSourceRangeAnnotation: "10.10.10.0/24, 192.168.0.0/16, 172.16.0.0/18",
				})
			r = mockMgr.addV1Ingress(ingress3)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			resources := mockMgr.resources()

			rs, ok := resources.Get(
				ServiceKey{ServiceName: "bar", ServicePort: 80, Namespace: "default"},
				NameRef{Name: FormatIngressVSName("1.2.3.4", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue(), "Ingress should be accessible.")
			Expect(rs).ToNot(BeNil(), "Ingress should be object.")
			Expect(rs.MetaData.Active).To(BeTrue())

			// Check to see that the condition
			Expect(len(rs.Policies)).To(Equal(1))
			Expect(len(rs.Policies[0].Rules)).To(Equal(1))

			// Check to see if there are three conditions.
			//
			// One condition for the /foo rule
			// One condition for the /bar condition
			// One condition for the whitelist entry
			//
			// as defined in ingressConfig above.
			Expect(len(rs.Policies[0].Rules[0].Conditions)).To(Equal(3))
			for _, x := range rs.Policies[0].Rules[0].Conditions {
				if x.Tcp == true {
					found = x
				}
			}
			Expect(found).NotTo(BeNil())
			Expect(found.Values).Should(ConsistOf("10.10.10.0/24", "192.168.0.0/16", "172.16.0.0/18"))
		})
		It("properly uses the default Ingress IP", func() {
			mockMgr.appMgr.defaultIngIP = "10.1.2.3"

			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37001}})
			barSvc := test.NewService("bar", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}})
			mockMgr.addService(fooSvc)
			mockMgr.addService(barSvc)

			ingCfg1 := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			ingCfg2 := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			ingress1 := NewV1Ingress("ingress1", "1", namespace, ingCfg1,
				map[string]string{
					F5VsBindAddrAnnotation:  "controller-default",
					F5VsPartitionAnnotation: "velcro",
				})
			ingress2 := NewV1Ingress("ingress2", "2", namespace, ingCfg2,
				map[string]string{
					F5VsBindAddrAnnotation:  "controller-default",
					F5VsPartitionAnnotation: "velcro",
				})
			mockMgr.addV1Ingress(ingress1)
			mockMgr.addV1Ingress(ingress2)
			resources := mockMgr.resources()
			Expect(resources.VirtualCount()).To(Equal(1))
			Expect(resources.PoolCount()).To(Equal(2))
			_, ok := resources.Get(
				ServiceKey{ServiceName: "foo", ServicePort: 80, Namespace: "default"}, NameRef{Name: FormatIngressVSName("10.1.2.3", 80), Partition: DEFAULT_PARTITION})
			Expect(ok).To(BeTrue())

			ingress2.Annotations[F5VsBindAddrAnnotation] = "1.2.3.4"
			mockMgr.updateV1Ingress(ingress2)
			Expect(resources.VirtualCount()).To(Equal(2))
			Expect(resources.PoolCount()).To(Equal(2))
		})

		It("properly configures redirect data group for ingress", func() {
			ns1 := "ns1"
			ns2 := "ns2"
			host := "foo.com"
			svcName := "foo"
			fooPath := "/foo"
			barPath := "/bar"
			err := mockMgr.startNonLabelMode([]string{ns1, ns2})
			for _, ns := range []string{ns1, ns2} {
				appInf, _ := mockMgr.appMgr.getNamespaceInformer(ns)
				appInf.ingClassInformer.GetStore().Add(ingClass)
			}
			Expect(err).To(BeNil())
			httpFoo := netv1.HTTPIngressRuleValue{
				Paths: []netv1.HTTPIngressPath{
					{Path: fooPath,
						Backend: netv1.IngressBackend{
							Service: &netv1.IngressServiceBackend{Name: svcName, Port: netv1.ServiceBackendPort{Number: int32(80)}},
						},
					},
				},
			}
			httpBar := netv1.HTTPIngressRuleValue{
				Paths: []netv1.HTTPIngressPath{
					{Path: barPath,
						Backend: netv1.IngressBackend{
							Service: &netv1.IngressServiceBackend{Name: svcName, Port: netv1.ServiceBackendPort{Number: int32(80)}},
						},
					},
				},
			}
			specFoo := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{Host: host,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &httpFoo,
						},
					},
				},
			}
			specBar := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{Host: host,
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &httpBar,
						},
					},
				},
			}

			// Create the first ingress and associate a service
			ing1a := NewV1Ingress("ing1a", "1", ns1, specFoo,
				map[string]string{
					F5VsBindAddrAnnotation:       "1.2.3.4",
					F5VsPartitionAnnotation:      DEFAULT_PARTITION,
					IngressSslRedirect:           "true",
					F5ClientSslProfileAnnotation: "[ { \"hosts\": [ \"foo.com\" ], \"bigIpProfile\": \"/Common/clientssl\" } ]",
				})
			r := mockMgr.addV1Ingress(ing1a)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			fooSvc1 := test.NewService(svcName, "1", ns1, "NodePort",
				[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
			r = mockMgr.addService(fooSvc1)
			Expect(r).To(BeTrue(), "Service should be processed.")

			// Create identical ingress and service in another namespace
			ing2 := NewV1Ingress("ing2", "1", ns2, specFoo,
				map[string]string{
					F5VsBindAddrAnnotation:       "1.2.3.4",
					F5VsPartitionAnnotation:      DEFAULT_PARTITION,
					IngressSslRedirect:           "true",
					F5ClientSslProfileAnnotation: "[ { \"hosts\": [ \"foo.com\" ], \"bigIpProfile\": \"/Common/clientssl\" } ]",
				})
			r = mockMgr.addV1Ingress(ing2)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			fooSvc2 := test.NewService(svcName, "1", ns2, "NodePort",
				[]v1.ServicePort{{Name: "foo-80", Port: 80, NodePort: 37001}})
			r = mockMgr.addService(fooSvc2)
			Expect(r).To(BeTrue(), "Service should be processed.")

			// Make sure the entry isn't duplicated in the dg
			grpRef := NameRef{
				Partition: DEFAULT_PARTITION,
				Name:      HttpsRedirectDgName,
			}
			nsMap, found := mockMgr.appMgr.intDgMap[grpRef]
			Expect(found).To(BeTrue(), "redirect group not found")
			flatDg := nsMap.FlattenNamespaces()
			Expect(flatDg).ToNot(BeNil(), "should have data")
			Expect(len(flatDg.Records)).To(Equal(2))
			Expect(flatDg.Records[0].Name).To(Equal(host + fooPath))
			Expect(flatDg.Records[0].Data).To(Equal(fooPath))
			Expect(flatDg.Records[1].Name).To(Equal(host + ":" + "80" + fooPath))
			Expect(flatDg.Records[1].Data).To(Equal(fooPath))
			// Add a route for the same host but different path
			ing1b := NewV1Ingress("ing1b", "1", ns1, specBar,
				map[string]string{
					F5VsBindAddrAnnotation:       "1.2.3.4",
					F5VsPartitionAnnotation:      "velcro",
					IngressSslRedirect:           "true",
					F5ClientSslProfileAnnotation: "[ { \"hosts\": [ \"bar.com\" ], \"bigIpProfile\": \"/Common/clientssl\" } ]",
				})
			r = mockMgr.addV1Ingress(ing1b)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
			Expect(found).To(BeTrue(), "redirect group not found")
			flatDg = nsMap.FlattenNamespaces()
			Expect(flatDg).ToNot(BeNil(), "should have data")
			Expect(len(flatDg.Records)).To(Equal(4))

			// Delete one of the duplicates for foo.com/foo, should not change dg
			r = mockMgr.deleteV1Ingress(ing2)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
			Expect(found).To(BeTrue(), "redirect group not found")
			flatDg = nsMap.FlattenNamespaces()
			Expect(flatDg).ToNot(BeNil(), "should have data")
			Expect(len(flatDg.Records)).To(Equal(4))

			// Delete the second duplicate for foo.com/foo, should change dg
			r = mockMgr.deleteV1Ingress(ing1a)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
			Expect(found).To(BeTrue(), "redirect group not found")
			flatDg = nsMap.FlattenNamespaces()
			Expect(flatDg).ToNot(BeNil(), "should have data")
			Expect(len(flatDg.Records)).To(Equal(2))
			Expect(flatDg.Records[0].Name).To(Equal(host + barPath))
			Expect(flatDg.Records[0].Data).To(Equal(barPath))
			Expect(flatDg.Records[1].Name).To(Equal(host + ":80" + barPath))
			Expect(flatDg.Records[1].Data).To(Equal(barPath))

			// Delete last ingress, should produce a nil dg
			r = mockMgr.deleteV1Ingress(ing1b)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			flatDg = nsMap.FlattenNamespaces()
			Expect(flatDg).To(BeNil(), "should not have data")

			// Re-create the first ingress without ssl-redirect = true, should not
			// be in the dg
			ing1a = NewV1Ingress("ing1a", "1", ns1, specFoo,
				map[string]string{
					F5VsBindAddrAnnotation:       "1.2.3.4",
					F5VsPartitionAnnotation:      DEFAULT_PARTITION,
					IngressSslRedirect:           "false",
					F5ClientSslProfileAnnotation: "[ { \"hosts\": [ \"foo.com\" ], \"bigIpProfile\": \"/Common/clientssl\" } ]",
				})
			r = mockMgr.addV1Ingress(ing1a)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			nsMap, found = mockMgr.appMgr.intDgMap[grpRef]
			Expect(found).To(BeFalse(), "redirect group should be gone")
			flatDg = nsMap.FlattenNamespaces()
			Expect(flatDg).To(BeNil(), "should not have data")
		})
	})
	Context("Test checkV1Ingress", func() {
		It("Test with URL Rewrite annotation", func() {
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			ingress := NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:   "1.2.3.4",
					F5VsPartitionAnnotation:  "velcro",
					F5VsURLRewriteAnnotation: "/foo",
				})

			expectedSvcQKey := []*serviceQueueKey{
				{
					Namespace:    "default",
					ServiceName:  "foo",
					ResourceKind: "ingresses",
					ResourceName: "ingress1",
				},
			}
			tf, svcQKey := mockMgr.appMgr.checkV1Ingress(ingress)
			Expect(tf).To(Equal(true))
			Expect(len(svcQKey)).To(Equal(1))
			Expect(svcQKey).To(Equal(expectedSvcQKey))
		})

		It("Test with App Root annotation", func() {
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			ingress := NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsAppRootAnnotation:   "/foo",
				})

			expectedSvcQKey := []*serviceQueueKey{
				{
					Namespace:    "default",
					ServiceName:  "foo",
					ResourceKind: "ingresses",
					ResourceName: "ingress1",
				},
			}
			tf, svcQKey := mockMgr.appMgr.checkV1Ingress(ingress)
			Expect(tf).To(Equal(true))
			Expect(len(svcQKey)).To(Equal(1))
			Expect(svcQKey).To(Equal(expectedSvcQKey))
		})

		It("Test resolveV1IngressHost", func() {
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
				Rules: []netv1.IngressRule{
					{Host: "", IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path: "/foo",
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{Name: "svc1"},
									},
								},
							},
						},
					}},
				},
			}
			ingress := NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					F5VsBindAddrAnnotation:  "1.2.3.4",
					F5VsPartitionAnnotation: "velcro",
					F5VsAppRootAnnotation:   "/foo",
				})
			mockMgr.appMgr.resolveV1IngressHost(ingress, namespace)

			ingress.Spec.Rules[0].Host = "f5.com"
			mockMgr.appMgr.resolveIng = "LOOKUP"
			ing, err := mockMgr.appMgr.kubeClient.NetworkingV1().Ingresses(namespace).Create(
				context.TODO(), ingress, metav1.CreateOptions{})
			Expect(ing).NotTo(BeNil())
			Expect(err).To(BeNil())
			mockMgr.appMgr.resolveV1IngressHost(ingress, namespace)
			ing, err = mockMgr.appMgr.kubeClient.NetworkingV1().Ingresses(namespace).Get(
				context.TODO(), ingress.Name, metav1.GetOptions{})
			Expect(ing).NotTo(BeNil())
			_, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]
			Expect(ok).To(BeTrue())
			Expect(err).To(BeNil())

			// DNS server with hostname
			mockMgr.appMgr.resolveIng = "google.com"
			mockMgr.appMgr.resolveV1IngressHost(ingress, namespace)
			ing, err = mockMgr.appMgr.kubeClient.NetworkingV1().Ingresses(namespace).Get(
				context.TODO(), ingress.Name, metav1.GetOptions{})
			Expect(ing).NotTo(BeNil())
			_, ok = ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]
			Expect(ok).To(BeTrue())
			Expect(err).To(BeNil())

			// DNS server with IP
			mockMgr.appMgr.resolveIng = "8.8.8.8"
			mockMgr.appMgr.resolveV1IngressHost(ingress, namespace)
			ing, err = mockMgr.appMgr.kubeClient.NetworkingV1().Ingresses(namespace).Get(
				context.TODO(), ingress.Name, metav1.GetOptions{})
			Expect(ing).NotTo(BeNil())
			_, ok = ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]
			Expect(ok).To(BeTrue())
			Expect(err).To(BeNil())
		})
	})
	Context("Test V1Ingress annotation updates", func() {
		It("Test single service ingress Partition Update", func() {
			var oldIngress *netv1.Ingress
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
			}
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			oldIngress = NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					IngressSslRedirect:           "true",
					IngressAllowHttp:             "false",
					F5VsBindAddrAnnotation:       "1.2.3.4",
					F5VsHttpPortAnnotation:       "8080",
					F5VsHttpsPortAnnotation:      "8443",
					F5VsPartitionAnnotation:      "velcro",
					F5ClientSslProfileAnnotation: "/Common/clientssl",
				})
			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37001}})
			mockMgr.addService(fooSvc)
			mockMgr.addV1Ingress(oldIngress)

			newIngress := NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					IngressSslRedirect:      "true",
					IngressAllowHttp:        "false",
					F5VsBindAddrAnnotation:  "1.1.1.1",
					F5VsHttpPortAnnotation:  "8080",
					F5VsHttpsPortAnnotation: "8443",
					F5VsPartitionAnnotation: "test",
				})
			mockMgr.appMgr.enqueueIngressUpdate(newIngress, oldIngress, OprTypeUpdate)
			for nameRef, _ := range mockMgr.appMgr.resources.RsMap {
				Expect(nameRef.Partition).ToNot(Equal("velcro"))
				Expect(nameRef.Partition).To(Equal("test"))
				Expect(nameRef.Name).To(ContainSubstring("1.1.1.1"))
				Expect(nameRef.Name).NotTo(ContainSubstring("1.2.3.4"))
			}
		})
		It("Test multi service ingress Partition Update", func() {
			var oldIngress *netv1.Ingress
			svc1Name := "svc1"
			svc1Port := 8080
			svc1Path := "/foo"
			svc2Name := "svc2"
			svc2Port := 9090
			svc2Path := "/bar"
			ingressConfig := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				Rules: []netv1.IngressRule{
					{
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: svc1Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc1Name, Port: netv1.ServiceBackendPort{Number: int32(svc1Port)}},
										},
									}, {
										Path: svc2Path,
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: svc2Name, Port: netv1.ServiceBackendPort{Number: int32(svc2Port)}},
										},
									},
								},
							},
						},
					},
				},
			}
			namespace := "default"
			mockMgr.appMgr.manageIngressClassOnly = false
			mockMgr.appMgr.ingressClass = "f5"
			oldIngress = NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					IngressSslRedirect:           "true",
					IngressAllowHttp:             "false",
					F5VsBindAddrAnnotation:       "1.2.3.4",
					F5VsHttpPortAnnotation:       "8080",
					F5VsHttpsPortAnnotation:      "8443",
					F5VsPartitionAnnotation:      "velcro",
					F5ClientSslProfileAnnotation: "/Common/clientssl",
				})
			svc1Ports := []v1.ServicePort{newServicePort(svc1Name, int32(svc1Port))}
			fooSvc := test.NewService(svc1Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc1Ports)
			svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
			barSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
				svc2Ports)
			mockMgr.addService(fooSvc)
			mockMgr.addService(barSvc)
			mockMgr.addV1Ingress(oldIngress)

			newIngress := NewV1Ingress("ingress1", "1", namespace, ingressConfig,
				map[string]string{
					IngressSslRedirect:      "true",
					IngressAllowHttp:        "false",
					F5VsBindAddrAnnotation:  "1.1.1.1",
					F5VsHttpPortAnnotation:  "8080",
					F5VsHttpsPortAnnotation: "8443",
					F5VsPartitionAnnotation: "test",
				})
			mockMgr.appMgr.enqueueIngressUpdate(newIngress, oldIngress, OprTypeUpdate)
			for nameRef, _ := range mockMgr.appMgr.resources.RsMap {
				Expect(nameRef.Partition).ToNot(Equal("velcro"))
				Expect(nameRef.Partition).To(Equal("test"))
				Expect(nameRef.Name).To(ContainSubstring("1.1.1.1"))
				Expect(nameRef.Name).NotTo(ContainSubstring("1.2.3.4"))
			}
		})

		It("Test backend rule host paths with same service and different ports", func() {
			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37001}, {Port: 81, NodePort: 37003}})
			barSvc := test.NewService("bar", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 80, NodePort: 37002}, {Port: 81, NodePort: 37004}})
			mockMgr.addService(fooSvc)
			mockMgr.addService(barSvc)

			ingCfg1 := netv1.IngressSpec{
				IngressClassName: &IngressClassName,
				DefaultBackend: &netv1.IngressBackend{
					Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
				},
				Rules: []netv1.IngressRule{
					{
						Host: "foo.com",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									},
									{
										Path: "/",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "foo", Port: netv1.ServiceBackendPort{Number: int32(81)}},
										},
									},
								},
							},
						},
					}, {
						Host: "bar.com",
						IngressRuleValue: netv1.IngressRuleValue{
							HTTP: &netv1.HTTPIngressRuleValue{
								Paths: []netv1.HTTPIngressPath{
									{
										Path: "/foo",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(80)}},
										},
									}, {
										Path: "/",
										Backend: netv1.IngressBackend{
											Service: &netv1.IngressServiceBackend{Name: "bar", Port: netv1.ServiceBackendPort{Number: int32(81)}},
										},
									},
								},
							},
						},
					},
				},
			}
			ingress1 := NewV1Ingress("ingress1", "1", namespace, ingCfg1,
				map[string]string{
					"virtual-server.f5.com/ip":           "10.1.0.3",
					"ingress.kubernetes.io/ssl-redirect": "true",
					"ingress.kubernetes.io/allow-http":   "false",
				})
			mockMgr.addV1Ingress(ingress1)
			resources := mockMgr.resources()
			Expect(resources.VirtualCount()).To(Equal(1))
			Expect(resources.PoolCount()).To(Equal(4))
		})
	})
})

// NewIngress returns a new ingress object
func NewV1Ingress(id, rv, namespace string,
	spec netv1.IngressSpec,
	annotations map[string]string) *netv1.Ingress {
	return &netv1.Ingress{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Ingress",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
			Annotations:     annotations,
		},
		Spec: spec,
	}
}

func (m *mockAppManager) addV1Ingress(ing *netv1.Ingress) bool {
	ok, keys := m.appMgr.checkValidIngress(ing)
	if ok {
		ns := ing.ObjectMeta.Namespace
		m.appMgr.kubeClient.NetworkingV1().Ingresses(ns).Create(context.TODO(), ing, metav1.CreateOptions{})
		appInf, _ := m.appMgr.getNamespaceInformer(ns)
		appInf.ingInformer.GetStore().Add(ing)
		for _, vsKey := range keys {
			vsKey.Operation = OprTypeCreate
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) updateV1Ingress(ing *netv1.Ingress) bool {
	ok, keys := m.appMgr.checkValidIngress(ing)
	if ok {
		ns := ing.ObjectMeta.Namespace
		_, err := m.appMgr.kubeClient.NetworkingV1().Ingresses(ns).Update(context.TODO(), ing, metav1.UpdateOptions{})
		if nil != err {
			// This can happen when an ingress is ignored by checkValidIngress
			// before, but now has been updated to be accepted.
			m.appMgr.kubeClient.NetworkingV1().Ingresses(ns).Create(context.TODO(), ing, metav1.CreateOptions{})
		}
		appInf, _ := m.appMgr.getNamespaceInformer(ns)
		appInf.ingInformer.GetStore().Update(ing)
		for _, vsKey := range keys {
			vsKey.Operation = OprTypeUpdate
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}

func (m *mockAppManager) deleteV1Ingress(ing *netv1.Ingress) bool {
	ok, keys := m.appMgr.checkValidIngress(ing)
	if ok {
		name := ing.ObjectMeta.Name
		ns := ing.ObjectMeta.Namespace
		m.appMgr.kubeClient.NetworkingV1().Ingresses(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
		appInf, _ := m.appMgr.getNamespaceInformer(ns)
		appInf.ingInformer.GetStore().Delete(ing)
		for _, vsKey := range keys {
			vsKey.Operation = OprTypeDelete
			mtx := m.getVsMutex(*vsKey)
			mtx.Lock()
			defer mtx.Unlock()
			m.appMgr.syncVirtualServer(*vsKey)
		}
	}
	return ok
}
