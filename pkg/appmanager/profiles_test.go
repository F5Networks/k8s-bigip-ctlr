/*-
 * Copyright (c) 2016-2018, F5 Networks, Inc.
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
	"fmt"
	"sort"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	routeapi "github.com/openshift/origin/pkg/route/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
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
				KubeClient:       fakeClient,
				ConfigWriter:     mw,
				restClient:       test.CreateFakeHTTPClient(),
				RouteClientV1:    test.CreateFakeHTTPClient(),
				IsNodePort:       true,
				broadcasterFunc:  NewFakeEventBroadcaster,
				ManageConfigMaps: true,
			})
			namespace = "default"
			mockMgr.appMgr.routeConfig = RouteConfig{
				HttpVs:  "ose-vserver",
				HttpsVs: "https-ose-vserver",
			}
			err := mockMgr.startNonLabelMode([]string{namespace})
			Expect(err).To(BeNil())
		})
		AfterEach(func() {
			mockMgr.shutdown()
		})

		It("handles ingress ssl profiles", func() {
			svcName := "foo"
			var svcPort int32 = 443
			svcKey := serviceKey{
				Namespace:   namespace,
				ServiceName: svcName,
				ServicePort: svcPort,
			}
			sslProfileName1 := "velcro/theSslProfileName"
			sslProfileName2 := "common/anotherSslProfileName"

			spec := v1beta1.IngressSpec{
				TLS: []v1beta1.IngressTLS{
					{
						SecretName: sslProfileName1,
					},
					{
						SecretName: sslProfileName2,
					},
				},
				Backend: &v1beta1.IngressBackend{
					ServiceName: svcName,
					ServicePort: intstr.IntOrString{IntVal: svcPort},
				},
			}
			fooIng := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					f5VsBindAddrAnnotation:  "1.2.3.4",
					f5VsPartitionAnnotation: "velcro",
				})
			svcPorts := []v1.ServicePort{newServicePort("port0", svcPort)}
			fooSvc := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP,
				svcPorts)
			emptyIps := []string{}
			readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
			endpts := test.NewEndpoints(svcName, "1", "node0", namespace,
				readyIps, emptyIps, convertSvcPortsToEndpointPorts(svcPorts))

			// Add ingress, service, and endpoints objects and make sure the
			// ssl-profile set in the ingress object shows up in the virtual server.
			r := mockMgr.addIngress(fooIng)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			r = mockMgr.addService(fooSvc)
			Expect(r).To(BeTrue(), "Service should be processed.")
			r = mockMgr.addEndpoints(endpts)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")
			resources := mockMgr.resources()
			Expect(resources.PoolCount()).To(Equal(1))
			Expect(resources.CountOf(svcKey)).To(Equal(2))
			httpCfg, found := resources.Get(svcKey, formatIngressVSName("1.2.3.4", 80))
			Expect(found).To(BeTrue())
			Expect(httpCfg).ToNot(BeNil())

			httpsCfg, found := resources.Get(svcKey, formatIngressVSName("1.2.3.4", 443))
			Expect(found).To(BeTrue())
			Expect(httpsCfg).ToNot(BeNil())
			secretArray := []string{
				formatIngressSslProfileName(sslProfileName1),
				formatIngressSslProfileName(sslProfileName2),
			}
			sort.Strings(secretArray)
			clientProfileNames := []string{}
			for _, prof := range httpsCfg.Virtual.Profiles {
				if prof.Context == customProfileClient {
					profName := fmt.Sprintf("%s/%s", prof.Partition, prof.Name)
					clientProfileNames = append(clientProfileNames, profName)
				}
			}
			sort.Strings(clientProfileNames)
			Expect(clientProfileNames).To(Equal(secretArray))

			// No annotations were specified to control http redirect, check that
			// we are in the default state 2.
			Expect(len(httpCfg.Virtual.IRules)).To(Equal(1))
			expectedIRuleName := fmt.Sprintf("/%s/%s_443",
				DEFAULT_PARTITION, httpRedirectIRuleName)
			Expect(httpCfg.Virtual.IRules[0]).To(Equal(expectedIRuleName))

			// Set the annotations the same as default and recheck
			fooIng.ObjectMeta.Annotations[ingressSslRedirect] = "true"
			fooIng.ObjectMeta.Annotations[ingressAllowHttp] = "false"
			r = mockMgr.addIngress(fooIng)
			httpCfg, found = resources.Get(svcKey, formatIngressVSName("1.2.3.4", 80))
			Expect(found).To(BeTrue())
			Expect(httpCfg).ToNot(BeNil())
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(len(httpCfg.Virtual.IRules)).To(Equal(1))
			expectedIRuleName = fmt.Sprintf("/%s/%s_443",
				DEFAULT_PARTITION, httpRedirectIRuleName)
			Expect(httpCfg.Virtual.IRules[0]).To(Equal(expectedIRuleName))

			// Now test state 1.
			fooIng.ObjectMeta.Annotations[ingressSslRedirect] = "false"
			fooIng.ObjectMeta.Annotations[ingressAllowHttp] = "false"
			r = mockMgr.addIngress(fooIng)
			httpsCfg, found = resources.Get(svcKey, formatIngressVSName("1.2.3.4", 443))
			Expect(found).To(BeTrue())
			Expect(httpsCfg).ToNot(BeNil())
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.PoolCount()).To(Equal(1))
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			Expect(len(httpsCfg.Policies)).To(Equal(0))
			clientProfileNames = clientProfileNames[:0]
			for _, prof := range httpsCfg.Virtual.Profiles {
				if prof.Context == customProfileClient {
					profName := fmt.Sprintf("%s/%s", prof.Partition, prof.Name)
					clientProfileNames = append(clientProfileNames, profName)
				}
			}
			sort.Strings(clientProfileNames)
			Expect(clientProfileNames).To(Equal(secretArray))
			// ServerSSL Profile tests
			fooIng.ObjectMeta.Annotations[f5ServerSslProfileAnnotation] = "Common/server"
			r = mockMgr.addIngress(fooIng)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			httpsCfg, found = resources.Get(svcKey, formatIngressVSName("1.2.3.4", 443))
			Expect(found).To(BeTrue())
			Expect(httpsCfg).ToNot(BeNil())
			Expect(httpsCfg.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Name:      "server",
					Partition: "Common",
					Context:   customProfileServer,
					Namespace: namespace,
				}))
			// Now test state 3.
			fooIng.ObjectMeta.Annotations[ingressSslRedirect] = "false"
			fooIng.ObjectMeta.Annotations[ingressAllowHttp] = "true"
			r = mockMgr.addIngress(fooIng)
			httpCfg, found = resources.Get(svcKey, formatIngressVSName("1.2.3.4", 80))
			Expect(found).To(BeTrue())
			Expect(httpCfg).ToNot(BeNil())
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(len(httpCfg.Policies)).To(Equal(0))

			// Clear out TLS in the ingress, but use default http redirect settings.
			fooIng.Spec.TLS = nil
			delete(fooIng.ObjectMeta.Annotations, ingressSslRedirect)
			delete(fooIng.ObjectMeta.Annotations, ingressAllowHttp)
			r = mockMgr.addIngress(fooIng)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
			Expect(resources.PoolCount()).To(Equal(1))
			Expect(resources.CountOf(svcKey)).To(Equal(1))
			httpCfg, found = resources.Get(svcKey, formatIngressVSName("1.2.3.4", 80))
			Expect(found).To(BeTrue())
			Expect(httpCfg).ToNot(BeNil())
			Expect(len(httpCfg.Policies)).To(Equal(0))

			httpsCfg, found = resources.Get(svcKey, formatIngressVSName("1.2.3.4", 443))
			Expect(found).To(BeFalse())
			Expect(httpsCfg).To(BeNil())
		})

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
			_, err := mockMgr.appMgr.kubeClient.Core().Secrets(namespace).Create(secret)
			Expect(err).To(BeNil())

			spec := v1beta1.IngressSpec{
				TLS: []v1beta1.IngressTLS{
					{
						SecretName: secret.ObjectMeta.Name,
					},
				},
				Backend: &v1beta1.IngressBackend{
					ServiceName: "foo",
					ServicePort: intstr.IntOrString{IntVal: 80},
				},
			}
			// Test for Ingress
			ingress := test.NewIngress("ingress", "1", namespace, spec,
				map[string]string{
					f5VsBindAddrAnnotation:  "1.2.3.4",
					f5VsPartitionAnnotation: "velcro",
				})
			// This should create a custom profile from the ingress secret.
			mockMgr.addIngress(ingress)
			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 443, NodePort: 37001}})
			mockMgr.addService(fooSvc)

			customProfiles := mockMgr.customProfiles()
			Expect(len(customProfiles)).To(Equal(2))

			// Test for ConfigMap
			var configmapSecret string = string(`{
				"virtualServer": {
						"backend": {
							"serviceName": "foo",
							"servicePort": 80
						},
						"frontend": {
							"partition": "velcro",
							"virtualAddress": {
								"port": 10000
							},
							"sslProfile": {
								"f5ProfileName": "secret2"
							}
						}
					}
				}`)
			secretCfg := test.NewConfigMap("secretCfg", "1", namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapSecret,
			})
			// This should NOT create a custom profile - it just references a
			// pre-configured one.
			mockMgr.addConfigMap(secretCfg)
			Expect(len(customProfiles)).To(Equal(2))
			// This should not affect any custom profiles.
			mockMgr.deleteConfigMap(secretCfg)
			Expect(len(customProfiles)).To(Equal(2))

			// This should remove the custom profile.
			mockMgr.deleteIngress(ingress)
			resources := mockMgr.resources()
			Expect(len(resources.GetAllResources())).To(Equal(0))
			Expect(len(customProfiles)).To(Equal(0))
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
					Certificate:              "cert",
					Key:                      "key",
					DestinationCACertificate: "destCaCert",
				},
			}
			route := test.NewRoute("route", "1", namespace, spec,
				map[string]string{
					f5ClientSslProfileAnnotation: "Common/client",
					f5ServerSslProfileAnnotation: "Common/server",
				})
			r := mockMgr.addRoute(route)
			Expect(r).To(BeTrue(), "Route resource should be processed.")

			fooSvc := test.NewService("foo", "1", namespace, "NodePort",
				[]v1.ServicePort{{Port: 443, NodePort: 37001}})
			mockMgr.addService(fooSvc)

			resources := mockMgr.resources()
			rs, ok := resources.Get(
				serviceKey{"foo", 443, namespace}, "https-ose-vserver")
			Expect(ok).To(BeTrue(), "Route should be accessible.")
			Expect(rs).ToNot(BeNil(), "Route should be object.")

			Expect(rs.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Partition: "Common",
					Name:      "client",
					Context:   customProfileClient,
					Namespace: namespace,
				}))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(
				ProfileRef{
					Partition: "velcro",
					Name:      "/openshift_route_default_route-client-ssl",
					Context:   customProfileClient,
				}))
			pRef := ProfileRef{
				Name:      "server",
				Partition: "Common",
				Context:   customProfileServer,
				Namespace: namespace,
			}
			Expect(rs.Virtual.Profiles).To(ContainElement(pRef))
			customPRef := ProfileRef{
				Name:      "openshift_route_default_route-server-ssl",
				Partition: "velcro",
				Context:   customProfileServer,
				Namespace: namespace,
			}
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(customPRef))

			// Remove profiles
			delete(route.Annotations, f5ClientSslProfileAnnotation)
			delete(route.Annotations, f5ServerSslProfileAnnotation)
			mockMgr.updateRoute(route)

			rs, _ = resources.Get(
				serviceKey{"foo", 443, namespace}, "https-ose-vserver")
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(
				ProfileRef{
					Partition: "Common",
					Name:      "client",
					Context:   customProfileClient,
				}))
			Expect(rs.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Partition: "velcro",
					Name:      "openshift_route_default_route-client-ssl",
					Context:   customProfileClient,
					Namespace: namespace,
				}))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(pRef))
			Expect(rs.Virtual.Profiles).To(ContainElement(customPRef))

			// Re-add the profiles
			route.Annotations[f5ClientSslProfileAnnotation] = "Common/newClient"
			route.Annotations[f5ServerSslProfileAnnotation] = "Common/newServer"
			mockMgr.updateRoute(route)

			rs, _ = resources.Get(
				serviceKey{"foo", 443, namespace}, "https-ose-vserver")
			Expect(rs.Virtual.Profiles).To(ContainElement(
				ProfileRef{
					Partition: "Common",
					Name:      "newClient",
					Context:   customProfileClient,
					Namespace: namespace,
				}))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(
				ProfileRef{
					Partition: "velcro",
					Name:      "openshift_route_default_route-client-ssl",
					Context:   customProfileClient,
					Namespace: namespace,
				}))
			pRef = ProfileRef{
				Name:      "newServer",
				Partition: "Common",
				Context:   customProfileServer,
				Namespace: namespace,
			}
			Expect(rs.Virtual.Profiles).To(ContainElement(pRef))
			Expect(rs.Virtual.Profiles).ToNot(ContainElement(customPRef))
		})
	})
})
