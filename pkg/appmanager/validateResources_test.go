package appmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Test Validation", func() {
	It(" Test validateURLRewriteAnnotations", func() {
		entries := make(map[string]string)
		entries[""] = "https://abc.com/home"
		validateURLRewriteAnnotations(0, entries)
		entries = make(map[string]string)
		entries["https://abc.com"] = "https://abc.com/home"
		validateURLRewriteAnnotations(0, entries)
		validateURLRewriteAnnotations(2, entries)
		entries = make(map[string]string)
		entries["/abc.com"] = "https://abc.com/home"
		validateURLRewriteAnnotations(2, entries)
		entries = make(map[string]string)
		entries["abc.com/abc.com"] = ""
		validateURLRewriteAnnotations(2, entries)
	})
	It("Test validateAppRootAnnotations", func() {
		entries := make(map[string]string)
		entries[""] = "https://abc.com/home"
		validateAppRootAnnotations(0, entries)
		entries = make(map[string]string)
		entries["https://abc.com/abc"] = "https://abc.com/home"
		validateAppRootAnnotations(2, entries)
		entries = make(map[string]string)
		entries["abc.com"] = "https://abc.com/home"
		validateAppRootAnnotations(2, entries)
		entries = make(map[string]string)
		entries["abc.com"] = ""
		validateAppRootAnnotations(2, entries)
	})
	It("Test checkCertificateHost", func() {
		// Check with valid cert and key
		ret := checkCertificateHost("test.com", cert, key)
		Expect(ret).To(BeTrue())

		// Check with invalid cert
		ret = checkCertificateHost("test.com", "invalid-cert", key)
		Expect(ret).To(BeFalse())
	})
	It("Test validateConfigJson", func() {
		tempCm := `{"test":"test1"}`
		err := validateConfigJson(tempCm)
		Expect(err).To(BeNil())
	})
	Context("Test Appmanager helper methods using Mock Manager", func() {
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
		It("Test checkValidPod", func() {
			namespace := "test"
			svcName := "svc1"
			defaultLabel := "f5type in (virtual-server)"
			label := make(map[string]string)
			label["app"] = "test"
			pod1 := test.NewPod("pod1", namespace, 8080, label)
			selector, err := labels.Parse(defaultLabel)
			Expect(err).To(BeNil())
			mockMgr.appMgr.AddNamespace(namespace, selector, 0)
			appInf := mockMgr.appMgr.appInformers[namespace]
			svcPorts := []v1.ServicePort{
				newServicePort("port0", 80),
			}
			svc1 := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP, svcPorts)
			svc1.Spec.Selector = label
			appInf.svcInformer.GetStore().Add(svc1)
			ret, scvKeyList := mockMgr.appMgr.checkValidPod(pod1, "create")
			Expect(ret).To(BeTrue())
			Expect(len(scvKeyList)).To(Equal(1))
			// enqueue and check queue length
			mockMgr.appMgr.poolMemberType = resource.NodePortLocal
			mockMgr.appMgr.enqueuePod(pod1, resource.OprTypeCreate)
			Expect(mockMgr.appMgr.vsQueue.Len()).To(Equal(1))
			// Pod in core ns
			pod1.Labels["component"] = "etcd"
			ret, scvKeyList = mockMgr.appMgr.checkValidPod(pod1, "create")
			Expect(ret).To(BeFalse())
			Expect(len(scvKeyList)).To(Equal(0))
			delete(pod1.Labels, "component")

			// With NPL annotation
			annotations := make(map[string]string)
			annotations[NPLPodAnnotation] = "true"
			pod1.Annotations = annotations
			ret, scvKeyList = mockMgr.appMgr.checkValidPod(pod1, "create")
			Expect(ret).To(BeTrue())
			Expect(len(scvKeyList)).To(Equal(1))

			// Delete operation
			ret, scvKeyList = mockMgr.appMgr.checkValidPod(pod1, "delete")
			Expect(ret).To(BeTrue())
			Expect(len(scvKeyList)).To(Equal(1))
		})

		It("Test getSecretServiceQueueKeyForConfigMap", func() {
			namespace := "test"
			defaultLabel := "f5type in (virtual-server)"
			// No Ns Informer
			secret1 := test.NewSecret("testcert", namespace, "cert", "key")
			keyList := mockMgr.appMgr.getSecretServiceQueueKeyForConfigMap(secret1)
			Expect(len(keyList)).To(Equal(0))

			// No configmap
			selector, err := labels.Parse(defaultLabel)
			Expect(err).To(BeNil())
			mockMgr.appMgr.AddNamespace(namespace, selector, 0)
			keyList = mockMgr.appMgr.getSecretServiceQueueKeyForConfigMap(secret1)
			Expect(len(keyList)).To(Equal(0))

			// With configmap
			cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo})
			appInfmr := mockMgr.appMgr.appInformers[namespace]
			appInfmr.cfgMapInformer.GetStore().Add(cfgFoo)
			keyList = mockMgr.appMgr.getSecretServiceQueueKeyForConfigMap(secret1)
			Expect(len(keyList)).To(Equal(1))
		})

		It("Test getSecretServiceQueueKeyForIngress", func() {
			namespace := "test"
			defaultLabel := "f5type in (virtual-server)"
			// No Ns Informer
			secret1 := test.NewSecret("secret1", namespace, "cert", "key")
			keyList := mockMgr.appMgr.getSecretServiceQueueKeyForIngress(secret1)
			Expect(len(keyList)).To(Equal(0))

			// No Ingress
			selector, err := labels.Parse(defaultLabel)
			Expect(err).To(BeNil())
			mockMgr.appMgr.AddNamespace(namespace, selector, 0)
			keyList = mockMgr.appMgr.getSecretServiceQueueKeyForIngress(secret1)
			Expect(len(keyList)).To(Equal(0))

			appInfmr := mockMgr.appMgr.appInformers[namespace]
			// Netv1 Ingress
			// With Ingress, No TLS
			ingCfg2 := netv1.IngressSpec{}
			ingress2 := test.NewIngressNetV1("ingress1", "1", namespace, ingCfg2,
				map[string]string{
					resource.F5VsBindAddrAnnotation:  "controller-default",
					resource.F5VsPartitionAnnotation: "velcro",
				})
			appInfmr.ingInformer.GetStore().Add(ingress2)
			keyList = mockMgr.appMgr.getSecretServiceQueueKeyForIngress(secret1)
			Expect(len(keyList)).To(Equal(0))

			// With Ingress and TLS and default backend
			ingCfg2.DefaultBackend = &netv1.IngressBackend{
				Service: &netv1.IngressServiceBackend{Name: "svc1"},
			}
			ingCfg2.TLS = []netv1.IngressTLS{
				{Hosts: []string{"abc.com"}, SecretName: "secret1"},
			}
			ingress2.Spec = ingCfg2
			appInfmr.ingInformer.GetStore().Update(ingress2)
			keyList = mockMgr.appMgr.getSecretServiceQueueKeyForIngress(secret1)
			Expect(len(keyList)).To(Equal(1))

			// With Ingress and TLS, with Rules
			ingCfg2.DefaultBackend = nil
			ingCfg2.Rules = []netv1.IngressRule{
				{
					Host: "abc.com",
					IngressRuleValue: netv1.IngressRuleValue{
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
					},
				},
			}
			ingress2.Spec = ingCfg2
			appInfmr.ingInformer.GetStore().Update(ingress2)
			keyList = mockMgr.appMgr.getSecretServiceQueueKeyForIngress(secret1)
			Expect(len(keyList)).To(Equal(1))
		})

		It("Test checkValidSecrets", func() {
			namespace := "test"
			defaultLabel := "f5type in (virtual-server)"
			// Not using secrets
			secret1 := test.NewSecret("testcert", namespace, "cert", "key")
			ret, keyList := mockMgr.appMgr.checkValidSecrets(secret1)
			Expect(ret).To(BeFalse())
			Expect(len(keyList)).To(Equal(0))
			// enqueue and check queue length
			mockMgr.appMgr.enqueueSecrets(secret1, resource.OprTypeCreate)
			Expect(mockMgr.appMgr.vsQueue.Len()).To(Equal(0))
			// Using secrets and configmap created
			mockMgr.appMgr.useSecrets = true
			selector, err := labels.Parse(defaultLabel)
			Expect(err).To(BeNil())
			mockMgr.appMgr.AddNamespace(namespace, selector, 0)
			cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo})
			appInfmr := mockMgr.appMgr.appInformers[namespace]
			appInfmr.cfgMapInformer.GetStore().Add(cfgFoo)
			ret, keyList = mockMgr.appMgr.checkValidSecrets(secret1)
			Expect(ret).To(BeTrue())
			Expect(len(keyList)).To(Equal(1))

			// Secret without key
			delete(secret1.Data, "tls.key")
			ret, keyList = mockMgr.appMgr.checkValidSecrets(secret1)
			Expect(ret).To(BeFalse())
			Expect(len(keyList)).To(Equal(0))

			// Secret without crt
			delete(secret1.Data, "tls.crt")
			ret, keyList = mockMgr.appMgr.checkValidSecrets(secret1)
			Expect(ret).To(BeFalse())
			Expect(len(keyList)).To(Equal(0))
		})
	})

})
