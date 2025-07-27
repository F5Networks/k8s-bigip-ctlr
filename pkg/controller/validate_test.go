package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/bigiphandler"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"net/http/httptest"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
)

var _ = Describe("Validation Tests", func() {
	var mockCtlr *mockController
	var mockPM *mockPostManager
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		mockWriter := &test.MockWriter{}
		mockCtlr.RequestHandler = newMockRequestHandler(mockWriter)
		mockPM = newMockPostManger()
		mockPM.TokenManagerInterface = test.NewMockTokenManager("test-token")
		mockPM.BIGIPURL = "bigip.com"
		mockCtlr.RequestHandler.PrimaryBigIPWorker.LTM.PostManager = mockPM.PostManager
		mockCtlr.resources = NewResourceStore()
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
	})

	Describe("Validating ExtendedServiceReference", func() {
		BeforeEach(func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			clusterConfigs := make(map[string]*ClusterConfig)
			clusterConfigs["cluster1"] = &ClusterConfig{}
			clusterConfigs["cluster2"] = &ClusterConfig{}
			mockCtlr.multiClusterHandler = &ClusterHandler{
				ClusterConfigs:    clusterConfigs,
				HAPairClusterName: "cluster2",
				LocalClusterName:  "cluster1",
			}
		})

		It("Validating ExtendedServiceReference in non multiCluster mode", func() {
			mockCtlr.multiClusterMode = ""
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				SvcName:     "svc1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
				ClusterName: "cluster1",
			}, true)).Error().To(Equal(fmt.Errorf("CIS is not running in multiCluster mode")))
		})

		It("Validating ExtendedServiceReference for missing parameters", func() {
			// Check for missing cluster name
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				SvcName:     "svc1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(Equal(fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")))
			// Check for missing service name
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(Equal(fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")))
			// Check for missing ServicePort
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster1",
				Namespace:   "namespace1",
				SvcName:     "svc1",
			}, true)).Error().To(Equal(fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")))
		})

		It("Validating ExtendedServiceReference running in HA and non-HA cluster", func() {
			// Service running in cluster3 which is not defined in extended configmap
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster3",
				SvcName:     "svc1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(Equal(fmt.Errorf("cluster config for the cluster cluster3 is not provided in extended configmap")))
			// Service running in non HA cluster
			mockCtlr.multiClusterHandler.ClusterConfigs["cluster3"] = &ClusterConfig{}
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster3",
				Namespace:   "namespace1",
				SvcName:     "svc1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(BeNil())
			//// Service running in primary cluster
			//Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
			//	ClusterName: "cluster1",
			//	SvcName:     "svc1",
			//	Namespace:   "namespace1",
			//	ServicePort: intstr.IntOrString{IntVal: 80},
			//}, true)).Error().To(Equal(fmt.Errorf("service is running in HA cluster, currently CIS doesn't support services running in " +
			//	"HA clusters to be defined in checkValidMultiClusterService")))
			// Service running in secondary cluster
			//Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
			//	ClusterName: "cluster2",
			//	SvcName:     "svc1",
			//	Namespace:   "namespace1",
			//	ServicePort: intstr.IntOrString{IntVal: 80},
			//}, true)).Error().To(Equal(fmt.Errorf("service is running in HA cluster, currently CIS doesn't support services running in " +
			//	"HA clusters to be defined in extendedServiceReference")))
		})
	})

	Describe("AdmissionReview validation handler", func() {
		var (
			w *httptest.ResponseRecorder
			r *http.Request
		)

		BeforeEach(func() {
			w = httptest.NewRecorder()
		})

		It("should allow valid VirtualServer", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "VirtualServer",
				"metadata":   map[string]interface{}{"name": "vs1"},
				"spec":       map[string]interface{}{"virtualServerAddress": "1.2.3.4"},
			}
			objRaw, _ := json.Marshal(obj)
			admission := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:    "vs-uid",
					Kind:   metav1.GroupVersionKind{Kind: "VirtualServer"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			mockCtlr.handleValidate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp v1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
		})

		It("should deny invalid VirtualServer", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "VirtualServer",
				"metadata":   map[string]interface{}{"name": "vs1"},
				"spec":       map[string]interface{}{}, // missing required fields
			}
			objRaw, _ := json.Marshal(obj)
			admission := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:    "vs-uid2",
					Kind:   metav1.GroupVersionKind{Kind: "VirtualServer"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			mockCtlr.handleValidate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp v1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeFalse())
			Expect(resp.Response.Result.Message).NotTo(BeEmpty())
		})

		It("should allow valid TransportServer", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "TransportServer",
				"metadata":   map[string]interface{}{"name": "ts1"},
				"spec": map[string]interface{}{"virtualServerAddress": "1.2.3.4",
					"pool": map[string]interface{}{"service": "pool1", "servicePort": intstr.IntOrString{IntVal: 80}}},
			}
			objRaw, _ := json.Marshal(obj)
			admission := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:    "ts-uid",
					Kind:   metav1.GroupVersionKind{Kind: "TransportServer"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			mockCtlr.handleValidate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp v1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
		})

		It("should deny invalid TransportServer", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "TransportServer",
				"metadata":   map[string]interface{}{"name": "ts1"},
				"spec":       map[string]interface{}{}, // missing required fields
			}
			objRaw, _ := json.Marshal(obj)
			admission := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:    "ts-uid2",
					Kind:   metav1.GroupVersionKind{Kind: "TransportServer"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			mockCtlr.handleValidate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp v1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeFalse())
			Expect(resp.Response.Result.Message).NotTo(BeEmpty())
		})

		It("should allow valid IngressLink", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "IngressLink",
				"metadata":   map[string]interface{}{"name": "il1"},
				"spec": map[string]interface{}{"virtualServerAddress": "1.2.3.4",
					"selector": map[string]interface{}{"matchLabels": map[string]interface{}{"app": "ingresslink"}}},
			}
			objRaw, _ := json.Marshal(obj)
			admission := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:    "il-uid",
					Kind:   metav1.GroupVersionKind{Kind: "IngressLink"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			mockCtlr.handleValidate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp v1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
		})

		It("should deny unsupported Kind", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "UnknownKind",
				"metadata":   map[string]interface{}{"name": "uk1"},
				"spec":       map[string]interface{}{},
			}
			objRaw, _ := json.Marshal(obj)
			admission := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:    "uk-uid",
					Kind:   metav1.GroupVersionKind{Kind: "UnknownKind"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/validate", bytes.NewBuffer(body))
			mockCtlr.handleValidate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp v1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeFalse())
			Expect(resp.Response.Result.Message).NotTo(BeEmpty())
		})
	})

	Describe("checkValidPolicy", func() {
		var validator bigiphandler.BigIPHandlerInterface
		BeforeEach(func() {
			validator = NewMockBigIPHandler()
		})
		It("should return nil for valid policy", func() {
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "valid-policy"},
				Spec:       cisapiv1.PolicySpec{},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
		})

		// check L7 policy validation
		It("validate L7 policy processing", func() {
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: cisapiv1.PolicySpec{
					L7Policies: cisapiv1.L7PolicySpec{
						WAF: "errorWAFPolicy",
					},
				},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L7Policies.WAF = "testWAFPolicy"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L7Policies.PolicyPerRequestAccess = "errorPolicyPerRequestAccess"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L7Policies.PolicyPerRequestAccess = "testPolicyPerRequestAccess"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L7Policies.ProfileAccess = "errorProfileAccess"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L7Policies.ProfileAccess = "testProfileAccess"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L7Policies.ProfileAdapt = cisapiv1.ProfileAdapt{
				Request: "errorProfileAdaptRequest",
			}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L7Policies.ProfileAdapt.Request = "testProfileAdaptRequest"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L7Policies.ProfileAdapt.Response = "errorProfileAdaptResponse"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L7Policies.ProfileAdapt.Response = "testProfileAdaptResponse"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
		})

		// check L3 policy validation
		It("validate L3 policy processing", func() {
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: cisapiv1.PolicySpec{
					L3Policies: cisapiv1.L3PolicySpec{
						DOS: "errorDOSProfile",
					},
				},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L3Policies.DOS = "testDOSProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L3Policies.BotDefense = "errorBotDefenseProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L3Policies.BotDefense = "testBotDefenseProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L3Policies.FirewallPolicy = "errorFirewallPolicy"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			policy.Spec.L3Policies.FirewallPolicy = "testFirewallPolicy"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L3Policies.AllowSourceRange = []string{"errorSourceRange"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L3Policies.AllowSourceRange = []string{"192.168.0.1/24"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L3Policies.AllowVlans = []string{"errorVLAN"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L3Policies.AllowVlans = []string{"vlan1"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.L3Policies.IpIntelligencePolicy = "errorIpIntelligencePolicy"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.L3Policies.IpIntelligencePolicy = "testIpIntelligencePolicy"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
		})

		// check LTM Policy is not supported
		It("validate LTM policy processing", func() {
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: cisapiv1.PolicySpec{
					LtmPolicies: cisapiv1.LtmIRulesSpec{
						Secure: "errorSecure",
					},
				},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.LtmPolicies.Secure = ""
			policy.Spec.LtmPolicies.InSecure = ""
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
		})

		//  check iRule validation
		It("validate iRule processing", func() {
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: cisapiv1.PolicySpec{
					IRuleList: []string{"errorIRule"},
				},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.IRuleList = []string{"testIRule"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policySecure := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "secure-policy"},
				Spec: cisapiv1.PolicySpec{
					IRules: cisapiv1.LtmIRulesSpec{
						Secure: "errorIRule",
					},
				},
			}
			_, err = mockCtlr.checkValidPolicy(policySecure, validator)
			Expect(err).NotTo(BeNil())
			policySecure.Spec.IRules.Secure = "testIRule"
			_, err = mockCtlr.checkValidPolicy(policySecure, validator)
			Expect(err).To(BeEmpty())
			policyInsecure := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "insecure-policy"},
				Spec: cisapiv1.PolicySpec{
					IRules: cisapiv1.LtmIRulesSpec{
						InSecure: "errorIRule",
					},
				},
			}
			_, err = mockCtlr.checkValidPolicy(policyInsecure, validator)
			Expect(err).NotTo(BeNil())
			policyInsecure.Spec.IRules.InSecure = "testIRule"
			_, err = mockCtlr.checkValidPolicy(policyInsecure, validator)
			Expect(err).To(BeEmpty())
		})

		// ProfileSpec validation
		It("validate ProfileSpec processing", func() {
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: cisapiv1.PolicySpec{
					Profiles: cisapiv1.ProfileSpec{
						TCP: cisapiv1.ProfileTCP{
							Client: "errorTCPProfile",
						},
					},
				},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.TCP.Client = "testTCPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.Profiles.TCP.Server = "errorTCPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.TCP.Server = "testTCPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// udp check
			policy.Spec.Profiles.UDP = "errorUDPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.UDP = "testUDPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// http check
			policy.Spec.Profiles.HTTP = "errorHTTPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.HTTP = "testHTTPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// http2 check
			policy.Spec.Profiles.HTTP2 = cisapiv1.ProfileHTTP2{
				Client: "errorHTTP2Profile",
			}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.HTTP2.Client = "testHTTP2Profile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.Profiles.HTTP2.Server = "errorHTTP2Profile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.HTTP2.Server = "testHTTP2Profile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// rewrite profile check
			policy.Spec.Profiles.RewriteProfile = "errorRewriteProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.RewriteProfile = "testRewriteProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// persistent profile
			policy.Spec.Profiles.PersistenceProfile = "errorPersistenceProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.PersistenceProfile = "testPersistenceProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// log profiles
			policy.Spec.Profiles.LogProfiles = []string{"errorLogProfile"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.LogProfiles = []string{"testLogProfile"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// profileL4
			policy.Spec.Profiles.ProfileL4 = "errorProfileL4"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.ProfileL4 = "testProfileL4"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// ProfileMultiplex
			policy.Spec.Profiles.ProfileMultiplex = "errorMultiplexProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.ProfileMultiplex = "testProfileMultiplex"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// SSLProfiles
			policy.Spec.Profiles.SSLProfiles = cisapiv1.SSLProfiles{
				ClientProfiles: []string{"errorClientSSL"},
			}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.SSLProfiles.ClientProfiles = []string{"testClientSSL"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			policy.Spec.Profiles.SSLProfiles.ServerProfiles = []string{"errorServerSSL"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.SSLProfiles.ServerProfiles = []string{"testServerSSL"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// AnalyticsProfiles
			policy.Spec.Profiles.AnalyticsProfiles = cisapiv1.AnalyticsProfiles{HTTPAnalyticsProfile: "errorAnalyticsProfile"}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile = "testAnalyticsProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// ProfileWebSocket
			policy.Spec.Profiles.ProfileWebSocket = "errorWebSocketProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.ProfileWebSocket = "testWebSocketProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// HTMLProfile
			policy.Spec.Profiles.HTMLProfile = "errorHTMLProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.HTMLProfile = "testHTMLProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// FTPProfile
			policy.Spec.Profiles.FTPProfile = "errorFTPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.FTPProfile = "testFTPProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// HTTPCompressionProfile
			policy.Spec.Profiles.HTTPCompressionProfile = "errorHTTPCompressionProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.Profiles.HTTPCompressionProfile = "testHTTPCompressionProfile"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
		})

		// other policy attributes validation
		It("validate other policy attributes", func() {
			// 	SNAT check
			policy := &cisapiv1.Policy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy"},
				Spec: cisapiv1.PolicySpec{
					SNAT: "errorSNATPool",
				},
			}
			_, err := mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.SNAT = "testSNATPool"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
			// 	DefaultPool check
			policy.Spec.DefaultPool = cisapiv1.DefaultPool{
				Name:      "errorPool",
				Reference: BIGIP,
			}
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).NotTo(BeNil())
			policy.Spec.DefaultPool.Name = "testPool"
			_, err = mockCtlr.checkValidPolicy(policy, validator)
			Expect(err).To(BeEmpty())
		})
	})
})
