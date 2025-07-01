package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
)

var _ = Describe("Validation Tests", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
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
			mockCtlr *mockController
			w        *httptest.ResponseRecorder
			r        *http.Request
		)

		BeforeEach(func() {
			mockCtlr = newMockController()
			mockCtlr.resources = NewResourceStore()
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
})
