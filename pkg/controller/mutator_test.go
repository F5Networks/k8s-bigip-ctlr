package controller

import (
	"bytes"
	"encoding/json"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"net/http"
	"net/http/httptest"
)

var _ = Describe("handleMutate", func() {
	var (
		mockCtlr *mockController
		w        *httptest.ResponseRecorder
		r        *http.Request
	)

	BeforeEach(func() {
		mockCtlr = newMockController()
		w = httptest.NewRecorder()
	})

	Context("when request body is invalid", func() {
		It("should return 400", func() {
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer([]byte("invalid")))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("when admission review is invalid", func() {
		It("should return 400", func() {
			// valid json, but not a valid admission review
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer([]byte(`{"foo": "bar}`)))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("when resource is unsupported", func() {
		It("should return 400", func() {
			admission := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Kind: metav1.GroupVersionKind{Kind: "Unknown"},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer(body))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("when resource is VirtualServer", func() {
		It("should return 200 and patch missing fields", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "VirtualServer",
				"metadata":   map[string]interface{}{"name": "vs1"},
				"spec":       map[string]interface{}{},
			}
			objRaw, _ := json.Marshal(obj)
			admission := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:    "123",
					Kind:   metav1.GroupVersionKind{Kind: "VirtualServer"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer(body))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp admissionv1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
			Expect(resp.Response.Patch).NotTo(BeNil())
		})
	})

	Context("when resource is TransportServer", func() {
		It("should return 200 and patch missing fields", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "TransportServer",
				"metadata":   map[string]interface{}{"name": "ts1"},
				"spec":       map[string]interface{}{},
			}
			objRaw, _ := json.Marshal(obj)
			admission := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:    "456",
					Kind:   metav1.GroupVersionKind{Kind: "TransportServer"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer(body))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp admissionv1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
			Expect(resp.Response.Patch).NotTo(BeNil())
		})
	})

	Context("when resource is IngressLink", func() {
		It("should return 200 and empty patch", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "IngressLink",
				"metadata":   map[string]interface{}{"name": "il1"},
				"spec":       map[string]interface{}{},
			}
			objRaw, _ := json.Marshal(obj)
			admission := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:    "789",
					Kind:   metav1.GroupVersionKind{Kind: "IngressLink"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer(body))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp admissionv1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
			Expect(resp.Response.Patch).NotTo(BeNil())
		})
	})

	Context("when resource is TLSProfile", func() {
		It("should return 200 and patch missing fields", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "TLSProfile",
				"metadata":   map[string]interface{}{"name": "tls1"},
				"spec": map[string]interface{}{
					"tls": map[string]interface{}{
						"clientSSLParams": map[string]interface{}{"renegotiationEnabled": false},
						"serverSSLParams": map[string]interface{}{"renegotiationEnabled": false},
					},
				},
			}
			objRaw, _ := json.Marshal(obj)
			admission := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:    "101",
					Kind:   metav1.GroupVersionKind{Kind: "TLSProfile"},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer(body))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp admissionv1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
			Expect(resp.Response.Patch).NotTo(BeNil())
		})
	})

	Context("when resource is CustomPolicy", func() {
		It("should return 200 and patch missing fields", func() {
			obj := map[string]interface{}{
				"apiVersion": "cis.f5.com/v1",
				"kind":       "CustomPolicy",
				"metadata":   map[string]interface{}{"name": "cp1"},
				"spec": map[string]interface{}{
					"poolSettings": map[string]interface{}{
						"multiPoolPersistence": map[string]interface{}{"timeOut": 0},
					},
				},
			}
			objRaw, _ := json.Marshal(obj)
			admission := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:    "202",
					Kind:   metav1.GroupVersionKind{Kind: CustomPolicy},
					Object: runtime.RawExtension{Raw: objRaw},
				},
			}
			body, _ := json.Marshal(admission)
			r = httptest.NewRequest("POST", "/mutate", bytes.NewBuffer(body))
			mockCtlr.handleMutate(w, r)
			Expect(w.Code).To(Equal(http.StatusOK))
			var resp admissionv1.AdmissionReview
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			Expect(resp.Response.Allowed).To(BeTrue())
			Expect(resp.Response.Patch).NotTo(BeNil())
		})
	})
})
