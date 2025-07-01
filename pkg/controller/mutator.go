package controller

import (
	"encoding/json"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"io"
	admissionv1 "k8s.io/api/admission/v1"
	"net/http"
)

func (ctlr *Controller) handleMutate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request", http.StatusBadRequest)
		return
	}

	var admissionReview admissionv1.AdmissionReview
	if _, _, err := deserializer.Decode(body, nil, &admissionReview); err != nil {
		http.Error(w, "could not decode admission review", http.StatusBadRequest)
		return
	}
	var patches []map[string]interface{}
	raw := admissionReview.Request.Object.Raw
	switch admissionReview.Request.Kind.Kind {
	case VirtualServer:
		obj := cisapiv1.VirtualServer{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if obj.Spec.VirtualServerHTTPPort == 0 {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/virtualServerHTTPPort",
				"value": DEFAULT_HTTP_PORT,
			})
		}
		if obj.Spec.VirtualServerHTTPSPort == 0 {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/virtualServerHTTPSPort",
				"value": DEFAULT_HTTPS_PORT,
			})
		}
		if obj.Spec.SNAT == "" {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/snat",
				"value": DEFAULT_SNAT,
			})
		}

	case TransportServer:
		obj := cisapiv1.TransportServer{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if obj.Spec.Type == "" {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/type",
				"value": "tcp",
			})
		}
		if obj.Spec.SNAT == "" {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/snat",
				"value": DEFAULT_SNAT,
			})
		}

	case IngressLink:

	case TLSProfile:
		obj := cisapiv1.TLSProfile{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !*obj.Spec.TLS.ClientSSLParams.RenegotiationEnabled {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/tls/clientSSLParams/renegotiationEnabled",
				"value": true,
			})
		}
		if !*obj.Spec.TLS.ServerSSLParams.RenegotiationEnabled {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/tls/serverSSLParams/renegotiationEnabled",
				"value": true,
			})
		}
	case CustomPolicy:
		obj := cisapiv1.Policy{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if obj.Spec.PoolSettings.MultiPoolPersistence.TimeOut == 0 {
			patches = append(patches, map[string]interface{}{
				"op":    "add",
				"path":  "/spec/poolSettings/multiPoolPersistence/timeOut",
				"value": 180,
			})
		}
	default:
		http.Error(w, "Unsupported Resource", http.StatusBadRequest)
		return

	}

	patchBytes, _ := json.Marshal(patches)
	resp := admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			UID:     admissionReview.Request.UID,
			Allowed: true,
			Patch:   patchBytes,
			PatchType: func() *admissionv1.PatchType {
				pt := admissionv1.PatchTypeJSONPatch
				return &pt
			}(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, "could not encode request", http.StatusBadRequest)
		return
	}
}
