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

package controller

import (
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"io"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"net/http"
	"strings"
)

var (
	deserializer = serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer()
)

func (ctlr *Controller) handleValidate(w http.ResponseWriter, r *http.Request) {
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

	admissionResponse := ctlr.validateResource(admissionReview.Request)
	admissionReview.Response = admissionResponse
	admissionReview.Response.UID = admissionReview.Request.UID

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		http.Error(w, "could not encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		log.Errorf("failed to write response: %v", err)
		http.Error(w, "failed to write response", http.StatusInternalServerError)
	}
}

func (ctlr *Controller) validateResource(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	var allowed bool
	var errMsg string

	switch req.Kind.Kind {
	case VirtualServer:
		vs := &cisapiv1.VirtualServer{}
		if _, _, err := deserializer.Decode(req.Object.Raw, nil, vs); err != nil {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("could not decode object: %v", err),
				},
			}
		}
		// Assuming you have a controller instance `ctlr`
		allowed, errMsg = ctlr.checkValidVirtualServer(vs)
	case TransportServer:
		ts := &cisapiv1.TransportServer{}
		if _, _, err := deserializer.Decode(req.Object.Raw, nil, ts); err != nil {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("could not decode object: %v", err),
				},
			}
		}
		allowed, errMsg = ctlr.checkValidTransportServer(ts)

	case IngressLink:
		il := &cisapiv1.IngressLink{}
		if _, _, err := deserializer.Decode(req.Object.Raw, nil, il); err != nil {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("could not decode object: %v", err),
				},
			}
		}
		allowed, errMsg = ctlr.checkValidIngressLink(il)
	case CustomPolicy, TLSProfile:
		allowed = true
	default:
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: "unsupported kind",
			},
		}
	}

	if !allowed {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: errMsg,
			},
		}
	}
	return &admissionv1.AdmissionResponse{Allowed: true}
}

func (ctlr *Controller) checkValidVirtualServer(
	vsResource *cisapiv1.VirtualServer,
) (bool, string) {

	vsName := vsResource.ObjectMeta.Name
	var errMsg string

	if vsResource.Spec.Partition == CommonPartition {
		errMsg = fmt.Sprintf("VirtualServer %s cannot be created in Common partition", vsName)
		return false, errMsg
	}

	if vsResource.Spec.TLSProfileName == "" && vsResource.Spec.HTTPTraffic != "" {
		errMsg = fmt.Sprintf("HTTPTraffic not allowed to be set for insecure VirtualServer: %v", vsName)
		return false, errMsg
	}

	if vsResource.Spec.Host == "" && len(vsResource.Spec.HostAliases) > 0 {
		errMsg = fmt.Sprintf("Host is not provided but HostAliases is present for VirtualServer: %v", vsName)
		return false, errMsg
	}

	bindAddr := vsResource.Spec.VirtualServerAddress
	if ctlr.ipamCli == nil {
		if bindAddr == "" {
			errMsg = fmt.Sprintf("No IP was specified for the virtual server %s", vsName)
			return false, errMsg
		}
	} else {
		ipamLabel := vsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			errMsg = fmt.Sprintf("No ipamLabel was specified for the virtual server %s", vsName)
			return false, errMsg
		}
	}
	for _, pool := range vsResource.Spec.Pools {
		if ctlr.discoveryMode == DefaultMode {
			if pool.MultiClusterServices == nil {
				errMsg = fmt.Sprintf("[MultiCluster] MultiClusterServices is not provided for VirtualServer %s/%s, pool %s but "+
					"CIS is running with default mode", vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name, pool.Name)
				return false, errMsg
			}
			if pool.Service != "" || pool.ServicePort != (intstr.IntOrString{}) ||
				pool.Weight != nil || pool.AlternateBackends != nil {
				log.Warningf("[MultiCluster] Ignoring Pool Service/ServicePort/Weight/AlternateBackends provided for "+
					"VirtualServer %s for pool %s as these are not supported in default mode", vsResource.ObjectMeta.Name, pool.Name)
			}
		} else {
			if pool.MultiClusterServices != nil && ctlr.multiClusterMode == "" {
				errMsg = fmt.Sprintf("MultiClusterServices is set for VirtualServer %s/%s for pool %s but CIS is not running in "+
					"multiCluster mode", vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name, pool.Name)
				return false, errMsg
			}
			if pool.Service == "" || pool.ServicePort == (intstr.IntOrString{}) {
				errMsg = fmt.Sprintf("Service/ServicePort is not provided in Pool %s for VirtualServer %s/%s",
					pool.Name, vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name)
				return false, errMsg
			}
		}

		for _, mcs := range pool.MultiClusterServices {
			err := ctlr.checkValidMultiClusterService(mcs, true)
			if err != nil {
				log.Errorf("[MultiCluster] invalid multiClusterServices: %v for VS: %s: %v", mcs, vsName, err)
				continue
			}
		}
	}

	return true, errMsg
}

func (ctlr *Controller) checkValidTransportServer(
	tsResource *cisapiv1.TransportServer,
) (bool, string) {
	if ctlr.discoveryMode == DefaultMode {
		if tsResource.Spec.Pool.MultiClusterServices == nil {
			errMsg := fmt.Sprintf("[MultiCluster] MultiClusterServices is not provided for TransportServer %s/%s when "+
				"CIS is running in default mode", tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
			return false, errMsg
		}
		if tsResource.Spec.Pool.Service != "" || tsResource.Spec.Pool.ServicePort != (intstr.IntOrString{}) ||
			tsResource.Spec.Pool.Weight != nil || tsResource.Spec.Pool.AlternateBackends != nil {
			log.Warningf("[MultiCluster] Ignoring Pool Service/ServicePort/Weight/AlternateBackends provided for "+
				"TransportServer %s as these are not supported in default mode", tsResource.ObjectMeta.Name)
		}
	} else {
		if tsResource.Spec.Pool.MultiClusterServices != nil && ctlr.multiClusterMode == "" {
			errMsg := fmt.Sprintf("MultiClusterServices is set for TransportServer %s/%s but CIS is not running in "+
				"multiCluster mode", tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
			return false, errMsg
		}
		if tsResource.Spec.Pool.Service == "" || tsResource.Spec.Pool.ServicePort == (intstr.IntOrString{}) {
			errMsg := fmt.Sprintf("Service/ServicePort is not provided in Pool for TransportServer %s/%s",
				tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
			return false, errMsg
		}
	}
	vsName := tsResource.ObjectMeta.Name

	if tsResource.Spec.Partition == CommonPartition {
		errMsg := fmt.Sprintf("TransportServer %s cannot be created in Common partition", vsName)
		return false, errMsg
	}

	bindAddr := tsResource.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		if bindAddr == "" {
			errMsg := fmt.Sprintf("No IP was specified for the transport server %s", vsName)
			return false, errMsg
		}
	} else {
		ipamLabel := tsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			errMsg := fmt.Sprintf("No ipamLabel was specified for the transport server %s", vsName)
			return false, errMsg
		}
	}
	key := ctlr.ipamClusterLabel + tsResource.ObjectMeta.Namespace + "/" + tsResource.ObjectMeta.Name + "_ts"
	if tsResource.Spec.HostGroup != "" {
		key = ctlr.ipamClusterLabel + tsResource.Spec.HostGroup + "_hg"
	}
	if appConfig := getL4AppConfig(tsResource.Spec.VirtualServerAddress, key, tsResource.Spec.VirtualServerPort, tsResource.Spec.BigIPRouteDomain); appConfig != (l4AppConfig{}) {
		if val, ok := ctlr.resources.processedL4Apps[appConfig]; ok {
			if val.timestamp.Before(&tsResource.CreationTimestamp) {
				errMsg := fmt.Sprintf("l4 app already exists with given ip-address/ipam-label, port or bigip route-domain  %v, while processing transport server %s/%s", appConfig, tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
				return false, errMsg
			}
		}
	}

	if tsResource.Spec.Pool.MultiClusterServices != nil {
		for _, mcs := range tsResource.Spec.Pool.MultiClusterServices {
			err := ctlr.checkValidMultiClusterService(mcs, true)
			if err != nil {
				log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for TS: %s: %v", mcs, vsName, err)
				continue
			}
		}
	}
	return true, ""
}

func (ctlr *Controller) checkValidIngressLink(
	il *cisapiv1.IngressLink,
) (bool, string) {

	var errMsg string
	ilName := il.ObjectMeta.Name
	if il.Spec.Partition == CommonPartition {
		errMsg = fmt.Sprintf("IngressLink %s cannot be created in Common partition", ilName)
		return false, errMsg
	}

	if il.Spec.Selector == nil && ctlr.multiClusterMode == "" {
		errMsg = fmt.Sprintf("Selector is not provided for IngressLink %s", ilName)
		return false, errMsg
	}
	bindAddr := il.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		if bindAddr == "" {
			errMsg = fmt.Sprintf("No IP was specified for ingresslink %s", ilName)
			return false, errMsg
		}
	} else {
		ipamLabel := il.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			errMsg = fmt.Sprintf("No ipamLabel was specified for the il server %s", ilName)
			return false, errMsg
		}
	}
	return true, errMsg
}

// checkValidMultiClusterService checks if extended service is valid or not
func (ctlr *Controller) checkValidMultiClusterService(mcs cisapiv1.MultiClusterServiceReference, isSpec bool) error {
	// Check if cis running in multiCluster mode
	if ctlr.multiClusterMode == "" {
		return fmt.Errorf("CIS is not running in multiCluster mode")
	}
	// Check if all required parameters are specified
	if mcs.SvcName == "" || mcs.Namespace == "" || (mcs.ClusterName == "" && isSpec) || mcs.ServicePort == (intstr.IntOrString{}) {
		return fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")
	}
	if mcs.ClusterName != "" {
		// Check if cluster config is provided for the cluster where the service is running
		if _, ok := ctlr.multiClusterHandler.ClusterConfigs[mcs.ClusterName]; !ok && mcs.ClusterName != ctlr.multiClusterHandler.LocalClusterName {
			return fmt.Errorf("cluster config for the cluster %s is not provided in extended configmap", mcs.ClusterName)
		}
	}
	return nil
}

// function to fetch the l4appconfig
func getL4AppConfig(ipaddress, ipamKey string, port, routeDomain int32) l4AppConfig {
	if ipaddress != "" {
		return l4AppConfig{
			ipOrIPAMKey: ipaddress,
			port:        port,
			routeDomain: routeDomain,
		}
	}
	if ipamKey != "" {
		return l4AppConfig{
			ipOrIPAMKey: ipamKey,
			port:        port,
			routeDomain: routeDomain,
		}
	}
	return l4AppConfig{}
}

// function to fetch the l4appconfig
func getL4AppConfigForService(svc *v1.Service, ipamClusterLabel string, routeDomain int32) l4AppConfig {
	if ip, ok := svc.Annotations[LBServiceIPAnnotation]; ok {
		return l4AppConfig{
			ipOrIPAMKey: ip,
			port:        svc.Spec.Ports[0].Port,
			routeDomain: routeDomain,
			protocol:    strings.ToLower(string(svc.Spec.Ports[0].Protocol)),
		}
	}
	if _, ok := svc.Annotations[LBServiceIPAMLabelAnnotation]; ok {
		return l4AppConfig{
			ipOrIPAMKey: ipamClusterLabel + svc.Namespace + "/" + svc.Name + "_svc",
			port:        svc.Spec.Ports[0].Port,
			routeDomain: routeDomain,
			protocol:    strings.ToLower(string(svc.Spec.Ports[0].Protocol)),
		}
	}
	return l4AppConfig{}
}
