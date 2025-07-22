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
	"context"
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/bigiphandler"
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
	"sync"
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
	var wg sync.WaitGroup

	errChan := make(chan string, 1)
	doneChan := make(chan struct{})
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Check partition
	wg.Add(1)
	go func() {
		defer wg.Done()
		if vsResource.Spec.Partition == CommonPartition {
			errChan <- fmt.Sprintf("VirtualServer %s cannot be created in Common partition", vsName)
			cancel()
		}
	}()

	// Check TLSProfileName and HTTPTraffic
	wg.Add(1)
	go func() {
		defer wg.Done()
		if vsResource.Spec.TLSProfileName == "" && vsResource.Spec.HTTPTraffic != "" {
			errChan <- fmt.Sprintf("HTTPTraffic not allowed to be set for insecure VirtualServer: %v", vsName)
			cancel()
		}
	}()

	// Check Host and HostAliases
	wg.Add(1)
	go func() {
		defer wg.Done()
		if vsResource.Spec.Host == "" && len(vsResource.Spec.HostAliases) > 0 {
			errChan <- fmt.Sprintf("Host is not provided but HostAliases is present for VirtualServer: %v", vsName)
			cancel()
		}
	}()

	// Check IPAM and VirtualServerAddress
	wg.Add(1)
	go func() {
		defer wg.Done()
		bindAddr := vsResource.Spec.VirtualServerAddress
		if ctlr.ipamCli == nil {
			if bindAddr == "" {
				errChan <- fmt.Sprintf("No IP was specified for the virtual server %s", vsName)
				cancel()
			}
		} else {
			ipamLabel := vsResource.Spec.IPAMLabel
			if ipamLabel == "" && bindAddr == "" {
				errChan <- fmt.Sprintf("No ipamLabel/IP was specified for the virtual server %s", vsName)
				cancel()
			}
		}
	}()

	// Check Pools
	for _, pool := range vsResource.Spec.Pools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ctlr.discoveryMode == DefaultMode {
				if pool.MultiClusterServices == nil {
					errChan <- fmt.Sprintf("[MultiCluster] MultiClusterServices is not provided for VirtualServer %s/%s, pool %s but "+
						"CIS is running with default mode", vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name, pool.Name)
					cancel()
					return
				}
				if pool.Service != "" || pool.ServicePort != (intstr.IntOrString{}) ||
					pool.Weight != nil || pool.AlternateBackends != nil {
					log.Warningf("[MultiCluster] Ignoring Pool Service/ServicePort/Weight/AlternateBackends provided for "+
						"VirtualServer %s for pool %s as these are not supported in default mode", vsResource.ObjectMeta.Name, pool.Name)
				}
			} else {
				if pool.MultiClusterServices != nil && ctlr.multiClusterMode == "" {
					errChan <- fmt.Sprintf("MultiClusterServices is set for VirtualServer %s/%s for pool %s but CIS is not running in "+
						"multiCluster mode", vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name, pool.Name)
					cancel()
					return
				}
				if pool.Service == "" || pool.ServicePort == (intstr.IntOrString{}) {
					errChan <- fmt.Sprintf("Service/ServicePort is not provided in Pool %s for VirtualServer %s/%s",
						pool.Name, vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name)
					cancel()
					return
				}
			}

			for _, mcs := range pool.MultiClusterServices {
				err := ctlr.checkValidMultiClusterService(mcs, true)
				if err != nil {
					log.Errorf("[MultiCluster] invalid multiClusterServices: %v for VS: %s: %v", mcs, vsName, err)
					continue
				}
			}
		}()
	}

	// create a session to BIG-IP
	bigipSession := bigiphandler.CreateSession(ctlr.agentParams.PrimaryParams.BIGIPURL, ctlr.PrimaryBigIPWorker.getPostManager().GetToken(), ctlr.agentParams.UserAgent, ctlr.agentParams.PrimaryParams.TrustedCerts, ctlr.agentParams.PrimaryParams.SSLInsecure, false)
	validator := &bigiphandler.BigIPHandler{Bigip: bigipSession}

	// Validate iRules
	for _, irule := range vsResource.Spec.IRules {
		wg.Add(1)
		go func(irule string) {
			defer wg.Done()
			if _, err := validator.GetIRule(irule); err != nil {
				errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for VirtualServer %s: %v", irule, vsName, err)
				cancel()
				return
			}
		}(irule)
	}

	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case errMsg = <-errChan:
		return false, errMsg
	case <-doneChan:
		close(errChan)
		return true, ""
	}
}

func (ctlr *Controller) checkValidTransportServer(
	tsResource *cisapiv1.TransportServer,
) (bool, string) {
	var errMsg string
	var wg sync.WaitGroup
	errChan := make(chan string, 1)
	doneChan := make(chan struct{})
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	vsName := tsResource.ObjectMeta.Name

	// Discovery mode checks
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ctlr.discoveryMode == DefaultMode {
			if tsResource.Spec.Pool.MultiClusterServices == nil {
				errChan <- fmt.Sprintf("[MultiCluster] MultiClusterServices is not provided for TransportServer %s/%s when "+
					"CIS is running in default mode", tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
				cancel()
				return
			}
			if tsResource.Spec.Pool.Service != "" || tsResource.Spec.Pool.ServicePort != (intstr.IntOrString{}) ||
				tsResource.Spec.Pool.Weight != nil || tsResource.Spec.Pool.AlternateBackends != nil {
				log.Warningf("[MultiCluster] Ignoring Pool Service/ServicePort/Weight/AlternateBackends provided for "+
					"TransportServer %s as these are not supported in default mode", tsResource.ObjectMeta.Name)
			}
		} else {
			if tsResource.Spec.Pool.MultiClusterServices != nil && ctlr.multiClusterMode == "" {
				errChan <- fmt.Sprintf("MultiClusterServices is set for TransportServer %s/%s but CIS is not running in "+
					"multiCluster mode", tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
				cancel()
				return
			}
			if tsResource.Spec.Pool.Service == "" || tsResource.Spec.Pool.ServicePort == (intstr.IntOrString{}) {
				errChan <- fmt.Sprintf("Service/ServicePort is not provided in Pool for TransportServer %s/%s",
					tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
				cancel()
				return
			}
		}
	}()

	// Partition check
	wg.Add(1)
	go func() {
		defer wg.Done()
		if tsResource.Spec.Partition == CommonPartition {
			errChan <- fmt.Sprintf("TransportServer %s cannot be created in Common partition", vsName)
			cancel()
			return
		}
	}()

	// IPAM and VirtualServerAddress check
	wg.Add(1)
	go func() {
		defer wg.Done()
		bindAddr := tsResource.Spec.VirtualServerAddress
		if ctlr.ipamCli == nil {
			if bindAddr == "" {
				errChan <- fmt.Sprintf("No IP was specified for the transport server %s", vsName)
				cancel()
				return
			}
		} else {
			ipamLabel := tsResource.Spec.IPAMLabel
			if ipamLabel == "" && bindAddr == "" {
				errChan <- fmt.Sprintf("No ipamLabel/IP was specified for the transport server %s", vsName)
				cancel()
				return
			}
		}
	}()

	// L4 AppConfig check
	wg.Add(1)
	go func() {
		defer wg.Done()
		key := ctlr.ipamClusterLabel + tsResource.ObjectMeta.Namespace + "/" + tsResource.ObjectMeta.Name + "_ts"
		if tsResource.Spec.HostGroup != "" {
			key = ctlr.ipamClusterLabel + tsResource.Spec.HostGroup + "_hg"
		}
		if appConfig := getL4AppConfig(tsResource.Spec.VirtualServerAddress, key, tsResource.Spec.VirtualServerPort, tsResource.Spec.BigIPRouteDomain); appConfig != (l4AppConfig{}) {
			if val, ok := ctlr.resources.processedL4Apps[appConfig]; ok {
				if val.timestamp.Before(&tsResource.CreationTimestamp) {
					errChan <- fmt.Sprintf("l4 app already exists with given ip-address/ipam-label, port or bigip route-domain  %v, while processing transport server %s/%s", appConfig, tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
					cancel()
					return
				}
			}
		}
	}()

	// MultiClusterServices check
	if tsResource.Spec.Pool.MultiClusterServices != nil {
		for _, mcs := range tsResource.Spec.Pool.MultiClusterServices {
			wg.Add(1)
			go func(mcs cisapiv1.MultiClusterServiceReference) {
				defer wg.Done()
				if err := ctlr.checkValidMultiClusterService(mcs, true); err != nil {
					log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for TS: %s: %v", mcs, vsName, err)
					// Not returning error, just logging as per original logic
				}
			}(mcs)
		}
	}

	bigipSession := bigiphandler.CreateSession(ctlr.agentParams.PrimaryParams.BIGIPURL, ctlr.PrimaryBigIPWorker.getPostManager().GetToken(), ctlr.agentParams.UserAgent, ctlr.agentParams.PrimaryParams.TrustedCerts, ctlr.agentParams.PrimaryParams.SSLInsecure, false)
	validator := &bigiphandler.BigIPHandler{Bigip: bigipSession}

	// Validate iRules
	for _, irule := range tsResource.Spec.IRules {
		wg.Add(1)
		go func(irule string) {
			defer wg.Done()
			if _, err := validator.GetIRule(irule); err != nil {
				errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for VirtualServer %s: %v", irule, vsName, err)
				cancel()
				return
			}
		}(irule)
	}

	// Validate ClientSSL Profile if TLSProfileName is set
	for _, clientssl := range tsResource.Spec.TLS.ClientSSLs {
		wg.Add(1)
		go func(clientssl string) {
			defer wg.Done()
			if _, err := validator.GetClientSSLProfile(clientssl); err != nil {
				errChan <- fmt.Sprintf("Referenced ClientSSL Profile '%s' does not exist on BIGIP for VirtualServer %s: %v", clientssl, vsName, err)
				cancel()
				return
			}
		}(clientssl)
	}

	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case errMsg = <-errChan:
		return false, errMsg
	case <-doneChan:
		close(errChan)
		return true, ""
	}
}

func (ctlr *Controller) checkValidIngressLink(
	il *cisapiv1.IngressLink,
) (bool, string) {
	var wg sync.WaitGroup
	errChan := make(chan string, 1)
	doneChan := make(chan struct{})
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	ilName := il.ObjectMeta.Name

	// Partition check
	wg.Add(1)
	go func() {
		defer wg.Done()
		if il.Spec.Partition == CommonPartition {
			errChan <- fmt.Sprintf("IngressLink %s cannot be created in Common partition", ilName)
			cancel()
		}
	}()

	// Selector check
	wg.Add(1)
	go func() {
		defer wg.Done()
		if il.Spec.Selector == nil && ctlr.multiClusterMode == "" {
			errChan <- fmt.Sprintf("Selector is not provided for IngressLink %s", ilName)
			cancel()
		}
	}()

	// IPAM/VirtualServerAddress check
	wg.Add(1)
	go func() {
		defer wg.Done()
		bindAddr := il.Spec.VirtualServerAddress
		if ctlr.ipamCli == nil {
			if bindAddr == "" {
				errChan <- fmt.Sprintf("No IP was specified for ingresslink %s", ilName)
				cancel()
			}
		} else {
			ipamLabel := il.Spec.IPAMLabel
			if ipamLabel == "" && bindAddr == "" {
				errChan <- fmt.Sprintf("No ipamLabel/IP was specified for the il server %s", ilName)
				cancel()
			}
		}
	}()

	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case errMsg := <-errChan:
		return false, errMsg
	case <-doneChan:
		close(errChan)
		return true, ""
	}
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
