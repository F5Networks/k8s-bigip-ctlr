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
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/tokenmanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"io"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"net"
	"net/http"
	"reflect"
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
	case TLSProfile:
		allowed = true

	case CustomPolicy:
		pl := &cisapiv1.Policy{}
		if _, _, err := deserializer.Decode(req.Object.Raw, nil, pl); err != nil {
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("could not decode object: %v", err),
				},
			}
		}
		allowed, errMsg = ctlr.checkValidPolicy(pl, nil)
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
			if ctlr.discoveryMode != "" {
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

	// create a session to BIG-IP using shared token manager
	log.Debugf("Creating session to BIG-IP for VirtualServer %s/%s", vsResource.ObjectMeta.Namespace, vsName)
	validator := ctlr.getBigIPHandlerWithSharedToken()

	// Validate iRules
	for _, irule := range vsResource.Spec.IRules {
		// if Irule is set to none, skip the check
		if irule == "none" {
			continue
		}
		wg.Add(1)
		go func(irule string) {
			defer wg.Done()
			if _, err := validator.GetIRule(irule); err != nil {
				errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for VirtualServer %s (iRules: %v): %v", irule, vsName, vsResource.Spec.IRules, err)
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
		if ctlr.discoveryMode != "" {
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
	log.Debugf("Creating session to BIG-IP for TransportServer %s/%s", tsResource.ObjectMeta.Name, vsName)
	validator := ctlr.getBigIPHandlerWithSharedToken()

	// Validate iRules
	for _, irule := range tsResource.Spec.IRules {
		wg.Add(1)
		go func(irule string) {
			defer wg.Done()
			if _, err := validator.GetIRule(irule); err != nil {
				errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for TransportServer %s (iRules: %v): %v", irule, vsName, tsResource.Spec.IRules, err)
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
				errChan <- fmt.Sprintf("Referenced ClientSSL Profile '%s' does not exist on BIGIP for TransportServer %s (tls.clientSSLs: %v): %v", clientssl, vsName, tsResource.Spec.TLS.ClientSSLs, err)
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
func getL4AppConfigForService(svc *v1.Service, ipamClusterLabel string, routeDomain int32) []l4AppConfig {
	var l4AppConfigs []l4AppConfig
	if svc == nil {
		return l4AppConfigs
	}
	ipOrIPAMKey := ""
	if ip, ok := svc.Annotations[LBServiceIPAnnotation]; ok {
		ipOrIPAMKey = ip
	} else if _, ok := svc.Annotations[LBServiceIPAMLabelAnnotation]; ok {
		ipOrIPAMKey = ipamClusterLabel + svc.Namespace + "/" + svc.Name + "_svc"
	}
	// for LB service with multiple ports, l4AppConfig for each port needs to be created
	for _, port := range svc.Spec.Ports {
		l4AppConfigs = append(l4AppConfigs, l4AppConfig{
			ipOrIPAMKey: ipOrIPAMKey,
			port:        port.Port,
			routeDomain: routeDomain,
			protocol:    strings.ToLower(string(svc.Spec.Ports[0].Protocol)),
		})
	}
	return l4AppConfigs
}

func (ctlr *Controller) checkValidPolicy(pl *cisapiv1.Policy, handler bigiphandler.BigIPHandlerInterface) (bool, string) {
	var errMsg string
	var wg sync.WaitGroup
	errChan := make(chan string, 1)
	doneChan := make(chan struct{})
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Debugf("Creating session to BIG-IP for Policy %s/%s", pl.ObjectMeta.Name, pl.ObjectMeta.Name)
	if handler == nil {
		bigipSession := bigiphandler.CreateSession(ctlr.agentParams.PrimaryParams.BIGIPURL, ctlr.PrimaryBigIPWorker.getPostManager().GetToken(), ctlr.agentParams.UserAgent, ctlr.agentParams.PrimaryParams.TrustedCerts, ctlr.agentParams.PrimaryParams.SSLInsecure, false)
		handler = &bigiphandler.BigIPHandler{Bigip: bigipSession}
	}
	policyName := pl.ObjectMeta.Name
	// Check WAF
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L7Policies.WAF != "" {
			if _, err := handler.GetWAF(pl.Spec.L7Policies.WAF); err != nil {
				errChan <- fmt.Sprintf("Referenced WAF policy '%s' does not exist on BIGIP for Policy %s (l7Policies.waf: %s): %v", pl.Spec.L7Policies.WAF, policyName, pl.Spec.L7Policies.WAF, err)
				cancel()
				return
			}
		}
	}()

	// Check profileAccess
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L7Policies.ProfileAccess != "" {
			if _, err := handler.GetProfileAccess(pl.Spec.L7Policies.ProfileAccess); err != nil {
				errChan <- fmt.Sprintf("Referenced profileAccess '%s' does not exist on BIGIP for Policy %s (l7Policies.profileAccess: %s): %v", pl.Spec.L7Policies.ProfileAccess, policyName, pl.Spec.L7Policies.ProfileAccess, err)
				cancel()
				return
			}
		}
	}()

	// Check policyPerRequestAccess
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L7Policies.PolicyPerRequestAccess != "" {
			if _, err := handler.GetPolicyPerRequestAccess(pl.Spec.L7Policies.PolicyPerRequestAccess); err != nil {
				errChan <- fmt.Sprintf("Referenced policyPerRequestAccess '%s' does not exist on BIGIP for Policy %s (l7Policies.policyPerRequestAccess: %s): %v", pl.Spec.L7Policies.PolicyPerRequestAccess, policyName, pl.Spec.L7Policies.PolicyPerRequestAccess, err)
				cancel()
				return
			}
		}
	}()

	// Check profileAdapt request & response
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.L7Policies.ProfileAdapt, cisapiv1.ProfileAdapt{}) {
			// Check profileAdapt request
			if pl.Spec.L7Policies.ProfileAdapt.Request != "" {
				if _, err := handler.GetProfileAdaptRequest(pl.Spec.L7Policies.ProfileAdapt.Request); err != nil {
					errChan <- fmt.Sprintf("Referenced profileAdapt request '%s' does not exist on BIGIP for Policy %s (l7Policies.profileAdapt.request: %s): %v", pl.Spec.L7Policies.ProfileAdapt.Request, policyName, pl.Spec.L7Policies.ProfileAdapt.Request, err)
					cancel()
					return
				}
			}
			// Check profileAdapt response
			if pl.Spec.L7Policies.ProfileAdapt.Response != "" {
				if _, err := handler.GetProfileAdaptResponse(pl.Spec.L7Policies.ProfileAdapt.Response); err != nil {
					errChan <- fmt.Sprintf("Referenced profileAdapt response '%s' does not exist on BIGIP for Policy %s (l7Policies.profileAdapt.response: %s): %v", pl.Spec.L7Policies.ProfileAdapt.Response, policyName, pl.Spec.L7Policies.ProfileAdapt.Response, err)
					cancel()
					return
				}
			}
		}
	}()

	// Check DOS Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L3Policies.DOS != "" {
			if _, err := handler.GetDOSProfile(pl.Spec.L3Policies.DOS); err != nil {
				errChan <- fmt.Sprintf("Referenced dos profile '%s' does not exist on BIGIP for Policy %s (l3Policies.dos: %s): %v", pl.Spec.L3Policies.DOS, policyName, pl.Spec.L3Policies.DOS, err)
				cancel()
				return
			}
		}
	}()

	// Check botDefense Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L3Policies.BotDefense != "" {
			if _, err := handler.GetBotDefenseProfile(pl.Spec.L3Policies.BotDefense); err != nil {
				errChan <- fmt.Sprintf("Referenced botDefense profile '%s' does not exist on BIGIP for Policy %s (l3Policies.botDefense: %s): %v", pl.Spec.L3Policies.BotDefense, policyName, pl.Spec.L3Policies.BotDefense, err)
				cancel()
				return
			}
		}
	}()

	// Check firewallPolicy Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L3Policies.FirewallPolicy != "" {
			if _, err := handler.GetFirewallPolicy(pl.Spec.L3Policies.FirewallPolicy); err != nil {
				errChan <- fmt.Sprintf("Referenced firewall policy '%s' does not exist on BIGIP for Policy %s (l3Policies.firewallPolicy: %s): %v", pl.Spec.L3Policies.FirewallPolicy, policyName, pl.Spec.L3Policies.FirewallPolicy, err)
				cancel()
				return
			}
		}
	}()

	// Check vlans exists on the BIGIP
	for _, vlan := range pl.Spec.L3Policies.AllowVlans {
		wg.Add(1)
		go func(vlan string) {
			defer wg.Done()
			if _, err := handler.GetVLAN(vlan); err != nil {
				errChan <- fmt.Sprintf("Referenced vlan '%s' does not exist on BIGIP for Policy %s (l3Policies.allowVlans: %v): %v", vlan, policyName, pl.Spec.L3Policies.AllowVlans, err)
				cancel()
				return
			}

		}(vlan)
	}

	// check if the IP Address/network is valid
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, r := range pl.Spec.L3Policies.AllowSourceRange {
			// check if the IP address or CIDR is valid
			if !IsValidIPOrCIDR(r) {
				errChan <- fmt.Sprintf("Invalid IP address or CIDR '%s' in AllowSourceRange for Policy %s", r, policyName)
				cancel()
				return
			}
		}
	}()

	// check ipIntelligence policy exists on the BIGIP
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.L3Policies.IpIntelligencePolicy != "" {
			if _, err := handler.GetIPIntelligencePolicy(pl.Spec.L3Policies.IpIntelligencePolicy); err != nil {
				errChan <- fmt.Sprintf("Referenced IpIntelligence policy '%s' does not exist on BIGIP for Policy %s (l3Policies.ipIntelligencePolicy: %s): %v", pl.Spec.L3Policies.IpIntelligencePolicy, policyName, pl.Spec.L3Policies.IpIntelligencePolicy, err)
				cancel()
				return
			}
		}
	}()

	// check ltmPolicies and mark as unsupported
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.LtmPolicies, cisapiv1.LtmIRulesSpec{}) {
			errChan <- fmt.Sprintf("LTM Policies are not supported in Policy %s", policyName)
			cancel()
			return
		}
	}()

	// check iRuleList and validate each iRule
	for _, irule := range pl.Spec.IRuleList {
		wg.Add(1)
		go func(irule string) {
			defer wg.Done()
			if _, err := handler.GetIRule(irule); err != nil {
				errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for Policy %s (iRuleList: %v): %v", irule, policyName, pl.Spec.IRuleList, err)
				cancel()
				return
			}
		}(irule)
	}

	// check the iRule
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.IRules, cisapiv1.LtmIRulesSpec{}) {
			// if Irule is set to none, skip the check
			if pl.Spec.IRules.InSecure != "" && pl.Spec.IRules.InSecure != "none" {
				if _, err := handler.GetIRule(pl.Spec.IRules.InSecure); err != nil {
					errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for Policy %s (iRules.inSecure: %s): %v", pl.Spec.IRules.InSecure, policyName, pl.Spec.IRules.InSecure, err)
					cancel()
					return
				}
			}
			// if Irule is set to none, skip the check
			if pl.Spec.IRules.Secure != "" && pl.Spec.IRules.Secure != "none" {
				if _, err := handler.GetIRule(pl.Spec.IRules.Secure); err != nil {
					errChan <- fmt.Sprintf("Referenced iRule '%s' does not exist on BIGIP for Policy %s (iRules.secure: %s): %v", pl.Spec.IRules.Secure, policyName, pl.Spec.IRules.Secure, err)
					cancel()
					return
				}
			}

		}
	}()

	// Check the snat pool
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.SNAT != Auto {
			if _, err := handler.GetSNATPool(pl.Spec.SNAT); err != nil {
				errChan <- fmt.Sprintf("Referenced SNAT '%s' does not exist on BIGIP for Policy %s (snat: %s): %v", pl.Spec.SNAT, policyName, pl.Spec.SNAT, err)
				cancel()
				return
			}
		}
	}()

	// Check the referenced ltm pool
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.DefaultPool.Reference == BIGIP {
			if _, err := handler.GetLTMPool(pl.Spec.DefaultPool.Name); err != nil {
				errChan <- fmt.Sprintf("Referenced LTM pool '%s' does not exist on BIGIP for Policy %s (defaultPool.name: %s): %v", pl.Spec.DefaultPool.Name, policyName, pl.Spec.DefaultPool.Name, err)
				cancel()
				return
			}
		}
	}()

	// Check the referenced TCP Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.Profiles.TCP, cisapiv1.ProfileTCP{}) {
			// If TCPProfile is set, check if it exists on BIG-IP
			if pl.Spec.Profiles.TCP.Client != "" {
				if _, err := handler.GetTCPProfile(pl.Spec.Profiles.TCP.Client); err != nil {
					errChan <- fmt.Sprintf("Referenced client side tcp profile %s does not exist on BIGIP for Policy %s (profiles.tcp.client: %s): %v", pl.Spec.Profiles.TCP.Client, policyName, pl.Spec.Profiles.TCP.Client, err)
					cancel()
					return
				}
			}
			// If TCPProfile is set, check if it exists on BIG-IP
			if pl.Spec.Profiles.TCP.Server != "" {
				if _, err := handler.GetTCPProfile(pl.Spec.Profiles.TCP.Server); err != nil {
					errChan <- fmt.Sprintf("Referenced server side tcp profile %s does not exist on BIGIP for Policy %s (profiles.tcp.server: %s): %v", pl.Spec.Profiles.TCP.Server, policyName, pl.Spec.Profiles.TCP.Server, err)
					cancel()
					return
				}
			}
		}
	}()

	// Check the referenced UDP Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.UDP != "" {
			// If UDP Profile is set, check if it exists on BIG-IP
			if _, err := handler.GetUDPProfile(pl.Spec.Profiles.UDP); err != nil {
				errChan <- fmt.Sprintf("Referenced udp profile %s does not exist on BIGIP for Policy %s (profiles.udp: %s): %v", pl.Spec.Profiles.UDP, policyName, pl.Spec.Profiles.UDP, err)
				cancel()
				return
			}
		}
	}()

	// Check the referenced HTTP Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.HTTP != "" {
			// If HTTP Profile is set, check if it exists on BIG-IP
			if _, err := handler.GetHTTPProfile(pl.Spec.Profiles.HTTP); err != nil {
				errChan <- fmt.Sprintf("Referenced http profile %s does not exist on BIGIP for Policy %s (profiles.http: %s): %v", pl.Spec.Profiles.HTTP, policyName, pl.Spec.Profiles.HTTP, err)
				cancel()
				return
			}
		}
	}()

	// check httpProfile secure and insecure
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.Profiles.HTTPProfiles, cisapiv1.HTTPProfiles{}) {
			// check the secure http profile
			if pl.Spec.Profiles.HTTPProfiles.Secure != "" {
				if _, err := handler.GetHTTPProfile(pl.Spec.Profiles.HTTPProfiles.Secure); err != nil {
					errChan <- fmt.Sprintf("Referenced secure http profile %s does not exist on BIGIP for Policy %s (profiles.httpProfiles.secure: %s): %v", pl.Spec.Profiles.HTTPProfiles.Secure, policyName, pl.Spec.Profiles.HTTPProfiles.Secure, err)
					cancel()
					return
				}
			}
			// check the insecure http profile
			if pl.Spec.Profiles.HTTPProfiles.Insecure != "" {
				if _, err := handler.GetHTTPProfile(pl.Spec.Profiles.HTTPProfiles.Insecure); err != nil {
					errChan <- fmt.Sprintf("Referenced insecure http profile %s does not exist on BIGIP for Policy %s (profiles.httpProfiles.insecure: %s): %v", pl.Spec.Profiles.HTTPProfiles.Insecure, policyName, pl.Spec.Profiles.HTTPProfiles.Insecure, err)
					cancel()
					return
				}
			}
		}
	}()

	// Check the referenced HTTP2 Profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.Profiles.HTTP2, cisapiv1.ProfileHTTP2{}) {
			// If HTTP2 Profile is set, check if it exists on BIG-IP
			if pl.Spec.Profiles.HTTP2.Client != "" {
				if _, err := handler.GetHTTP2Profile(pl.Spec.Profiles.HTTP2.Client); err != nil {
					errChan <- fmt.Sprintf("Referenced client side http2 profile %s does not exist on BIGIP for Policy %s (profiles.http2.client: %s): %v", pl.Spec.Profiles.HTTP2.Client, policyName, pl.Spec.Profiles.HTTP2.Client, err)
					cancel()
					return
				}
			}
			// If HTTP2 Profile is set, check if it exists on BIG-IP
			if pl.Spec.Profiles.HTTP2.Server != "" {
				if _, err := handler.GetHTTP2Profile(pl.Spec.Profiles.HTTP2.Server); err != nil {
					errChan <- fmt.Sprintf("Referenced server side http2 profile %s does not exist on BIGIP for Policy %s (profiles.http2.server: %s): %v", pl.Spec.Profiles.HTTP2.Server, policyName, pl.Spec.Profiles.HTTP2.Server, err)
					cancel()
					return
				}
			}
		}
	}()

	// check referenced rewriteProfile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.RewriteProfile != "" {
			if _, err := handler.GetRewriteProfile(pl.Spec.Profiles.RewriteProfile); err != nil {
				errChan <- fmt.Sprintf("Referenced rewrite profile %s does not exist on BIGIP for Policy %s (profiles.rewriteProfile: %s): %v", pl.Spec.Profiles.RewriteProfile, policyName, pl.Spec.Profiles.RewriteProfile, err)
				cancel()
				return
			}
		}
	}()

	// check referenced persistenceProfile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.PersistenceProfile != "" {
			if _, err := handler.GetPersistenceProfile(pl.Spec.Profiles.PersistenceProfile); err != nil {
				errChan <- fmt.Sprintf("Referenced persistence profile %s does not exist on BIGIP for Policy %s (profiles.persistenceProfile: %s): %v", pl.Spec.Profiles.PersistenceProfile, policyName, pl.Spec.Profiles.PersistenceProfile, err)
				cancel()
				return
			}
		}
	}()

	// check referenced logProfiles
	for _, logProfile := range pl.Spec.Profiles.LogProfiles {
		wg.Add(1)
		go func(logProfile string) {
			defer wg.Done()
			if _, err := handler.GetLogProfile(logProfile); err != nil {
				errChan <- fmt.Sprintf("Referenced log profile %s does not exist on BIGIP for Policy %s (profiles.logProfiles: %v): %v", logProfile, policyName, pl.Spec.Profiles.LogProfiles, err)
				cancel()
				return
			}
		}(logProfile)
	}

	// check referenced profileL4
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.ProfileL4 != "" {
			if _, err := handler.GetL4Profile(pl.Spec.Profiles.ProfileL4); err != nil {
				errChan <- fmt.Sprintf("Referenced fast L4 profile %s does not exist on BIGIP for Policy %s (profiles.profileL4: %s): %v", pl.Spec.Profiles.ProfileL4, policyName, pl.Spec.Profiles.ProfileL4, err)
				cancel()
				return
			}
		}
	}()

	// check referenced profileMultiplex
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.ProfileMultiplex != "" {
			if _, err := handler.GetMultiplexProfile(pl.Spec.Profiles.ProfileMultiplex); err != nil {
				errChan <- fmt.Sprintf("Referenced multiplex profile %s does not exist on BIGIP for Policy %s (profiles.profileMultiplex: %s): %v", pl.Spec.Profiles.ProfileMultiplex, policyName, pl.Spec.Profiles.ProfileMultiplex, err)
				cancel()
				return
			}
		}
	}()

	// check referenced sslProfiles
	if !reflect.DeepEqual(pl.Spec.Profiles.SSLProfiles, cisapiv1.SSLProfiles{}) {
		for _, sslProfile := range pl.Spec.Profiles.SSLProfiles.ClientProfiles {
			wg.Add(1)
			go func(sslProfile string) {
				defer wg.Done()
				if _, err := handler.GetClientSSLProfile(sslProfile); err != nil {
					errChan <- fmt.Sprintf("Referenced client SSL profile %s does not exist on BIGIP for Policy %s (profiles.sslProfiles.clientProfiles: %v): %v", sslProfile, policyName, pl.Spec.Profiles.SSLProfiles.ClientProfiles, err)
					cancel()
					return
				}
			}(sslProfile)
		}
		for _, sslProfile := range pl.Spec.Profiles.SSLProfiles.ServerProfiles {
			wg.Add(1)
			go func(sslProfile string) {
				defer wg.Done()
				if _, err := handler.GetServerSSLProfile(sslProfile); err != nil {
					errChan <- fmt.Sprintf("Referenced server SSL profile %s does not exist on BIGIP for Policy %s (profiles.sslProfiles.serverProfiles: %v): %v", sslProfile, policyName, pl.Spec.Profiles.SSLProfiles.ServerProfiles, err)
					cancel()
					return
				}
			}(sslProfile)
		}
	}

	// check referenced analyticsProfiles
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !reflect.DeepEqual(pl.Spec.Profiles.AnalyticsProfiles, cisapiv1.AnalyticsProfiles{}) {
			if pl.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile != "" {
				if _, err := handler.GetAnalyticsProfile(pl.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile); err != nil {
					errChan <- fmt.Sprintf("Referenced analytic profile %s does not exist on BIGIP for Policy %s (profiles.analyticsProfiles.httpAnalyticsProfile: %s): %v", pl.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile, policyName, pl.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile, err)
					cancel()
					return
				}
			}
		}
	}()

	// check referenced profileWebSocket
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.ProfileWebSocket != "" {
			if _, err := handler.GetProfileWebSocket(pl.Spec.Profiles.ProfileWebSocket); err != nil {
				errChan <- fmt.Sprintf("Referenced WebSocket profile %s does not exist on BIGIP for Policy %s (profiles.profileWebSocket: %s): %v", pl.Spec.Profiles.ProfileWebSocket, policyName, pl.Spec.Profiles.ProfileWebSocket, err)
				cancel()
				return
			}
		}
	}()

	// check referenced htmlProfile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.HTMLProfile != "" {
			if _, err := handler.GetHTMLProfile(pl.Spec.Profiles.HTMLProfile); err != nil {
				errChan <- fmt.Sprintf("Referenced HTML profile %s does not exist on BIGIP for Policy %s (profiles.htmlProfile: %s): %v", pl.Spec.Profiles.HTMLProfile, policyName, pl.Spec.Profiles.HTMLProfile, err)
				cancel()
				return
			}
		}
	}()

	// check referenced ftpProfile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.FTPProfile != "" {
			if _, err := handler.GetFTPProfile(pl.Spec.Profiles.FTPProfile); err != nil {
				errChan <- fmt.Sprintf("Referenced FTP profile %s does not exist on BIGIP for Policy %s (profiles.ftpProfile: %s): %v", pl.Spec.Profiles.FTPProfile, policyName, pl.Spec.Profiles.FTPProfile, err)
				cancel()
				return
			}
		}
	}()

	// check referenced httpCompressionProfile
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pl.Spec.Profiles.HTTPCompressionProfile != "" {
			if _, err := handler.GetHTTPCompressionProfile(pl.Spec.Profiles.HTTPCompressionProfile); err != nil {
				errChan <- fmt.Sprintf("Referenced HTTP Compression profile %s does not exist on BIGIP for Policy %s: %v", pl.Spec.Profiles.HTTPCompressionProfile, policyName, err)
				cancel()
				return
			}
		}
	}()

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

// IsValidIPOrCIDR checks if the input is a valid IP address or CIDR notation.
func IsValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true // Valid IPv4 or IPv6 address
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true // Valid IPv4 or IPv6 CIDR
	}
	return false
}

// getBigIPHandlerWithSharedToken creates a BIG-IP handler using the shared token manager
func (ctlr *Controller) getBigIPHandlerWithSharedToken() *bigiphandler.BigIPHandler {
	// Extract host from BIG-IP URL
	bigipHost := ctlr.agentParams.PrimaryParams.BIGIPURL
	if strings.HasPrefix(bigipHost, "https://") {
		bigipHost = strings.TrimPrefix(bigipHost, "https://")
	} else if strings.HasPrefix(bigipHost, "http://") {
		bigipHost = strings.TrimPrefix(bigipHost, "http://")
	}

	// Remove port and path if present to get clean hostname
	if idx := strings.Index(bigipHost, ":"); idx != -1 {
		bigipHost = bigipHost[:idx]
	}
	if idx := strings.Index(bigipHost, "/"); idx != -1 {
		bigipHost = bigipHost[:idx]
	}

	// Get or create token manager using shared token manager
	sharedTM := tokenmanager.GetSharedTokenManager()
	tm := sharedTM.GetOrCreateTokenManager(
		bigipHost,
		ctlr.agentParams.PrimaryParams.BIGIPUsername,
		ctlr.agentParams.PrimaryParams.BIGIPPassword,
		nil, // Use default HTTP client from shared token manager
	)

	// Create BIG-IP session using shared token manager
	bigipSession := bigiphandler.CreateSession(
		ctlr.agentParams.PrimaryParams.BIGIPURL,
		tm.GetToken(),
		ctlr.agentParams.UserAgent,
		ctlr.agentParams.PrimaryParams.TrustedCerts,
		ctlr.agentParams.PrimaryParams.SSLInsecure,
		false,
	)

	return &bigiphandler.BigIPHandler{Bigip: bigipSession}
}
