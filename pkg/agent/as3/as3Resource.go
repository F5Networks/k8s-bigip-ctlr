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

package as3

import (
	"fmt"
	"sort"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

func (am *AS3Manager) prepareAS3ResourceConfig() as3ADC {
	adc := am.generateAS3ResourceDeclaration()
	// Support `Controls` class for TEEMs in user-defined AS3 configMap.
	controlObj := make(as3Control)
	controlObj.initDefault(am.userAgent)
	adc["controls"] = controlObj
	return adc
}

func (am *AS3Manager) generateAS3ResourceDeclaration() as3ADC {
	// Create Shared as3Application object for Routes
	adc := as3ADC{}
	var partitions map[string]struct{}
	if len(am.Resources.Partitions) == 0 && !am.disableDefaultPartition {
		partitions = make(map[string]struct{})
		partitions[DEFAULT_PARTITION] = struct{}{}
	} else {
		partitions = am.Resources.Partitions
	}
	for partition := range partitions {
		adc.initTenant(partition, am.defaultRouteDomain)
		sharedApp := adc.getAS3SharedApp(partition)

		// Process CIS Resources to create AS3 Resources
		am.processResourcesForAS3(sharedApp, partition)

		// Process CustomProfiles
		am.processCustomProfilesForAS3(sharedApp, partition)

		// Process RouteProfiles
		am.processProfilesForAS3(sharedApp, partition)

		// For Ingress process SecretName
		// Process IRules
		am.processIRulesForAS3(sharedApp, partition)

		// Process DataGroup to be consumed by IRule
		am.processDataGroupForAS3(sharedApp, partition)

		// Process F5 Resources
		am.processF5ResourcesForAS3(sharedApp)
	}
	return adc
}

func (am *AS3Manager) processProfilesForAS3(sharedApp as3Application, partition string) {
	// Processes RouteProfs to create AS3 Declaration for Route annotations
	// Override/Set ServerTLS/ClientTLS in AS3 Service as annotation takes higher priority
	for svcName, cfg := range am.Resources.RsMap {
		if svcName.Partition == partition {
			if svc, ok := sharedApp[as3FormattedString(svcName.Name, cfg.MetaData.ResourceType)].(*as3Service); ok {
				switch cfg.MetaData.ResourceType {
				case ResourceTypeRoute:
					processRouteTLSProfilesForAS3(&cfg.MetaData, svc)
				case ResourceTypeIngress:
					processIngressTLSProfilesForAS3(&cfg.Virtual, svc)
				default:
					log.Warningf("Unsupported resource type: %v", cfg.MetaData.ResourceType)
				}
			}
		}
	}
}

func processIngressTLSProfilesForAS3(virtual *Virtual, svc *as3Service) {
	// lets discard BIGIP profile creation when there exists a custom profile.
	var serverTLS []as3ResourcePointer
	for _, profile := range virtual.Profiles {
		if profile.Partition == "Common" {
			switch profile.Context {
			case CustomProfileClient:
				// Incoming traffic (clientssl) from a web client will be handled by ServerTLS in AS3
				rsPointer := as3ResourcePointer{
					BigIP: fmt.Sprintf("/%v/%v", profile.Partition, profile.Name),
				}
				serverTLS = append(serverTLS, rsPointer)
				// svc.ServerTLS = serverTLS

				updateVirtualToHTTPS(svc)
			case CustomProfileServer:
				// Outgoing traffic (serverssl) to BackEnd Servers from BigIP will be handled by ClientTLS in AS3
				svc.ClientTLS = &as3ResourcePointer{
					BigIP: fmt.Sprintf("/%v/%v", profile.Partition, profile.Name),
				}
				updateVirtualToHTTPS(svc)
			}
		}
	}
	if len(serverTLS) > 0 {
		sortedServerTLS := getSortedServerTLS(serverTLS)
		svc.ServerTLS = sortedServerTLS
	}
}

func processRouteTLSProfilesForAS3(metadata *MetaData, svc *as3Service) {
	var serverTLS []as3ResourcePointer
	existingProfile := map[string]struct{}{}
	// handle duplicate BIGIP pointers
	for key, val := range metadata.RouteProfs {
		if _, ok := existingProfile[val]; ok {
			continue
		}
		existingProfile[val] = struct{}{}
		switch key.Context {
		case CustomProfileClient:
			// Incoming traffic (clientssl) from a web client will be handled by ServerTLS in AS3
			rsPointer := as3ResourcePointer{BigIP: val}
			serverTLS = append(serverTLS, rsPointer)
			// svc.ServerTLS = serverTLS
			updateVirtualToHTTPS(svc)
		case CustomProfileServer:
			// Outgoing traffic (serverssl) to BackEnd Servers from BigIP will be handled by ClientTLS in AS3
			svc.ClientTLS = &as3ResourcePointer{
				BigIP: val,
			}
			updateVirtualToHTTPS(svc)
		}
	}
	if len(serverTLS) > 0 {
		sortedServerTLS := getSortedServerTLS(serverTLS)
		svc.ServerTLS = sortedServerTLS
	}

}

// Get sorted ServerTLS by value
func getSortedServerTLS(serverTLS []as3ResourcePointer) []as3ResourcePointer {
	if len(serverTLS) == 1 {
		return serverTLS
	}
	var ref []string
	for _, val := range serverTLS {
		ref = append(ref, val.BigIP)
	}
	sort.Strings(ref)
	var sortedServerTLS []as3ResourcePointer
	for _, val := range ref {
		rsPointer := as3ResourcePointer{
			BigIP: val,
		}
		sortedServerTLS = append(sortedServerTLS, rsPointer)
	}
	return sortedServerTLS
}

// processF5ResourcesForAS3 does the following steps to implement WAF
// * Add WAF policy action to the corresponding rules
// * Add a default WAF disable Rule to corresponding policy
// * Add WAF disable action to all rules that do not handle WAF
func (am *AS3Manager) processF5ResourcesForAS3(sharedApp as3Application) {

	// Identify rules that do not handle waf and add waf disable action to that rule
	addWAFDisableAction := func(ep *as3EndpointPolicy) {
		enabled := false
		wafDisableAction := &as3Action{
			Type:    "waf",
			Enabled: &enabled,
		}

		for _, rule := range ep.Rules {
			isWAFRule := false
			for _, action := range rule.Actions {
				if action.Type == "waf" {
					isWAFRule = true
					break
				}
			}
			// BigIP requires a default WAF disable rule doesn't require WAF
			if !isWAFRule {
				rule.Actions = append(rule.Actions, wafDisableAction)
			}
		}
	}

	var isSecureWAF, isInsecureWAF bool
	var secureEP, insecureEP *as3EndpointPolicy

	secureEP, _ = sharedApp["openshift_secure_routes"].(*as3EndpointPolicy)
	insecureEP, _ = sharedApp["openshift_insecure_routes"].(*as3EndpointPolicy)

	// Update Rules with WAF action
	for _, resGroup := range am.IntF5Res {
		for rec, res := range resGroup {
			switch res.Virtual {
			case HTTPS:
				if secureEP != nil {
					isSecureWAF = true
					updatePolicyWithWAF(secureEP, rec, res)
				}
			case HTTPANDS:
				if secureEP != nil {
					isSecureWAF = true
					updatePolicyWithWAF(secureEP, rec, res)
				}
				fallthrough
			case HTTP:
				if insecureEP != nil {
					isInsecureWAF = true
					updatePolicyWithWAF(insecureEP, rec, res)
				}
			}
		}
	}

	enabled := false
	wafDisableAction := &as3Action{
		Type:    "waf",
		Enabled: &enabled,
	}

	wafDropAction := &as3Action{
		Type:  "drop",
		Event: "request",
	}

	wafDisableRule := &as3Rule{
		Name:    "openshift_route_waf_disable",
		Actions: []*as3Action{wafDropAction, wafDisableAction},
	}

	// Add a default WAF disable action to all non-WAF rules
	// BigIP requires a default WAF disable rule doesn't require WAF
	if isSecureWAF && secureEP != nil {
		secureEP.Rules = append(secureEP.Rules, wafDisableRule)
		addWAFDisableAction(secureEP)
	}

	if isInsecureWAF && insecureEP != nil {
		insecureEP.Rules = append(insecureEP.Rules, wafDisableRule)
		addWAFDisableAction(insecureEP)
	}
}
