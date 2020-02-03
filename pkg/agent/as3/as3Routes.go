/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
)

func (appMgr *AS3Manager) prepareAS3RouteConfig() AS3Config {
	routeCfg := appMgr.as3ActiveConfig
	routeCfg.adc = appMgr.generateAS3RouteDeclaration()

	// If default partition is empty, do not perform override operation
	if routeCfg.isDefaultAS3PartitionEmpty() {
		routeCfg.overrideConfigmap.Data = ""
	}

	return routeCfg
}

func (appMgr *AS3Manager) generateAS3RouteDeclaration() as3ADC {
	// Create Shared as3Application object for Routes
	adc := as3ADC{}
	adc.initDefault(DEFAULT_PARTITION)
	sharedApp := adc.getAS3SharedApp(DEFAULT_PARTITION)

	// Process CIS Resources to create AS3 Resources
	appMgr.processResourcesForAS3(sharedApp)

	// Process CustomProfiles
	appMgr.processCustomProfilesForAS3(sharedApp)

	// Process RouteProfiles
	appMgr.processRouteProfilesForAS3(sharedApp)

	// For Ingress process SecretName
	// Process IRules
	appMgr.processIRulesForAS3(sharedApp)

	// Process DataGroup to be consumed by IRule
	appMgr.processDataGroupForAS3(sharedApp)

	// Process F5 Resources
	appMgr.processF5ResourcesForAS3(sharedApp)

	return adc
}

func (appMgr *AS3Manager) processRouteProfilesForAS3(sharedApp as3Application) {
	// Processes RouteProfs to create AS3 Declaration for Route annotations
	// Override/Set ServerTLS/ClientTLS in AS3 Service as annotation takes higher priority
	for svcName, cfg := range appMgr.resources.RsMap {
		if svc, ok := sharedApp[as3FormatedString(svcName, cfg.MetaData.ResourceType)].(*as3Service); ok {
			processRouteTLSProfilesForAS3(&cfg.MetaData, svc)
		}
	}
}

func processRouteTLSProfilesForAS3(metadata *MetaData, svc *as3Service) {
	for key, val := range metadata.RouteProfs {
		switch key.Context {
		case CustomProfileClient:
			// Incoming traffic (clientssl) from a web client will be handled by ServerTLS in AS3
			svc.ServerTLS = &as3ResourcePointer{
				BigIP: val,
			}
			updateVirtualToHTTPS(svc)
		case CustomProfileServer:
			// Outgoing traffic (serverssl) to BackEnd Servers from BigIP will be handled by ClientTLS in AS3
			svc.ClientTLS = &as3ResourcePointer{
				BigIP: val,
			}
			updateVirtualToHTTPS(svc)
		}
	}
}

// processF5ResourcesForAS3 does the following steps to implement WAF
// * Add WAF policy action to the corresponding rules
// * Add a default WAF disable Rule to corresponding policy
// * Add WAF disable action to all rules that do not handle WAF
func (appMgr *AS3Manager) processF5ResourcesForAS3(sharedApp as3Application) {

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
	for _, resGroup := range appMgr.intF5Res {
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

