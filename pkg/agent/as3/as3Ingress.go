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
	"fmt"

	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
)

func (appMgr *AS3Manager) prepareAS3IngressConfig() AS3Config {
	ingressCfg := appMgr.as3ActiveConfig
	ingressCfg.adc = appMgr.generateAS3IngressDeclaration()
	if ingressCfg.isDefaultAS3PartitionEmpty() {
		// If default partition is empty, do not perform override operation
		ingressCfg.overrideConfigmap.Data = ""
	}
	return ingressCfg
}

func (appMgr *AS3Manager) processIngressProfilesForAS3(sharedApp as3Application) {
	// Processes Ingress Profs to create AS3 Declaration for Ingress annotations
	// Override/Set ServerTLS/ClientTLS in AS3 Service as annotation takes higher priority
	for svcName, cfg := range appMgr.resources.RsMap {
		if svc, ok := sharedApp[as3FormatedString(svcName, cfg.MetaData.ResourceType)].(*as3Service); ok {
			processIngressTLSProfilesForAS3(&cfg.Virtual, svc)
		}
	}
}

func (appMgr *AS3Manager) generateAS3IngressDeclaration() as3ADC {
	// Create Shared as3Application object for ingress resource
	adc := as3ADC{}
	adc.initDefault(DEFAULT_PARTITION)
	sharedApp := adc.getAS3SharedApp(DEFAULT_PARTITION)

	// Process CIS Resources to create AS3 Resources
	appMgr.processResourcesForAS3(sharedApp)

	// Process CustomProfiles
	appMgr.processCustomProfilesForAS3(sharedApp)

	// Process RouteProfiles
	appMgr.processIngressProfilesForAS3(sharedApp)

	// For Ingress process SecretName
	// Process IRules
	appMgr.processIRulesForAS3(sharedApp)

	// Process DataGroup to be consumed by IRule
	appMgr.processDataGroupForAS3(sharedApp)

	return adc
}

func processIngressTLSProfilesForAS3(virtual *Virtual, svc *as3Service) {
	// lets discard BIGIP profile creation when there exists a custom profile.
	for _, profile := range virtual.Profiles {
		if profile.Partition == "Common" {
			switch profile.Context {
			case CustomProfileClient:
				// Incoming traffic (clientssl) from a web client will be handled by ServerTLS in AS3
				svc.ServerTLS = &as3ResourcePointer{
					BigIP: fmt.Sprintf("/%v/%v", profile.Partition, profile.Name),
				}
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

}
