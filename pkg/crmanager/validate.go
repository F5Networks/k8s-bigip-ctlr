/*-
* Copyright (c) 2016-2020, F5 Networks, Inc.
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

package crmanager

import (
	"fmt"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

func (crMgr *CRManager) checkValidVirtualServer(
	vsResource *cisapiv1.VirtualServer,
) bool {

	vsNamespace := vsResource.ObjectMeta.Namespace
	vsName := vsResource.ObjectMeta.Name
	vkey := fmt.Sprintf("%s/%s", vsNamespace, vsName)

	crInf, ok := crMgr.getNamespacedInformer(vsNamespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", vsNamespace)
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.vsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		log.Infof("VirtualServer %s is invalid", vsName)
		return false
	}

	if crMgr.ipamCli == nil {
		bindAddr := vsResource.Spec.VirtualServerAddress

		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			log.Infof("No IP was specified for the virtual server %s", vsName)
			return false
		}
	} else {
		cidr := vsResource.Spec.Cidr
		if cidr == "" {
			log.Infof("No CIDR was specified for the virtual server %s", vsName)
			return false
		}
	}

	return true
}

func (crMgr *CRManager) checkValidTransportServer(
	tsResource *cisapiv1.TransportServer,
) bool {

	vsNamespace := tsResource.ObjectMeta.Namespace
	vsName := tsResource.ObjectMeta.Name
	vkey := fmt.Sprintf("%s/%s", vsNamespace, vsName)

	crInf, ok := crMgr.getNamespacedInformer(vsNamespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", vsNamespace)
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.tsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		log.Infof("TransportServer %s is invalid", vsName)
		return false
	}

	bindAddr := tsResource.Spec.VirtualServerAddress

	// This ensures that pool-only mode only logs the message below the first
	// time we see a config.
	if bindAddr == "" {
		log.Infof("No IP was specified for the transport server %s", vsName)
		return false
	}

	return true
}
