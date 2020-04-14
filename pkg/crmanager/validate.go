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

	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crMgr.crInformers[vsNamespace].
		vsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		// VirtualServer was deleted. Lets proceed with delete operation.
		// TODO ==> Delete operation for VirtualServer.
		//          Typically, we will make a call to some DeleteVirtualServer method.
		log.Infof("VirtualServer %s Not found, Possibly Deleted", vsName)
		return false
	}

	bindAddr := vsResource.Spec.VirtualServerAddress

	// This ensures that pool-only mode only logs the message below the first
	// time we see a config.
	if bindAddr == "" {
		log.Infof("No IP was specified for the virtual server %s", vsName)
		return false
	}

	return true
}
