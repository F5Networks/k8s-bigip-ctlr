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
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (ctlr *Controller) checkValidVirtualServer(
	vsResource *cisapiv1.VirtualServer,
) bool {

	vsNamespace := vsResource.ObjectMeta.Namespace
	vsName := vsResource.ObjectMeta.Name
	vkey := fmt.Sprintf("%s/%s", vsNamespace, vsName)

	crInf, ok := ctlr.getNamespacedCRInformer(vsNamespace)
	if !ok {
		log.Errorf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), vsNamespace)
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.vsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		log.Infof("VirtualServer %s is invalid", vsName)
		return false
	}
	// Check if HTTPTraffic is set for insecure VS
	if vsResource.Spec.TLSProfileName == "" && vsResource.Spec.HTTPTraffic != "" {
		log.Errorf("HTTPTraffic not allowed to be set for insecure VirtualServer: %v", vsName)
		return false
	}

	bindAddr := vsResource.Spec.VirtualServerAddress
	if ctlr.ipamCli == nil {

		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			log.Infof("No IP was specified for the virtual server %s", vsName)
			return false
		}
	} else {
		ipamLabel := vsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			log.Infof("No ipamLabel was specified for the virtual server %s", vsName)
			return false
		}
	}
	for _, pool := range vsResource.Spec.Pools {
		if pool.MultiClusterServices == nil {
			continue
		}
		for _, mcs := range pool.MultiClusterServices {
			if !ctlr.checkValidExtendedService(mcs) {
				// In case of invalid extendedServiceReference, just log the error and proceed
				log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for VS: %s. Some of the mandatory "+
					"parameters (clusterName/namespace/serviceName/port) are missing or cluster "+
					"config for the cluster in which it's running is not provided in extended configmap.", mcs, vsName)
				continue
			}
		}
	}

	return true
}

func (ctlr *Controller) checkValidTransportServer(
	tsResource *cisapiv1.TransportServer,
) bool {

	vsNamespace := tsResource.ObjectMeta.Namespace
	vsName := tsResource.ObjectMeta.Name
	vkey := fmt.Sprintf("%s/%s", vsNamespace, vsName)

	crInf, ok := ctlr.getNamespacedCRInformer(vsNamespace)
	if !ok {
		log.Errorf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), vsNamespace)
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.tsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		log.Infof("TransportServer %s is invalid", vsName)
		return false
	}

	bindAddr := tsResource.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			log.Infof("No IP was specified for the transport server %s", vsName)
			return false
		}
	} else {
		ipamLabel := tsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			log.Infof("No ipamLabel was specified for the transport server %s", vsName)
			return false
		}
	}

	if tsResource.Spec.Type == "" {
		tsResource.Spec.Type = "tcp"
	} else if !(tsResource.Spec.Type == "udp" || tsResource.Spec.Type == "tcp" || tsResource.Spec.Type == "sctp") {
		log.Errorf("Invalid type value for transport server %s. Supported values are tcp, udp and sctp only", vsName)
		return false
	}
	if tsResource.Spec.Pool.MultiClusterServices != nil {
		for _, mcs := range tsResource.Spec.Pool.MultiClusterServices {
			if !ctlr.checkValidExtendedService(mcs) {
				// In case of invalid extendedServiceReference, just log the error and proceed
				log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for TS: %s. Some of the mandatory "+
					"parameters (clusterName/namespace/serviceName/port) are missing or cluster "+
					"config for the cluster in which it's running is not provided in extended configmap.", mcs, vsName)
				continue
			}
		}
	}
	return true
}

func (ctlr *Controller) checkValidIngressLink(
	il *cisapiv1.IngressLink,
) bool {

	ilNamespace := il.ObjectMeta.Namespace
	ilName := il.ObjectMeta.Name
	ilkey := fmt.Sprintf("%s/%s", ilNamespace, ilName)

	crInf, ok := ctlr.getNamespacedCRInformer(ilNamespace)
	if !ok {
		log.Errorf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), ilNamespace)
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.ilInformer.GetIndexer().GetByKey(ilkey)
	if !virtualFound {
		log.Infof("IngressLink %s is invalid", ilName)
		return false
	}

	bindAddr := il.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		if bindAddr == "" {
			log.Infof("No IP was specified for ingresslink %s", ilName)
			return false
		}
	} else {
		ipamLabel := il.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			log.Infof("No ipamLabel was specified for the il server %s", ilName)
			return false
		}
	}
	return true
}

// checkValidExtendedService checks if extended service is valid or not
func (ctlr *Controller) checkValidExtendedService(mcs cisapiv1.MultiClusterServiceReference) bool {
	// Check if cis running in multiCluster mode
	if ctlr.multiClusterMode == "" {
		return false
	}
	// Check if all required parameters are specified
	if mcs.SvcName == "" || mcs.Namespace == "" || mcs.ClusterName == "" || mcs.ServicePort == (intstr.IntOrString{}) {
		return false
	}
	if mcs.ClusterName != "" {
		// Check if cluster config is provided for the cluster where the service is running
		if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[mcs.ClusterName]; !ok {
			return false
		}
	}
	return true
}
