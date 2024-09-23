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
	"errors"
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
	var err string

	crInf, ok := ctlr.getNamespacedCRInformer(vsNamespace)
	if !ok {
		err = fmt.Sprintf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), vsNamespace)
		log.Errorf(err)
		ctlr.updateResourceStatus(VirtualServer, vsResource, "", "", errors.New(err))
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.vsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		err = fmt.Sprintf("VirtualServer %s is invalid", vsName)
		log.Errorf(err)
		ctlr.updateResourceStatus(VirtualServer, vsResource, "", "", errors.New(err))
		return false
	}

	// Check if Partition is set as Common
	if vsResource.Spec.Partition == CommonPartition {
		err = fmt.Sprintf("VirtualServer %s cannot be created in Common partition", vsName)
		log.Errorf(err)
		ctlr.updateResourceStatus(VirtualServer, vsResource, "", "", errors.New(err))
		return false
	}

	// Check if HTTPTraffic is set for insecure VS
	if vsResource.Spec.TLSProfileName == "" && vsResource.Spec.HTTPTraffic != "" {
		err = fmt.Sprintf("HTTPTraffic not allowed to be set for insecure VirtualServer: %v", vsName)
		log.Errorf(err)
		ctlr.updateResourceStatus(VirtualServer, vsResource, "", "", errors.New(err))
		return false
	}

	bindAddr := vsResource.Spec.VirtualServerAddress
	if ctlr.ipamCli == nil {

		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			err = fmt.Sprintf("No IP was specified for the virtual server %s", vsName)
			log.Errorf(err)
			ctlr.updateResourceStatus(VirtualServer, vsResource, "", "", errors.New(err))
			return false
		}
	} else {
		ipamLabel := vsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			err = fmt.Sprintf("No ipamLabel was specified for the virtual server %s", vsName)
			log.Errorf(err)
			ctlr.updateResourceStatus(VirtualServer, vsResource, "", "", errors.New(err))
			return false
		}
	}
	for _, pool := range vsResource.Spec.Pools {
		if pool.MultiClusterServices == nil {
			continue
		}
		for _, mcs := range pool.MultiClusterServices {
			err := ctlr.checkValidExtendedService(mcs, true)
			if err != nil {
				// In case of invalid extendedServiceReference, just log the error and proceed
				log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for VS: %s: %v", mcs, vsName, err)
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
	var err string

	crInf, ok := ctlr.getNamespacedCRInformer(vsNamespace)
	if !ok {
		err = fmt.Sprintf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), vsNamespace)
		log.Errorf(err)
		ctlr.updateResourceStatus(TransportServer, tsResource, "", "", errors.New(err))
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.tsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		err = fmt.Sprintf("TransportServer %s is invalid", vsName)
		log.Errorf(err)
		ctlr.updateResourceStatus(TransportServer, tsResource, "", "", errors.New(err))
		return false
	}

	// Check if Partition is set as Common
	if tsResource.Spec.Partition == CommonPartition {
		err = fmt.Sprintf("TransportServer %s cannot be created in Common partition", vsName)
		log.Errorf(err)
		ctlr.updateResourceStatus(TransportServer, tsResource, "", "", errors.New(err))
		return false
	}

	bindAddr := tsResource.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			err = fmt.Sprintf("No IP was specified for the transport server %s", vsName)
			log.Errorf(err)
			ctlr.updateResourceStatus(TransportServer, tsResource, "", "", errors.New(err))
			return false
		}
	} else {
		ipamLabel := tsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			err = fmt.Sprintf("No ipamLabel was specified for the transport server %s", vsName)
			log.Errorf(err)
			ctlr.updateResourceStatus(TransportServer, tsResource, "", "", errors.New(err))
			return false
		}
	}

	if tsResource.Spec.Type == "" {
		tsResource.Spec.Type = "tcp"
	} else if !(tsResource.Spec.Type == "udp" || tsResource.Spec.Type == "tcp" || tsResource.Spec.Type == "sctp") {
		err = fmt.Sprintf("Invalid type value for transport server %s. Supported values are tcp, udp and sctp only", vsName)
		log.Errorf(err)
		ctlr.updateResourceStatus(TransportServer, tsResource, "", "", errors.New(err))
		return false
	}
	if tsResource.Spec.Pool.MultiClusterServices != nil {
		for _, mcs := range tsResource.Spec.Pool.MultiClusterServices {
			err := ctlr.checkValidExtendedService(mcs, true)
			if err != nil {
				// In case of invalid extendedServiceReference, just log the error and proceed
				log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for TS: %s: %v", mcs, vsName, err)
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
	var err string

	crInf, ok := ctlr.getNamespacedCRInformer(ilNamespace)
	if !ok {
		err = fmt.Sprintf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), ilNamespace)
		log.Errorf(err)
		ctlr.updateResourceStatus(IngressLink, il, "", "", errors.New(err))
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.ilInformer.GetIndexer().GetByKey(ilkey)
	if !virtualFound {
		err = fmt.Sprintf("IngressLink %s is invalid", ilName)
		log.Errorf(err)
		ctlr.updateResourceStatus(IngressLink, il, "", "", errors.New(err))
		return false
	}

	// Check if Partition is set as Common
	if il.Spec.Partition == CommonPartition {
		err = fmt.Sprintf("IngressLink %s cannot be created in Common partition", ilName)
		log.Errorf(err)
		ctlr.updateResourceStatus(IngressLink, il, "", "", errors.New(err))
		return false
	}

	bindAddr := il.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		if bindAddr == "" {
			err = fmt.Sprintf("No IP was specified for ingresslink %s", ilName)
			log.Errorf(err)
			ctlr.updateResourceStatus(IngressLink, il, "", "", errors.New(err))
			return false
		}
	} else {
		ipamLabel := il.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			err = fmt.Sprintf("No ipamLabel was specified for the il server %s", ilName)
			log.Errorf(err)
			ctlr.updateResourceStatus(IngressLink, il, "", "", errors.New(err))
			return false
		}
	}
	return true
}

// checkValidExtendedService checks if extended service is valid or not
func (ctlr *Controller) checkValidExtendedService(mcs cisapiv1.MultiClusterServiceReference, isSpec bool) error {
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
		if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[mcs.ClusterName]; !ok && mcs.ClusterName != ctlr.multiClusterConfigs.LocalClusterName {
			return fmt.Errorf("cluster config for the cluster %s is not provided in extended configmap", mcs.ClusterName)
		}
	}
	return nil
}
