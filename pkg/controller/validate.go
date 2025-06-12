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
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"strings"
)

func (ctlr *Controller) checkValidVirtualServer(
	vsResource *cisapiv1.VirtualServer,
) bool {

	vsNamespace := vsResource.ObjectMeta.Namespace
	vsName := vsResource.ObjectMeta.Name
	vkey := fmt.Sprintf("%s/%s", vsNamespace, vsName)
	var err string

	crInf, ok := ctlr.getNamespacedCRInformer(vsNamespace, ctlr.multiClusterHandler.LocalClusterName)
	if !ok {
		err = fmt.Sprintf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), vsNamespace)
		log.Errorf(err)
		ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.vsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		err = fmt.Sprintf("VirtualServer %s is invalid", vsName)
		log.Errorf(err)
		ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
		return false
	}

	// Check if Partition is set as Common
	if vsResource.Spec.Partition == CommonPartition {
		err = fmt.Sprintf("VirtualServer %s cannot be created in Common partition", vsName)
		log.Errorf(err)
		ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
		return false
	}

	// Check if HTTPTraffic is set for insecure VS
	if vsResource.Spec.TLSProfileName == "" && vsResource.Spec.HTTPTraffic != "" {
		err = fmt.Sprintf("HTTPTraffic not allowed to be set for insecure VirtualServer: %v", vsName)
		log.Errorf(err)
		ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
		return false
	}

	if vsResource.Spec.Host == "" && len(vsResource.Spec.HostAliases) > 0 {
		err = fmt.Sprintf("Host is not provided but HostAliases is present for VirtualServer: %v", vsName)
		log.Errorf(err)
		ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
		return false
	}

	bindAddr := vsResource.Spec.VirtualServerAddress
	if ctlr.ipamCli == nil {

		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			err = fmt.Sprintf("No IP was specified for the virtual server %s", vsName)
			log.Errorf(err)
			ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
			return false
		}
	} else {
		ipamLabel := vsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			err = fmt.Sprintf("No ipamLabel was specified for the virtual server %s", vsName)
			log.Errorf(err)
			ctlr.updateVSStatus(vsResource, "", StatusError, errors.New(err))
			return false
		}
	}
	for _, pool := range vsResource.Spec.Pools {
		// Check if the required fields are set as per the recommendations
		// Validation for multiCluster setup with default mode
		if ctlr.discoveryMode == DefaultMode {
			if pool.MultiClusterServices == nil {
				err := fmt.Sprintf("[MultiCluster] MultiClusterServices is not provided for VirtualServer %s/%s, pool %s but "+
					"CIS is running with default mode", vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name, pool.Name)
				log.Errorf(err)
				ctlr.updateVSStatus(vsResource, "", "", errors.New(err))
				return false
			}
			if pool.Service != "" || pool.ServicePort != (intstr.IntOrString{}) ||
				pool.Weight != nil || pool.AlternateBackends != nil {
				log.Warningf("[MultiCluster] Ignoring Pool Service/ServicePort/Weight/AlternateBackends provided for "+
					"VirtualServer %s for pool %s as these are not supported in default mode", vsResource.ObjectMeta.Name, pool.Name)
			}
		} else {
			// validation for non multiCluster case
			if pool.MultiClusterServices != nil && ctlr.multiClusterMode == "" {
				err := fmt.Sprintf("MultiClusterServices is set for VirtualServer %s/%s for pool %s but CIS is not running in "+
					"multiCluster mode", vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name, pool.Name)
				log.Errorf(err)
				ctlr.updateVSStatus(vsResource, "", "", errors.New(err))
				return false
			}
			if pool.Service == "" || pool.ServicePort == (intstr.IntOrString{}) {
				err := fmt.Sprintf("Service/ServicePort is not provided in Pool %s for VirtualServer %s/%s",
					pool.Name, vsResource.ObjectMeta.Namespace, vsResource.ObjectMeta.Name)
				log.Errorf(err)
				ctlr.updateVSStatus(vsResource, "", "", errors.New(err))
				return false
			}
		}

		for _, mcs := range pool.MultiClusterServices {
			err := ctlr.checkValidMultiClusterService(mcs, true)
			if err != nil {
				// In case of invalid multiClusterServices, just log the error and proceed
				log.Errorf("[MultiCluster] invalid multiClusterServices: %v for VS: %s: %v", mcs, vsName, err)
				continue
			}
		}
	}

	return true
}

func (ctlr *Controller) checkValidTransportServer(
	tsResource *cisapiv1.TransportServer,
) bool {

	// Check if the required fields are set as per the recommendations
	// Validation for multiCluster setup with default mode
	if ctlr.discoveryMode == DefaultMode {
		if tsResource.Spec.Pool.MultiClusterServices == nil {
			err := fmt.Sprintf("[MultiCluster] MultiClusterServices is not provided for TransportServer %s/%s when "+
				"CIS is running in default mode", tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
			log.Warningf(err)
			ctlr.updateTSStatus(tsResource, "", "", errors.New(err))
			return false
		}
		if tsResource.Spec.Pool.Service != "" || tsResource.Spec.Pool.ServicePort != (intstr.IntOrString{}) ||
			tsResource.Spec.Pool.Weight != nil || tsResource.Spec.Pool.AlternateBackends != nil {
			log.Warningf("[MultiCluster] Ignoring Pool Service/ServicePort/Weight/AlternateBackends provided for "+
				"TransportServer %s as these are not supported in default mode", tsResource.ObjectMeta.Name)
		}
	} else {
		// validation for non multiCluster case
		if tsResource.Spec.Pool.MultiClusterServices != nil && ctlr.multiClusterMode == "" {
			err := fmt.Sprintf("MultiClusterServices is set for TransportServer %s/%s but CIS is not running in "+
				"multiCluster mode", tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
			log.Errorf(err)
			ctlr.updateTSStatus(tsResource, "", "", errors.New(err))
			return false
		}
		if tsResource.Spec.Pool.Service == "" || tsResource.Spec.Pool.ServicePort == (intstr.IntOrString{}) {
			err := fmt.Sprintf("Service/ServicePort is not provided in Pool for TransportServer %s/%s",
				tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
			log.Errorf(err)
			ctlr.updateTSStatus(tsResource, "", "", errors.New(err))
			return false
		}
	}
	vsNamespace := tsResource.ObjectMeta.Namespace
	vsName := tsResource.ObjectMeta.Name
	vkey := fmt.Sprintf("%s/%s", vsNamespace, vsName)
	var err string

	crInf, ok := ctlr.getNamespacedCRInformer(vsNamespace, ctlr.multiClusterHandler.LocalClusterName)
	if !ok {
		err = fmt.Sprintf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), vsNamespace)
		log.Errorf(err)
		ctlr.updateTSStatus(tsResource, "", StatusError, errors.New(err))
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.tsInformer.GetIndexer().GetByKey(vkey)
	if !virtualFound {
		err = fmt.Sprintf("TransportServer %s is invalid", vsName)
		log.Errorf(err)
		ctlr.updateTSStatus(tsResource, "", StatusError, errors.New(err))
		return false
	}

	// Check if Partition is set as Common
	if tsResource.Spec.Partition == CommonPartition {
		err = fmt.Sprintf("TransportServer %s cannot be created in Common partition", vsName)
		log.Errorf(err)
		ctlr.updateTSStatus(tsResource, "", StatusError, errors.New(err))
		return false
	}

	bindAddr := tsResource.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if bindAddr == "" {
			err = fmt.Sprintf("No IP was specified for the transport server %s", vsName)
			log.Errorf(err)
			ctlr.updateTSStatus(tsResource, "", StatusError, errors.New(err))
			return false
		}
	} else {
		ipamLabel := tsResource.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			err = fmt.Sprintf("No ipamLabel was specified for the transport server %s", vsName)
			log.Errorf(err)
			ctlr.updateTSStatus(tsResource, "", StatusError, errors.New(err))
			return false
		}
	}
	key := ctlr.ipamClusterLabel + tsResource.ObjectMeta.Namespace + "/" + tsResource.ObjectMeta.Name + "_ts"
	if tsResource.Spec.HostGroup != "" {
		key = ctlr.ipamClusterLabel + tsResource.Spec.HostGroup + "_hg"
	}
	// check that app with duplicate ip and port is not created
	if appConfig := getL4AppConfig(tsResource.Spec.VirtualServerAddress, key, tsResource.Spec.VirtualServerPort, tsResource.Spec.BigIPRouteDomain); appConfig != (l4AppConfig{}) {
		if val, ok := ctlr.resources.processedL4Apps[appConfig]; ok {
			if val.timestamp.Before(&tsResource.CreationTimestamp) {
				err = fmt.Sprintf("l4 app already exists with given ip-address/ipam-label and port %v, while processing transport server %s/%s", appConfig, tsResource.ObjectMeta.Namespace, tsResource.ObjectMeta.Name)
				log.Errorf(err)
				ctlr.updateTSStatus(tsResource, "", StatusError, errors.New(err))
			}
		}
	}

	if tsResource.Spec.Pool.MultiClusterServices != nil {
		for _, mcs := range tsResource.Spec.Pool.MultiClusterServices {
			err := ctlr.checkValidMultiClusterService(mcs, true)
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

	crInf, ok := ctlr.getNamespacedCRInformer(ilNamespace, ctlr.multiClusterHandler.LocalClusterName)
	if !ok {
		err = fmt.Sprintf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), ilNamespace)
		log.Errorf(err)
		ctlr.updateILStatus(il, "", StatusError, errors.New(err))
		return false
	}
	// Check if the virtual exists and valid for us.
	_, virtualFound, _ := crInf.ilInformer.GetIndexer().GetByKey(ilkey)
	if !virtualFound {
		err = fmt.Sprintf("IngressLink %s is invalid", ilName)
		log.Errorf(err)
		ctlr.updateILStatus(il, "", StatusError, errors.New(err))
		return false
	}

	// Check if Partition is set as Common
	if il.Spec.Partition == CommonPartition {
		err = fmt.Sprintf("IngressLink %s cannot be created in Common partition", ilName)
		log.Errorf(err)
		ctlr.updateILStatus(il, "", StatusError, errors.New(err))
		return false
	}

	// Check if Selector is empty for non-multicluster mode
	if il.Spec.Selector == nil && ctlr.multiClusterMode == "" {
		err = fmt.Sprintf("Selector is not provided for IngressLink %s", ilName)
		log.Errorf(err)
		ctlr.updateILStatus(il, "", StatusError, errors.New(err))
		return false
	}
	bindAddr := il.Spec.VirtualServerAddress

	if ctlr.ipamCli == nil {
		if bindAddr == "" {
			err = fmt.Sprintf("No IP was specified for ingresslink %s", ilName)
			log.Errorf(err)
			ctlr.updateILStatus(il, "", StatusError, errors.New(err))
			return false
		}
	} else {
		ipamLabel := il.Spec.IPAMLabel
		if ipamLabel == "" && bindAddr == "" {
			err = fmt.Sprintf("No ipamLabel was specified for the il server %s", ilName)
			log.Errorf(err)
			ctlr.updateILStatus(il, "", StatusError, errors.New(err))
			return false
		}
	}
	return true
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
