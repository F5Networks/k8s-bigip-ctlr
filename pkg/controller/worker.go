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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"gopkg.in/yaml.v2"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/apimachinery/pkg/util/intstr"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

const nginxMonitorPort int32 = 8081

const (
	NotEnabled = iota
	InvalidInput
	NotRequested
	Requested
	Allocated
)

// nextGenResourceWorker starts the Custom Resource Worker.
func (ctlr *Controller) nextGenResourceWorker() {
	log.Debugf("Starting Custom Resource Worker")
	ctlr.setInitialResourceCount()
	ctlr.migrateIPAM()
	// process the extended configmap if present
	if ctlr.globalExtendedCMKey != "" {
		ctlr.processGlobalExtendedConfigMap()
	}

	// when CIS is running in the secondary mode then enable health probe on the primary cluster
	if ctlr.multiClusterMode == SecondaryCIS {
		ctlr.firstPollPrimaryClusterHealthStatus()
		go ctlr.probePrimaryClusterHealthStatus()
	}

	// process static routes after extended configMap is processed, so as to support external cluster static routes during cis init
	if ctlr.StaticRoutingMode {
		clusterNodes := ctlr.getNodesFromAllClusters()
		ctlr.processStaticRouteUpdate(clusterNodes)
	}
	for ctlr.processResources() {
	}
}

//func (ctlr *Controller) setInitialServiceCount() {
//	var svcCount int
//	for _, ns := range ctlr.getWatchingNamespaces() {
//		comInf, found := ctlr.getNamespacedCommonInformer(ns)
//		if !found {
//			continue
//		}
//		services, err := comInf.svcInformer.GetIndexer().ByIndex("namespace", ns)
//		if err != nil {
//			continue
//		}
//		for _, obj := range services {
//			svc := obj.(*v1.Service)
//			if _, ok := K8SCoreServices[svc.Name]; ok {
//				continue
//			}
//			if ctlr.mode == OpenShiftMode {
//				if _, ok := OSCPCoreServices[svc.Name]; ok {
//					continue
//				}
//			}
//			if svc.Spec.Type != v1.ServiceTypeExternalName {
//				svcCount++
//			}
//		}
//	}
//	ctlr.initialResourceCount = svcCount
//}

func (ctlr *Controller) setInitialResourceCount() {
	var rscCount int
	for _, ns := range ctlr.getWatchingNamespaces() {
		switch ctlr.mode {
		case OpenShiftMode:
			nrInf, found := ctlr.getNamespacedNativeInformer(ns)
			if !found {
				continue
			}
			routes, err := nrInf.routeInformer.GetIndexer().ByIndex("namespace", ns)
			if err != nil {
				continue
			}
			rscCount += len(routes)
		default:
			crInf, found := ctlr.getNamespacedCRInformer(ns)
			if !found {
				continue
			}
			vs, err := crInf.vsInformer.GetIndexer().ByIndex("namespace", ns)
			if err != nil {
				continue
			}
			rscCount += len(vs)
			ts, err := crInf.tsInformer.GetIndexer().ByIndex("namespace", ns)
			if err != nil {
				continue
			}
			rscCount += len(ts)
			il, err := crInf.ilInformer.GetIndexer().ByIndex("namespace", ns)
			if err != nil {
				continue
			}
			rscCount += len(il)
			if comInf, ok := ctlr.comInformers[ns]; ok {
				edns, err := comInf.ednsInformer.GetIndexer().ByIndex("namespace", ns)
				if err != nil {
					continue
				}
				rscCount += len(edns)
			}
		}
		comInf, found := ctlr.getNamespacedCommonInformer(ns)
		if !found {
			continue
		}
		services, err := comInf.svcInformer.GetIndexer().ByIndex("namespace", ns)
		if err != nil {
			continue
		}
		for _, obj := range services {
			svc := obj.(*v1.Service)
			if _, ok := K8SCoreServices[svc.Name]; ok {
				continue
			}
			if ctlr.mode == OpenShiftMode {
				if _, ok := OSCPCoreServices[svc.Name]; ok {
					continue
				}
			}
			if _, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
				rscCount++
			}
		}
	}

	ctlr.initialResourceCount = rscCount
}

// function to determine if CIS should process the service type LoadBalancer
func (ctlr *Controller) shouldProcessServiceTypeLB(svc *v1.Service) (error, bool) {
	var err error
	if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
		return err, false
	}
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != ctlr.loadBalancerClass {
		err = fmt.Errorf("Skipping loadBalancer service '%v/%v' as it's not using the loadBalancerClass '%v'", svc.Namespace, svc.Name, ctlr.loadBalancerClass)
		return err, false
	}
	// check if manage load balancer class only is enabled
	if svc.Spec.LoadBalancerClass == nil && ctlr.manageLoadBalancerClassOnly {
		err = fmt.Errorf("Skipping loadBalancer service '%v/%v' as CIS is configured to monitor the loadBalancerClass '%v' only", svc.Namespace, svc.Name, ctlr.loadBalancerClass)
		return err, false
	}
	return err, true
}

// processResources gets resources from the resourceQueue and processes the resource
// depending  on its kind.
func (ctlr *Controller) processResources() bool {

	key, quit := ctlr.resourceQueue.Get()
	if quit {
		// The controller is shutting down.
		log.Debugf("Resource Queue is empty, Going to StandBy Mode")
		return false
	}
	var isRetryableError bool

	defer ctlr.resourceQueue.Done(key)
	// If CIS resources like CRDS, routes or servicetype LB are not present
	// on startup, check initalresourcecount and update initState
	if ctlr.initialResourceCount <= 0 {
		ctlr.initState = false
	}
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)
	// During Init time, just process all the resources
	if ctlr.initState && rKey.kind != Namespace {
		if rKey.kind == VirtualServer || rKey.kind == TransportServer || rKey.kind == Service ||
			rKey.kind == IngressLink || rKey.kind == Route || rKey.kind == ExternalDNS {
			if rKey.kind == Service {
				if svc, ok := rKey.rsc.(*v1.Service); ok {
					if _, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
						ctlr.initialResourceCount--
					} else {
						// return as we don't process other services at start up
						return true
					}
				}
			} else {
				ctlr.initialResourceCount--
			}
			if ctlr.initialResourceCount <= 0 {
				ctlr.initState = false
			}
		} else {
			return true
		}
	}

	rscDelete := false
	if rKey.event == Delete {
		rscDelete = true
	}

	// Check the type of resource and process accordingly.
	switch rKey.kind {
	case Route:
		if ctlr.mode != OpenShiftMode {
			break
		}
		route := rKey.rsc.(*routeapi.Route)
		// processRoutes knows when to delete a VS (in the event of global config update and route delete)
		// so should not trigger delete from here
		resourceKey := resourceRef{
			kind:      Route,
			namespace: route.Namespace,
			name:      route.Name,
		}
		if rKey.event == Create {
			if _, ok := ctlr.resources.processedNativeResources[resourceKey]; ok {
				break
			}
		}

		if rscDelete {
			delete(ctlr.resources.processedNativeResources, resourceKey)
			// Delete the route entry from hostPath Map
			ctlr.deleteHostPathMapEntry(route)
		}
		if rKey.event != Create {
			// update the poolMem cache, clusterSvcResource & resource-svc maps
			ctlr.deleteResourceExternalClusterSvcRouteReference(resourceKey)
		}
		if routeGroup, ok := ctlr.resources.invertedNamespaceLabelMap[route.Namespace]; ok {
			err := ctlr.processRoutes(routeGroup, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		}
		if rKey.event != Create && ctlr.multiClusterMode != "" {
			ctlr.deleteUnrefereedMultiClusterInformers()
		}

	case ConfigMap:
		cm := rKey.rsc.(*v1.ConfigMap)
		err, ok := ctlr.processConfigMap(cm, rscDelete)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
			break
		}

		if !ok {
			isRetryableError = true
		}
	case VirtualServer:
		if ctlr.mode == OpenShiftMode || ctlr.mode == KubernetesMode {
			break
		}
		virtual := rKey.rsc.(*cisapiv1.VirtualServer)
		rscRefKey := resourceRef{
			kind:      VirtualServer,
			name:      virtual.Name,
			namespace: virtual.Namespace,
		}
		if _, ok := ctlr.resources.processedNativeResources[rscRefKey]; ok {
			if rKey.event == Create {
				break
			}
			if rKey.event == Delete {
				delete(ctlr.resources.processedNativeResources, rscRefKey)
			}
		}

		if rKey.event != Create {
			// update the poolMem cache, clusterSvcResource & resource-svc maps
			ctlr.deleteResourceExternalClusterSvcRouteReference(rscRefKey)
		}

		err := ctlr.processVirtualServers(virtual, rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
			isRetryableError = true
		}
		if rKey.event != Create && ctlr.multiClusterMode != "" {
			ctlr.deleteUnrefereedMultiClusterInformers()
		}
	case TLSProfile:
		if ctlr.mode == OpenShiftMode || ctlr.mode == KubernetesMode {
			break
		}
		tlsProfile := rKey.rsc.(*cisapiv1.TLSProfile)
		virtuals := ctlr.getVirtualsForTLSProfile(tlsProfile)
		// No Virtuals are effected with the change in TLSProfile.
		if nil == virtuals {
			break
		}
		for _, virtual := range virtuals {
			err := ctlr.processVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		}
	case K8sSecret:
		secret := rKey.rsc.(*v1.Secret)
		mcc := ctlr.getClusterForSecret(secret)
		// TODO: Process all the resources again that refer to any resource running in the affected cluster?
		if mcc != (ExternalClusterConfig{}) {
			err := ctlr.updateClusterConfigStore(secret, mcc, rscDelete)
			if err != nil {
				log.Warningf(err.Error())
			}
			break
		}
		switch ctlr.mode {
		case OpenShiftMode:
			routeGroup := ctlr.getRouteGroupForSecret(secret)
			if routeGroup != "" {
				_ = ctlr.processRoutes(routeGroup, false)
			}
		default:
			tlsProfiles := ctlr.getTLSProfilesForSecret(secret)
			for _, tlsProfile := range tlsProfiles {
				virtuals := ctlr.getVirtualsForTLSProfile(tlsProfile)
				// No Virtuals are effected with the change in TLSProfile.
				if nil == virtuals {
					break
				}
				for _, virtual := range virtuals {
					err := ctlr.processVirtualServers(virtual, false)
					if err != nil {
						// TODO
						utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
						isRetryableError = true
					}
				}
			}
		}

	case TransportServer:
		if ctlr.mode == OpenShiftMode || ctlr.mode == KubernetesMode {
			break
		}
		virtual := rKey.rsc.(*cisapiv1.TransportServer)
		rscRefKey := resourceRef{
			kind:      TransportServer,
			name:      virtual.Name,
			namespace: virtual.Namespace,
		}
		if _, ok := ctlr.resources.processedNativeResources[rscRefKey]; ok {
			// Skip processing for create event if already processed
			if rKey.event == Create {
				break
			}
			// Remove resource key from processedNativeResources on delete event
			if rKey.event == Delete {
				delete(ctlr.resources.processedNativeResources, rscRefKey)
			}
		}
		if rKey.event != Create {
			// update the poolMem cache, clusterSvcResource & resource-svc maps
			ctlr.deleteResourceExternalClusterSvcRouteReference(rscRefKey)
		}
		err := ctlr.processTransportServers(virtual, rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
			isRetryableError = true
		}
		if rKey.event != Create && ctlr.multiClusterMode != "" {
			ctlr.deleteUnrefereedMultiClusterInformers()
		}
	case IngressLink:
		if ctlr.mode == OpenShiftMode || ctlr.mode == KubernetesMode {
			break
		}
		ingLink := rKey.rsc.(*cisapiv1.IngressLink)
		log.Infof("Worker got IngressLink: %v\n", ingLink)
		log.Infof("IngressLink Selector: %v\n", ingLink.Spec.Selector.String())
		if rKey.event != Create {
			rsRef := resourceRef{
				name:      ingLink.Name,
				namespace: ingLink.Namespace,
				kind:      IngressLink,
			}
			// clean the CIS cache
			ctlr.deleteResourceExternalClusterSvcRouteReference(rsRef)
		}
		err := ctlr.processIngressLink(ingLink, rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
			isRetryableError = true
		}
	case ExternalDNS:
		if ctlr.mode == KubernetesMode {
			break
		}
		edns := rKey.rsc.(*cisapiv1.ExternalDNS)
		ctlr.processExternalDNS(edns, rscDelete)
	case IPAM:
		ipam := rKey.rsc.(*ficV1.IPAM)
		_ = ctlr.processIPAM(ipam)

	case CustomPolicy:
		cp := rKey.rsc.(*cisapiv1.Policy)
		switch ctlr.mode {
		case OpenShiftMode:
			routeGroups := ctlr.getRouteGroupForCustomPolicy(cp.Namespace + "/" + cp.Name)
			for _, routeGroup := range routeGroups {
				_ = ctlr.processRoutes(routeGroup, false)
			}
		default:
			virtuals := ctlr.getVirtualsForCustomPolicy(cp)
			//Sync Custompolicy for Virtual Servers
			for _, virtual := range virtuals {
				err := ctlr.processVirtualServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
					isRetryableError = true
				}
			}
			//Sync Custompolicy for Transport Servers
			tsVirtuals := ctlr.getTransportServersForCustomPolicy(cp)
			for _, virtual := range tsVirtuals {
				err := ctlr.processTransportServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
					isRetryableError = true
				}
			}
			//Sync Custompolicy for Services of type LB
			lbServices := ctlr.getLBServicesForCustomPolicy(cp)
			for _, lbService := range lbServices {
				err := ctlr.processLBServices(lbService, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
					isRetryableError = true
				}
			}
		}
	case Service:
		svc := rKey.rsc.(*v1.Service)
		svcKey := MultiClusterServiceKey{
			serviceName: svc.Name,
			namespace:   svc.Namespace,
			clusterName: rKey.clusterName,
		}

		if err, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
			if rKey.event != Create {
				rsRef := resourceRef{
					name:      svc.Name,
					namespace: svc.Namespace,
					kind:      Service,
				}
				// clean the CIS cache
				ctlr.deleteResourceExternalClusterSvcRouteReference(rsRef)
			}
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		} else {
			log.Debugf("%v", err)
		}

		// Don't process the service as it's not used by any resource
		if _, ok := ctlr.resources.poolMemCache[svcKey]; !ok {
			log.Debugf("Skipping service '%v' as it's not used by any CIS monitored resource", svcKey)
			break
		}

		_ = ctlr.processService(svc, rKey.clusterName)

		// Update the poolMembers for affected resources
		ctlr.updatePoolMembersForService(svcKey, rKey.svcPortUpdated)

	case Endpoints:
		ep := rKey.rsc.(*v1.Endpoints)
		svc := ctlr.getServiceForEndpoints(ep, rKey.clusterName)
		// No Services are effected with the change in service.
		if nil == svc {
			break
		}
		svcKey := MultiClusterServiceKey{
			serviceName: svc.Name,
			namespace:   svc.Namespace,
			clusterName: rKey.clusterName,
		}
		// Don't process the service as it's not used by any resource
		if _, ok := ctlr.resources.poolMemCache[svcKey]; !ok {
			log.Debugf("Skipping endpoint '%v/%v' as it's not used by any CIS monitored resource", ep.Namespace, ep.Name)
			break
		}
		_ = ctlr.processService(svc, rKey.clusterName)

		if err, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		} else {
			log.Debugf("%v", err)
		}
		// Just update the endpoints instead of processing them entirely
		ctlr.updatePoolMembersForService(svcKey, false)

	case Pod:
		pod := rKey.rsc.(*v1.Pod)
		_ = ctlr.processPod(pod, rscDelete)
		svc := ctlr.GetServicesForPod(pod, rKey.clusterName)
		if nil == svc {
			break
		}
		svcKey := MultiClusterServiceKey{
			serviceName: svc.Name,
			namespace:   svc.Namespace,
			clusterName: rKey.clusterName,
		}
		// Don't process the service as it's not used by any resource
		if _, ok := ctlr.resources.poolMemCache[svcKey]; !ok {
			log.Debugf("Skipping pod '%v/%v' as it's not used by any CIS monitored resource", pod.Namespace, pod.Name)
			break
		}
		_ = ctlr.processService(svc, rKey.clusterName)
		if _, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
				isRetryableError = true
			}
			break
		}
		// Update the poolMembers for affected resources
		ctlr.updatePoolMembersForService(svcKey, false)

		if ctlr.mode == OpenShiftMode && rscDelete == false && ctlr.resources.baseRouteConfig.AutoMonitor != None {
			ctlr.UpdatePoolHealthMonitors(svcKey)
		}

	case Namespace:
		ns := rKey.rsc.(*v1.Namespace)
		nsName := ns.ObjectMeta.Name
		switch ctlr.mode {

		case OpenShiftMode:
			var triggerDelete bool
			if rscDelete {
				// TODO: Delete all the resource configs from the store
				if nrInf, ok := ctlr.nrInformers[nsName]; ok {
					nrInf.stop()
					delete(ctlr.nrInformers, nsName)
				}
				if comInf, ok := ctlr.comInformers[nsName]; ok {
					comInf.stop()
					delete(ctlr.comInformers, nsName)
				}
				ctlr.namespacesMutex.Lock()
				delete(ctlr.namespaces, nsName)
				ctlr.namespacesMutex.Unlock()
				log.Infof("Removed Namespace: '%v' from CIS scope", nsName)
				triggerDelete = true
			} else {
				ctlr.namespacesMutex.Lock()
				ctlr.namespaces[nsName] = true
				ctlr.namespacesMutex.Unlock()
				_ = ctlr.addNamespacedInformers(nsName, true)
				log.Infof("Added Namespace: '%v' to CIS scope", nsName)
			}
			if ctlr.namespaceLabelMode {
				ctlr.processGlobalExtendedConfigMap()
			} else {
				if routeGroup, ok := ctlr.resources.invertedNamespaceLabelMap[nsName]; ok {
					_ = ctlr.processRoutes(routeGroup, triggerDelete)
				}
			}

		default:
			if rscDelete {
				for _, vrt := range ctlr.getAllVirtualServers(nsName) {
					err := ctlr.processVirtualServers(vrt, true)
					if err != nil {
						// TODO
						utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
						isRetryableError = true
					}
				}

				for _, ts := range ctlr.getAllTransportServers(nsName) {
					err := ctlr.processTransportServers(ts, true)
					if err != nil {
						// TODO
						utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
						isRetryableError = true
					}
				}

				ctlr.crInformers[nsName].stop()
				delete(ctlr.crInformers, nsName)
				ctlr.namespacesMutex.Lock()
				delete(ctlr.namespaces, nsName)
				ctlr.namespacesMutex.Unlock()
				log.Infof("Removed Namespace: '%v' from CIS scope", nsName)
			} else {
				ctlr.namespacesMutex.Lock()
				ctlr.namespaces[nsName] = true
				ctlr.namespacesMutex.Unlock()
				_ = ctlr.addNamespacedInformers(nsName, true)
				log.Infof("Added Namespace: '%v' to CIS scope", nsName)
			}
		}
	case HACIS:
		log.Infof("posting declaration on primary cluster down event")
	case NodeUpdate:
		if &ctlr.multiClusterResources.clusterSvcMap != nil {
			if svcKeys, ok := ctlr.multiClusterResources.clusterSvcMap[rKey.clusterName]; ok {
				for svcKey := range svcKeys {
					ctlr.updatePoolMembersForService(svcKey, false)
				}
			}
		}
		log.Debugf("posting declaration on node update")
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}

	if isRetryableError {
		if rKey.clusterName == "" {
			log.Warningf("Request from cluster local resulted in retry for  %v in %v %v/%v", strings.ToTitle(rKey.event), strings.ToTitle(rKey.kind), rKey.namespace, rKey.rscName)
		} else {
			log.Warningf("Request from cluster %v resulted in retry for %v in %v %v/%v", rKey.clusterName, strings.ToTitle(rKey.event), strings.ToTitle(rKey.kind), rKey.namespace, rKey.rscName)
		}
		ctlr.resourceQueue.AddRateLimited(key)
	} else {
		ctlr.resourceQueue.Forget(key)
	}

	// we have processed the resource but as controller is still in init state do not post the config
	if ctlr.initState {
		return true
	}

	if (ctlr.resourceQueue.Len() == 0 && ctlr.resources.isConfigUpdated()) ||
		(ctlr.multiClusterMode == SecondaryCIS && rKey.kind == HACIS) {
		config := ResourceConfigRequest{
			ltmConfig:          ctlr.resources.getLTMConfigDeepCopy(),
			shareNodes:         ctlr.shareNodes,
			gtmConfig:          ctlr.resources.getGTMConfigCopy(),
			defaultRouteDomain: ctlr.defaultRouteDomain,
		}

		if ctlr.multiClusterMode != "" {
			// only standalone CIS & Primary CIS should post the teems data
			if ctlr.multiClusterMode != SecondaryCIS {
				// using node informers to count the clusters as it will be available in all CNIs
				// adding 1 for the current cluster
				ctlr.TeemData.ClusterCount = len(ctlr.multiClusterNodeInformers) + 1
				go ctlr.TeemData.PostTeemsData()
			}
		} else {
			// In non multi-cluster mode, we should post the teems data
			go ctlr.TeemData.PostTeemsData()
		}
		config.reqId = ctlr.enqueueReq(config)
		config.poolMemberType = ctlr.PoolMemberType
		if rKey.kind == HACIS {
			log.Infof("[Request: %v] primary cluster down event requested %v", config.reqId, strings.ToTitle(Update))
		} else if rKey.clusterName == "" {
			log.Infof("[Request: %v] cluster local requested %v in %v %v/%v", config.reqId, strings.ToTitle(rKey.event), strings.ToTitle(rKey.kind), rKey.namespace, rKey.rscName)
		} else {
			log.Infof("[Request: %v] cluster %v requested %v in %v %v/%v", config.reqId, rKey.clusterName, strings.ToTitle(rKey.event), strings.ToTitle(rKey.kind), rKey.namespace, rKey.rscName)
		}
		ctlr.Agent.PostConfig(config)
		ctlr.initState = false
		ctlr.resources.updateCaches()
	}
	return true
}

// getServiceForEndpoints returns the service associated with endpoints.
func (ctlr *Controller) getServiceForEndpoints(ep *v1.Endpoints, clusterName string) *v1.Service {
	var svc interface{}
	var exists bool
	var err error
	svcKey := fmt.Sprintf("%s/%s", ep.Namespace, ep.Name)
	if clusterName == "" {
		comInf, ok := ctlr.getNamespacedCommonInformer(ep.Namespace)
		if !ok {
			log.Errorf("Informer not found for namespace: %v", ep.Namespace)
			return nil
		}
		svc, exists, err = comInf.svcInformer.GetIndexer().GetByKey(svcKey)
	} else {
		poolInf, ok := ctlr.getNamespaceMultiClusterPoolInformer(ep.Namespace, clusterName)
		if !ok {
			log.Errorf("[MultiCluster] Informer not found for namespace %v and cluster %v", ep.Namespace, clusterName)
			return nil
		}
		svc, exists, err = poolInf.svcInformer.GetIndexer().GetByKey(svcKey)
	}
	if err != nil {
		log.Infof("%v Error fetching service %v %v from the store: %v", ctlr.getMultiClusterLog(), svcKey,
			getClusterLog(clusterName), err)
		return nil
	}
	if !exists {
		log.Infof("%v Service %v %v doesn't exist", ctlr.getMultiClusterLog(), svcKey, getClusterLog(clusterName))
		return nil
	}
	return svc.(*v1.Service)
}

// getVirtualsForTLSProfile gets the List of VirtualServers which are effected
// by the addition/deletion/updation of TLSProfile.
func (ctlr *Controller) getVirtualsForTLSProfile(tls *cisapiv1.TLSProfile) []*cisapiv1.VirtualServer {

	allVirtuals := ctlr.getAllVirtualServers(tls.ObjectMeta.Namespace)
	if nil == allVirtuals {
		log.Infof("No VirtualServers found in namespace %s",
			tls.ObjectMeta.Namespace)
		return nil
	}

	// find VirtualServers that reference the TLSProfile
	virtualsForTLSProfile := getVirtualServersForTLSProfile(allVirtuals, tls)
	if nil == virtualsForTLSProfile {
		log.Infof("Change in TLSProfile %s does not effect any VirtualServer",
			tls.ObjectMeta.Name)
		return nil
	}
	return virtualsForTLSProfile
}

func (ctlr *Controller) getVirtualsForCustomPolicy(plc *cisapiv1.Policy) []*cisapiv1.VirtualServer {
	nsVirtuals := ctlr.getAllVirtualServers(plc.Namespace)
	if nil == nsVirtuals {
		log.Debugf("No VirtualServers found in namespace %s",
			plc.Namespace)
		return nil
	}

	var plcVSs []*cisapiv1.VirtualServer
	var plcVSNames []string
	for _, vs := range nsVirtuals {
		if vs.Spec.PolicyName == plc.Name {
			plcVSs = append(plcVSs, vs)
			plcVSNames = append(plcVSNames, vs.Name)
		}
	}

	log.Debugf("VirtualServers %v are affected with Custom Policy %s: ",
		plcVSNames, plc.Name)

	return plcVSs
}

func (ctlr *Controller) getTransportServersForCustomPolicy(plc *cisapiv1.Policy) []*cisapiv1.TransportServer {
	nsVirtuals := ctlr.getAllTransportServers(plc.Namespace)
	if nil == nsVirtuals {
		log.Debugf("No TransportServers found in namespace %s",
			plc.Namespace)
		return nil
	}

	var plcVSs []*cisapiv1.TransportServer
	var plcVSNames []string
	for _, vs := range nsVirtuals {
		if vs.Spec.PolicyName == plc.Name {
			plcVSs = append(plcVSs, vs)
			plcVSNames = append(plcVSNames, vs.Name)
		}
	}

	log.Debugf("VirtualServers %v are affected with Custom Policy %s: ",
		plcVSNames, plc.Name)

	return plcVSs
}

// getLBServicesForCustomPolicy gets all services of type LB affected by the policy
func (ctlr *Controller) getLBServicesForCustomPolicy(plc *cisapiv1.Policy) []*v1.Service {
	LBServices := ctlr.getAllLBServices(plc.Namespace)
	if nil == LBServices {
		log.Debugf("No LB service found in namespace %s",
			plc.Namespace)
		return nil
	}

	var plcSvcs []*v1.Service
	var plcSvcNames []string
	for _, svc := range LBServices {
		if plcName, found := svc.Annotations[LBServicePolicyNameAnnotation]; found && plcName == plc.Name {
			plcSvcs = append(plcSvcs, svc)
			plcSvcNames = append(plcSvcNames, svc.Name)
		}
	}

	log.Debugf("LB Services %v are affected with Custom Policy %s: ",
		plcSvcNames, plc.Name)

	return plcSvcs
}

// getAllVirtualServers returns list of all valid VirtualServers in rkey namespace.
func (ctlr *Controller) getAllVirtualServers(namespace string) []*cisapiv1.VirtualServer {
	var allVirtuals []*cisapiv1.VirtualServer

	crInf, ok := ctlr.getNamespacedCRInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}

	var orderedVSs []interface{}
	var err error
	if namespace == "" {
		orderedVSs = crInf.vsInformer.GetIndexer().List()
	} else {
		// Get list of VirtualServers and process them.
		orderedVSs, err = crInf.vsInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("Unable to get list of VirtualServers for namespace '%v': %v",
				namespace, err)
			return nil
		}
	}

	for _, obj := range orderedVSs {
		vs := obj.(*cisapiv1.VirtualServer)
		// TODO: Validate the VirtualServers List to check if all the vs are valid.
		allVirtuals = append(allVirtuals, vs)
	}

	return allVirtuals
}

// getAllVirtualServers returns list of all valid VirtualServers in rkey namespace.
func (ctlr *Controller) getAllVSFromMonitoredNamespaces() []*cisapiv1.VirtualServer {
	var allVirtuals []*cisapiv1.VirtualServer
	if ctlr.watchingAllNamespaces() {
		return ctlr.getAllVirtualServers("")
	}
	for ns := range ctlr.namespaces {
		allVirtuals = append(allVirtuals, ctlr.getAllVirtualServers(ns)...)
	}
	return allVirtuals
}

// getVirtualServersForTLS returns list of VirtualServers that are
// affected by the TLSProfile under process.
func getVirtualServersForTLSProfile(allVirtuals []*cisapiv1.VirtualServer,
	tls *cisapiv1.TLSProfile) []*cisapiv1.VirtualServer {

	var result []*cisapiv1.VirtualServer
	tlsName := tls.ObjectMeta.Name
	tlsNamespace := tls.ObjectMeta.Namespace

	for _, vs := range allVirtuals {
		hostsMap := make(map[string]struct{})
		if vs.Spec.Host != "" {
			hostsMap[vs.Spec.Host] = struct{}{}
		}
		for _, host := range vs.Spec.HostAliases {
			hostsMap[host] = struct{}{}
		}
		if vs.ObjectMeta.Namespace == tlsNamespace && vs.Spec.TLSProfileName == tlsName {
			found := false
			for _, host := range tls.Spec.Hosts {
				if _, ok := hostsMap[host]; ok {
					result = append(result, vs)
					found = true
					break
				}
				// check for wildcard match
				if strings.HasPrefix(host, "*") {
					host = strings.TrimPrefix(host, "*")
					if strings.HasSuffix(vs.Spec.Host, host) {
						// TLSProfile Object
						result = append(result, vs)
						found = true
						break
					}
				}
			}
			if !found {
				log.Errorf("TLSProfile hostname is not same as virtual host(s) %v for profile %s", reflect.ValueOf(hostsMap).MapKeys(), vs.Spec.TLSProfileName)
			}
		}
	}

	return result
}

func (ctlr *Controller) getTerminationFromTLSProfileForVirtualServer(vs *cisapiv1.VirtualServer) string {
	if vs.Spec.TLSProfileName == "" {
		return ""
	}
	// get TLSProfile for VirtualServer
	tlsProfile, err := ctlr.getTLSProfile(vs.Spec.TLSProfileName, vs.Namespace)
	if err != nil {
		log.Errorf("Error fetching TLSProfile %s: %v", vs.Spec.TLSProfileName, err)
		return ""
	}
	return tlsProfile.Spec.TLS.Termination
}

func (ctlr *Controller) getTLSProfile(tlsName string, namespace string) (*cisapiv1.TLSProfile, error) {
	tlsKey := fmt.Sprintf("%s/%s", namespace, tlsName)
	// Initialize CustomResource Informer for required namespace
	crInf, ok := ctlr.getNamespacedCRInformer(namespace)
	if !ok {
		return nil, fmt.Errorf("Informer not found for namespace: %v", namespace)
	}
	obj, tlsFound, _ := crInf.tlsInformer.GetIndexer().GetByKey(tlsKey)
	if !tlsFound {
		return nil, fmt.Errorf("TLSProfile %s does not exist", tlsName)
	}
	return obj.(*cisapiv1.TLSProfile), nil
}

func (ctlr *Controller) getTLSProfileForVirtualServer(vs *cisapiv1.VirtualServer) *cisapiv1.TLSProfile {
	tlsName := vs.Spec.TLSProfileName
	namespace := vs.Namespace
	vsKey := fmt.Sprintf("%s/%s", vs.Namespace, vs.Name)
	// Initialize CustomResource Informer for required namespace
	comInf, ok := ctlr.getNamespacedCommonInformer(namespace)
	if !ok {
		log.Errorf("Common Informer not found for namespace: %v", namespace)
		return nil
	}
	// TODO: Create Internal Structure to hold TLSProfiles. Make API call only for a new TLSProfile
	// Check if the TLSProfile exists and valid for us.
	tlsProfile, err := ctlr.getTLSProfile(tlsName, namespace)
	if err != nil {
		log.Errorf("Error fetching TLSProfile %s: %v", tlsName, err)
		return nil
	}

	// validate TLSProfile
	validation := validateTLSProfile(tlsProfile)
	if validation == false {
		return nil
	}

	if tlsProfile.Spec.TLS.Reference == "secret" {
		var match bool
		if len(tlsProfile.Spec.TLS.ClientSSLs) > 0 {
			for _, secret := range tlsProfile.Spec.TLS.ClientSSLs {
				secretKey := namespace + "/" + secret
				clientSecretobj, found, err := comInf.secretsInformer.GetIndexer().GetByKey(secretKey)
				if err != nil || !found {
					return nil
				}
				clientSecret := clientSecretobj.(*v1.Secret)
				//validate at least one clientSSL certificates matches the VS hostname
				if checkCertificateHost(vs.Spec.Host, VirtualServer, vsKey, clientSecret.Data["tls.crt"], clientSecret.Data["tls.key"]) {
					match = true
					break
				}
			}

		} else {
			secretKey := namespace + "/" + tlsProfile.Spec.TLS.ClientSSL
			clientSecretobj, found, err := comInf.secretsInformer.GetIndexer().GetByKey(secretKey)
			if err != nil || !found {
				return nil
			}
			clientSecret := clientSecretobj.(*v1.Secret)
			//validate clientSSL certificates and hostname
			match = checkCertificateHost(vs.Spec.Host, VirtualServer, vsKey, clientSecret.Data["tls.crt"], clientSecret.Data["tls.key"])
		}
		if match == false {
			return nil
		}
	}
	if len(vs.Spec.Host) == 0 {
		// VirtualServer without host may be used for group of services
		// which are common amongst multiple hosts. Example: Error Page
		// application may be common for multiple hosts.
		// However, each host use a unique TLSProfile w.r.t SNI
		return tlsProfile
	}

	for _, host := range tlsProfile.Spec.Hosts {
		if host == vs.Spec.Host {
			// TLSProfile Object
			return tlsProfile
		}
		// check for wildcard match
		if strings.HasPrefix(host, "*") {
			host = strings.TrimPrefix(host, "*")
			if strings.HasSuffix(vs.Spec.Host, host) {
				// TLSProfile Object
				return tlsProfile
			}
		}
	}
	log.Errorf("TLSProfile %s with host %s does not match with virtual server %s host.", tlsName, vs.Spec.Host, vs.ObjectMeta.Name)
	return nil

}

func isTLSVirtualServer(vrt *cisapiv1.VirtualServer) bool {
	return len(vrt.Spec.TLSProfileName) != 0
}

func doesVSHandleHTTP(vrt *cisapiv1.VirtualServer) bool {
	if !isTLSVirtualServer(vrt) {
		// If it is not TLS VirtualServer(HTTPS), then it is HTTP server
		return true
	}
	// If Allow or Redirect happens then HTTP Traffic is being handled.
	return vrt.Spec.HTTPTraffic == TLSAllowInsecure ||
		vrt.Spec.HTTPTraffic == TLSRedirectInsecure
}

// doVSHandleHTTP checks if any of the associated vituals handle HTTP traffic and use same port
func doVSHandleHTTP(virtuals []*cisapiv1.VirtualServer, virtual *cisapiv1.VirtualServer) bool {
	effectiveHTTPPort := getEffectiveHTTPPort(virtual)
	for _, vrt := range virtuals {
		if doesVSHandleHTTP(vrt) && effectiveHTTPPort == getEffectiveHTTPPort(vrt) {
			return true
		}
	}
	return false
}

// processVirtualServers takes the Virtual Server as input and processes all
// associated VirtualServers to create a resource config(Internal DataStructure)
// or to update if exists already.
func (ctlr *Controller) processVirtualServers(
	virtual *cisapiv1.VirtualServer,
	isVSDeleted bool,
) error {

	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing virtual servers %+v (%v)",
			virtual, endTime.Sub(startTime))
	}()

	// Skip validation for a deleted Virtual Server
	if !isVSDeleted {
		// check if the virutal server matches all the requirements.
		vkey := virtual.ObjectMeta.Namespace + "/" + virtual.ObjectMeta.Name
		valid := ctlr.checkValidVirtualServer(virtual)
		if false == valid {
			log.Errorf("VirtualServer %s, is not valid",
				vkey)
			return nil
		}
	}

	var allVirtuals []*cisapiv1.VirtualServer
	if virtual.Spec.HostGroup != "" {
		// grouping by hg across all namespaces
		allVirtuals = ctlr.getAllVSFromMonitoredNamespaces()
	} else {
		allVirtuals = ctlr.getAllVirtualServers(virtual.ObjectMeta.Namespace)
	}
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.VirtualServer[virtual.ObjectMeta.Namespace] = len(allVirtuals)
	ctlr.TeemData.Unlock()

	// Prepare list of associated VirtualServers to be processed
	// In the event of deletion, exclude the deleted VirtualServer
	log.Debugf("Process all the Virtual Servers which share same VirtualServerAddress")

	VSSpecProps := &VSSpecProperties{}
	virtuals := ctlr.getAssociatedVirtualServers(virtual, allVirtuals, isVSDeleted, VSSpecProps)
	//ctlr.getAssociatedSpecVirtuals(virtuals,VSSpecProps)

	var ip string
	var status int
	var altErr string
	partition := ctlr.getCRPartition(virtual.Spec.Partition)
	if ctlr.ipamCli != nil {
		if isVSDeleted && len(virtuals) == 0 && virtual.Spec.VirtualServerAddress == "" {
			if virtual.Spec.HostGroup != "" {
				//hg is unique across namespaces
				//all virtuals with same hg are grouped together across namespaces
				key := ctlr.ipamClusterLabel + virtual.Spec.HostGroup + "_hg"
				ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, "", key)
			} else {
				key := ctlr.ipamClusterLabel + virtual.Namespace + "/" + virtual.Spec.Host + "_host"
				ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, virtual.Spec.Host, key)
			}
		} else if virtual.Spec.VirtualServerAddress != "" {
			// Prioritise VirtualServerAddress specified over IPAMLabel
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ipamLabel := getIPAMLabel(virtuals)
			if virtual.Spec.HostGroup != "" {
				//hg is unique across namepsaces
				key := ctlr.ipamClusterLabel + virtual.Spec.HostGroup + "_hg"
				ip, status = ctlr.requestIP(ipamLabel, "", key)
			} else {
				key := ctlr.ipamClusterLabel + virtual.Namespace + "/" + virtual.Spec.Host + "_host"
				ip, status = ctlr.requestIP(ipamLabel, virtual.Spec.Host, key)
			}

			switch status {
			case NotEnabled:
				altErr = "[IPAM] IPAM Custom Resource Not Available"
				log.Error(altErr)
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
				return nil
			case InvalidInput:
				altErr = fmt.Sprintf("IPAM Invalid IPAM Label: %v for Virtual Server: %s/%s", ipamLabel, virtual.Namespace, virtual.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
				return nil
			case NotRequested:
				altErr = "unable to make IPAM Request, will be re-requested soon"
				log.Error(altErr)
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
				return fmt.Errorf("%s", altErr)
			case Requested:
				altErr = fmt.Sprintf("IP address requested for service: %s/%s", virtual.Namespace, virtual.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
				return nil
			}
		}
	} else {
		if virtual.Spec.HostGroup == "" {
			if virtual.Spec.VirtualServerAddress == "" {
				altErr = "no VirtualServer address or IPAM found"
				log.Error(altErr)
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
				return fmt.Errorf("%s", altErr)
			}
			ip = virtual.Spec.VirtualServerAddress
		} else {
			var err error
			ip, err = getVirtualServerAddress(virtuals)
			if err != nil {
				altErr = fmt.Sprintf("Error in virtualserver address: %s", err.Error())
				log.Errorf(altErr)
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
				return err
			}
			if ip == "" {
				ip = virtual.Spec.VirtualServerAddress
				if ip == "" {
					altErr = fmt.Sprintf("No VirtualServer address found for: %s", virtual.Name)
					log.Errorf(altErr)
					ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New(altErr))
					return fmt.Errorf(altErr)
				}
			}
		}
	}
	// Depending on the ports defined, TLS type or Unsecured we will populate the resource config.
	portStructs := ctlr.virtualPorts(virtual)

	// vsMap holds Resource Configs of current virtuals temporarily
	vsMap := make(ResourceMap)
	processingError := false
	for _, portS := range portStructs {
		// TODO: Add Route Domain
		var rsName string
		if virtual.Spec.HostGroup != "" && virtual.Spec.HostGroupVirtualServerName != "" {
			rsName = formatCustomVirtualServerName(
				virtual.Spec.HostGroupVirtualServerName,
				portS.port,
			)
		} else if virtual.Spec.VirtualServerName != "" {
			if virtual.Spec.HostGroup != "" {
				//Ignore virtualServerName if hostgroup is configured on virtual
				log.Warningf("virtualServerName is ignored as hostgroup is configured on virtualserver %v", virtual.Name)
				rsName = formatVirtualServerName(
					ip,
					portS.port,
				)
			} else {
				rsName = formatCustomVirtualServerName(
					virtual.Spec.VirtualServerName,
					portS.port,
				)
			}
		} else {
			rsName = formatVirtualServerName(
				ip,
				portS.port,
			)
		}

		// Delete rsCfg if no corresponding virtuals exist
		// Delete rsCfg if it is HTTP rsCfg and the CR VirtualServer does not handle HTTPTraffic
		if (len(virtuals) == 0) ||
			(portS.protocol == HTTP && !doVSHandleHTTP(virtuals, virtual)) ||
			(isVSDeleted && portS.protocol == HTTPS && !doVSUseSameHTTPSPort(virtuals, virtual)) {
			var hostnames []string
			rsMap := ctlr.resources.getPartitionResourceMap(partition)

			if _, ok := rsMap[rsName]; ok {
				hostnames = rsMap[rsName].MetaData.hosts
			}
			ctlr.deleteVirtualServer(partition, rsName)
			if len(hostnames) > 0 {
				ctlr.ProcessAssociatedExternalDNS(hostnames)
			}
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = partition
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.MetaData.Protocol = portS.protocol
		rsCfg.MetaData.httpTraffic = virtual.Spec.HTTPTraffic
		if virtual.Spec.HttpMrfRoutingEnabled != nil {
			rsCfg.Virtual.HttpMrfRoutingEnabled = virtual.Spec.HttpMrfRoutingEnabled
		}
		rsCfg.MetaData.baseResources = make(map[string]string)
		if virtual.Spec.BigIPRouteDomain > 0 {
			if ctlr.PoolMemberType == Cluster {
				log.Warning("bigipRouteDomain is not supported in cluster mode")
			} else {
				rsCfg.Virtual.BigIPRouteDomain = virtual.Spec.BigIPRouteDomain
				rsCfg.Virtual.SetVirtualAddress(
					fmt.Sprintf("%s%%%d", ip, virtual.Spec.BigIPRouteDomain),
					portS.port,
				)
			}
		} else {
			rsCfg.Virtual.SetVirtualAddress(
				ip,
				portS.port,
			)
		}
		//set additionalVirtualAddresses if present
		if len(virtual.Spec.AdditionalVirtualServerAddresses) > 0 {
			rsCfg.Virtual.AdditionalVirtualAddresses = virtual.Spec.AdditionalVirtualServerAddresses
		}
		rsCfg.IntDgMap = make(InternalDataGroupMap)
		rsCfg.IRulesMap = make(IRulesMap)
		rsCfg.customProfiles = make(map[SecretKey]CustomProfile)

		plc, err := ctlr.getPolicyFromVirtuals(virtuals)
		if plc != nil {
			err := ctlr.handleVSResourceConfigForPolicy(rsCfg, plc)
			if err != nil {
				processingError = true
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", err)
				break
			}
		}
		if err != nil {
			processingError = true
			log.Errorf("%v", err)
			ctlr.updateResourceStatus(VirtualServer, virtual, "", "", err)
			break
		}

		tlsProfs := ctlr.getTLSProfilesForVirtuals(virtuals)
		passthroughVSGrp := true
		if tlsProfs != nil {
			for _, value := range tlsProfs {
				if value != nil {
					if value.Spec.TLS.Termination != TLSPassthrough {
						passthroughVSGrp = false
						break
					}
				}
			}
		} else {
			passthroughVSGrp = false
		}

		for _, vrt := range virtuals {
			// Updating the virtual server IP Address status for all associated virtuals
			vrt.Status.VSAddress = ip
			passthroughVS := false
			var tlsProf *cisapiv1.TLSProfile
			var tlsTermination string
			if isTLSVirtualServer(vrt) {
				// Handle TLS configuration for VirtualServer Custom Resource
				if tlsProfs != nil {
					tlsProf = tlsProfs[vrt.Name+"/"+vrt.Namespace]
				}
				if tlsProf == nil {
					// Processing failed
					// Stop processing further virtuals
					processingError = true
					ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New("TLS profile not found for the Virtual Server"))
					break
				} else {
					tlsTermination = tlsProf.Spec.TLS.Termination
				}
				if tlsProf.Spec.TLS.Termination == TLSPassthrough {
					passthroughVS = true
				}
			}

			log.Debugf("Processing Virtual Server %s for port %v",
				vrt.ObjectMeta.Name, portS.port)
			rsCfg.MetaData.baseResources[vrt.Namespace+"/"+vrt.Name] = VirtualServer
			err := ctlr.prepareRSConfigFromVirtualServer(
				rsCfg,
				vrt,
				passthroughVS,
				tlsTermination,
			)
			if err != nil {
				processingError = true
				ctlr.updateResourceStatus(VirtualServer, virtual, "", "", err)
				break
			}
			// handle pool settings from policy cr
			if plc != nil {
				if plc.Spec.PoolSettings != (cisapiv1.PoolSettingsSpec{}) {
					err := ctlr.handlePoolResourceConfigForPolicy(rsCfg, plc)
					if err != nil {
						processingError = true
						ctlr.updateResourceStatus(VirtualServer, virtual, "", "", err)
						break
					}
				}
				// handle default pool from policy if not set in virtual
				if reflect.DeepEqual(virtual.Spec.DefaultPool, cisapiv1.DefaultPool{}) {
					if !reflect.DeepEqual(plc.Spec.DefaultPool, cisapiv1.DefaultPool{}) {
						rsRef := resourceRef{
							name:      virtual.Name,
							namespace: virtual.Namespace,
							kind:      VirtualServer,
						}
						ctlr.handleDefaultPoolForPolicy(rsCfg, plc, rsRef, virtual.Spec.Host, virtual.Spec.HTTPTraffic, isTLSVirtualServer(virtual))
					}
				}
			}
			if tlsProf != nil {
				processed := ctlr.handleVirtualServerTLS(rsCfg, vrt, tlsProf, ip, passthroughVSGrp)
				if !processed {
					// Processing failed
					// Stop processing further virtuals
					processingError = true
					ctlr.updateResourceStatus(VirtualServer, virtual, "", "", errors.New("error while handling TLS Virtual Server"))
					break
				}

				log.Debugf("Updated Virtual %s with TLSProfile %s",
					vrt.ObjectMeta.Name, vrt.Spec.TLSProfileName)
			}

			ctlr.resources.processedNativeResources[resourceRef{
				kind:      VirtualServer,
				namespace: vrt.Namespace,
				name:      vrt.Name,
			}] = struct{}{}

		}

		if VSSpecProps.PoolWAF && rsCfg.Virtual.WAF == "" {
			ctlr.addDefaultWAFDisableRule(rsCfg, "vs_waf_disable")
		}
		if processingError {
			log.Errorf("Cannot Publish VirtualServer %s", virtual.ObjectMeta.Name)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg
	}

	if !processingError {
		var hostnames []string
		rsMap := ctlr.resources.getPartitionResourceMap(partition)

		// Update ltmConfig with ResourceConfigs created for the current virtuals
		for rsName, rsCfg := range vsMap {
			// Get the hostnames associated with the VirtualServers, without caring about whether the resource is
			// already processed or not, to make sure that ExternalDNS is updated/processed for all the hostnames in case
			// multiple VirtualServer CRs with different hosts are grouped under one Big-IP Virtual.
			hostnames = rsCfg.MetaData.hosts
			rsMap[rsName] = rsCfg
		}

		if len(hostnames) > 0 {
			ctlr.ProcessAssociatedExternalDNS(hostnames)
		}
	}
	ctlr.updateResourceStatus(VirtualServer, virtual, ip, "", nil)

	return nil
}

func (ctlr *Controller) getTLSProfilesForVirtuals(virtuals []*cisapiv1.VirtualServer) map[string]*cisapiv1.TLSProfile {
	tlsProfileMap := make(map[string]*cisapiv1.TLSProfile)
	for _, vrt := range virtuals {
		if isTLSVirtualServer(vrt) {
			tlsProf := ctlr.getTLSProfileForVirtualServer(vrt)
			tlsProfileMap[vrt.Name+"/"+vrt.Namespace] = tlsProf
		}
	}
	return tlsProfileMap
}

// getEffectiveHTTPPort returns the final HTTP port considered for virtual server
func getEffectiveHTTPSPort(vrt *cisapiv1.VirtualServer) int32 {
	effectiveHTTPSPort := DEFAULT_HTTPS_PORT
	if vrt.Spec.VirtualServerHTTPSPort != 0 {
		effectiveHTTPSPort = vrt.Spec.VirtualServerHTTPSPort
	}
	return effectiveHTTPSPort
}

// getEffectiveHTTPPort returns the final HTTP port considered for virtual server
func getEffectiveHTTPPort(vrt *cisapiv1.VirtualServer) int32 {
	effectiveHTTPPort := DEFAULT_HTTP_PORT
	if vrt.Spec.VirtualServerHTTPPort != 0 {
		effectiveHTTPPort = vrt.Spec.VirtualServerHTTPPort
	}
	return effectiveHTTPPort
}

func (ctlr *Controller) getAssociatedVirtualServers(
	currentVS *cisapiv1.VirtualServer,
	allVirtuals []*cisapiv1.VirtualServer,
	isVSDeleted bool,
	VSSpecProperties *VSSpecProperties,
) []*cisapiv1.VirtualServer {
	// Associated VirutalServers are grouped based on "hostGroup" parameter
	// if hostGroup parameter is not available, they will be grouped on "host" parameter
	// if "host" parameter is not available, they will be grouped on "VirtualServerAddress"

	// The VirtualServers that are being grouped by "hostGroup" or "host" should obey below rules,
	// otherwise the grouping would be treated as invalid and the associatedVirtualServers will be nil.
	//		* all of them should have same "ipamLabel"
	//      * if no "ipamLabel" present, should have same "VirtualServerAddress" and "additionalVirtualServerAddresses"
	//
	// However, there are some parameters that are not as stringent as above.
	// which include
	// 		* "VirtualServerHTTPPort" to be same across the group of VirtualServers
	//      * "VirtualServerHTTPSPort" to be same across the group of VirtualServers
	//      * unique paths for a given host name
	// If one (or multiple) of the above parameters are specified in wrong manner in any VirtualServer,
	// that particular VirtualServer will be skipped.

	var virtuals []*cisapiv1.VirtualServer
	var err string
	// {hostname: {path: <empty_struct>}}
	uniqueHostPathMap := make(map[string]map[string]struct{})
	currentVSPartition := ctlr.getCRPartition(currentVS.Spec.Partition)

	for _, vrt := range allVirtuals {
		// skip the deleted virtual in the event of deletion
		if isVSDeleted && vrt.Name == currentVS.Name && vrt.ObjectMeta.Namespace == currentVS.ObjectMeta.Namespace {
			continue
		}

		// Multiple VS sharing same VS address with different partition is invalid
		// This also handles for host group/VS with same hosts
		if currentVS.Spec.VirtualServerAddress != "" &&
			currentVS.Spec.VirtualServerAddress == vrt.Spec.VirtualServerAddress &&
			currentVSPartition != ctlr.getCRPartition(vrt.Spec.Partition) {
			err = fmt.Sprintf("Multiple Virtual Servers %v,%v are configured with same VirtualServerAddress : %v with different partitions", currentVS.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
			log.Error(err)
			ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
			return nil
		}

		// skip the virtuals in other HostGroups
		if vrt.Spec.HostGroup != currentVS.Spec.HostGroup {
			if currentVS.Spec.VirtualServerAddress != "" && vrt.Spec.VirtualServerAddress != "" && currentVS.Spec.VirtualServerAddress == vrt.Spec.VirtualServerAddress {
				err = fmt.Sprintf("Multiple Virtual Servers %v, %v are configured with same VirtualServerAddress: %v", currentVS.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
				log.Error(err)
				ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
				return nil
			}
			continue
		}

		if vrt.Spec.HostGroup != "" && currentVS.Spec.HostGroup != "" && vrt.Spec.HostGroup == currentVS.Spec.HostGroup {
			if currentVS.Spec.VirtualServerAddress != "" && vrt.Spec.VirtualServerAddress != "" && currentVS.Spec.VirtualServerAddress != vrt.Spec.VirtualServerAddress {
				err = fmt.Sprintf("Multiple Virtual Servers %v, %v are configured with different VirtualServerAddress: %v %v", currentVS.Name, vrt.Name, currentVS.Spec.VirtualServerAddress, vrt.Spec.VirtualServerAddress)
				log.Error(err)
				ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
				return nil
			}
			if currentVS.Spec.IPAMLabel != "" && vrt.Spec.IPAMLabel != "" && currentVS.Spec.IPAMLabel != vrt.Spec.IPAMLabel {
				err = fmt.Sprintf("Multiple Virtual Servers %v, %v are configured with different IPAM Labels: %v %v", currentVS.Name, vrt.Name, currentVS.Spec.IPAMLabel, vrt.Spec.IPAMLabel)
				log.Error(err)
				ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
				return nil
			}
		}

		if currentVS.Spec.HostGroup != "" && vrt.Spec.HostGroup == currentVS.Spec.HostGroup && vrt.Spec.HostGroupVirtualServerName != currentVS.Spec.HostGroupVirtualServerName {
			err = fmt.Sprintf("Same host %v is configured with different HostGroupVirtualServerNames : %v ", vrt.Spec.HostGroup, vrt.Spec.HostGroupVirtualServerName)
			log.Error(err)
			ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
			return nil
		}

		if currentVS.Spec.HostGroup == "" {
			// in the absence of HostGroup, skip the virtuals with other host name if tls terminations are also same
			if vrt.Spec.Host != currentVS.Spec.Host {
				if vrt.Spec.TLSProfileName != "" && currentVS.Spec.TLSProfileName != "" {
					vrtTLSTermination := ctlr.getTerminationFromTLSProfileForVirtualServer(vrt)
					currentVSTLSTermination := ctlr.getTerminationFromTLSProfileForVirtualServer(currentVS)
					// Skip VS if terminations are different
					if (vrtTLSTermination == "" || currentVSTLSTermination == "") || vrtTLSTermination == currentVSTLSTermination {
						continue
					}
					// In case the terminations are different then consider the VS in the this group
				} else {
					// Skip VS if hosts don't match and any one of VS is unsecured VS
					continue
				}
			}

			// Same host with different VirtualServerAddress is invalid
			if vrt.Spec.VirtualServerAddress != currentVS.Spec.VirtualServerAddress {
				if vrt.Spec.Host != "" && vrt.Spec.Host == currentVS.Spec.Host {
					err = fmt.Sprintf("Same host %v is configured with different VirtualServerAddress : %v ", vrt.Spec.Host, vrt.Spec.VirtualServerName)
					log.Error(err)
					ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
					return nil
				}
				// In case of empty host name or host names not matching, skip the virtual with other VirtualServerAddress
				continue
			}
			//with additonalVirtualServerAddresses, skip the virtuals if ip list doesn't match
			if !reflect.DeepEqual(currentVS.Spec.AdditionalVirtualServerAddresses, vrt.Spec.AdditionalVirtualServerAddresses) {
				if vrt.Spec.Host != "" {
					err = fmt.Sprintf("Same host %v is configured with different AdditionalVirtualServerAddress : %v ", vrt.Spec.Host, vrt.ObjectMeta.Name)
					log.Error(err)
					ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
					return nil
				}
				// In case of empty host name, skip the virtual with other AdditionalVirtualServerAddress
				continue
			}
		}

		if ctlr.ipamCli != nil {
			if currentVS.Spec.HostGroup == "" && vrt.Spec.IPAMLabel != currentVS.Spec.IPAMLabel {
				err = fmt.Sprintf("Same host %v is configured with different IPAM labels: %v, %v. Unable to process %v", vrt.Spec.Host, vrt.Spec.IPAMLabel, currentVS.Spec.IPAMLabel, currentVS.Name)
				log.Error(err)
				ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
				return nil
			}
			// Empty host and hostGroup with IPAM label is invalid for a Virtual Server
			if vrt.Spec.IPAMLabel != "" && vrt.Spec.Host == "" && vrt.Spec.HostGroup == "" {
				err = fmt.Sprintf("Hostless VS %v is configured with IPAM label: %v and missing HostGroup", vrt.ObjectMeta.Name, vrt.Spec.IPAMLabel)
				log.Error(err)
				ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
				return nil
			}

			// Empty host with empty IPAM label is invalid
			if vrt.Spec.Host == "" && vrt.Spec.VirtualServerAddress == "" && len(vrt.Spec.AdditionalVirtualServerAddresses) == 0 {
				if vrt.Spec.IPAMLabel == "" && vrt.Spec.HostGroup != "" {
					err = fmt.Sprintf("Hostless VS %v is configured with missing IPAM label", vrt.ObjectMeta.Name)
					log.Error(err)
					ctlr.updateResourceStatus(VirtualServer, currentVS, "", "", errors.New(err))
					return nil
				}
				if vrt.Spec.IPAMLabel == "" {
					continue
				}
			}
		}

		// skip the virtuals with different custom HTTP/HTTPS ports
		if skipVirtual(currentVS, vrt) {
			continue
		}

		// skip the virtuals with different default pool
		if !reflect.DeepEqual(currentVS.Spec.DefaultPool, vrt.Spec.DefaultPool) {
			log.Errorf("%v/%v and %v/%v VS should have same default pool.", vrt.Namespace, vrt.Name, currentVS.Namespace, currentVS.Name)
			continue
		}

		// Check for duplicate path entries among virtuals
		uniquePaths, ok := uniqueHostPathMap[vrt.Spec.Host]
		if !ok {
			uniqueHostPathMap[vrt.Spec.Host] = make(map[string]struct{})
			uniquePaths = uniqueHostPathMap[vrt.Spec.Host]
		}
		isUnique := true
		for _, pool := range vrt.Spec.Pools {
			//Setting PoolWAF to true if exists
			if pool.WAF != "" {
				VSSpecProperties.PoolWAF = true
			}
			if _, ok := uniquePaths[pool.Path]; ok {
				// path already exists for the same host
				log.Warningf("Discarding the VirtualServer %v/%v due to duplicate path",
					vrt.ObjectMeta.Namespace, vrt.ObjectMeta.Name)
				isUnique = false
				break
			}
			uniquePaths[pool.Path] = struct{}{}
		}
		if isUnique {
			virtuals = append(virtuals, vrt)
		}
	}
	return virtuals
}

func (ctlr *Controller) validateTSWithSameVSAddress(
	currentTS *cisapiv1.TransportServer,
	allVirtuals []*cisapiv1.TransportServer,
	isVSDeleted bool) bool {
	currentTSPartition := ctlr.getCRPartition(currentTS.Spec.Partition)
	for _, vrt := range allVirtuals {
		// skip the deleted virtual in the event of deletion
		if isVSDeleted && vrt.Name == currentTS.Name {
			continue
		}

		// Multiple TS sharing same VS address with different partition is invalid
		// This also handles for host group/ vs with same hosts
		if currentTS.Spec.VirtualServerAddress != "" &&
			currentTS.Spec.VirtualServerAddress == vrt.Spec.VirtualServerAddress &&
			currentTSPartition != ctlr.getCRPartition(vrt.Spec.Partition) {
			err := fmt.Errorf("Multiple Transport Servers %v,%v are configured with same VirtualServerAddress : %v "+
				"with different partitions", currentTS.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
			log.Errorf("%s", err)
			ctlr.updateResourceStatus(TransportServer, currentTS, "", "", err)
			return false
		}
	}
	return true
}
func (ctlr *Controller) validateILsWithSameVSAddress(
	currentIL *cisapiv1.IngressLink,
	allILs []*cisapiv1.IngressLink,
	isILDeleted bool) bool {
	currentILPartition := ctlr.getCRPartition(currentIL.Spec.Partition)
	for _, vrt := range allILs {
		// skip the deleted virtual in the event of deletion
		if isILDeleted && vrt.Name == currentIL.Name {
			continue
		}

		// Multiple IL sharing same VS address with different partition is invalid
		if currentIL.Spec.VirtualServerAddress != "" &&
			currentIL.Spec.VirtualServerAddress == vrt.Spec.VirtualServerAddress &&
			currentILPartition != ctlr.getCRPartition(vrt.Spec.Partition) {
			err := fmt.Errorf("Multiple Ingress Links %v,%v are configured with same VirtualServerAddress : %v "+
				"with different partitions", currentIL.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
			log.Errorf("%s", err)
			ctlr.updateResourceStatus(IngressLink, currentIL, "", "", err)
			return false
		}
	}
	return true
}
func (ctlr *Controller) getCRPartition(partition string) string {
	if partition == "" {
		return ctlr.Partition
	}
	return partition
}

func (ctlr *Controller) getPolicyFromVirtuals(virtuals []*cisapiv1.VirtualServer) (*cisapiv1.Policy, error) {

	if len(virtuals) == 0 {
		log.Errorf("No virtuals to extract policy from")
		return nil, nil
	}
	plcName := ""
	ns := virtuals[0].Namespace

	for _, vrt := range virtuals {
		if plcName != "" && vrt.Spec.PolicyName != "" && plcName != vrt.Spec.PolicyName {
			return nil, fmt.Errorf("Multiple Policies specified for host: %v", vrt.Spec.Host)
		}
		if vrt.Spec.PolicyName != "" {
			plcName = vrt.Spec.PolicyName
		}
	}
	if plcName == "" {
		return nil, nil
	}
	crInf, ok := ctlr.getNamespacedCommonInformer(ns)
	if !ok {
		return nil, fmt.Errorf("Informer not found for namespace: %v", ns)
	}

	key := ns + "/" + plcName

	obj, exist, err := crInf.plcInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return nil, fmt.Errorf("Error while fetching Policy: %v: %v", key, err)
	}

	if !exist {
		return nil, fmt.Errorf("Policy Not Found: %v", key)
	}

	return obj.(*cisapiv1.Policy), nil
}

func (ctlr *Controller) getPolicyFromTransportServer(virtual *cisapiv1.TransportServer) (*cisapiv1.Policy, error) {

	if virtual == nil {
		log.Errorf("No virtuals to extract policy from")
		return nil, nil
	}

	plcName := virtual.Spec.PolicyName
	if plcName == "" {
		return nil, nil
	}
	ns := virtual.Namespace
	return ctlr.getPolicy(ns, plcName)
}

// getPolicy fetches the policy CR
func (ctlr *Controller) getPolicy(ns string, plcName string) (*cisapiv1.Policy, error) {
	crInf, ok := ctlr.getNamespacedCommonInformer(ns)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", ns)
		return nil, fmt.Errorf("Informer not found for namespace: %v", ns)
	}
	key := ns + "/" + plcName

	obj, exist, err := crInf.plcInformer.GetIndexer().GetByKey(key)
	if err != nil {
		log.Errorf("Error while fetching Policy: %v: %v",
			key, err)
		return nil, fmt.Errorf("Error while fetching Policy: %v: %v", key, err)
	}

	if !exist {
		log.Errorf("Policy Not Found: %v", key)
		return nil, fmt.Errorf("Policy Not Found: %v", key)
	}
	return obj.(*cisapiv1.Policy), nil
}

func getIPAMLabel(virtuals []*cisapiv1.VirtualServer) string {
	for _, vrt := range virtuals {
		if vrt.Spec.IPAMLabel != "" {
			return vrt.Spec.IPAMLabel
		}
	}
	return ""
}

func getVirtualServerAddress(virtuals []*cisapiv1.VirtualServer) (string, error) {
	vsa := ""
	for _, vrt := range virtuals {
		if vrt.Spec.VirtualServerAddress != "" {
			if vsa == "" || (vsa == vrt.Spec.VirtualServerAddress) {
				vsa = vrt.Spec.VirtualServerAddress
			} else {
				return "", fmt.Errorf("more than one Virtual Server Address Found")
			}
		}
	}
	if len(virtuals) != 0 && vsa == "" {
		return "", fmt.Errorf("no Virtual Server Address Found")
	}
	return vsa, nil
}

func (ctlr *Controller) getIPAMCR() *ficV1.IPAM {
	cr := strings.Split(ctlr.ipamCR, "/")
	if len(cr) != 2 {
		log.Errorf("[IPAM] error while retrieving IPAM namespace and name.")
		return nil
	}
	ipamCR, err := ctlr.ipamCli.Get(cr[0], cr[1])
	if err != nil {
		log.Errorf("[IPAM] error while retrieving IPAM custom resource.")
		return nil
	}
	return ipamCR
}

func (ctlr *Controller) migrateIPAM() {
	if ctlr.ipamCli == nil {
		return
	}

	ipamCR := ctlr.getIPAMCR()
	if ipamCR == nil {
		return
	}

	var specsToMigrate []ficV1.IPSpec

	for _, spec := range ipamCR.Status.IPStatus {
		idx := strings.LastIndex(spec.Key, "_")
		var rscKind string
		if idx != -1 {
			rscKind = spec.Key[idx+1:]
			switch rscKind {
			case "host", "ts", "il", "svc":
				// This entry is fine, process next entry
				continue
			case "hg":
				//Check for format of hg.if key is of format ns/hostgroup_hg
				//this is stale entry from older version, release ip
				if !strings.Contains(spec.Key, "/") {
					continue
				}
			}
		}
		specsToMigrate = append(specsToMigrate, *spec)
	}

	for _, spec := range specsToMigrate {
		ctlr.releaseIP(spec.IPAMLabel, spec.Host, spec.Key)
	}
}

// Request IPAM for virtual IP address
func (ctlr *Controller) requestIP(ipamLabel string, host string, key string) (string, int) {
	ipamCR := ctlr.getIPAMCR()
	var ip string
	var ipReleased bool
	if ipamCR == nil {
		return "", NotEnabled
	}

	if ipamLabel == "" {
		return "", InvalidInput
	}

	// Add all processed IPAM entries till first PostCall.
	if !ctlr.firstPostResponse {
		if ctlr.cacheIPAMHostSpecs == (CacheIPAM{}) {
			ctlr.cacheIPAMHostSpecs = CacheIPAM{
				IPAM: &ficV1.IPAM{
					TypeMeta: metav1.TypeMeta{
						Kind:       "IPAM",
						APIVersion: "v1",
					},
				},
			}
		}
		ctlr.cacheIPAMHostSpecs.Lock()
		ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs = append(ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs, &ficV1.HostSpec{
			Host:      host,
			Key:       key,
			IPAMLabel: ipamLabel,
		})
		ctlr.cacheIPAMHostSpecs.Unlock()
	}
	if host != "" {
		//For VS server
		for _, ipst := range ipamCR.Status.IPStatus {
			if ipst.IPAMLabel == ipamLabel && ipst.Host == host {
				// IP will be returned later when availability of corresponding spec is confirmed
				ip = ipst.IP
			}
		}

		for _, hst := range ipamCR.Spec.HostSpecs {
			if hst.Host == host {
				if hst.IPAMLabel == ipamLabel {
					if ip != "" {
						// IP extracted from the corresponding status of the spec
						return ip, Allocated
					}

					// HostSpec is already updated with IPAMLabel and Host but IP not got allocated yet
					return "", Requested
				} else {
					// Different Label for same host, this indicates Label is updated
					// Release the old IP, so that new IP can be requested
					ctlr.releaseIP(hst.IPAMLabel, hst.Host, "")
					ipReleased = true
					break
				}
			}
		}

		if ip != "" && !ipReleased {
			// Status is available for non-existing Spec
			// Let the resource get cleaned up and re request later
			return "", NotRequested
		}

		ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
		ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs, &ficV1.HostSpec{
			Host:      host,
			Key:       key,
			IPAMLabel: ipamLabel,
		})
	} else if key != "" {
		//For Transport Server
		for _, ipst := range ipamCR.Status.IPStatus {
			if ipst.IPAMLabel == ipamLabel && ipst.Key == key {
				// IP will be returned later when availability of corresponding spec is confirmed
				ip = ipst.IP
			}
		}

		for _, hst := range ipamCR.Spec.HostSpecs {
			if hst.Key == key {
				if hst.IPAMLabel == ipamLabel {
					if ip != "" {
						// IP extracted from the corresponding status of the spec
						return ip, Allocated
					}

					// HostSpec is already updated with IPAMLabel and Host but IP not got allocated yet
					return "", Requested
				} else {
					// Different Label for same key, this indicates Label is updated
					// Release the old IP, so that new IP can be requested
					ctlr.releaseIP(hst.IPAMLabel, "", hst.Key)
					ipReleased = true
					break
				}
			}
		}

		if ip != "" && !ipReleased {
			// Status is available for non-existing Spec
			// Let the resource get cleaned up and re request later
			return "", NotRequested
		}

		ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
		ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs, &ficV1.HostSpec{
			Key:       key,
			IPAMLabel: ipamLabel,
		})
	} else {
		log.Debugf("[IPAM] Invalid host and key.")
		return "", InvalidInput
	}

	_, err := ctlr.ipamCli.Update(ipamCR)
	if err != nil {
		log.Errorf("[IPAM] Error updating IPAM CR : %v", err)
		return "", NotRequested
	}

	log.Debugf("[IPAM] Updated IPAM CR.")
	return "", Requested

}

// Get List of VirtualServers associated with the IPAM resource
func (ctlr *Controller) VerifyIPAMAssociatedHostGroupExists(key string) bool {
	allTS := ctlr.getAllTSFromMonitoredNamespaces()
	for _, ts := range allTS {
		tskey := ctlr.ipamClusterLabel + ts.Spec.HostGroup + "_hg"
		if tskey == key {
			return true
		}
	}
	allVS := ctlr.getAllVSFromMonitoredNamespaces()
	for _, vs := range allVS {
		vskey := ctlr.ipamClusterLabel + vs.Spec.HostGroup + "_hg"
		if vskey == key {
			return true
		}
	}
	return false
}

func (ctlr *Controller) RemoveIPAMCRHostSpec(ipamCR *ficV1.IPAM, key string, index int) (res *ficV1.IPAM, err error) {
	isExists := false
	if strings.HasSuffix(key, "_hg") {
		isExists = ctlr.VerifyIPAMAssociatedHostGroupExists(key)
	}
	if !isExists {
		delete(ctlr.resources.ipamContext, key)
		ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs[:index], ipamCR.Spec.HostSpecs[index+1:]...)
		ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
		return ctlr.ipamCli.Update(ipamCR)
	}
	return res, err
}

func (ctlr *Controller) releaseIP(ipamLabel string, host string, key string) string {
	ipamCR := ctlr.getIPAMCR()
	var ip string
	if ipamCR == nil || ipamLabel == "" {
		return ip
	}
	index := -1
	if host != "" {
		//Find index for deleted host
		for i, hostSpec := range ipamCR.Spec.HostSpecs {
			if hostSpec.IPAMLabel == ipamLabel && hostSpec.Host == host {
				index = i
				break
			}
		}
		//Find IP address for deleted host
		for _, ipst := range ipamCR.Status.IPStatus {
			if ipst.IPAMLabel == ipamLabel && ipst.Host == host {
				ip = ipst.IP
			}
		}
		if index != -1 {
			_, err := ctlr.RemoveIPAMCRHostSpec(ipamCR, key, index)
			if err != nil {
				log.Errorf("[IPAM] ipam hostspec update error: %v", err)
				return ""
			}
			log.Debug("[IPAM] Updated IPAM CR hostspec while releasing IP.")
		}
	} else if key != "" {
		//Find index for deleted key
		for i, hostSpec := range ipamCR.Spec.HostSpecs {
			if hostSpec.IPAMLabel == ipamLabel && hostSpec.Key == key {
				index = i
				break
			}
		}
		//Find IP address for deleted host
		for _, ipst := range ipamCR.Status.IPStatus {
			if ipst.IPAMLabel == ipamLabel && ipst.Key == key {
				ip = ipst.IP
				break
			}
		}
		if index != -1 {
			_, err := ctlr.RemoveIPAMCRHostSpec(ipamCR, key, index)
			if err != nil {
				log.Errorf("[IPAM] ipam hostspec update error: %v", err)
				return ""
			}
			log.Debug("[IPAM] Updated IPAM CR hostspec while releasing IP.")
		}

	} else {
		log.Debugf("[IPAM] Invalid host and key.")
	}

	if len(ctlr.resources.ipamContext) == 0 {
		ctlr.ipamHostSpecEmpty = true
	}

	return ip
}

func (ctlr *Controller) updatePoolIdentifierForService(key MultiClusterServiceKey, rsKey resourceRef, svcPort intstr.IntOrString, poolName, partition, rsName, path string) {
	poolId := PoolIdentifier{
		poolName:  poolName,
		partition: partition,
		rsName:    rsName,
		path:      path,
		rsKey:     rsKey,
	}
	multiClusterSvcConfig := MultiClusterServiceConfig{svcPort: svcPort}
	if _, ok := ctlr.multiClusterResources.clusterSvcMap[key.clusterName]; !ok {
		ctlr.multiClusterResources.clusterSvcMap[key.clusterName] = make(map[MultiClusterServiceKey]map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})
	}
	if _, ok := ctlr.multiClusterResources.clusterSvcMap[key.clusterName][key]; !ok {
		ctlr.multiClusterResources.clusterSvcMap[key.clusterName][key] = make(map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})
	}
	if _, ok := ctlr.multiClusterResources.clusterSvcMap[key.clusterName][key][multiClusterSvcConfig]; !ok {
		ctlr.multiClusterResources.clusterSvcMap[key.clusterName][key][multiClusterSvcConfig] = make(map[PoolIdentifier]struct{})
	}
	ctlr.multiClusterResources.clusterSvcMap[key.clusterName][key][multiClusterSvcConfig][poolId] = struct{}{}
}

func (ctlr *Controller) updatePoolMembersForService(svcKey MultiClusterServiceKey, svcPortUpdated bool) {
	if serviceKey, ok := ctlr.multiClusterResources.clusterSvcMap[svcKey.clusterName]; ok {
		if svcPorts, ok2 := serviceKey[svcKey]; ok2 {
			for _, poolIds := range svcPorts {
				for poolId := range poolIds {
					rsCfg := ctlr.getVirtualServer(poolId.partition, poolId.rsName)
					if rsCfg == nil {
						continue
					}
					freshRsCfg := &ResourceConfig{}
					freshRsCfg.copyConfig(rsCfg)
					for index, pool := range freshRsCfg.Pools {
						if pool.Name == poolId.poolName && pool.Partition == poolId.partition {
							// Reprocess the resources if:
							// 1. service port has been updated or
							// 2. ServicePort.IntVal is 0 or ServicePortUsed is true which happens when endpoints have not been created at the time of resource processing,
							// cis needs to process the Resource again to make sure that servicePort in pool is updated with the target port,
							// which handled the scenario where VS/TS is process first then service(with different servicePort and target port) and app are created.
							if pool.ServicePort.IntVal == 0 || svcPortUpdated || pool.ServicePortUsed {
								switch poolId.rsKey.kind {
								case Route:
									// this case happens when a route does not contain a target port and service is created after route creation
									if routeGroup, found := ctlr.resources.invertedNamespaceLabelMap[poolId.rsKey.namespace]; found {
										// update the poolMem cache, clusterSvcResource & resource-svc maps
										ctlr.deleteResourceExternalClusterSvcRouteReference(poolId.rsKey)
										ctlr.processRoutes(routeGroup, false)
										return
									}
								case VirtualServer:
									var item interface{}
									inf, _ := ctlr.getNamespacedCRInformer(poolId.rsKey.namespace)
									item, _, _ = inf.vsInformer.GetIndexer().GetByKey(poolId.rsKey.namespace + "/" + poolId.rsKey.name)
									if item == nil {
										// This case won't arise
										continue
									}
									virtual, found := item.(*cisapiv1.VirtualServer)
									if found {
										_ = ctlr.processVirtualServers(virtual, false)
									}
									return
								case TransportServer:
									var item interface{}
									inf, _ := ctlr.getNamespacedCRInformer(poolId.rsKey.namespace)
									item, _, _ = inf.tsInformer.GetIndexer().GetByKey(poolId.rsKey.namespace + "/" + poolId.rsKey.name)
									if item == nil {
										// This case won't arise
										continue
									}
									virtual, found := item.(*cisapiv1.TransportServer)
									if found {
										_ = ctlr.processTransportServers(virtual, false)
									}
									return
								case IngressLink:
									var item interface{}
									inf, _ := ctlr.getNamespacedCRInformer(poolId.rsKey.namespace)
									item, _, _ = inf.ilInformer.GetIndexer().GetByKey(poolId.rsKey.namespace + "/" + poolId.rsKey.name)
									if item == nil {
										// This case won't arise
										continue
									}
									il, found := item.(*cisapiv1.IngressLink)
									if found {
										_ = ctlr.processIngressLink(il, false)
									}
									return
								}
							}
							ctlr.updatePoolMembersForResources(&pool)
							freshRsCfg.Pools[index] = pool
						}
					}
					freshRsCfg.MetaData.Active = false
					for _, pool := range freshRsCfg.Pools {
						if len(pool.Members) > 0 {
							freshRsCfg.MetaData.Active = true
							break
						}
					}
					_ = ctlr.resources.setResourceConfig(poolId.partition, poolId.rsName, freshRsCfg)
				}
			}
		}
	}
}

func (ctlr *Controller) fetchService(svcKey MultiClusterServiceKey) (error, *v1.Service) {
	var svc *v1.Service
	if svcKey.clusterName == "" {
		comInf, ok := ctlr.getNamespacedCommonInformer(svcKey.namespace)
		if !ok {
			return fmt.Errorf("Informer not found for service: %v", svcKey), svc
		}
		svcInf := comInf.svcInformer
		item, found, _ := svcInf.GetIndexer().GetByKey(svcKey.namespace + "/" + svcKey.serviceName)
		if !found {
			return fmt.Errorf("service not found: %v", svcKey), svc
		}
		svc, _ = item.(*v1.Service)
	} else {
		if namespaces, ok := ctlr.multiClusterPoolInformers[svcKey.clusterName]; ok {
			for namespace, poolInf := range namespaces {
				// namespace = "" for HA pair cluster if cis watches all namespaces
				if svcKey.namespace == namespace || namespace == "" {
					mSvcInf := poolInf.svcInformer
					mItem, mFound, _ := mSvcInf.GetIndexer().GetByKey(svcKey.namespace + "/" + svcKey.serviceName)
					if !mFound {
						return fmt.Errorf("[MultiCluster] Service %v not found!", svcKey), svc
					}
					svc, _ = mItem.(*v1.Service)
				}
			}

		}
	}
	if svc == nil {
		return fmt.Errorf("Service '%v' not found!", svcKey), svc
	}
	return nil, svc
}

// updatePoolMembersForResources updates the pool members for service present in the provided Pool
func (ctlr *Controller) updatePoolMembersForResources(pool *Pool) {
	var poolMembers []PoolMember
	var clsSvcPoolMemMap = make(map[MultiClusterServiceKey][]PoolMember)
	// for local cluster
	// Skip adding the pool members if adding pool member is restricted for local cluster in multi cluster mode
	if pool.Cluster == "" && !ctlr.isAddingPoolRestricted(pool.Cluster) {
		pms := ctlr.fetchPoolMembersForService(pool.ServiceName, pool.ServiceNamespace, pool.ServicePort,
			pool.NodeMemberLabel, "", pool.ConnectionLimit, pool.BigIPRouteDomain)
		poolMembers = append(poolMembers, pms...)
		if len(ctlr.clusterRatio) > 0 && !pool.SinglePoolRatioEnabled {
			pool.Members = pms
			return
		}

		if pool.SinglePoolRatioEnabled {
			clsSvcPoolMemMap[MultiClusterServiceKey{serviceName: pool.ServiceName, namespace: pool.ServiceNamespace,
				clusterName: ""}] = pms
		}
	}

	// for HA cluster pair service
	// Skip adding the pool members for the HA peer cluster if adding pool member is restricted for HA peer cluster in multi cluster mode
	// Process HA cluster in active / ratio mode only with - SinglePoolRatioEnabled(ts)
	if (ctlr.haModeType == Active || (len(ctlr.clusterRatio) > 0 && pool.SinglePoolRatioEnabled)) && ctlr.multiClusterConfigs.HAPairClusterName != "" &&
		!ctlr.isAddingPoolRestricted(ctlr.multiClusterConfigs.HAPairClusterName) {
		pms := ctlr.fetchPoolMembersForService(pool.ServiceName, pool.ServiceNamespace, pool.ServicePort,
			pool.NodeMemberLabel, ctlr.multiClusterConfigs.HAPairClusterName, pool.ConnectionLimit, pool.BigIPRouteDomain)
		poolMembers = append(poolMembers, pms...)

		if pool.SinglePoolRatioEnabled {
			clsSvcPoolMemMap[MultiClusterServiceKey{serviceName: pool.ServiceName, namespace: pool.ServiceNamespace,
				clusterName: ctlr.multiClusterConfigs.HAPairClusterName}] = pms
		}
	}

	// In case of ratio mode unique pools are created for each service so only update the pool members for this backend
	// pool associated with the HA peer cluster or external cluster and return
	if len(ctlr.clusterRatio) > 0 && !pool.SinglePoolRatioEnabled {
		poolMembers = append(poolMembers,
			ctlr.fetchPoolMembersForService(pool.ServiceName, pool.ServiceNamespace, pool.ServicePort,
				pool.NodeMemberLabel, pool.Cluster, pool.ConnectionLimit, pool.BigIPRouteDomain)...)
		pool.Members = poolMembers
		return
	}

	// For multiCluster services
	for _, mcs := range pool.MultiClusterServices {
		// Skip invalid extended service or if adding pool member is restricted for the cluster
		if ctlr.checkValidExtendedService(mcs) != nil || ctlr.isAddingPoolRestricted(mcs.ClusterName) {
			continue
		}
		// Update pool members for all the multi cluster services specified in the route annotations
		// Ensure cluster services of the HA pair cluster (if specified as multi cluster service in route annotations)
		// isn't considered for updating the pool members as it may lead to duplicate pool members as it may have been
		// already populated while updating the HA cluster pair service pool members above
		if _, ok := ctlr.multiClusterPoolInformers[mcs.ClusterName]; ok && ctlr.multiClusterConfigs.HAPairClusterName != mcs.ClusterName {
			pms := ctlr.fetchPoolMembersForService(mcs.SvcName, mcs.Namespace, mcs.ServicePort,
				pool.NodeMemberLabel, mcs.ClusterName, pool.ConnectionLimit, pool.BigIPRouteDomain)
			poolMembers = append(poolMembers, pms...)

			if pool.SinglePoolRatioEnabled {
				clsSvcPoolMemMap[MultiClusterServiceKey{serviceName: mcs.SvcName, namespace: mcs.Namespace,
					clusterName: mcs.ClusterName}] = pms
			}
		}
	}

	if !ctlr.isAddingPoolRestricted(pool.Cluster) {
		for _, svc := range pool.AlternateBackends {
			pms := ctlr.fetchPoolMembersForService(svc.Service, svc.ServiceNamespace, pool.ServicePort,
				pool.NodeMemberLabel, pool.Cluster, pool.ConnectionLimit, pool.BigIPRouteDomain)
			poolMembers = append(poolMembers, pms...)

			if pool.SinglePoolRatioEnabled {
				clsSvcPoolMemMap[MultiClusterServiceKey{serviceName: svc.Service, namespace: svc.ServiceNamespace,
					clusterName: pool.Cluster}] = pms
			}

			// for HA cluster pair service
			// Skip adding the pool members for the HA peer cluster if adding pool member is restricted for HA peer cluster in multi cluster mode
			if ctlr.multiClusterConfigs.HAPairClusterName != "" &&
				!ctlr.isAddingPoolRestricted(ctlr.multiClusterConfigs.HAPairClusterName) {
				pms := ctlr.fetchPoolMembersForService(svc.Service, svc.ServiceNamespace, pool.ServicePort,
					pool.NodeMemberLabel, ctlr.multiClusterConfigs.HAPairClusterName, pool.ConnectionLimit, pool.BigIPRouteDomain)
				poolMembers = append(poolMembers, pms...)

				if pool.SinglePoolRatioEnabled {
					clsSvcPoolMemMap[MultiClusterServiceKey{serviceName: svc.Service, namespace: svc.ServiceNamespace,
						clusterName: ctlr.multiClusterConfigs.HAPairClusterName}] = pms
				}
			}
		}
	}

	if pool.SinglePoolRatioEnabled {
		poolMembers = ctlr.updatePoolMemberWeights(clsSvcPoolMemMap, pool)
	}
	pool.Members = poolMembers
}

func (ctlr *Controller) updatePoolMemberWeights(svcMemMap map[MultiClusterServiceKey][]PoolMember, pool *Pool) []PoolMember {
	var totalWeight = 0
	var defaultWeight = 100
	var poolMem []PoolMember
	var ratio int

	// in non ratio mode don't do any ratio calculation
	// assign simple weights
	if len(ctlr.clusterRatio) == 0 {
		// for each service -  pool members
		for svcKey, plMem := range svcMemMap {
			// for local or ha cluster check config
			if (svcKey.clusterName == pool.Cluster || svcKey.clusterName == ctlr.multiClusterConfigs.HAPairClusterName) && svcKey.serviceName == pool.ServiceName &&
				svcKey.namespace == pool.ServiceNamespace {
				if pool.Weight > 0 {
					ratio = int(float32(pool.Weight) / float32(len(plMem)))
				}
				for idx, _ := range plMem {
					if pool.Weight == 0 {
						plMem[idx].AdminState = "disable"
					} else {
						plMem[idx].Ratio = ratio
					}
				}
				poolMem = append(poolMem, plMem...)
			}

			for _, svc := range pool.AlternateBackends {
				// for local or ha cluster check config
				if (svcKey.clusterName == pool.Cluster || svcKey.clusterName == ctlr.multiClusterConfigs.HAPairClusterName) && svcKey.serviceName == svc.Service &&
					svcKey.namespace == svc.ServiceNamespace {
					if svc.Weight > 0 {
						ratio = int(float32(svc.Weight) / float32(len(plMem)))
					}
					for idx, _ := range plMem {
						if svc.Weight == 0 {
							plMem[idx].AdminState = "disable"
						} else {
							plMem[idx].Ratio = ratio
						}
					}
					poolMem = append(poolMem, plMem...)
					break
				}
			}

			for _, mcSvc := range pool.MultiClusterServices {
				if svcKey.clusterName == mcSvc.ClusterName && svcKey.serviceName == mcSvc.SvcName &&
					svcKey.namespace == mcSvc.Namespace {
					if mcSvc.Weight == nil {
						ratio = int(float32(defaultWeight) / float32(len(plMem)))
					} else {
						ratio = int(float32(*mcSvc.Weight) / float32(len(plMem)))
					}
					for idx, _ := range plMem {
						if ratio == 0 {
							plMem[idx].AdminState = "disable"
						} else {
							plMem[idx].Ratio = ratio
						}
					}
					poolMem = append(poolMem, plMem...)
					break
				}
			}
		}
	} else {
		// First we calculate the total service weights, total ratio and the total number of backends

		// store the localClusterPool state and HA peer cluster pool state in advance for further processing
		localClusterPoolRestricted := ctlr.isAddingPoolRestricted(ctlr.multiClusterConfigs.LocalClusterName)
		hAPeerClusterPoolRestricted := true // By default, skip HA cluster service backend
		// If HA peer cluster is present then update the hAPeerClusterPoolRestricted state based on the cluster pool state
		if ctlr.multiClusterConfigs.HAPairClusterName != "" {
			hAPeerClusterPoolRestricted = ctlr.isAddingPoolRestricted(ctlr.multiClusterConfigs.HAPairClusterName)
		}
		// factor is used to track whether both the primary and secondary cluster needs to be considered or none/one/both of
		// them have to be considered( this is based on multiCluster mode and cluster pool state)
		factor := 0
		if !localClusterPoolRestricted {
			factor++ // it ensures local cluster services associated with the VS are considered
		}
		if ctlr.multiClusterConfigs.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
			factor++ // it ensures HA peer cluster services associated with the VS are considered
		}
		// clusterSvcMap helps in ensuring the cluster ratio is considered only if there is at least one service associated
		// with the VS running in that cluster
		clusterSvcMap := make(map[string]struct{})
		clusterSvcMap[""] = struct{}{} // "" is used as key for the local cluster where this CIS is running
		// totalClusterRatio stores the sum total of all the ratio of clusters contributing services to this VS
		totalClusterRatio := 0.0
		// totalSvcWeights stores the sum total of all the weights of services associated with this VS
		totalSvcWeights := 0.0
		// Include local cluster ratio in the totalClusterRatio calculation
		if !localClusterPoolRestricted {
			totalClusterRatio += float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.LocalClusterName])
		}
		// Include HA partner cluster ratio in the totalClusterRatio calculation
		if ctlr.multiClusterConfigs.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
			totalClusterRatio += float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.HAPairClusterName])
		}
		// if adding pool member is restricted for both local or HA partner cluster then skip adding service weights for both the clusters
		if !localClusterPoolRestricted || !hAPeerClusterPoolRestricted {
			if pool.Weight > 0 {
				totalSvcWeights += float64(pool.Weight) * float64(factor)
			} else {
				totalSvcWeights += float64(defaultWeight) * float64(factor)
			}
		}

		if pool.Weight > 0 {
			totalWeight += int(pool.Weight)
		}

		for _, svc := range pool.AlternateBackends {
			if svc.Weight > 0 {
				totalWeight += int(svc.Weight)
			}
		}

		for _, svc := range pool.MultiClusterServices {
			if ctlr.checkValidExtendedService(svc) != nil || ctlr.isAddingPoolRestricted(svc.ClusterName) {
				continue
			}
			if _, ok := clusterSvcMap[svc.ClusterName]; !ok {
				if r, ok := ctlr.clusterRatio[svc.ClusterName]; ok {
					totalClusterRatio += float64(*r)
				}
			}
			if svc.Weight != nil {
				totalWeight += *svc.Weight
			} else {
				totalWeight += defaultWeight
			}
		}

		// Calibrate totalSvcWeights and totalClusterRatio if any of these is 0 to avoid division by zero
		if totalWeight == 0 {
			totalWeight = 1
		}
		if totalClusterRatio == 0 {
			totalClusterRatio = 1
		}
		// Process VS spec primary service
		// for each service -  pool members
		for svcKey, plMem := range svcMemMap {
			// for local or ha cluster check config
			if (svcKey.clusterName == pool.Cluster || svcKey.clusterName == ctlr.multiClusterConfigs.HAPairClusterName) && svcKey.serviceName == pool.ServiceName &&
				svcKey.namespace == pool.ServiceNamespace {
				if pool.Weight > 0 {
					cluster := svcKey.clusterName
					if cluster == "" {
						cluster = ctlr.multiClusterConfigs.LocalClusterName
					}
					ratio = int((float64(pool.Weight) / float64(totalWeight*len(plMem))) * (float64(*ctlr.clusterRatio[cluster]) / totalClusterRatio) * 100)
				}
				for idx, _ := range plMem {
					if pool.Weight == 0 {
						plMem[idx].AdminState = "disable"
					} else {
						plMem[idx].Ratio = ratio
					}
				}
				poolMem = append(poolMem, plMem...)
			}

			for _, svc := range pool.AlternateBackends {
				// for local or ha cluster check config
				if (svcKey.clusterName == pool.Cluster || svcKey.clusterName == ctlr.multiClusterConfigs.HAPairClusterName) && svcKey.serviceName == svc.Service &&
					svcKey.namespace == svc.ServiceNamespace {
					if svc.Weight > 0 {
						cluster := svcKey.clusterName
						if cluster == "" {
							cluster = ctlr.multiClusterConfigs.LocalClusterName
						}
						ratio = int((float64(svc.Weight) / float64(totalWeight*len(plMem))) * (float64(*ctlr.clusterRatio[cluster]) / totalClusterRatio) * 100)
					}
					for idx, _ := range plMem {
						if svc.Weight == 0 {
							plMem[idx].AdminState = "disable"
						} else {
							plMem[idx].Ratio = ratio
						}
					}
					poolMem = append(poolMem, plMem...)
					break
				}
			}

			for _, mcSvc := range pool.MultiClusterServices {
				if svcKey.clusterName == mcSvc.ClusterName && svcKey.serviceName == mcSvc.SvcName &&
					svcKey.namespace == mcSvc.Namespace {
					if mcSvc.Weight == nil {
						ratio = int((float64(defaultWeight) / float64(totalWeight*len(plMem))) * (float64(*ctlr.clusterRatio[svcKey.clusterName]) / totalClusterRatio) * 100)
					} else {
						ratio = int((float64(*mcSvc.Weight) / float64(totalWeight*len(plMem))) * (float64(*ctlr.clusterRatio[svcKey.clusterName]) / totalClusterRatio) * 100)
					}
					for idx, _ := range plMem {
						if ratio == 0 {
							plMem[idx].AdminState = "disable"
						} else {
							plMem[idx].Ratio = ratio
						}
					}
					poolMem = append(poolMem, plMem...)
					break
				}
			}
		}

	}

	return poolMem
}

// fetchPoolMembersForService returns pool members associated with a service created in specified cluster
func (ctlr *Controller) fetchPoolMembersForService(serviceName string, serviceNamespace string,
	servicePort intstr.IntOrString, nodeMemberLabel string, clusterName string, podConnections int32, bigipRouteDomain int32) []PoolMember {
	svcKey := MultiClusterServiceKey{
		serviceName: serviceName,
		namespace:   serviceNamespace,
		clusterName: clusterName,
	}
	if _, ok := ctlr.resources.poolMemCache[svcKey]; !ok {
		log.Debugf("Adding service '%v' in CIS cache %v", svcKey, getClusterLog(clusterName))
		ctlr.resources.poolMemCache[svcKey] = &poolMembersInfo{
			memberMap: make(map[portRef][]PoolMember),
		}
	}
	err, svc := ctlr.fetchService(svcKey)
	if err != nil {
		log.Warningf("service '%v' %s not found", svcKey, getClusterLog(clusterName))
	}
	var poolMembers []PoolMember
	var svcOk bool
	// check for load balancer class in service spec
	if svc != nil && svc.Spec.Type == v1.ServiceTypeLoadBalancer {
		err, svcOk = ctlr.shouldProcessServiceTypeLB(svc)
		if err != nil {
			log.Warningf("%v", err)
		}
	} else {
		svcOk = true
	}
	if svc != nil && svcOk {
		_ = ctlr.processService(svc, clusterName)
		// update the nlpStore cache with pods and their node annotations
		if ctlr.PoolMemberType == NodePortLocal {
			pods := ctlr.GetPodsForService(svcKey.namespace, svcKey.serviceName, svcKey.clusterName, true)
			for _, pod := range pods {
				ctlr.processPod(pod, false)
			}
		}
		poolMembers = append(poolMembers, ctlr.getPoolMembersForService(svcKey, servicePort, nodeMemberLabel)...)
	}

	if bigipRouteDomain > 0 {
		for index, _ := range poolMembers {
			poolMembers[index].Address = fmt.Sprintf("%s%%%d", poolMembers[index].Address, bigipRouteDomain)
		}
	}

	// Update the cluster admin state for pool members if multi cluster mode is enabled
	ctlr.updatePoolMembersConfig(&poolMembers, clusterName, podConnections)

	// Sort pool members in NPL mode.
	// Antrea allocates port numbers for each pod via node IP annotations.
	// Pool members order is not guaranteed, causing reconfiguration.
	// In other modes like ClusterIP and NodePort, the service port remains the same.
	if ctlr.PoolMemberType == NodePortLocal {
		//Sort the pool members slice by the Port field
		sort.SliceStable(poolMembers, func(i, j int) bool {
			return poolMembers[i].Port < poolMembers[j].Port
		})
	}

	return poolMembers
}

func (ctlr *Controller) getPoolMembersForEndpoints(mSvcKey MultiClusterServiceKey, servicePort intstr.IntOrString) []PoolMember {
	var poolMembers []PoolMember
	poolMemInfo, ok := ctlr.resources.poolMemCache[mSvcKey]
	if !ok || len(poolMemInfo.memberMap) == 0 {
		log.Errorf("[CORE]Endpoints could not be fetched for service %v with targetPort  %v:%v%v", mSvcKey, servicePort.Type, servicePort.IntVal, servicePort.StrVal)
		return poolMembers
	}
	for ref, mems := range poolMemInfo.memberMap {
		if ref.name != servicePort.StrVal && ref.port != servicePort.IntVal {
			continue
		}
		poolMembers = append(poolMembers, mems...)
	}
	return poolMembers
}

func (ctlr *Controller) getPoolMembersForService(mSvcKey MultiClusterServiceKey, servicePort intstr.IntOrString, nodeMemberLabel string) []PoolMember {
	var poolMembers []PoolMember
	poolMemInfo, _ := ctlr.resources.poolMemCache[mSvcKey]
	var poolMemType = ctlr.PoolMemberType
	if poolMemType == Auto {
		poolMemType = string(poolMemInfo.svcType)
	}

	switch poolMemType {
	case string(v1.ServiceTypeNodePort), NodePort, string(v1.ServiceTypeLoadBalancer):
		if !(poolMemInfo.svcType == v1.ServiceTypeNodePort ||
			poolMemInfo.svcType == v1.ServiceTypeLoadBalancer) {
			log.Errorf("Requested service backend %s not of NodePort or LoadBalancer type",
				mSvcKey)
			return poolMembers
		}
		// In non multi-cluster mode return empty poolMembers so the nodes can be removed from bigip, when app is scaled down to zero
		// In multi-cluster mode and next gen routes as the endpoint informers are not started, we won't be updating the nodes when app is scaled down to zero.
		if ctlr.multiClusterMode == "" {
			epPoolMembers := ctlr.getPoolMembersForEndpoints(mSvcKey, servicePort)
			if len(epPoolMembers) == 0 {
				return epPoolMembers
			}
		}
		for _, svcPort := range poolMemInfo.portSpec {
			// if target port is a named port then we need to match it with service port name, otherwise directly match with the target port
			// also we need to match the resource service port with service's actual port
			if (servicePort.StrVal != "" && svcPort.Name == servicePort.StrVal) || svcPort.TargetPort == servicePort || svcPort.Port == servicePort.IntVal {
				mems := ctlr.getEndpointsForNodePort(svcPort.NodePort, nodeMemberLabel, mSvcKey.clusterName)
				poolMembers = append(poolMembers, mems...)
			}
		}
	case Cluster, string(v1.ServiceTypeClusterIP):
		return ctlr.getPoolMembersForEndpoints(mSvcKey, servicePort)
	case NodePortLocal:
		if poolMemInfo.svcType == v1.ServiceTypeNodePort {
			log.Debugf("Requested service backend %s is of type NodePort is not valid for nodeportlocal mode.",
				mSvcKey)
			return poolMembers
		}
		// In non multi-cluster mode return empty poolMembers so the nodes can be removed from bigip, when app is scaled down to zero
		// In multi-cluster mode and next gen routes as the endpoint informers are not started, we won't be updating the nodes when app is scaled down to zero.
		if ctlr.multiClusterMode == "" {
			epPoolMembers := ctlr.getPoolMembersForEndpoints(mSvcKey, servicePort)
			if len(epPoolMembers) == 0 {
				return epPoolMembers
			}
		}
		pods := ctlr.GetPodsForService(mSvcKey.namespace, mSvcKey.serviceName, mSvcKey.clusterName, true)
		if pods != nil {
			for _, svcPort := range poolMemInfo.portSpec {
				// if target port is a named port then we need to match it with service port name, otherwise directly match with the target port
				// also we need to match the resource service port with service's actual port
				if (servicePort.StrVal != "" && svcPort.Name == servicePort.StrVal) || svcPort.TargetPort == servicePort || svcPort.Port == servicePort.IntVal {
					podPort := svcPort.TargetPort
					mems := ctlr.getEndpointsForNPL(podPort, pods)
					poolMembers = append(poolMembers, mems...)
				}
			}
		}
	}
	//check if endpoints are found
	if len(poolMembers) == 0 {
		log.Errorf("Pool Members could not be fetched for service %v with targetPort %v:%v%v", mSvcKey, servicePort.Type, servicePort.IntVal, servicePort.StrVal)
	}
	return poolMembers
}

// getEndpointsForNodePort returns members.
func (ctlr *Controller) getEndpointsForNodePort(
	nodePort int32,
	nodeMemberLabel, clusterName string,
) []PoolMember {
	var nodes []Node
	if nodeMemberLabel == "" {
		nodes = ctlr.getNodesFromCache(clusterName)
	} else {
		nodes = ctlr.getNodesWithLabel(nodeMemberLabel, clusterName)
	}
	var members []PoolMember
	for _, v := range nodes {
		member := PoolMember{
			MemberType: NodePort,
			Address:    v.Addr,
			Port:       nodePort,
			Session:    "user-enabled",
		}
		members = append(members, member)
	}
	return members
}

// getEndpointsForNPL returns members.
func (ctlr *Controller) getEndpointsForNPL(
	targetPort intstr.IntOrString,
	pods []*v1.Pod,
) []PoolMember {
	var members []PoolMember
	for _, pod := range pods {
		anns, found := ctlr.resources.nplStore[pod.Namespace+"/"+pod.Name]
		if !found {
			continue
		}
		var podPort int32
		//Support for named targetPort
		if targetPort.StrVal != "" {
			targetPortStr := targetPort.StrVal
			//Get the containerPort matching targetPort from pod spec.
			for _, container := range pod.Spec.Containers {
				for _, port := range container.Ports {
					portStr := port.Name
					if targetPortStr == portStr {
						podPort = port.ContainerPort
					}
				}
			}
		} else {
			// targetPort with int value
			podPort = targetPort.IntVal
		}
		for _, annotation := range anns {
			if annotation.PodPort == podPort {
				member := PoolMember{
					Address: annotation.NodeIP,
					Port:    annotation.NodePort,
					Session: "user-enabled",
				}
				members = append(members, member)
			}
		}
	}
	return members
}

// containsNode returns true for a valid node.
func containsNode(nodes []Node, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}

// processTransportServers takes the Transport Server as input and processes all
// associated TransportServers to create a resource config(Internal DataStructure)
// or to update if exists already.
func (ctlr *Controller) processTransportServers(
	virtual *cisapiv1.TransportServer,
	isTSDeleted bool,
) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing transport servers %+v (%v)",
			virtual, endTime.Sub(startTime))
	}()

	// Skip validation for a deleted Virtual Server
	if !isTSDeleted {
		// check if the virutal server matches all the requirements.
		vkey := virtual.ObjectMeta.Namespace + "/" + virtual.ObjectMeta.Name
		valid := ctlr.checkValidTransportServer(virtual)
		if false == valid {
			log.Errorf("TransportServer %s, is not valid",
				vkey)
			return nil
		}
	}
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.TransportServer[virtual.ObjectMeta.Namespace] = len(ctlr.getAllTransportServers(virtual.Namespace))
	ctlr.TeemData.Unlock()

	if isTSDeleted {
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.TransportServer[virtual.ObjectMeta.Namespace]--
		ctlr.TeemData.Unlock()
	}

	var allVirtuals []*cisapiv1.TransportServer
	if virtual.Spec.HostGroup != "" {
		// grouping by hg across all namespaces
		allVirtuals = ctlr.getAllTSFromMonitoredNamespaces()
	} else {
		allVirtuals = ctlr.getAllTransportServers(virtual.ObjectMeta.Namespace)
	}
	isValidTS := ctlr.validateTSWithSameVSAddress(virtual, allVirtuals, isTSDeleted)
	if !isValidTS {
		return nil
	}

	var ip string
	var key string
	var status int
	var altErr string
	partition := ctlr.getCRPartition(virtual.Spec.Partition)
	key = ctlr.ipamClusterLabel + virtual.ObjectMeta.Namespace + "/" + virtual.ObjectMeta.Name + "_ts"
	if ctlr.ipamCli != nil {
		if virtual.Spec.HostGroup != "" {
			key = ctlr.ipamClusterLabel + virtual.Spec.HostGroup + "_hg"
		}
		if isTSDeleted && virtual.Spec.VirtualServerAddress == "" {
			ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, "", key)
		} else if virtual.Spec.VirtualServerAddress != "" {
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ip, status = ctlr.requestIP(virtual.Spec.IPAMLabel, "", key)

			switch status {
			case NotEnabled:
				altErr = "[IPAM] IPAM Custom Resource Not Available"
				log.Error(altErr)
				ctlr.updateResourceStatus(TransportServer, virtual, "", "", errors.New(altErr))
				return nil
			case InvalidInput:
				altErr = fmt.Sprintf("[IPAM] IPAM Invalid IPAM Label: %v for Transport Server: %s/%s",
					virtual.Spec.IPAMLabel, virtual.Namespace, virtual.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(TransportServer, virtual, "", "", errors.New(altErr))
				return nil
			case NotRequested:
				altErr = "[IPAM] unable to make IPAM Request, will be re-requested soon"
				log.Error(altErr)
				ctlr.updateResourceStatus(TransportServer, virtual, "", "", errors.New(altErr))
				return fmt.Errorf("%s", altErr)
			case Requested:
				altErr = fmt.Sprintf("[IPAM] IP address requested for Transport Server: %s/%s", virtual.Namespace, virtual.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(TransportServer, virtual, "", "", errors.New(altErr))
				return nil
			}
		}
	} else {
		if virtual.Spec.VirtualServerAddress == "" {
			altErr = "no VirtualServer address in TS or IPAM found"
			log.Error(altErr)
			ctlr.updateResourceStatus(TransportServer, virtual, "", "", errors.New(altErr))
			return fmt.Errorf("%s", altErr)
		}
		ip = virtual.Spec.VirtualServerAddress
	}
	// Updating the virtual server IP Address status
	virtual.Status.VSAddress = ip
	var rsName string
	if virtual.Spec.VirtualServerName != "" {
		rsName = formatCustomVirtualServerName(
			virtual.Spec.VirtualServerName,
			virtual.Spec.VirtualServerPort,
		)
	} else {
		rsName = formatVirtualServerName(
			ip,
			virtual.Spec.VirtualServerPort,
		)
	}

	if isTSDeleted {
		rsMap := ctlr.resources.getPartitionResourceMap(partition)
		var hostnames []string
		if _, ok := rsMap[rsName]; ok {
			hostnames = rsMap[rsName].MetaData.hosts
		}

		ctlr.deleteVirtualServer(partition, rsName)
		if len(hostnames) > 0 {
			ctlr.ProcessAssociatedExternalDNS(hostnames)
		}

		return nil
	}

	rsCfg := &ResourceConfig{}
	rsCfg.Virtual.Partition = partition
	rsCfg.MetaData.ResourceType = TransportServer
	rsCfg.Virtual.Enabled = true
	rsCfg.Virtual.Name = rsName
	rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, virtual.Spec.Host)
	rsCfg.Virtual.IpProtocol = virtual.Spec.Type
	rsCfg.MetaData.baseResources = make(map[string]string)
	if virtual.Spec.BigIPRouteDomain > 0 {
		if ctlr.PoolMemberType == Cluster {
			log.Warning("bigipRouteDomain is not supported in cluster mode")
		} else {
			rsCfg.Virtual.BigIPRouteDomain = virtual.Spec.BigIPRouteDomain
			rsCfg.Virtual.SetVirtualAddress(
				fmt.Sprintf("%s%%%d", ip, virtual.Spec.BigIPRouteDomain),
				virtual.Spec.VirtualServerPort,
			)
		}
	} else {
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			virtual.Spec.VirtualServerPort,
		)
	}
	plc, err := ctlr.getPolicyFromTransportServer(virtual)
	if plc != nil {
		err := ctlr.handleTSResourceConfigForPolicy(rsCfg, plc)
		if err != nil {
			log.Errorf("%v", err)
			ctlr.updateResourceStatus(TransportServer, virtual, "", "", err)
			return nil
		}
	}
	if err != nil {
		log.Errorf("%v", err)
		ctlr.updateResourceStatus(TransportServer, virtual, "", "", err)
		return nil
	}

	log.Debugf("Processing Transport Server %s for port %v",
		virtual.ObjectMeta.Name, virtual.Spec.VirtualServerPort)
	rsCfg.MetaData.baseResources[virtual.ObjectMeta.Namespace+"/"+virtual.ObjectMeta.Name] = TransportServer
	err = ctlr.prepareRSConfigFromTransportServer(
		rsCfg,
		virtual,
	)
	if err != nil {
		log.Errorf("Cannot Publish TransportServer %s", virtual.ObjectMeta.Name)
		ctlr.updateResourceStatus(TransportServer, virtual, "", "", err)
		return nil
	}
	// handle pool settings from policy cr
	if plc != nil {
		if plc.Spec.PoolSettings != (cisapiv1.PoolSettingsSpec{}) {
			err := ctlr.handlePoolResourceConfigForPolicy(rsCfg, plc)
			if err != nil {
				log.Errorf("%v", err)
				ctlr.updateResourceStatus(TransportServer, virtual, "", "", err)
				return nil
			}
		}
	}
	// Add TS resource key to processedNativeResources to mark it as processed
	ctlr.resources.processedNativeResources[resourceRef{
		kind:      TransportServer,
		namespace: virtual.Namespace,
		name:      virtual.Name,
	}] = struct{}{}

	rsMap := ctlr.resources.getPartitionResourceMap(partition)
	rsMap[rsName] = rsCfg
	ctlr.updateResourceStatus(TransportServer, virtual, ip, "", nil)
	if len(rsCfg.MetaData.hosts) > 0 {
		ctlr.ProcessAssociatedExternalDNS(rsCfg.MetaData.hosts)
	}

	return nil
}

// getAllTSFromMonitoredNamespaces returns list of all valid TransportServers in monitored namespaces.
func (ctlr *Controller) getAllTSFromMonitoredNamespaces() []*cisapiv1.TransportServer {
	var allVirtuals []*cisapiv1.TransportServer
	if ctlr.watchingAllNamespaces() {
		return ctlr.getAllTransportServers("")
	}
	for ns := range ctlr.namespaces {
		allVirtuals = append(allVirtuals, ctlr.getAllTransportServers(ns)...)
	}
	return allVirtuals
}

// getAllTransportServers returns list of all valid TransportServers in rkey namespace.
func (ctlr *Controller) getAllTransportServers(namespace string) []*cisapiv1.TransportServer {
	var allVirtuals []*cisapiv1.TransportServer

	crInf, ok := ctlr.getNamespacedCRInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	var orderedTSs []interface{}
	var err error

	if namespace == "" {
		orderedTSs = crInf.tsInformer.GetIndexer().List()
	} else {
		orderedTSs, err = crInf.tsInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("Unable to get list of TransportServers for namespace '%v': %v",
				namespace, err)
			return nil
		}
	}
	for _, obj := range orderedTSs {
		vs := obj.(*cisapiv1.TransportServer)
		// TODO Validate the TransportServers List to check if all the vs are valid.
		allVirtuals = append(allVirtuals, vs)
	}

	return allVirtuals
}

// getAllLBServices returns list of all valid LB Services in rkey namespace.
func (ctlr *Controller) getAllLBServices(namespace string) []*v1.Service {
	var allLBServices []*v1.Service

	comInf, ok := ctlr.getNamespacedCommonInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	var orderedSVCs []interface{}
	var err error

	if namespace == "" {
		orderedSVCs = comInf.svcInformer.GetIndexer().List()
	} else {
		orderedSVCs, err = comInf.svcInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("Unable to get list of Services for namespace '%v': %v",
				namespace, err)
			return nil
		}
	}
	for _, obj := range orderedSVCs {
		svc := obj.(*v1.Service)
		if _, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
			allLBServices = append(allLBServices, svc)
		}
	}

	return allLBServices
}

func (ctlr *Controller) processLBServices(
	svc *v1.Service,
	isSVCDeleted bool,
) error {

	ip, ok1 := svc.Annotations[LBServiceIPAnnotation]
	ipamLabel, ok2 := svc.Annotations[LBServiceIPAMLabelAnnotation]
	if !ok1 && !ok2 {
		log.Debugf("Service %v/%v does not have either of annotation: %v, annotation:%v, continuing.",
			svc.Namespace,
			svc.Name,
			LBServiceIPAMLabelAnnotation,
			LBServiceIPAnnotation,
		)
		return nil
	}
	svcKey := ctlr.ipamClusterLabel + svc.Namespace + "/" + svc.Name + "_svc"
	// ip annotation has more preference than ipam
	if !ok1 {
		if ctlr.ipamCli == nil {
			log.Warningf("[IPAM] IPAM is not enabled, Unable to process Services of Type LoadBalancer")
			return nil
		}

		var status int
		if isSVCDeleted {
			ip = ctlr.releaseIP(ipamLabel, "", svcKey)
		} else {
			ip, status = ctlr.requestIP(ipamLabel, "", svcKey)

			switch status {
			case NotEnabled:
				log.Debug("[IPAM] IPAM Custom Resource Not Available")
				return nil
			case InvalidInput:
				log.Debugf("[IPAM] IPAM Invalid IPAM Label: %v for service: %s/%s", ipamLabel, svc.Namespace, svc.Name)
				return nil
			case NotRequested:
				return fmt.Errorf("[IPAM] unable to make IPAM Request, will be re-requested soon")
			case Requested:
				log.Debugf("[IPAM] IP address requested for service: %s/%s", svc.Namespace, svc.Name)
				return nil
			}
		}
	}

	if !isSVCDeleted {
		ctlr.setLBServiceIngressStatus(svc, ip)
	} else {
		ctlr.unSetLBServiceIngressStatus(svc, ip)
	}

	for _, portSpec := range svc.Spec.Ports {

		log.Debugf("Processing Service Type LB %s for port %v",
			svc.ObjectMeta.Name, portSpec)

		rsName := AS3NameFormatter(fmt.Sprintf("vs_lb_svc_%s_%s_%s_%v", svc.Namespace, svc.Name, ip, portSpec.Port))
		if isSVCDeleted {
			rsMap := ctlr.resources.getPartitionResourceMap(ctlr.Partition)
			var hostnames []string
			if _, ok := rsMap[rsName]; ok {
				hostnames = rsMap[rsName].MetaData.hosts
			}
			ctlr.deleteVirtualServer(ctlr.Partition, rsName)
			if len(hostnames) > 0 {
				ctlr.ProcessAssociatedExternalDNS(hostnames)
			}
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = ctlr.Partition
		rsCfg.Virtual.IpProtocol = strings.ToLower(string(portSpec.Protocol))
		rsCfg.MetaData.ResourceType = TransportServer
		rsCfg.MetaData.namespace = svc.ObjectMeta.Namespace
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			portSpec.Port,
		)
		//set host if annotation present on service
		host, ok := svc.Annotations[LBServiceHostAnnotation]
		if ok {
			rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, host)
		}
		processingError := false
		// Handle policy
		plc, err := ctlr.getPolicyFromLBService(svc)
		if plc != nil {
			err := ctlr.handleTSResourceConfigForPolicy(rsCfg, plc)
			if err != nil {
				log.Errorf("%v", err)
				processingError = true
			}
		}
		if err != nil {
			processingError = true
			log.Errorf("%v", err)
		}

		if processingError {
			log.Errorf("Cannot Publish LB Service %s", svc.ObjectMeta.Name)
			break
		}

		_ = ctlr.prepareRSConfigFromLBService(rsCfg, svc, portSpec)

		rsMap := ctlr.resources.getPartitionResourceMap(ctlr.Partition)

		rsMap[rsName] = rsCfg
		if len(rsCfg.MetaData.hosts) > 0 {
			ctlr.ProcessAssociatedExternalDNS(rsCfg.MetaData.hosts)
		}
	}

	return nil
}

func (ctlr *Controller) processService(
	svc *v1.Service,
	clusterName string,
) error {
	namespace := svc.Namespace
	svcKey := MultiClusterServiceKey{
		serviceName: svc.Name,
		namespace:   svc.Namespace,
		clusterName: clusterName,
	}

	pmi, _ := ctlr.resources.poolMemCache[svcKey]
	pmi.portSpec = svc.Spec.Ports
	pmi.svcType = svc.Spec.Type
	nodes := ctlr.getNodesFromCache(svcKey.clusterName)
	var eps *v1.Endpoints
	if clusterName == "" {
		comInf, ok := ctlr.getNamespacedCommonInformer(namespace)
		if !ok {
			log.Errorf("Informer not found for namespace: %v %v", namespace, getClusterLog(clusterName))
			return fmt.Errorf("unable to process Service: %v %v", svcKey, getClusterLog(clusterName))
		}
		if comInf.epsInformer != nil {
			item, found, _ := comInf.epsInformer.GetIndexer().GetByKey(svc.Namespace + "/" + svc.Name)
			if !found {
				return fmt.Errorf("Endpoints for service %v %v not found!", svcKey, getClusterLog(clusterName))
			}
			eps, _ = item.(*v1.Endpoints)
		}
	} else {
		if _, ok := ctlr.multiClusterPoolInformers[svcKey.clusterName]; ok {
			var poolInf *MultiClusterPoolInformer
			var found bool
			if poolInf, found = ctlr.multiClusterPoolInformers[clusterName][""]; !found {
				poolInf, found = ctlr.multiClusterPoolInformers[clusterName][svcKey.namespace]
			}
			if !found {
				return fmt.Errorf("[MultiCluster] Informer not found for namespace: %v in cluster: %s", svcKey.namespace, clusterName)
			}

			if poolInf.epsInformer != nil {
				mItem, mFound, _ := poolInf.epsInformer.GetIndexer().GetByKey(svcKey.namespace + "/" + svcKey.serviceName)
				if !mFound {
					return fmt.Errorf("[MultiCluster] Endpoints for service %v %v not found!", svcKey, getClusterLog(clusterName))
				}
				eps, _ = mItem.(*v1.Endpoints)
			}
		}
	}

	if eps != nil {
		if len(eps.Subsets) == 0 {
			for _, port := range pmi.portSpec {
				portKey := portRef{name: port.Name, port: port.TargetPort.IntVal}
				var members []PoolMember
				pmi.memberMap[portKey] = members
			}
		}
		for _, subset := range eps.Subsets {
			for _, p := range subset.Ports {
				var members []PoolMember
				for _, addr := range subset.Addresses {
					// Checking for headless services
					if svc.Spec.ClusterIP == "None" || (addr.NodeName != nil && containsNode(nodes, *addr.NodeName)) {
						member := PoolMember{
							Address: addr.IP,
							Port:    p.Port,
							Session: "user-enabled",
						}
						members = append(members, member)
					}
				}
				portKey := portRef{name: p.Name, port: p.Port}
				pmi.memberMap[portKey] = members
			}
		}
	} else {
		for _, port := range pmi.portSpec {
			portKey := portRef{name: port.Name, port: port.TargetPort.IntVal}
			// currently we are adding the empty pool member as nodes will be updated at the time of Pool processing
			// nodes are updated based on the node selector label which is available in the Pool Resource
			var members []PoolMember
			pmi.memberMap[portKey] = members
		}
	}
	ctlr.resources.poolMemCache[svcKey] = pmi
	return nil
}

func (ctlr *Controller) processExternalDNS(edns *cisapiv1.ExternalDNS, isDelete bool) {

	if gtmPartitionConfig, ok := ctlr.resources.gtmConfig[DEFAULT_GTM_PARTITION]; ok {
		if processedWIP, ok := gtmPartitionConfig.WideIPs[edns.Spec.DomainName]; ok {
			if processedWIP.UID != string(edns.UID) {
				log.Errorf("EDNS with same domain name %s present", edns.Spec.DomainName)
				return
			}
		}
	}

	if isDelete {
		if _, ok := ctlr.resources.gtmConfig[DEFAULT_GTM_PARTITION]; !ok {
			return
		}

		delete(ctlr.resources.gtmConfig[DEFAULT_GTM_PARTITION].WideIPs, edns.Spec.DomainName)
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.ExternalDNS[edns.Namespace]--
		ctlr.TeemData.Unlock()
		return
	}

	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.ExternalDNS[edns.Namespace] = len(ctlr.getAllExternalDNS(edns.Namespace))
	ctlr.TeemData.Unlock()

	wip := WideIP{
		DomainName:         edns.Spec.DomainName,
		RecordType:         edns.Spec.DNSRecordType,
		LBMethod:           edns.Spec.LoadBalanceMethod,
		PersistenceEnabled: edns.Spec.PersistenceEnabled,
		PersistCidrIPv4:    edns.Spec.PersistCidrIPv4,
		PersistCidrIPv6:    edns.Spec.PersistCidrIPv6,
		TTLPersistence:     edns.Spec.TTLPersistence,
		UID:                string(edns.UID),
	}

	if edns.Spec.ClientSubnetPreferred != nil {
		wip.ClientSubnetPreferred = edns.Spec.ClientSubnetPreferred
	}

	if edns.Spec.TTLPersistence == 0 {
		wip.TTLPersistence = 3600
	}
	if edns.Spec.PersistCidrIPv6 == 0 {
		wip.PersistCidrIPv6 = 128
	}
	if edns.Spec.PersistCidrIPv4 == 0 {
		wip.PersistCidrIPv4 = 32
	}

	if edns.Spec.DNSRecordType == "" {
		wip.RecordType = "A"
	}
	if edns.Spec.LoadBalanceMethod == "" {
		wip.LBMethod = "round-robin"
	}

	log.Debugf("Processing WideIP: %v", edns.Spec.DomainName)

	partitions := ctlr.resources.getLTMPartitions()

	for _, pl := range edns.Spec.Pools {
		UniquePoolName := strings.Replace(edns.Spec.DomainName, "*", "wildcard", -1) + "_" +
			AS3NameFormatter(strings.TrimPrefix(ctlr.Agent.BIGIPURL, "https://")) + "_" + DEFAULT_GTM_PARTITION
		log.Debugf("Processing WideIP Pool: %v", UniquePoolName)
		pool := GSLBPool{
			Name:          UniquePoolName,
			RecordType:    pl.DNSRecordType,
			LBMethod:      pl.LoadBalanceMethod,
			PriorityOrder: pl.PriorityOrder,
			DataServer:    pl.DataServerName,
			Ratio:         pl.Ratio,
		}
		if pl.LBModeFallback != "" {
			pool.LBModeFallBack = pl.LBModeFallback
		} else {
			pool.LBModeFallBack = "return-to-dns"
		}

		if pl.DNSRecordType == "" {
			pool.RecordType = "A"
		}
		if pl.LoadBalanceMethod == "" {
			pool.LBMethod = "round-robin"
		}
		for _, partition := range partitions {
			rsMap := ctlr.resources.getPartitionResourceMap(partition)

			for vsName, vs := range rsMap {
				var found bool
				for _, host := range vs.MetaData.hosts {
					if host == edns.Spec.DomainName {
						found = true
						break
					}
				}
				if found {
					//No need to add insecure VS into wideIP pool if VS configured with httpTraffic as redirect
					if vs.MetaData.Protocol == "http" && (vs.MetaData.httpTraffic == TLSRedirectInsecure || vs.MetaData.httpTraffic == TLSAllowInsecure) {
						continue
					}
					preGTMServerName := ""
					if ctlr.Agent.ccclGTMAgent {
						preGTMServerName = fmt.Sprintf("%v:", pl.DataServerName)
					}
					// add only one VS member to pool.
					if len(pool.Members) > 0 && strings.HasPrefix(vsName, "ingress_link_") {
						if strings.HasSuffix(vsName, "_443") {
							pool.Members[0] = fmt.Sprintf("%v/%v/Shared/%v", preGTMServerName, partition, vsName)
						}
						continue
					}
					log.Debugf("Adding WideIP Pool Member: %v", fmt.Sprintf("/%v/Shared/%v",
						partition, vsName))
					pool.Members = append(
						pool.Members,
						fmt.Sprintf("%v/%v/Shared/%v", preGTMServerName, partition, vsName),
					)
				}
			}
		}
		if len(pl.Monitors) > 0 {
			var monitors []Monitor
			for i, monitor := range pl.Monitors {
				monitors = append(monitors,
					Monitor{
						Name:      fmt.Sprintf("%s_monitor%d", UniquePoolName, i),
						Partition: "Common",
						Type:      monitor.Type,
						Interval:  monitor.Interval,
						Send:      monitor.Send,
						Recv:      monitor.Recv,
						Timeout:   monitor.Timeout})
			}
			pool.Monitors = monitors

		} else if pl.Monitor.Type != "" {
			// TODO: Need to change to DEFAULT_PARTITION from Common, once Agent starts to support DEFAULT_PARTITION
			var monitors []Monitor

			if pl.Monitor.Type == "http" || pl.Monitor.Type == "https" {
				monitors = append(monitors,
					Monitor{
						Name:      UniquePoolName + "_monitor",
						Partition: "Common",
						Type:      pl.Monitor.Type,
						Interval:  pl.Monitor.Interval,
						Send:      pl.Monitor.Send,
						Recv:      pl.Monitor.Recv,
						Timeout:   pl.Monitor.Timeout,
					})
			} else {
				monitors = append(monitors,
					Monitor{
						Name:      UniquePoolName + "_monitor",
						Partition: "Common",
						Type:      pl.Monitor.Type,
						Interval:  pl.Monitor.Interval,
						Timeout:   pl.Monitor.Timeout,
					})
			}
			pool.Monitors = monitors
		}
		wip.Pools = append(wip.Pools, pool)
	}
	if _, ok := ctlr.resources.gtmConfig[DEFAULT_GTM_PARTITION]; !ok {
		ctlr.resources.gtmConfig[DEFAULT_GTM_PARTITION] = GTMPartitionConfig{
			WideIPs: make(map[string]WideIP),
		}
	}

	ctlr.resources.gtmConfig[DEFAULT_GTM_PARTITION].WideIPs[wip.DomainName] = wip
	return
}

func (ctlr *Controller) getAllExternalDNS(namespace string) []*cisapiv1.ExternalDNS {
	var allEDNS []*cisapiv1.ExternalDNS
	comInf, ok := ctlr.getNamespacedCommonInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	var orderedEDNSs []interface{}
	var err error

	if namespace == "" {
		orderedEDNSs = comInf.ednsInformer.GetIndexer().List()
	} else {
		orderedEDNSs, err = comInf.ednsInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("Unable to get list of ExternalDNSs for namespace '%v': %v",
				namespace, err)
			return allEDNS
		}
	}

	for _, obj := range orderedEDNSs {
		edns := obj.(*cisapiv1.ExternalDNS)
		allEDNS = append(allEDNS, edns)
	}

	return allEDNS
}

func (ctlr *Controller) ProcessRouteEDNS(hosts []string) {
	if len(ctlr.processedHostPath.removedHosts) > 0 {
		removedHosts := ctlr.processedHostPath.removedHosts
		ctlr.processedHostPath.Lock()
		ctlr.processedHostPath.removedHosts = make([]string, 0)
		ctlr.processedHostPath.Unlock()
		//This will remove existing EDNS pool members
		ctlr.ProcessAssociatedExternalDNS(removedHosts)
	}
	if len(hosts) > 0 {
		ctlr.ProcessAssociatedExternalDNS(hosts)
	}
}

func (ctlr *Controller) ProcessAssociatedExternalDNS(hostnames []string) {
	var allEDNS []*cisapiv1.ExternalDNS
	if ctlr.watchingAllNamespaces() {
		allEDNS = ctlr.getAllExternalDNS("")
	} else {
		for ns := range ctlr.namespaces {
			allEDNS = append(allEDNS, ctlr.getAllExternalDNS(ns)...)
		}
	}
	for _, edns := range allEDNS {
		for _, hostname := range hostnames {
			if edns.Spec.DomainName == hostname {
				ctlr.processExternalDNS(edns, false)
			}
		}
	}
}

// Validate certificate hostname
func checkCertificateHost(host, kind, rkey string, certificate []byte, key []byte) bool {
	cert, certErr := tls.X509KeyPair(certificate, key)
	if certErr != nil {
		log.Errorf("Failed to validate TLS cert and key: %v", certErr)
		return false
	}
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Errorf("failed to parse certificate; %s", err)
		return false
	}

	if len(x509cert.DNSNames) > 0 {
		ok := x509cert.VerifyHostname(host)
		if ok != nil {
			log.Warningf("Hostname in %v %v does not match with certificate hostname: %v", kind, rkey, ok)
			return false
		}
	} else if !verifyCertificateCommonName(strings.ToLower(x509cert.Subject.CommonName), strings.ToLower(host)) {
		log.Warningf("Hostname %v in %v %v does not match with certificate hostname: %v", host, kind, rkey, x509cert.Subject.CommonName)
		return false
	}
	return true
}

func verifyCertificateCommonName(certCommonName, hostname string) bool {
	if validHostname(hostname, false) && validHostname(hostname, true) {
		if matchHostnames(certCommonName, hostname) {
			return true
		}
	} else {
		if certCommonName == hostname {
			return true
		}
	}
	return false
}

func matchHostnames(pattern, host string) bool {
	host = strings.TrimSuffix(host, ".")

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if i == 0 && patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}

func validHostname(host string, isPattern bool) bool {
	if !isPattern {
		host = strings.TrimSuffix(host, ".")
	}
	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if isPattern && i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' {
				// Not a valid character in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

func (ctlr *Controller) processIPAM(ipam *ficV1.IPAM) error {
	var keysToProcess []string

	if ctlr.ipamHostSpecEmpty {
		ipamRes, _ := ctlr.ipamCli.Get(ipam.Namespace, ipam.Name)
		if len(ipamRes.Spec.HostSpecs) > 0 {
			ctlr.ipamHostSpecEmpty = false
		}
	}

	if !ctlr.ipamHostSpecEmpty {
		for _, ipSpec := range ipam.Status.IPStatus {
			if cachedIPSpec, ok := ctlr.resources.ipamContext[ipSpec.Key]; ok {
				if cachedIPSpec.IP != ipSpec.IP {
					// TODO: Delete the VS with old IP in BIGIP in case of FIC reboot
					keysToProcess = append(keysToProcess, ipSpec.Key)
				}
			} else {
				ctlr.resources.ipamContext[ipSpec.Key] = *ipSpec
				keysToProcess = append(keysToProcess, ipSpec.Key)
			}
		}

		// process resource entries which are present in ipamContext but not in status
		for k, _ := range ctlr.resources.ipamContext {
			found := false
			for _, key := range ipam.Status.IPStatus {
				if k == key.Key {
					found = true
					break
				}
			}
			if !found {
				keysToProcess = append(keysToProcess, k)
				delete(ctlr.resources.ipamContext, k)
			}
		}
		if len(ctlr.resources.ipamContext) == 0 {
			ctlr.ipamHostSpecEmpty = true
		}
	}

	for _, pKey := range keysToProcess {
		idx := strings.LastIndex(pKey, "_")
		if idx == -1 {
			continue
		}
		rscKind := pKey[idx+1:]
		var crInf *CRInformer
		var comInf *CommonInformer
		var ns string
		rscName := ctlr.getResourceNameFromIPAMKey(pKey)
		ns = ctlr.getNamespaceFromIPAMKey(pKey)
		if rscKind != "hg" {
			var ok bool
			crInf, ok = ctlr.getNamespacedCRInformer(ns)
			comInf, ok = ctlr.getNamespacedCommonInformer(ns)
			if !ok {
				log.Errorf("Informer not found for namespace: %v", ns)
				return nil
			}
		}
		switch rscKind {
		case "hg":
			// For Virtual Server
			var vss []*cisapiv1.VirtualServer
			vss = ctlr.getAllVSFromMonitoredNamespaces()
			for _, vs := range vss {
				key := ctlr.ipamClusterLabel + vs.Spec.HostGroup + "_hg"
				if pKey == key {
					ctlr.TeemData.Lock()
					ctlr.TeemData.ResourceType.IPAMVS[ns]++
					ctlr.TeemData.Unlock()
					err := ctlr.processVirtualServers(vs, false)
					if err != nil {
						log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
					}
					break
				}
			}
			// For Transport Server
			var tss []*cisapiv1.TransportServer
			tss = ctlr.getAllTSFromMonitoredNamespaces()
			for _, ts := range tss {
				key := ctlr.ipamClusterLabel + ts.Spec.HostGroup + "_hg"
				if pKey == key {
					ctlr.TeemData.Lock()
					ctlr.TeemData.ResourceType.IPAMTS[ns]++
					ctlr.TeemData.Unlock()
					err := ctlr.processTransportServers(ts, false)
					if err != nil {
						log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
					}
					break
				}
			}
		case "host":
			var vss []*cisapiv1.VirtualServer
			vss = ctlr.getAllVirtualServers(ns)
			for _, vs := range vss {
				key := ctlr.ipamClusterLabel + vs.Namespace + "/" + vs.Spec.Host + "_host"
				if pKey == key {
					ctlr.TeemData.Lock()
					ctlr.TeemData.ResourceType.IPAMVS[ns]++
					ctlr.TeemData.Unlock()
					err := ctlr.processVirtualServers(vs, false)
					if err != nil {
						log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
					}
					break
				}
			}
		case "ts":
			item, exists, err := crInf.tsInformer.GetIndexer().GetByKey(rscName)
			if !exists || err != nil {
				log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
				continue
			}
			ctlr.TeemData.Lock()
			ctlr.TeemData.ResourceType.IPAMTS[ns]++
			ctlr.TeemData.Unlock()
			ts := item.(*cisapiv1.TransportServer)
			err = ctlr.processTransportServers(ts, false)
			if err != nil {
				log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
			}
		case "il":
			item, exists, err := crInf.ilInformer.GetIndexer().GetByKey(rscName)
			if !exists || err != nil {
				log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
				continue
			}
			il := item.(*cisapiv1.IngressLink)
			err = ctlr.processIngressLink(il, false)
			if err != nil {
				log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
			}
		case "svc":
			item, exists, err := comInf.svcInformer.GetIndexer().GetByKey(rscName)
			if !exists || err != nil {
				log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
				continue
			}
			ctlr.TeemData.Lock()
			ctlr.TeemData.ResourceType.IPAMSvcLB[ns]++
			ctlr.TeemData.Unlock()
			svc := item.(*v1.Service)
			err = ctlr.processLBServices(svc, false)
			if err != nil {
				log.Errorf("[IPAM] Unable to process IPAM entry: %v", pKey)
			}
		default:
			log.Errorf("[IPAM] Found Invalid Key: %v while Processing IPAM", pKey)
		}
	}

	return nil
}

func (ctlr *Controller) getResourceNameFromIPAMKey(key string) string {
	if ctlr.ipamClusterLabel != "" {
		key = strings.Replace(key, ctlr.ipamClusterLabel, "", 1)
	}
	idx := strings.LastIndex(key, "_")
	return key[:idx]
}

func (ctlr *Controller) getNamespaceFromIPAMKey(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) < 2 {
		return ""
	}

	if ctlr.ipamClusterLabel != "" {
		// If the ipamClusterLabel is enabled, the namespace is in the 2nd part
		if len(parts) >= 3 {
			return parts[1]
		}
	}

	// if ipamClusterLabel is not enabled or if enabled with old key , the namespace is in the 1st part
	return parts[0]
}

func (ctlr *Controller) processIngressLink(
	ingLink *cisapiv1.IngressLink,
	isILDeleted bool,
) error {

	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing Ingress Links %+v (%v)",
			ingLink, endTime.Sub(startTime))
	}()
	// Skip validation for a deleted ingressLink
	if !isILDeleted {
		// check if the virutal server matches all the requirements.
		vkey := ingLink.ObjectMeta.Namespace + "/" + ingLink.ObjectMeta.Name
		valid := ctlr.checkValidIngressLink(ingLink)
		if false == valid {
			log.Errorf("ingressLink %s, is not valid",
				vkey)
			return nil
		}
	}
	var ingLinks []*cisapiv1.IngressLink
	if ingLink.Spec.Host != "" {
		ingLinks = ctlr.getAllIngLinkFromMonitoredNamespaces()
	} else {
		ingLinks = ctlr.getAllIngressLinks(ingLink.ObjectMeta.Namespace)
	}
	isValidIL := ctlr.validateILsWithSameVSAddress(ingLink, ingLinks, isILDeleted)
	if !isValidIL {
		return nil
	}

	var ip string
	var key string
	var status int
	var altErr string
	partition := ctlr.getCRPartition(ingLink.Spec.Partition)
	key = ctlr.ipamClusterLabel + ingLink.ObjectMeta.Namespace + "/" + ingLink.ObjectMeta.Name + "_il"
	if ctlr.ipamCli != nil {
		if isILDeleted && ingLink.Spec.VirtualServerAddress == "" {
			ip = ctlr.releaseIP(ingLink.Spec.IPAMLabel, "", key)
		} else if ingLink.Spec.VirtualServerAddress != "" {
			ip = ingLink.Spec.VirtualServerAddress
		} else {
			ip, status = ctlr.requestIP(ingLink.Spec.IPAMLabel, "", key)

			switch status {
			case NotEnabled:
				altErr = "[IPAM] IPAM Custom Resource Not Available"
				log.Error(altErr)
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New(altErr))
				return nil
			case InvalidInput:
				altErr = fmt.Sprintf("[IPAM] IPAM Invalid IPAM Label: %v for IngressLink: %s/%s",
					ingLink.Spec.IPAMLabel, ingLink.Namespace, ingLink.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New(altErr))
				return nil
			case NotRequested:
				altErr = "[IPAM] unable to make IPAM Request, will be re-requested soon"
				log.Error(altErr)
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New(altErr))
				return fmt.Errorf("%s", altErr)
			case Requested:
				altErr = fmt.Sprintf("[IPAM] IP address requested for IngressLink: %s/%s", ingLink.Namespace, ingLink.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New(altErr))
				return nil
			}
			log.Debugf("[IPAM] requested IP for ingLink %v is: %v", ingLink.ObjectMeta.Name, ip)
			if ip == "" {
				altErr = fmt.Sprintf("[IPAM] requested IP for ingLink %v is empty.", ingLink.ObjectMeta.Name)
				log.Error(altErr)
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New(altErr))
				return nil
			}
			// ctlr.updateIngressLinkStatus(ingLink, ip)
			svc, err := ctlr.getKICServiceOfIngressLink(ingLink)
			if err != nil {
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", err)
				return err
			}
			if svc == nil {
				ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New("ingress service not found"))
				return nil
			}
			if _, ok := ctlr.shouldProcessServiceTypeLB(svc); ok {
				ctlr.setLBServiceIngressStatus(svc, ip)
			}
		}
	} else {
		if ingLink.Spec.VirtualServerAddress == "" {
			altErr = "no VirtualServer address in ingLink or IPAM found"
			log.Error(altErr)
			ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New(altErr))
			return fmt.Errorf("%s", altErr)
		}
		ip = ingLink.Spec.VirtualServerAddress
	}
	if isILDeleted {
		var delRes []string
		rsMap := ctlr.resources.getPartitionResourceMap(partition)
		for k := range rsMap {
			rsName := "ingress_link_" + formatVirtualServerName(
				ip,
				0,
			)
			if strings.HasPrefix(k, rsName[:len(rsName)-1]) {
				delRes = append(delRes, k)
			}
		}
		for _, rsName := range delRes {
			var hostnames []string
			if rsMap[rsName] != nil {
				rsCfg, err := ctlr.resources.getResourceConfig(partition, rsName)
				if err == nil {
					hostnames = rsCfg.MetaData.hosts
				}
			}
			ctlr.deleteVirtualServer(partition, rsName)
			if len(hostnames) > 0 {
				ctlr.ProcessAssociatedExternalDNS(hostnames)
			}
		}
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.IngressLink[ingLink.Namespace]--
		ctlr.TeemData.Unlock()
		return nil
	}
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.IngressLink[ingLink.Namespace] = len(ctlr.getAllIngressLinks(ingLink.Namespace))
	ctlr.TeemData.Unlock()
	svc, err := ctlr.getKICServiceOfIngressLink(ingLink)
	if err != nil {
		ctlr.updateResourceStatus(IngressLink, ingLink, "", "", err)
		return err
	}

	if svc == nil {
		ctlr.updateResourceStatus(IngressLink, ingLink, "", "", errors.New("ingress service not found"))
		return nil
	}
	targetPort := nginxMonitorPort
	if ctlr.PoolMemberType == NodePort || (ctlr.PoolMemberType == Auto && svc.Spec.Type != v1.ServiceTypeClusterIP) {
		targetPort = getNodeport(svc, nginxMonitorPort)
		if targetPort == 0 {
			log.Errorf("Nodeport not found for nginx monitor port: %v", nginxMonitorPort)
		}
	} else if ctlr.PoolMemberType == NodePortLocal {
		targetPort = ctlr.getNodeportForNPL(nginxMonitorPort, svc.Name, svc.Namespace)
		if targetPort == 0 {
			log.Errorf("Nodeport not found for nginx monitor port: %v", nginxMonitorPort)
		}
	}

	rsMap := ctlr.resources.getPartitionResourceMap(partition)
	for _, port := range svc.Spec.Ports {
		//for nginx health monitor port skip vs creation
		if port.Port == nginxMonitorPort {
			continue
		}
		rsName := "ingress_link_" + formatVirtualServerName(
			ip,
			port.Port,
		)

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = partition
		rsCfg.MetaData.ResourceType = TransportServer
		rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, ingLink.Spec.Host)
		rsCfg.Virtual.Mode = "standard"
		rsCfg.Virtual.TranslateServerAddress = true
		rsCfg.Virtual.TranslateServerPort = true
		rsCfg.Virtual.Source = "0.0.0.0/0"
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
		if len(ingLink.Spec.IRules) > 0 {
			rsCfg.Virtual.IRules = ingLink.Spec.IRules
		}
		if ingLink.Spec.BigIPRouteDomain > 0 {
			if ctlr.PoolMemberType == Cluster {
				log.Warning("bigipRouteDomain is not supported in Cluster mode")
			} else {
				rsCfg.Virtual.BigIPRouteDomain = ingLink.Spec.BigIPRouteDomain
				rsCfg.Virtual.SetVirtualAddress(
					fmt.Sprintf("%s%%%d", ip, rsCfg.Virtual.BigIPRouteDomain),
					port.Port,
				)
			}
		} else {
			rsCfg.Virtual.SetVirtualAddress(
				ip,
				port.Port,
			)
		}
		svcPort := intstr.IntOrString{IntVal: port.Port}
		pool := Pool{
			Name: ctlr.formatPoolName(
				svc.ObjectMeta.Namespace,
				svc.ObjectMeta.Name,
				svcPort,
				"",
				"",
				"",
			),
			Partition:        rsCfg.Virtual.Partition,
			ServiceName:      svc.ObjectMeta.Name,
			ServicePort:      svcPort,
			ServiceNamespace: svc.ObjectMeta.Namespace,
			BigIPRouteDomain: rsCfg.Virtual.BigIPRouteDomain,
		}
		// udpating the service cache
		rsRef := resourceRef{
			name:      ingLink.Name,
			namespace: ingLink.Namespace,
			kind:      IngressLink,
		}
		// updating the service cache
		ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, svc.ObjectMeta.Name, "", pool, svcPort, "")
		// Update the pool Members
		ctlr.updatePoolMembersForResources(&pool)
		if len(pool.Members) > 0 {
			rsCfg.MetaData.Active = true
		}
		monitorName := fmt.Sprintf("%s_monitor", pool.Name)
		rsCfg.Monitors = append(
			rsCfg.Monitors,
			Monitor{Name: monitorName, Partition: rsCfg.Virtual.Partition, Interval: 20,
				Type: "http", Send: "GET /nginx-ready HTTP/1.1\r\n", Recv: "", Timeout: 10, TargetPort: targetPort})
		pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitorName})
		rsCfg.Virtual.PoolName = pool.Name
		rsCfg.Pools = append(rsCfg.Pools, pool)
		// Update rsMap with ResourceConfigs created for the current ingresslink virtuals
		rsMap[rsName] = rsCfg
		var hostnames []string
		hostnames = rsCfg.MetaData.hosts
		if len(hostnames) > 0 {
			ctlr.ProcessAssociatedExternalDNS(hostnames)
		}
	}
	ctlr.updateResourceStatus(IngressLink, ingLink, ip, "", nil)
	return nil
}

func (ctlr *Controller) getAllIngressLinks(namespace string) []*cisapiv1.IngressLink {
	var allIngLinks []*cisapiv1.IngressLink

	crInf, ok := ctlr.getNamespacedCRInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	var orderedIngLinks []interface{}
	var err error
	if namespace == "" {
		orderedIngLinks = crInf.ilInformer.GetIndexer().List()
	} else {
		// Get list of VirtualServers and process them.
		orderedIngLinks, err = crInf.ilInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("Unable to get list of VirtualServers for namespace '%v': %v",
				namespace, err)
			return nil
		}
	}
	for _, obj := range orderedIngLinks {
		ingLink := obj.(*cisapiv1.IngressLink)
		// TODO
		// Validate the IngressLink List to check if all the vs are valid.

		allIngLinks = append(allIngLinks, ingLink)
	}
	return allIngLinks
}

// filterIngressLinkForService returns list of ingressLinks that are
// affected by the service under process.
func filterIngressLinkForService(allIngressLinks []*cisapiv1.IngressLink,
	svc *v1.Service) []*cisapiv1.IngressLink {

	var result []*cisapiv1.IngressLink
	svcNamespace := svc.ObjectMeta.Namespace

	// find IngressLinks which reference the service
	for _, ingLink := range allIngressLinks {
		if ingLink.ObjectMeta.Namespace != svcNamespace {
			continue
		}
		for k, v := range ingLink.Spec.Selector.MatchLabels {
			if svc.ObjectMeta.Labels[k] == v {
				result = append(result, ingLink)
			}
		}
	}

	return result
}

// get returns list of all ingressLink
func (ctlr *Controller) getAllIngLinkFromMonitoredNamespaces() []*cisapiv1.IngressLink {
	var allInglink []*cisapiv1.IngressLink
	if ctlr.watchingAllNamespaces() {
		return ctlr.getAllIngressLinks("")
	}
	for ns := range ctlr.namespaces {
		allInglink = append(allInglink, ctlr.getAllIngressLinks(ns)...)
	}
	return allInglink
}

func (ctlr *Controller) getKICServiceOfIngressLink(ingLink *cisapiv1.IngressLink) (*v1.Service, error) {
	selector := ""
	for k, v := range ingLink.Spec.Selector.MatchLabels {
		selector += fmt.Sprintf("%v=%v,", k, v)
	}
	selector = selector[:len(selector)-1]

	comInf, ok := ctlr.getNamespacedCommonInformer(ingLink.ObjectMeta.Namespace)
	if !ok {
		return nil, fmt.Errorf("informer not found for namepsace %v", ingLink.ObjectMeta.Namespace)
	}
	ls, _ := createLabel(selector)
	serviceList, err := listerscorev1.NewServiceLister(comInf.svcInformer.GetIndexer()).Services(ingLink.ObjectMeta.Namespace).List(ls)

	if err != nil {
		log.Errorf("Error getting service list From IngressLink. Error: %v", err)
		return nil, err
	}

	if len(serviceList) == 0 {
		log.Infof("No services for with labels : %v", ingLink.Spec.Selector.MatchLabels)
		return nil, nil
	}

	if len(serviceList) == 1 {
		return serviceList[0], nil
	}

	sort.Sort(Services(serviceList))
	return serviceList[0], nil
}

func (ctlr *Controller) setLBServiceIngressStatus(
	svc *v1.Service,
	ip string,
) {
	if _, ok := ctlr.shouldProcessServiceTypeLB(svc); !ok {
		return
	}
	// Set the ingress status to include the virtual IP
	lbIngress := v1.LoadBalancerIngress{IP: ip}
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, lbIngress)
	} else if svc.Status.LoadBalancer.Ingress[0].IP != ip {
		svc.Status.LoadBalancer.Ingress[0] = lbIngress
	}

	_, updateErr := ctlr.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
	if nil != updateErr {
		// Multi-service causes the controller to try to update the status multiple times
		// at once. Ignore this error.
		if strings.Contains(updateErr.Error(), "object has been modified") {
			return
		}
		warning := fmt.Sprintf(
			"Error when setting Service LB Ingress status IP: %v", updateErr)
		log.Warning(warning)
		ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeWarning, "StatusIPError", warning)
	} else {
		message := fmt.Sprintf("F5 CIS assigned LoadBalancer IP: %v", ip)
		ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeNormal, "ExternalIP", message)
	}
}

func (ctlr *Controller) unSetLBServiceIngressStatus(
	svc *v1.Service,
	ip string,
) {

	svcName := svc.Namespace + "/" + svc.Name
	comInf, _ := ctlr.getNamespacedCommonInformer(svc.Namespace)
	service, found, err := comInf.svcInformer.GetIndexer().GetByKey(svcName)
	if !found || err != nil {
		log.Debugf("Unable to Update Status of Service: %v due to unavailability", svcName)
		return
	}
	svc = service.(*v1.Service)
	index := -1
	for i, lbIng := range svc.Status.LoadBalancer.Ingress {
		if lbIng.IP == ip {
			index = i
			break
		}
	}

	if index != -1 {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress[:index],
			svc.Status.LoadBalancer.Ingress[index+1:]...)

		_, updateErr := ctlr.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(
			context.TODO(), svc, metav1.UpdateOptions{})
		if nil != updateErr {
			// Multi-service causes the controller to try to update the status multiple times
			// at once. Ignore this error.
			if strings.Contains(updateErr.Error(), "object has been modified") {
				log.Debugf("Error while updating service: %v %v", svcName, updateErr.Error())
				return
			}
			warning := fmt.Sprintf(
				"Error when unsetting Service LB Ingress status IP: %v", updateErr)
			log.Warning(warning)
			ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeWarning, "StatusIPError", warning)
		} else {
			message := fmt.Sprintf("F5 CIS unassigned LoadBalancer IP: %v", ip)
			ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeNormal, "ExternalIP", message)
		}
	}
}

//func (ctlr *Controller) eraseLBServiceIngressStatus(
//	svc *v1.Service,
//) {
//	svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{}
//
//	_, updateErr := ctlr.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(
//		context.TODO(), svc, metav1.UpdateOptions{})
//	if nil != updateErr {
//		// Multi-service causes the controller to try to update the status multiple times
//		// at once. Ignore this error.
//		if strings.Contains(updateErr.Error(), "object has been modified") {
//			log.Debugf("Error while updating service: %v/%v %v", svc.Namespace, svc.Name, updateErr.Error())
//			return
//		}
//		warning := fmt.Sprintf(
//			"Error when erasing Service LB Ingress status IP: %v", updateErr)
//		log.Warning(warning)
//		ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeWarning, "StatusIPError", warning)
//	} else {
//		message := fmt.Sprintf("F5 CIS erased LoadBalancer IP in Status")
//		ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeNormal, "ExternalIP", message)
//	}
//}

func (ctlr *Controller) recordLBServiceIngressEvent(
	svc *v1.Service,
	eventType string,
	reason string,
	message string,
) {
	namespace := svc.ObjectMeta.Namespace
	// Create the event
	evNotifier := ctlr.eventNotifier.CreateNotifierForNamespace(
		namespace, ctlr.kubeClient.CoreV1())
	evNotifier.RecordEvent(svc, eventType, reason, message)
}

// sort services by timestamp
func (svcs Services) Len() int {
	return len(svcs)
}

func (svcs Services) Less(i, j int) bool {
	d1 := svcs[i].GetCreationTimestamp()
	d2 := svcs[j].GetCreationTimestamp()
	return d1.Before(&d2)
}

func (svcs Services) Swap(i, j int) {
	svcs[i], svcs[j] = svcs[j], svcs[i]
}

// sort Nodes by Name
func (nodes NodeList) Len() int {
	return len(nodes)
}

func (nodes NodeList) Less(i, j int) bool {
	return nodes[i].Name < nodes[j].Name
}

func (nodes NodeList) Swap(i, j int) {
	nodes[i], nodes[j] = nodes[j], nodes[i]
}

func getNodeport(svc *v1.Service, servicePort int32) int32 {
	for _, port := range svc.Spec.Ports {
		if port.Port == servicePort {
			return port.NodePort
		}
	}
	return 0
}

// Update virtual server status with virtual server address
func (ctlr *Controller) updateVirtualServerStatus(vs *cisapiv1.VirtualServer, ip string, statusOk string) {
	// Set the vs status to include the virtual IP address
	vsStatus := cisapiv1.VirtualServerStatus{VSAddress: ip, StatusOk: statusOk}
	log.Debugf("Updating VirtualServer Status with %v for resource name:%v , namespace: %v", vsStatus, vs.Name, vs.Namespace)
	vs.Status = vsStatus
	vs.Status.VSAddress = ip
	vs.Status.StatusOk = statusOk
	_, updateErr := ctlr.kubeCRClient.CisV1().VirtualServers(vs.ObjectMeta.Namespace).UpdateStatus(context.TODO(), vs, metav1.UpdateOptions{})
	if nil != updateErr {
		log.Debugf("Error while updating virtual server status:%v", updateErr)
		return
	}
}

// Update Transport server status with virtual server address
func (ctlr *Controller) updateTransportServerStatus(ts *cisapiv1.TransportServer, ip string, statusOk string) {
	// Set the vs status to include the virtual IP address
	tsStatus := cisapiv1.TransportServerStatus{VSAddress: ip, StatusOk: statusOk}
	log.Debugf("Updating VirtualServer Status with %v for resource name:%v , namespace: %v", tsStatus, ts.Name, ts.Namespace)
	ts.Status = tsStatus
	ts.Status.VSAddress = ip
	ts.Status.StatusOk = statusOk
	_, updateErr := ctlr.kubeCRClient.CisV1().TransportServers(ts.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ts, metav1.UpdateOptions{})
	if nil != updateErr {
		log.Debugf("Error while updating Transport server status:%v", updateErr)
		return
	}
}

// Update ingresslink status with virtual server address
func (ctlr *Controller) updateIngressLinkStatus(il *cisapiv1.IngressLink, ip string) {
	// Set the vs status to include the virtual IP address
	ilStatus := cisapiv1.IngressLinkStatus{VSAddress: ip}
	il.Status = ilStatus
	_, updateErr := ctlr.kubeCRClient.CisV1().IngressLinks(il.ObjectMeta.Namespace).UpdateStatus(context.TODO(), il, metav1.UpdateOptions{})
	if nil != updateErr {
		log.Debugf("Error while updating ingresslink status:%v", updateErr)
		return
	}
}

// returns service obj with servicename
func (ctlr *Controller) GetService(namespace, serviceName string) *v1.Service {
	svcKey := namespace + "/" + serviceName
	comInf, ok := ctlr.getNamespacedCommonInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	svc, found, err := comInf.svcInformer.GetIndexer().GetByKey(svcKey)
	if err != nil {
		log.Infof("Error fetching service %v from the store: %v", svcKey, err)
		return nil
	}
	if !found {
		log.Errorf("Error: Service %v not found %v", svcKey, getClusterLog(""))
		return nil
	}
	return svc.(*v1.Service)
}

// GetPodsForService returns podList with labels set to svc selector
func (ctlr *Controller) GetPodsForService(namespace, serviceName, clusterName string, nplAnnotationRequired bool) []*v1.Pod {
	svcKey := namespace + "/" + serviceName

	var svc interface{}
	var found bool
	var err error

	var comInf *CommonInformer
	var poolInf *MultiClusterPoolInformer
	var podList []*v1.Pod
	var ok bool
	if clusterName == "" {
		comInf, ok = ctlr.getNamespacedCommonInformer(namespace)
		if !ok {
			log.Errorf("Informer not found for namespace: %v", namespace)
			return nil
		}
		svc, found, err = comInf.svcInformer.GetIndexer().GetByKey(svcKey)
	} else {
		poolInf, ok = ctlr.getNamespaceMultiClusterPoolInformer(namespace, clusterName)
		if !ok {
			log.Errorf("[MultiCluster] Informer not found for namespace %v and cluster %v", namespace, clusterName)
			return nil
		}
		svc, found, err = poolInf.svcInformer.GetIndexer().GetByKey(svcKey)
	}

	if err != nil {
		log.Infof("Error fetching service %v from the store: %v", svcKey, err)
		return nil
	}
	if !found {
		log.Errorf("Error: Service %v not found %v", svcKey, getClusterLog(clusterName))
		return nil
	}
	annotations := svc.(*v1.Service).Annotations
	if _, ok := annotations[NPLSvcAnnotation]; !ok && nplAnnotationRequired {
		log.Errorf("NPL annotation %v not set on service %v", NPLSvcAnnotation, serviceName)
		return nil
	}

	selector := svc.(*v1.Service).Spec.Selector
	if len(selector) == 0 {
		log.Infof("label selector is not set on svc")
		return nil
	}
	labelSelector, err := metav1.ParseToLabelSelector(labels.Set(selector).AsSelectorPreValidated().String())
	labelmap, err := metav1.LabelSelectorAsMap(labelSelector)
	if err != nil {
		return nil
	}
	pl, _ := createLabel(labels.SelectorFromSet(labelmap).String())
	if clusterName == "" {
		podList, err = listerscorev1.NewPodLister(comInf.podInformer.GetIndexer()).Pods(namespace).List(pl)
	} else {
		podList, err = listerscorev1.NewPodLister(poolInf.podInformer.GetIndexer()).Pods(namespace).List(pl)
	}
	if err != nil {
		log.Debugf("Got error while listing Pods with selector %v: %v", selector, err)
		return nil
	}
	return podList
}

func (ctlr *Controller) GetServicesForPod(pod *v1.Pod, clusterName string) *v1.Service {
	var services []interface{}
	var err error
	if clusterName == "" {
		comInf, ok := ctlr.getNamespacedCommonInformer(pod.Namespace)
		if !ok {
			log.Errorf("Informer not found for namespace: %v ", pod.Namespace)
			return nil
		}
		services, err = comInf.svcInformer.GetIndexer().ByIndex("namespace", pod.Namespace)
		if err != nil {
			log.Debugf("Unable to find services for namespace %v with error: %v", pod.Namespace, err)
		}
	} else if _, ok := ctlr.multiClusterPoolInformers[clusterName]; ok {
		var poolInf *MultiClusterPoolInformer
		var found bool
		if poolInf, found = ctlr.multiClusterPoolInformers[clusterName][""]; !found {
			poolInf, found = ctlr.multiClusterPoolInformers[clusterName][pod.Namespace]
		}
		if !found {
			log.Errorf("[MultiCluster] Informer not found for namespace: %v, cluster: %s", pod.Namespace, clusterName)
			return nil
		}
		services, err = poolInf.svcInformer.GetIndexer().ByIndex("namespace", pod.Namespace)
		if err != nil {
			log.Debugf("[MultiCluster] Unable to find services for namespace %v in cluster %s with error: %v", pod.Namespace,
				clusterName, err)
		}
	} else {
		log.Errorf("[MultiCluster] Informer not found for namespace: %v, cluster: %s", pod.Namespace, clusterName)
		return nil
	}
	for _, obj := range services {
		svc := obj.(*v1.Service)

		// in the nodeportlocal mode, svc type nodeport is not supported by antrea CNI, we ignore svc type nodeport
		if ctlr.PoolMemberType == NodePortLocal {
			if svc.Spec.Type != v1.ServiceTypeNodePort {
				if ctlr.matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
					return svc
				}
			}
		} else if ctlr.matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
			return svc
		}
	}
	return nil
}

func (ctlr *Controller) matchSvcSelectorPodLabels(svcSelector, podLabel map[string]string) bool {
	if len(svcSelector) == 0 {
		return false
	}

	for selectorKey, selectorVal := range svcSelector {
		if labelVal, ok := podLabel[selectorKey]; !ok || selectorVal != labelVal {
			return false
		}
	}
	return true
}

// processPod populates NPL annotations for a pod in store.
func (ctlr *Controller) processPod(pod *v1.Pod, ispodDeleted bool) error {
	podKey := pod.Namespace + "/" + pod.Name
	if ispodDeleted {
		delete(ctlr.resources.nplStore, podKey)
		log.Debugf("Deleting Pod '%v/%v' from CIS cache as it's not referenced by monitored resources", pod.Namespace, pod.Name)
		return nil
	}
	ann := pod.GetAnnotations()
	var annotations []NPLAnnotation
	if val, ok := ann[NPLPodAnnotation]; ok {
		if err := json.Unmarshal([]byte(val), &annotations); err != nil {
			log.Errorf("key: %s, got error while unmarshaling NPL annotations: %v", podKey, err)
		}
		log.Debugf("Adding Pod '%v/%v' in CIS cache", pod.Namespace, pod.Name)
		ctlr.resources.nplStore[podKey] = annotations
	} else {
		log.Debugf("key: %s, NPL annotation not found for Pod", pod.Name)
		delete(ctlr.resources.nplStore, podKey)
	}
	return nil
}

func (ctlr *Controller) processConfigMap(cm *v1.ConfigMap, isDelete bool) (error, bool) {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		key := cm.Namespace + string('/') + cm.Name
		if ctlr.globalExtendedCMKey == key {
			log.Debugf("Finished syncing extended global spec configmap: %v/%v (%v)",
				cm.Namespace, cm.Name, endTime.Sub(startTime))
		} else {
			log.Debugf("Finished syncing extended local spec configmap: %v/%v (%v)",
				cm.Namespace, cm.Name, endTime.Sub(startTime))
		}

	}()
	ersData := cm.Data
	es := extendedSpec{}
	//log.Debugf("GCM: %v", cm.Data)
	err := yaml.UnmarshalStrict([]byte(ersData["extendedSpec"]), &es)
	if err != nil {
		return fmt.Errorf("invalid extended route spec in configmap: %v/%v error: %v", cm.Namespace, cm.Name, err), false
	}
	// Check if Partition is set to Common, which is not allowed
	if es.DefaultRouteGroupConfig.BigIpPartition == CommonPartition {
		return fmt.Errorf("invalid partition %v provided in defaultRouteGroup of configmap: %v/%v",
			CommonPartition, cm.Namespace, cm.Name), false
	}
	// clusterConfigUpdated, oldClusterRatio and oldClusterAdminState are used for tracking cluster ratio and cluster Admin state updates
	clusterConfigUpdated := false
	oldClusterRatio := make(map[string]int)
	oldClusterAdminState := make(map[string]clustermanager.AdminState)
	if ctlr.isGlobalExtendedCM(cm) && ctlr.multiClusterMode != "" {
		// Get Multicluster kube-config
		if isDelete {
			// Handle configmap deletion
			es.HAClusterConfig = HAClusterConfig{}
		}
		// Check if HA configurations are specified properly
		if ctlr.multiClusterMode != StandAloneCIS && ctlr.multiClusterMode != "" {
			if es.HAClusterConfig == (HAClusterConfig{}) || es.HAClusterConfig.PrimaryCluster == (ClusterDetails{}) ||
				es.HAClusterConfig.SecondaryCluster == (ClusterDetails{}) {
				log.Errorf("[MultiCluster] CIS High availability cluster config not provided properly.")
				os.Exit(1)
			}
		}
		// Read multiCluster mode
		// Set the active-active/active-standby/ratio mode for the HA cluster
		if es.HAMode != "" {
			if es.HAMode == Active || es.HAMode == StandBy || es.HAMode == Ratio {
				ctlr.haModeType = es.HAMode
				ctlr.Agent.HAMode = true
			} else {
				log.Errorf("[MultiCluster] Invalid Type of high availability mode specified, supported values (active-active, " +
					"active-standby, ratio)")
				os.Exit(1)
			}
		}
		// Update cluster ratio
		if ctlr.haModeType == Ratio && ctlr.multiClusterMode == StandAloneCIS {
			if es.LocalClusterRatio != nil {
				ctlr.clusterRatio[""] = es.LocalClusterRatio
			} else {
				one := 1
				ctlr.clusterRatio[""] = &one
			}
		}
		// Store old cluster ratio before processing multiClusterConfig
		if len(ctlr.clusterRatio) > 0 {
			for cluster, ratio := range ctlr.clusterRatio {
				oldClusterRatio[cluster] = *ratio
			}
		}
		// Store old cluster admin state before processing multiClusterConfig
		if len(ctlr.clusterAdminState) > 0 {
			for clusterName, adminState := range ctlr.clusterAdminState {
				oldClusterAdminState[clusterName] = adminState
			}
		}
		// Update cluster admin state for local cluster in standalone mode
		if ctlr.multiClusterMode == StandAloneCIS {
			if es.LocalClusterAdminState == "" {
				ctlr.clusterAdminState[""] = clustermanager.Enable
			} else if es.LocalClusterAdminState == clustermanager.Enable ||
				es.LocalClusterAdminState == clustermanager.Disable || es.LocalClusterAdminState == clustermanager.Offline ||
				es.LocalClusterAdminState == clustermanager.NoPool {
				ctlr.clusterAdminState[""] = es.LocalClusterAdminState
			} else {
				log.Warningf("[MultiCluster] Invalid cluster adminState: %v specified for local cluster, supported "+
					"values (enable, disable, offline, no-pool). Defaulting to enable", es.LocalClusterAdminState)
				ctlr.clusterAdminState[""] = clustermanager.Enable
			}
		}
		// Read multi-cluster config from extended CM
		err := ctlr.readMultiClusterConfigFromGlobalCM(es.HAClusterConfig, es.ExternalClustersConfig)
		ctlr.checkSecondaryCISConfig()
		ctlr.stopDeletedGlobalCMMultiClusterInformers()
		if err != nil {
			return err, false
		}
		// Log cluster ratios used
		if len(ctlr.clusterRatio) > 0 {
			ratioKeyValues := ""
			for cluster, ratio := range ctlr.clusterRatio {
				// Check if cluster ratio is updated
				if oldRatio, ok := oldClusterRatio[cluster]; ok {
					if oldRatio != *ctlr.clusterRatio[cluster] {
						clusterConfigUpdated = true
					}
				} else {
					clusterConfigUpdated = true
				}
				if cluster == "" {
					cluster = "local cluster"
				}
				ratioKeyValues += fmt.Sprintf(" %s:%d", cluster, *ratio)
			}
			log.Infof("[MultiCluster] Cluster ratios:%s", ratioKeyValues)
		}
		// Check if cluster Admin state has been updated for any cluster
		// Check only if CIS is running in multiCluster mode
		if ctlr.multiClusterConfigs != nil {
			for clusterName, _ := range ctlr.clusterAdminState {
				// Check any cluster has been removed which means config has been updated
				if adminState, ok := oldClusterAdminState[clusterName]; ok {
					if adminState != ctlr.clusterAdminState[clusterName] {
						log.Debugf("[MultiCluster] Cluster Admin State has been modified.")
						clusterConfigUpdated = true
						break
					}
				} else {
					clusterConfigUpdated = true
					break
				}
			}
		}
	}
	// Process the routeSpec defined in extended configMap
	if ctlr.mode == OpenShiftMode {
		if ctlr.isGlobalExtendedCM(cm) {
			return ctlr.processRouteConfigFromGlobalCM(es, isDelete, clusterConfigUpdated)
		} else if len(es.ExtendedRouteGroupConfigs) > 0 && !ctlr.resourceContext.namespaceLabelMode {
			return ctlr.processRouteConfigFromLocalCM(es, isDelete, cm.Namespace)
		}
	} else {
		// Re-process all the VS and TS resources
		for resRef, _ := range ctlr.resources.processedNativeResources {
			var rs interface{}
			var exists bool
			var err error
			var crInf *CRInformer
			crInf, _ = ctlr.crInformers[""]
			switch resRef.kind {
			case VirtualServer:
				// Fetch the latest VS
				if crInf != nil {
					rs, exists, err = crInf.vsInformer.GetIndexer().GetByKey(
						fmt.Sprintf("%s/%s", resRef.namespace, resRef.name))
				} else if _, ok := ctlr.crInformers[resRef.namespace]; ok {
					rs, exists, err = ctlr.crInformers[resRef.namespace].vsInformer.GetIndexer().GetByKey(
						fmt.Sprintf("%s/%s", resRef.namespace, resRef.name))
				}
			case TransportServer:
				// Fetch the latest TS
				if crInf != nil {
					rs, exists, err = crInf.tsInformer.GetIndexer().GetByKey(
						fmt.Sprintf("%s/%s", resRef.namespace, resRef.name))
				} else if _, ok := ctlr.crInformers[resRef.namespace]; ok {
					rs, exists, err = ctlr.crInformers[resRef.namespace].tsInformer.GetIndexer().GetByKey(
						fmt.Sprintf("%s/%s", resRef.namespace, resRef.name))
				}
			default:
				// Don't process other resources except VS and TS
				continue
			}
			// Skip processing if resource could not be fetched
			if !exists || err != nil {
				continue
			}
			key := &rqKey{
				namespace: resRef.namespace,
				kind:      resRef.kind,
				rscName:   resRef.name,
				rsc:       rs,
				event:     Update,
			}
			ctlr.resourceQueue.Add(key)
		}
	}
	return nil, true
}

// getPolicyFromLBService gets the policy attached to the service and returns it
func (ctlr *Controller) getPolicyFromLBService(svc *v1.Service) (*cisapiv1.Policy, error) {
	plcName, found := svc.Annotations[LBServicePolicyNameAnnotation]
	if !found || plcName == "" {
		return nil, nil
	}
	ns := svc.Namespace
	return ctlr.getPolicy(ns, plcName)
}

// skipVirtual return true if virtuals don't have any common HTTP/HTTPS ports, else returns false
func skipVirtual(currentVS *cisapiv1.VirtualServer, vrt *cisapiv1.VirtualServer) bool {
	effectiveCurrentVSHTTPSPort := getEffectiveHTTPSPort(currentVS)
	effectiveVrtVSHTTPSPort := getEffectiveHTTPSPort(vrt)
	effectiveCurrentVSHTTPPort := getEffectiveHTTPPort(currentVS)
	effectiveVrtVSHTTPPort := getEffectiveHTTPPort(vrt)
	if effectiveCurrentVSHTTPSPort == effectiveVrtVSHTTPSPort && effectiveCurrentVSHTTPPort == effectiveVrtVSHTTPPort {
		// both virtuals use same ports
		return false
	}
	if effectiveCurrentVSHTTPSPort != effectiveVrtVSHTTPSPort && effectiveCurrentVSHTTPPort != effectiveVrtVSHTTPPort {
		// virtuals don't have any port in common
		return true
	}
	if effectiveCurrentVSHTTPSPort == effectiveVrtVSHTTPSPort && effectiveCurrentVSHTTPPort != effectiveVrtVSHTTPPort {
		// virtuals have HTTPS port is common
		if currentVS.Spec.TLSProfileName == "" || vrt.Spec.TLSProfileName == "" {
			// One of the vs is an unsecured vs so common HTTPS port is insignificant for this vs
			return true
		}
		// both vs are secured vs and have common HTTPS port
		return false
	}

	// virtuals have HTTP port in common
	// setting HTTPTraffic="" for both none and "" value for HTTPTraffic to simplify comparison
	currentVSHTTPTraffic := currentVS.Spec.HTTPTraffic
	vrtVSHTTPTraffic := vrt.Spec.HTTPTraffic
	if currentVSHTTPTraffic == "" || currentVSHTTPTraffic == "none" {
		currentVSHTTPTraffic = ""
	}
	if vrtVSHTTPTraffic == "" || vrtVSHTTPTraffic == "none" {
		vrtVSHTTPTraffic = ""
	}
	if currentVS.Spec.TLSProfileName != "" && vrt.Spec.TLSProfileName != "" {
		if currentVSHTTPTraffic == "" || vrtVSHTTPTraffic == "" {
			// both vs are secured vs but one/both of them doesn't handle HTTP traffic so common HTTP port is insignificant
			return true
		}
		// both vs are secured and both of them handle HTTP traffic via the common HTTP port
		return false
	}
	if currentVS.Spec.TLSProfileName != "" && currentVSHTTPTraffic == "" {
		// current vs is secured vs, and it doesn't handle HTTP traffic so common HTTP port is insignificant
		return true
	}
	if vrt.Spec.TLSProfileName != "" && vrtVSHTTPTraffic == "" {
		// It's a secured vs, and it doesn't handle HTTP traffic so common HTTP port is insignificant
		return true
	}
	// Either both are unsecured vs and have common HTTP port
	// or one of them is a secured vs and handles HTTP traffic through the common port
	return false
}

// doVSUseSameHTTPSPort checks if any of the associated secured VS uses the same HTTPS port that the current VS does
func doVSUseSameHTTPSPort(virtuals []*cisapiv1.VirtualServer, currentVirtual *cisapiv1.VirtualServer) bool {
	effectiveCurrentVSHTTPSPort := getEffectiveHTTPSPort(currentVirtual)
	for _, virtual := range virtuals {
		if virtual.Spec.TLSProfileName != "" && effectiveCurrentVSHTTPSPort == getEffectiveHTTPSPort(virtual) {
			return true
		}
	}
	return false
}

func fetchPortString(port intstr.IntOrString) string {
	if port.StrVal != "" {
		return port.StrVal
	}
	if port.IntVal != 0 {
		return fmt.Sprintf("%v", port.IntVal)
	}
	return ""
}

// fetch list of tls profiles for given secret.
func (ctlr *Controller) getTLSProfilesForSecret(secret *v1.Secret) []*cisapiv1.TLSProfile {
	var allTLSProfiles []*cisapiv1.TLSProfile

	crInf, ok := ctlr.getNamespacedCRInformer(secret.Namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", secret.Namespace)
		return nil
	}

	var orderedTLS []interface{}
	var err error
	orderedTLS, err = crInf.tlsInformer.GetIndexer().ByIndex("namespace", secret.Namespace)
	if err != nil {
		log.Errorf("Unable to get list of TLS Profiles for namespace '%v': %v",
			secret.Namespace, err)
		return nil
	}

	for _, obj := range orderedTLS {
		tlsProfile := obj.(*cisapiv1.TLSProfile)
		if tlsProfile.Spec.TLS.Reference == Secret {
			if len(tlsProfile.Spec.TLS.ClientSSLs) > 0 {
				for _, name := range tlsProfile.Spec.TLS.ClientSSLs {
					if name == secret.Name {
						allTLSProfiles = append(allTLSProfiles, tlsProfile)
					}
				}
			} else if tlsProfile.Spec.TLS.ClientSSL == secret.Name {
				allTLSProfiles = append(allTLSProfiles, tlsProfile)
			}
		}
	}
	return allTLSProfiles
}

func createLabel(label string) (labels.Selector, error) {
	var l labels.Selector
	var err error
	if label == "" {
		l = labels.Everything()
	} else {
		l, err = labels.Parse(label)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Label Selector string: %v", err)
		}
	}
	return l, nil
}

func (ctlr *Controller) getNodesFromAllClusters() []interface{} {
	var nodes []interface{}
	//for local cluster
	nodes = ctlr.nodeInformer.nodeInformer.GetIndexer().List()
	//fetch nodes from other clusters
	if ctlr.multiClusterNodeInformers != nil && len(ctlr.multiClusterNodeInformers) > 0 {
		for _, nodeInf := range ctlr.multiClusterNodeInformers {
			nodes = append(nodes, nodeInf.nodeInformer.GetIndexer().List()...)
		}
	} else {
		// In init state node informers may not be initaialized yet for external cluster
		// Use client config to look for nodes
		nodescluster := ctlr.fetchNodesFromClusters()
		if len(nodescluster) > 0 {
			nodes = append(nodes, nodescluster...)
		}
	}
	return nodes
}

func (ctlr *Controller) fetchNodesFromClusters() []interface{} {
	//fetch nodes from other clusters
	var nodescluster []interface{}
	if ctlr.multiClusterConfigs != nil && len(ctlr.multiClusterConfigs.ClusterConfigs) > 0 {
		for clusterName, _ := range ctlr.multiClusterConfigs.ClusterConfigs {
			if config, ok := ctlr.multiClusterConfigs.ClusterConfigs[clusterName]; ok {
				nodesObj, err := config.KubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: ctlr.nodeLabelSelector})
				if err != nil {
					log.Debugf("[MultiCluster] Unable to fetch nodes for cluster %v with err %v", clusterName, err)
				} else {
					for _, node := range nodesObj.Items {
						node := node
						nodescluster = append(nodescluster, &node)
					}
				}
			}
		}
	}
	return nodescluster
}

func (ctlr *Controller) getNodeportForNPL(port int32, svcName string, namespace string) int32 {
	var nodePort int32
	pods := ctlr.GetPodsForService(namespace, svcName, "", true)
	if pods != nil {
		for _, pod := range pods {
			anns, found := ctlr.resources.nplStore[pod.Namespace+"/"+pod.Name]
			if !found {
				continue
			}
			for _, annotation := range anns {
				if annotation.PodPort == port {
					return annotation.NodePort
				}
			}
		}
	}
	return nodePort
}

func (ctlr *Controller) getResourceServicePortForRoute(
	svcIndexer cache.Indexer,
	route *routeapi.Route,
) (int32, error) {
	// GetServicePort returns the port number, for a given port name,
	// else, returns the first port found for a Route's service.

	// The strategy used to get the port number is as follows:
	// Step 1: Try to fetch the port number from the base service in the local cluster
	// Step 2: If the base service is not found, try to fetch the port number from the base service in the HA peer cluster(in case of multi-cluster active-active)
	// Step 3: If the base service is not found in HA peer cluster, try to fetch the port number from the alternate backend services in the local cluster
	// Step 4: If the A/B services are not found in local cluster, try to fetch the port number from the alternate backend services in the HA peer cluster(in case of multi-cluster active-active)

	if route == nil {
		return 0, fmt.Errorf("Route is nil")
	}
	portName := "" // portName used in the service
	// if port is defined in the route then use it
	if route.Spec.Port != nil {
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			return route.Spec.Port.TargetPort.IntVal, nil
		} else {
			portName = strVal
		}
	}

	// Look for the base service
	key := route.Namespace + "/" + route.Spec.To.Name
	// 1. look for base service in the local cluster
	port, err := getSvcPortFromLocalCluster(portName, key, resource.ResourceTypeRoute, svcIndexer)
	if err == nil && port != 0 {
		log.Warningf("Could not find service '%s' associated with route '%s' in local cluster", key,
			route.Name)
		return port, err
	}

	// 2. look for base service in the HA peer cluster
	if ctlr.haModeType == Active && ctlr.multiClusterPoolInformers != nil {
		port, err := ctlr.getSvcPortFromHACluster(route.Namespace, route.Spec.To.Name, portName, resource.ResourceTypeRoute)
		// If service and port found then return the port
		if err == nil && port != 0 {
			log.Warningf("Could not find service '%s' associated with route '%s' in HA peer cluster", key,
				route.Name)
			return port, err
		}
	}

	// 3. look for the AB services in the local clusters
	if route.Spec.AlternateBackends == nil || len(route.Spec.AlternateBackends) == 0 {
		return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
	}
	for _, ab := range route.Spec.AlternateBackends {
		key = route.Namespace + "/" + ab.Name
		port, err = getSvcPortFromLocalCluster(portName, key, resource.ResourceTypeRoute, svcIndexer)
		if err == nil && port != 0 {
			log.Warningf("Could not find service '%s' associated with route '%s' in HA peer cluster", key,
				route.Name)
			return port, err
		}
	}

	// 4th look for the AB services in the HA peer clusters
	if ctlr.haModeType == Active && ctlr.multiClusterPoolInformers != nil {
		for _, ab := range route.Spec.AlternateBackends {
			port, err := ctlr.getSvcPortFromHACluster(route.Namespace, ab.Name, portName, resource.ResourceTypeRoute)
			if nil != err || port == 0 {
				// ignore error and continue to next service
				log.Warningf("Could not find service '%s' associated with route '%s' in HA peer cluster", key,
					route.Name)
				continue
			}
			return port, nil
		}
	}
	return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
}

// getSvcPortFromLocalCluster returns the port number for a given port name from the service in the local cluster
func getSvcPortFromLocalCluster(portName, key, resourceType string, svcIndexer cache.Indexer) (int32, error) {
	obj, found, err := svcIndexer.GetByKey(key)
	if nil != err {
		// ignore error and continue to next service
		return 0, fmt.Errorf("Error looking for service '%s': %v", key, err)
	}
	if found {
		svc := obj.(*v1.Service)
		if portName != "" {
			for _, port := range svc.Spec.Ports {
				if port.Name == portName {
					return port.Port, nil
				}
			}
			return 0,
				fmt.Errorf("Could not find service port '%s' on service '%s'", portName, key)
		} else if resourceType == resource.ResourceTypeRoute {
			return svc.Spec.Ports[0].Port, nil
		}
	}
	return 0,
		fmt.Errorf("Could not find service port '%s' on service '%s'", portName, key)
}

func (ctlr *Controller) isAddingPoolRestricted(cluster string) bool {
	// Always populate pool members in case of non-multiCluster mode
	if ctlr.multiClusterMode == "" {
		return false
	}
	// In case of multiCluster mode, populate pool members only if adminState is not set to NoPool
	if adminState, ok := ctlr.clusterAdminState[cluster]; ok && adminState == clustermanager.NoPool {
		return true
	}
	return false
}

func (ctlr *Controller) updateResourceStatus(rscType string, obj interface{}, ip string, statusOk string, err error) {
	unmonitoredOptions := metav1.ListOptions{
		LabelSelector: strings.ReplaceAll(ctlr.customResourceSelector.String(), " in ", " notin "),
	}
	switch rscType {
	case VirtualServer:
		vs := obj.(*cisapiv1.VirtualServer)
		vsStatus := cisapiv1.VirtualServerStatus{LastUpdated: metav1.Now()}
		if err != nil {
			vsStatus.Error = err.Error()
		} else if ip != "" {
			vsStatus.VSAddress = ip
			vsStatus.StatusOk = statusOk
		} else {
			vsStatus.Error = fmt.Sprintf("Missing label f5cr on VS %v/%v", vs.Namespace, vs.Name)
		}
		vs.Status = vsStatus
		_, updateErr := ctlr.kubeCRClient.CisV1().VirtualServers(vs.ObjectMeta.Namespace).UpdateStatus(context.TODO(), vs, metav1.UpdateOptions{})
		if nil != updateErr {
			log.Errorf("Error while updating VS status:%v", updateErr)
		}
		unmonitoredVS, err := ctlr.kubeCRClient.CisV1().VirtualServers("").List(context.TODO(), unmonitoredOptions)
		if err != nil {
			log.Errorf("Error while fetching unmonitored virtual servers: %v %v", err, unmonitoredVS)
		}

		for _, virtualServer := range unmonitoredVS.Items {
			erased := false
			for retryCount := 0; !erased && retryCount < 3; retryCount++ {
				virtual, getErr := ctlr.kubeCRClient.CisV1().VirtualServers(virtualServer.ObjectMeta.Namespace).Get(context.TODO(), virtualServer.ObjectMeta.Name, metav1.GetOptions{})
				if getErr != nil {
					log.Errorf("Error while fetching virtual server %v/%v: %v", virtualServer.ObjectMeta.Namespace, virtualServer.ObjectMeta.Name, getErr)
				}
				if virtual == nil {
					break
				}
				virtual.Status = cisapiv1.VirtualServerStatus{
					Error: fmt.Sprintf("Missing label f5cr on VS %v/%v", virtual.Namespace, virtual.Name),
				}
				_, err := ctlr.kubeCRClient.CisV1().VirtualServers(virtualServer.ObjectMeta.Namespace).UpdateStatus(context.TODO(), virtual, metav1.UpdateOptions{})
				if err != nil {
					log.Errorf("Error while Erasing Virtual Server Status: %v\n", err)
				} else {
					erased = true
					log.Debugf("Status Erased for Virtual Server - %v\n", virtual.ObjectMeta.Name)
				}
			}
		}

	case TransportServer:
		ts := obj.(*cisapiv1.TransportServer)
		tsStatus := cisapiv1.TransportServerStatus{LastUpdated: metav1.Now()}
		if err != nil {
			tsStatus.Error = err.Error()
		} else if ip != "" {
			tsStatus.VSAddress = ip
			tsStatus.StatusOk = statusOk
		} else {
			tsStatus.Error = fmt.Sprintf("Missing label f5cr on TS %v/%v", ts.Namespace, ts.Name)
		}
		ts.Status = tsStatus
		_, updateErr := ctlr.kubeCRClient.CisV1().TransportServers(ts.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ts, metav1.UpdateOptions{})
		if nil != updateErr {
			log.Errorf("Error while updating TS status:%v", updateErr)
		}

		unmonitoredTS, err := ctlr.kubeCRClient.CisV1().TransportServers("").List(context.TODO(), unmonitoredOptions)
		if err != nil {
			log.Errorf("Error while fetching unmonitored transport servers: %v %v", err, unmonitoredTS)
		}

		for _, transportServer := range unmonitoredTS.Items {
			erased := false
			for retryCount := 0; !erased && retryCount < 3; retryCount++ {
				virtual, getErr := ctlr.kubeCRClient.CisV1().TransportServers(transportServer.ObjectMeta.Namespace).Get(context.TODO(), transportServer.ObjectMeta.Name, metav1.GetOptions{})
				if getErr != nil {
					log.Errorf("Error while fetching transport server %v/%v: %v", transportServer.ObjectMeta.Namespace, transportServer.ObjectMeta.Name, getErr)
				}
				if virtual == nil {
					break
				}
				virtual.Status = cisapiv1.TransportServerStatus{
					Error: fmt.Sprintf("Missing label f5cr on TS %v/%v", virtual.Namespace, virtual.Name),
				}
				_, err := ctlr.kubeCRClient.CisV1().TransportServers(transportServer.ObjectMeta.Namespace).UpdateStatus(context.TODO(), virtual, metav1.UpdateOptions{})
				if err != nil {
					log.Errorf("Error while Erasing Transport Server Status: %v\n", err)
				} else {
					erased = true
					log.Debugf("Status Erased for Transport Server - %v\n", virtual.ObjectMeta.Name)
				}
			}
		}
	case IngressLink:
		il := obj.(*cisapiv1.IngressLink)
		ilStatus := cisapiv1.IngressLinkStatus{LastUpdated: metav1.Now()}
		if err != nil {
			ilStatus.Error = err.Error()
		} else if ip != "" {
			ilStatus.VSAddress = ip
			ilStatus.StatusOk = statusOk
		} else {
			ilStatus.Error = fmt.Sprintf("Missing label f5cr on il %v/%v", il.Namespace, il.Name)
		}
		il.Status = ilStatus
		_, updateErr := ctlr.kubeCRClient.CisV1().IngressLinks(il.ObjectMeta.Namespace).UpdateStatus(context.TODO(), il, metav1.UpdateOptions{})
		if nil != updateErr {
			log.Errorf("Error while updating il status:%v", updateErr)
		}
	}
}
