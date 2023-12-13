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
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/intstr"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// nextGenResourceWorker starts the Custom Resource Worker.
func (ctlr *Controller) nextGenResourceWorker() {
	log.Debugf("Starting resource worker")
	ctlr.setInitialResourceCount()
	ctlr.migrateIPAM()
	// process the DeployConfig CR if present
	if ctlr.CISConfigCRKey != "" {
		ctlr.processGlobalDeployConfigCR()
	}

	// when CIS is running in the secondary mode then enable health probe on the primary cluster
	if ctlr.multiClusterMode == SecondaryCIS {
		ctlr.firstPollPrimaryClusterHealthStatus()
		go ctlr.probePrimaryClusterHealthStatus()
	}

	// process static routes after DeployConfig CR if present is processed, so as to support external cluster static routes during cis init
	if ctlr.StaticRoutingMode {
		clusterNodes := ctlr.getNodesFromAllClusters()
		ctlr.processStaticRouteUpdate(clusterNodes)
	}
	log.Infof("Started Controller")
	for ctlr.processResources() {
	}
}

func (ctlr *Controller) setInitialResourceCount() {
	var rscCount int
	for _, ns := range ctlr.getWatchingNamespaces() {
		if ctlr.managedResources.ManageRoutes {
			nrInf, found := ctlr.getNamespacedNativeInformer(ns)
			if !found {
				continue
			}
			routes, err := nrInf.routeInformer.GetIndexer().ByIndex("namespace", ns)
			if err != nil {
				continue
			}
			rscCount += len(routes)
		}
		if ctlr.managedResources.ManageCustomResources {
			crInf, found := ctlr.getNamespacedCRInformer(ns)
			if !found {
				continue
			}
			if ctlr.managedResources.ManageVirtualServer {
				vs, err := crInf.vsInformer.GetIndexer().ByIndex("namespace", ns)
				if err != nil {
					continue
				}
				rscCount += len(vs)
			}

			if ctlr.managedResources.ManageTransportServer {
				ts, err := crInf.tsInformer.GetIndexer().ByIndex("namespace", ns)
				if err != nil {
					continue
				}
				rscCount += len(ts)
			}

			if ctlr.managedResources.ManageIL {
				il, err := crInf.ilInformer.GetIndexer().ByIndex("namespace", ns)
				if err != nil {
					continue
				}
				rscCount += len(il)
			}

			if ctlr.managedResources.ManageEDNS {
				if comInf, ok := ctlr.comInformers[ns]; ok {
					edns, err := comInf.ednsInformer.GetIndexer().ByIndex("namespace", ns)
					if err != nil {
						continue
					}
					rscCount += len(edns)
				}
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
			if ctlr.managedResources.ManageRoutes {
				if _, ok := OSCPCoreServices[svc.Name]; ok {
					continue
				}
			}
			//if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			//	rscCount++
			//}
		}
	}

	ctlr.initialResourceCount = rscCount
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
				//if svc, ok := rKey.rsc.(*v1.Service); ok {
				//	if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
				//		ctlr.initialResourceCount--
				//	} else {
				//		// return as we don't process other services at start up
				//		return true
				//	}
				//}
				return true
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
		if !ctlr.managedResources.ManageRoutes {
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
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		}
		if rKey.event != Create && ctlr.multiClusterMode != "" {
			ctlr.deleteUnrefereedMultiClusterInformers()
		}

	case ConfigCR:
		cm := rKey.rsc.(*cisapiv1.DeployConfig)
		err, ok := ctlr.processConfigCR(cm, rscDelete)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("[ERROR] Sync %v failed with %v", key, err))
			break
		}

		if !ok {
			isRetryableError = true
		}
	case VirtualServer:
		if !ctlr.managedResources.ManageCustomResources {
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
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isRetryableError = true
		}
		if rKey.event != Create && ctlr.multiClusterMode != "" {
			ctlr.deleteUnrefereedMultiClusterInformers()
		}
	case TLSProfile:
		if !ctlr.managedResources.ManageCustomResources {
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
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		}
	case K8sSecret:
		secret := rKey.rsc.(*v1.Secret)
		mcc := ctlr.getClusterForSecret(secret)
		// TODO: Process all the resources again that refer to any resource running in the affected cluster?
		if mcc != (cisapiv1.ExternalClusterConfig{}) {
			err := ctlr.updateClusterConfigStore(secret, mcc, rscDelete)
			if err != nil {
				log.Warningf(err.Error())
			}
			break
		}
		if ctlr.managedResources.ManageRoutes {
			routeGroup := ctlr.getRouteGroupForSecret(secret)
			if routeGroup != "" {
				_ = ctlr.processRoutes(routeGroup, false)
			}
		}
		if ctlr.managedResources.ManageCustomResources {
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
						utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
						isRetryableError = true
					}
				}
			}
		}

	case TransportServer:
		if !ctlr.managedResources.ManageCustomResources {
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
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isRetryableError = true
		}
		if rKey.event != Create && ctlr.multiClusterMode != "" {
			ctlr.deleteUnrefereedMultiClusterInformers()
		}
	case IngressLink:
		if !ctlr.managedResources.ManageCustomResources {
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
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isRetryableError = true
		}
	case ExternalDNS:
		if !ctlr.managedResources.ManageRoutes && !ctlr.managedResources.ManageCustomResources {
			break
		}
		edns := rKey.rsc.(*cisapiv1.ExternalDNS)
		ctlr.processExternalDNS(edns, rscDelete)
	case IPAM:
		ipam := rKey.rsc.(*ficV1.IPAM)
		_ = ctlr.processIPAM(ipam)

	case CustomPolicy:
		cp := rKey.rsc.(*cisapiv1.Policy)
		if ctlr.managedResources.ManageRoutes {
			routeGroups := ctlr.getRouteGroupForCustomPolicy(cp.Namespace + "/" + cp.Name)
			for _, routeGroup := range routeGroups {
				_ = ctlr.processRoutes(routeGroup, false)
			}
		}
		if ctlr.managedResources.ManageCustomResources {
			virtuals := ctlr.getVirtualsForCustomPolicy(cp)
			//Sync Custompolicy for Virtual Servers
			for _, virtual := range virtuals {
				err := ctlr.processVirtualServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isRetryableError = true
				}
			}
			//Sync Custompolicy for Transport Servers
			tsVirtuals := ctlr.getTransportServersForCustomPolicy(cp)
			for _, virtual := range tsVirtuals {
				err := ctlr.processTransportServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isRetryableError = true
				}
			}
			//Sync Custompolicy for Services of type LB
			lbServices := ctlr.getLBServicesForCustomPolicy(cp)
			for _, lbService := range lbServices {
				err := ctlr.processLBServices(lbService, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
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

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
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
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
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

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
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
		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
			break
		}
		// Update the poolMembers for affected resources
		ctlr.updatePoolMembersForService(svcKey, false)

		if ctlr.managedResources.ManageRoutes && rscDelete == false && ctlr.resources.baseRouteConfig.AutoMonitor != None {
			ctlr.UpdatePoolHealthMonitors(svcKey)
		}

	case Namespace:
		ns := rKey.rsc.(*v1.Namespace)
		nsName := ns.ObjectMeta.Name
		if ctlr.managedResources.ManageRoutes {
			var triggerDelete bool
			if rscDelete {
				// TODO: Delete all the resource configs from the store
				if nrInf, ok := ctlr.nrInformers[nsName]; ok {
					nrInf.stop()
					delete(ctlr.nrInformers, nsName)
				}
				if comInf, ok := ctlr.comInformers[nsName]; ok {
					comInf.stop(nsName)
					delete(ctlr.comInformers, nsName)
				}
				ctlr.namespacesMutex.Lock()
				delete(ctlr.namespaces, nsName)
				ctlr.namespacesMutex.Unlock()
				log.Debugf("Removed namespace: '%v' from CIS scope", nsName)
				triggerDelete = true
			} else {
				ctlr.namespacesMutex.Lock()
				ctlr.namespaces[nsName] = true
				ctlr.namespacesMutex.Unlock()
				_ = ctlr.addNamespacedInformers(nsName, true)
				log.Debugf("Added namespace: '%v' to CIS scope", nsName)
			}
			if ctlr.namespaceLabelMode {
				ctlr.processGlobalDeployConfigCR()
			} else {
				if routeGroup, ok := ctlr.resources.invertedNamespaceLabelMap[nsName]; ok {
					_ = ctlr.processRoutes(routeGroup, triggerDelete)
				}
			}
		}

		if ctlr.managedResources.ManageCustomResources {
			if rscDelete {
				for _, vrt := range ctlr.getAllVirtualServers(nsName) {
					err := ctlr.processVirtualServers(vrt, true)
					if err != nil {
						// TODO
						utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
						isRetryableError = true
					}
				}

				for _, ts := range ctlr.getAllTransportServers(nsName) {
					err := ctlr.processTransportServers(ts, true)
					if err != nil {
						// TODO
						utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
						isRetryableError = true
					}
				}

				ctlr.crInformers[nsName].stop()
				delete(ctlr.crInformers, nsName)
				ctlr.namespacesMutex.Lock()
				delete(ctlr.namespaces, nsName)
				ctlr.namespacesMutex.Unlock()
				log.Debugf("Removed namespace: '%v' from CIS scope", nsName)
			} else {
				ctlr.namespacesMutex.Lock()
				ctlr.namespaces[nsName] = true
				ctlr.namespacesMutex.Unlock()
				_ = ctlr.addNamespacedInformers(nsName, true)
				log.Debugf("Added namespace: '%v' to CIS scope", nsName)
			}
		}
	case HACIS:
		log.Debugf("posting declaration on primary cluster down event")
	case NodeUpdate:
		log.Debugf("posting declaration on node update")
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}

	if isRetryableError {
		ctlr.resourceQueue.AddRateLimited(key)
	} else {
		ctlr.resourceQueue.Forget(key)
	}
	if ctlr.initState {
		return true
	}

	if (ctlr.resourceQueue.Len() == 0) ||
		(ctlr.multiClusterMode == SecondaryCIS && rKey.kind == HACIS) {

		if ctlr.multiClusterMode != "" {
			// only standalone CIS & Primary CIS should post the teems data
			if ctlr.multiClusterMode != SecondaryCIS {
				// using node informers to count the clusters as it will be available in all CNIs
				// adding 1 for the current cluster
				ctlr.TeemData.ClusterCount = len(ctlr.multiClusterNodeInformers) + 1
				//TODO add support for teems data
				// go ctlr.TeemData.PostTeemsData()
			}
		} else {
			// In non multi-cluster mode, we should post the teems data
			//TODO add support for teems data
			// go ctlr.TeemData.PostTeemsData()
		}
		// set prometheus resource metrics
		ctlr.setPrometheusResourceCount()
		// Put each BIGIPConfig per bigip  pair into specific requestChannel
		for bigip, bigipConfig := range ctlr.resources.bigIpMap {
			if (!reflect.DeepEqual(bigipConfig.ltmConfig, LTMConfig{}) || !reflect.DeepEqual(bigipConfig.gtmConfig, GTMConfig{})) && ctlr.resources.isConfigUpdated(bigip) {
				for _, bigIpKey := range getBigIpList(bigip) {
					agent := ctlr.AgentMap[bigIpKey]
					config := ResourceConfigRequest{
						bigipConfig:         bigIpKey,
						bigIpResourceConfig: bigipConfig,
					}
					config.reqId = ctlr.enqueueReq(bigipConfig)
					agent.EnqueueRequestConfig(config)
				}
			}
		}
		ctlr.initState = false
		ctlr.resources.updateCaches()

	}
	return true
}

func getBigIpList(config cisapiv1.BigIpConfig) []BigIpKey {
	var bigIpList []BigIpKey
	bigIpList = append(bigIpList, BigIpKey{BigIpAddress: config.BigIpAddress, BigIpLabel: config.BigIpLabel})
	if config.HaBigIpAddress != "" {
		bigIpList = append(bigIpList, BigIpKey{BigIpAddress: config.HaBigIpAddress, BigIpLabel: config.BigIpLabel})
	}
	return bigIpList
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
		log.Infof("No VirtualServers found in namespace %s",
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
		log.Infof("No VirtualServers found in namespace %s",
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
		log.Infof("No LB service found in namespace %s",
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
		if vs.ObjectMeta.Namespace == tlsNamespace && vs.Spec.TLSProfileName == tlsName {
			found := false
			for _, host := range tls.Spec.Hosts {
				if vs.Spec.Host == host {
					result = append(result, vs)
					found = true
					break
				}
			}
			if !found {
				log.Errorf("TLSProfile hostname is not same as virtual host %s for profile %s", vs.Spec.Host, vs.Spec.TLSProfileName)
			}
		}
	}

	return result
}

func (ctlr *Controller) getTLSProfileForVirtualServer(
	vs *cisapiv1.VirtualServer,
	namespace string) *cisapiv1.TLSProfile {
	tlsName := vs.Spec.TLSProfileName
	tlsKey := fmt.Sprintf("%s/%s", namespace, tlsName)

	// Initialize CustomResource Informer for required namespace
	crInf, ok := ctlr.getNamespacedCRInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	comInf, ok := ctlr.getNamespacedCommonInformer(namespace)
	if !ok {
		log.Errorf("Common Informer not found for namespace: %v", namespace)
		return nil
	}
	// TODO: Create Internal Structure to hold TLSProfiles. Make API call only for a new TLSProfile
	// Check if the TLSProfile exists and valid for us.
	obj, tlsFound, _ := crInf.tlsInformer.GetIndexer().GetByKey(tlsKey)
	if !tlsFound {
		log.Errorf("TLSProfile %s does not exist", tlsName)
		return nil
	}

	// validate TLSProfile
	validation := validateTLSProfile(obj.(*cisapiv1.TLSProfile))
	if validation == false {
		return nil
	}

	tlsProfile := obj.(*cisapiv1.TLSProfile)

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
				if checkCertificateHost(vs.Spec.Host, clientSecret.Data["tls.crt"], clientSecret.Data["tls.key"]) {
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
			match = checkCertificateHost(vs.Spec.Host, clientSecret.Data["tls.crt"], clientSecret.Data["tls.key"])
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
			warning := fmt.Sprintf("VirtualServer %s, is not valid", vkey)
			log.Warningf(warning)
			prometheus.ConfigurationWarnings.WithLabelValues(VirtualServer, virtual.ObjectMeta.Namespace, virtual.ObjectMeta.Name, warning).Set(1)
			return nil
		}
	}
	prometheus.ConfigurationWarnings.WithLabelValues(VirtualServer, virtual.ObjectMeta.Namespace, virtual.ObjectMeta.Name, "").Set(0)
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
	// TODO: phase2 get bigipLabel from cr resource or service address cr
	// Phase1 setting bigipLabel to empty string
	bigipLabel := BigIPLabel
	bigipConfig := ctlr.getBIGIPConfig(bigipLabel)
	VSSpecProps := &VSSpecProperties{}
	virtuals := ctlr.getAssociatedVirtualServers(virtual, allVirtuals, isVSDeleted, VSSpecProps)
	//ctlr.getAssociatedSpecVirtuals(virtuals,VSSpecProps)

	var ip string
	var status int
	partition := ctlr.getCRPartition(virtual.Spec.Partition)
	if ctlr.ipamCli != nil {
		if isVSDeleted && len(virtuals) == 0 && virtual.Spec.VirtualServerAddress == "" {
			if virtual.Spec.HostGroup != "" {
				//hg is unique across namespaces
				//all virtuals with same hg are grouped together across namespaces
				key := virtual.Spec.HostGroup + "_hg"
				ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, "", key)
			} else {
				key := virtual.Namespace + "/" + virtual.Spec.Host + "_host"
				ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, virtual.Spec.Host, key)
			}
		} else if virtual.Spec.VirtualServerAddress != "" {
			// Prioritise VirtualServerAddress specified over IPAMLabel
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ipamLabel := getIPAMLabel(virtuals)
			if virtual.Spec.HostGroup != "" {
				//hg is unique across namepsaces
				key := virtual.Spec.HostGroup + "_hg"
				ip, status = ctlr.requestIP(ipamLabel, "", key)
			} else {
				key := virtual.Namespace + "/" + virtual.Spec.Host + "_host"
				ip, status = ctlr.requestIP(ipamLabel, virtual.Spec.Host, key)
			}

			switch status {
			case NotEnabled:
				log.Debug("IPAM Custom Resource Not Available")
				return nil
			case InvalidInput:
				log.Debugf("IPAM Invalid IPAM Label: %v for Virtual Server: %s/%s", ipamLabel, virtual.Namespace, virtual.Name)
				return nil
			case NotRequested:
				return fmt.Errorf("unable make do IPAM Request, will be re-requested soon")
			case Requested:
				log.Debugf("IP address requested for service: %s/%s", virtual.Namespace, virtual.Name)
				return nil
			}
		}
	} else {
		if virtual.Spec.HostGroup == "" {
			if virtual.Spec.VirtualServerAddress == "" {
				return fmt.Errorf("No VirtualServer address or IPAM found.")
			}
			ip = virtual.Spec.VirtualServerAddress
		} else {
			var err error
			ip, err = getVirtualServerAddress(virtuals)
			if err != nil {
				log.Errorf("Error in virtualserver address: %s", err.Error())
				return err
			}
			if ip == "" {
				ip = virtual.Spec.VirtualServerAddress
				if ip == "" {
					return fmt.Errorf("No VirtualServer address found for: %s", virtual.Name)
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
		if virtual.Spec.VirtualServerName != "" {
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
			rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)

			if _, ok := rsMap[rsName]; ok {
				hostnames = rsMap[rsName].MetaData.hosts
			}
			ctlr.deleteVirtualServer(partition, rsName, bigipConfig)
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
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			portS.port,
		)
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
				break
			}
		}
		if err != nil {
			processingError = true
			log.Errorf("%v", err)
			break
		}

		for _, vrt := range virtuals {
			// Updating the virtual server IP Address status for all associated virtuals
			vrt.Status.VSAddress = ip
			passthroughVS := false
			var tlsProf *cisapiv1.TLSProfile
			var tlsTermination string
			if isTLSVirtualServer(vrt) {
				// Handle TLS configuration for VirtualServer Custom Resource
				tlsProf = ctlr.getTLSProfileForVirtualServer(vrt, vrt.Namespace)
				if tlsProf == nil {
					// Processing failed
					// Stop processing further virtuals
					processingError = true
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
				break
			}
			// handle pool settings from policy cr
			if plc != nil {
				if plc.Spec.PoolSettings != (cisapiv1.PoolSettingsSpec{}) {
					err := ctlr.handlePoolResourceConfigForPolicy(rsCfg, plc)
					if err != nil {
						processingError = true
						break
					}
				}
			}
			if tlsProf != nil {
				processed := ctlr.handleVirtualServerTLS(rsCfg, vrt, tlsProf, ip)
				if !processed {
					// Processing failed
					// Stop processing further virtuals
					processingError = true
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
		rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)

		// Update ltmConfig with ResourceConfigs created for the current virtuals
		for rsName, rsCfg := range vsMap {
			if _, ok := rsMap[rsName]; !ok {
				hostnames = rsCfg.MetaData.hosts
			}
			rsMap[rsName] = rsCfg
		}

		if len(hostnames) > 0 {
			ctlr.ProcessAssociatedExternalDNS(hostnames)
		}
	}

	return nil
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
	// {hostname: {path: <empty_struct>}}
	uniqueHostPathMap := make(map[string]map[string]struct{})
	currentVSPartition := ctlr.getCRPartition(currentVS.Spec.Partition)

	for _, vrt := range allVirtuals {
		// skip the deleted virtual in the event of deletion
		if isVSDeleted && vrt.Name == currentVS.Name {
			continue
		}

		// Multiple VS sharing same VS address with different partition is invalid
		// This also handles for host group/VS with same hosts
		if currentVS.Spec.VirtualServerAddress != "" &&
			currentVS.Spec.VirtualServerAddress == vrt.Spec.VirtualServerAddress &&
			currentVSPartition != ctlr.getCRPartition(vrt.Spec.Partition) {
			log.Errorf("Multiple Virtual Servers %v,%v are configured with same VirtualServerAddress : %v with different partitions", currentVS.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
			return nil
		}

		// skip the virtuals in other HostGroups
		if vrt.Spec.HostGroup != currentVS.Spec.HostGroup {
			continue
		}

		if currentVS.Spec.HostGroup == "" {
			// in the absence of HostGroup, skip the virtuals with other host name if tls terminations are also same
			if vrt.Spec.Host != currentVS.Spec.Host {
				if vrt.Spec.TLSProfileName != "" && currentVS.Spec.TLSProfileName != "" {
					vrtTLS := ctlr.getTLSProfileForVirtualServer(vrt, vrt.Namespace)
					currentVSTLS := ctlr.getTLSProfileForVirtualServer(currentVS, currentVS.Namespace)
					// Skip VS if terminations are different
					if (vrtTLS == nil || currentVSTLS == nil) || vrtTLS.Spec.TLS.Termination == currentVSTLS.Spec.TLS.Termination {
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
					log.Errorf("Same host %v is configured with different VirtualServerAddress : %v ", vrt.Spec.Host, vrt.Spec.VirtualServerName)
					return nil
				}
				// In case of empty host name or host names not matching, skip the virtual with other VirtualServerAddress
				continue
			}
			//with additonalVirtualServerAddresses, skip the virtuals if ip list doesn't match
			if !reflect.DeepEqual(currentVS.Spec.AdditionalVirtualServerAddresses, vrt.Spec.AdditionalVirtualServerAddresses) {
				if vrt.Spec.Host != "" {
					log.Errorf("Same host %v is configured with different AdditionalVirtualServerAddress : %v ", vrt.Spec.Host, vrt.ObjectMeta.Name)
					return nil
				}
				// In case of empty host name, skip the virtual with other AdditionalVirtualServerAddress
				continue
			}
		}

		if ctlr.ipamCli != nil {
			if currentVS.Spec.HostGroup == "" && vrt.Spec.IPAMLabel != currentVS.Spec.IPAMLabel {
				log.Errorf("Same host %v is configured with different IPAM labels: %v, %v. Unable to process %v", vrt.Spec.Host, vrt.Spec.IPAMLabel, currentVS.Spec.IPAMLabel, currentVS.Name)
				return nil
			}
			// Empty host and hostGroup with IPAM label is invalid for a Virtual Server
			if vrt.Spec.IPAMLabel != "" && vrt.Spec.Host == "" && vrt.Spec.HostGroup == "" {
				log.Errorf("Hostless VS %v is configured with IPAM label: %v and missing HostGroup", vrt.ObjectMeta.Name, vrt.Spec.IPAMLabel)
				return nil
			}

			// Empty host with empty IPAM label is invalid
			if vrt.Spec.Host == "" && vrt.Spec.VirtualServerAddress == "" && len(vrt.Spec.AdditionalVirtualServerAddresses) == 0 {
				if vrt.Spec.IPAMLabel == "" && vrt.Spec.HostGroup != "" {
					log.Errorf("Hostless VS %v is configured with missing IPAM label", vrt.ObjectMeta.Name)
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
				log.Debugf("Discarding the VirtualServer %v/%v due to duplicate path",
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
			log.Errorf("Multiple Transport Servers %v,%v are configured with same VirtualServerAddress : %v "+
				"with different partitions", currentTS.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
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
			log.Errorf("Multiple Ingress Links %v,%v are configured with same VirtualServerAddress : %v "+
				"with different partitions", currentIL.Name, vrt.Name, vrt.Spec.VirtualServerAddress)
			return false
		}
	}
	return true
}
func (ctlr *Controller) getCRPartition(partition string) string {
	if partition == "" {
		return ctlr.getPartitionForBIGIP("")
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
		tskey := ts.Spec.HostGroup + "_hg"
		if tskey == key {
			return true
		}
	}
	allVS := ctlr.getAllVSFromMonitoredNamespaces()
	for _, vs := range allVS {
		vskey := vs.Spec.HostGroup + "_hg"
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

func (ctlr *Controller) updatePoolIdentifierForService(key MultiClusterServiceKey, rsKey resourceRef, svcPort intstr.IntOrString, poolName, partition, rsName, path string, bigipLabel string) {
	poolId := PoolIdentifier{
		poolName:   poolName,
		partition:  partition,
		rsName:     rsName,
		path:       path,
		rsKey:      rsKey,
		bigIpLabel: bigipLabel,
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
					rsCfg := ctlr.getVirtualServer(poolId.partition, poolId.rsName, poolId.bigIpLabel)
					if rsCfg == nil {
						continue
					}
					freshRsCfg := &ResourceConfig{}
					freshRsCfg.copyConfig(rsCfg)
					for index, pool := range freshRsCfg.Pools {
						if pool.Name == poolId.poolName && pool.Partition == poolId.partition {
							if pool.ServicePort.IntVal == 0 || svcPortUpdated {
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
								}
							}
							ctlr.updatePoolMembersForResources(&pool)
							if len(pool.Members) > 0 {
								freshRsCfg.MetaData.Active = true
							} else {
								freshRsCfg.MetaData.Active = false
							}
							freshRsCfg.Pools[index] = pool
						}
					}
					bigipConfig := ctlr.getBIGIPConfig(BigIPLabel)
					_ = ctlr.resources.setResourceConfig(poolId.partition, poolId.rsName, freshRsCfg, bigipConfig)
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
	// for local cluster
	if pool.Cluster == "" {
		poolMembers = append(poolMembers,
			ctlr.fetchPoolMembersForService(pool.ServiceName, pool.ServiceNamespace, pool.ServicePort,
				pool.NodeMemberLabel, "", pool.ConnectionLimit)...)
		if len(ctlr.clusterRatio) > 0 {
			pool.Members = poolMembers
			return
		}
	}

	// for HA cluster pair service
	if ctlr.haModeType == Active && ctlr.multiClusterConfigs.HAPairClusterName != "" {
		poolMembers = append(poolMembers,
			ctlr.fetchPoolMembersForService(pool.ServiceName, pool.ServiceNamespace, pool.ServicePort,
				pool.NodeMemberLabel, ctlr.multiClusterConfigs.HAPairClusterName, pool.ConnectionLimit)...)
	}

	// In case of ratio mode unique pools are created for each service so only update the pool members for this backend
	// pool associated with the HA peer cluster or external cluster and return
	if len(ctlr.clusterRatio) > 0 {
		poolMembers = append(poolMembers,
			ctlr.fetchPoolMembersForService(pool.ServiceName, pool.ServiceNamespace, pool.ServicePort,
				pool.NodeMemberLabel, pool.Cluster, pool.ConnectionLimit)...)
		pool.Members = poolMembers
		return
	}

	// For multiCluster services
	for _, mcs := range pool.MultiClusterServices {
		// Skip invalid extended service
		if !ctlr.checkValidExtendedService(mcs) {
			continue
		}
		// Update pool members for all the multi cluster services specified in the route annotations
		// Ensure cluster services of the HA pair cluster (if specified as multi cluster service in route annotations)
		// isn't considered for updating the pool members as it may lead to duplicate pool members as it may have been
		// already populated while updating the HA cluster pair service pool members above
		if _, ok := ctlr.multiClusterPoolInformers[mcs.ClusterName]; ok && ctlr.multiClusterConfigs.HAPairClusterName != mcs.ClusterName {
			poolMembers = append(poolMembers,
				ctlr.fetchPoolMembersForService(mcs.SvcName, mcs.Namespace, mcs.ServicePort,
					pool.NodeMemberLabel, mcs.ClusterName, pool.ConnectionLimit)...)
		}
	}
	pool.Members = poolMembers
}

// fetchPoolMembersForService returns pool members associated with a service created in specified cluster
func (ctlr *Controller) fetchPoolMembersForService(serviceName string, serviceNamespace string,
	servicePort intstr.IntOrString, nodeMemberLabel string, clusterName string, podConnections int32) []PoolMember {
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
		log.Errorf("%v %v", err, getClusterLog(clusterName))
	}
	var poolMembers []PoolMember
	if svc != nil {
		_ = ctlr.processService(svc, clusterName)
		// update the nlpStore cache with pods and their node annotations
		if ctlr.PoolMemberType == NodePortLocal {
			pods := ctlr.GetPodsForService(svcKey.namespace, svcKey.serviceName, true)
			for _, pod := range pods {
				ctlr.processPod(pod, false)
			}
		}
		poolMembers = append(poolMembers, ctlr.getPoolMembersForService(svcKey, servicePort, nodeMemberLabel)...)
	}
	// Update the cluster admin state for pool members if multi cluster mode is enabled
	ctlr.updatePoolMembersConfig(&poolMembers, clusterName, podConnections)

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
	switch ctlr.PoolMemberType {
	case NodePort:
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
	case Cluster:
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
		pods := ctlr.GetPodsForService(mSvcKey.namespace, mSvcKey.serviceName, true)
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
			Address: v.Addr,
			Port:    nodePort,
			Session: "user-enabled",
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
			warning := fmt.Sprintf("TransportServer %s, is not valid", vkey)
			log.Warningf(warning)
			prometheus.ConfigurationWarnings.WithLabelValues(TransportServer, virtual.ObjectMeta.Namespace, virtual.ObjectMeta.Name, warning).Set(1)
			return nil
		}
	}
	prometheus.ConfigurationWarnings.WithLabelValues(TransportServer, virtual.ObjectMeta.Namespace, virtual.ObjectMeta.Name, "").Set(0)
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.TransportServer[virtual.ObjectMeta.Namespace] = len(ctlr.getAllTransportServers(virtual.Namespace))
	ctlr.TeemData.Unlock()

	if isTSDeleted {
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.TransportServer[virtual.ObjectMeta.Namespace]--
		ctlr.TeemData.Unlock()
	}

	var allVirtuals []*cisapiv1.TransportServer
	// TODO: phase2 get bigipLabel from cr resource or service address cr
	// Phase1 setting bigipLabel to empty string
	bigipLabel := BigIPLabel
	bigipConfig := ctlr.getBIGIPConfig(bigipLabel)
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
	partition := ctlr.getCRPartition(virtual.Spec.Partition)
	key = virtual.ObjectMeta.Namespace + "/" + virtual.ObjectMeta.Name + "_ts"
	if ctlr.ipamCli != nil {
		if virtual.Spec.HostGroup != "" {
			key = virtual.Spec.HostGroup + "_hg"
		}
		if isTSDeleted && virtual.Spec.VirtualServerAddress == "" {
			ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, "", key)
		} else if virtual.Spec.VirtualServerAddress != "" {
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ip, status = ctlr.requestIP(virtual.Spec.IPAMLabel, "", key)

			switch status {
			case NotEnabled:
				log.Debug("[IPAM] IPAM Custom Resource Not Available")
				return nil
			case InvalidInput:
				log.Debugf("[IPAM] IPAM Invalid IPAM Label: %v for Transport Server: %s/%s",
					virtual.Spec.IPAMLabel, virtual.Namespace, virtual.Name)
				return nil
			case NotRequested:
				return fmt.Errorf("[IPAM] unable to make IPAM Request, will be re-requested soon")
			case Requested:
				log.Debugf("[IPAM] IP address requested for Transport Server: %s/%s", virtual.Namespace, virtual.Name)
				return nil
			}
		}
	} else {
		if virtual.Spec.VirtualServerAddress == "" {
			return fmt.Errorf("No VirtualServer address in TS or IPAM found.")
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
		rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)
		var hostnames []string
		if _, ok := rsMap[rsName]; ok {
			hostnames = rsMap[rsName].MetaData.hosts
		}

		ctlr.deleteVirtualServer(partition, rsName, bigipConfig)
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
	rsCfg.Virtual.SetVirtualAddress(
		ip,
		virtual.Spec.VirtualServerPort,
	)
	plc, err := ctlr.getPolicyFromTransportServer(virtual)
	if plc != nil {
		err := ctlr.handleTSResourceConfigForPolicy(rsCfg, plc)
		if err != nil {
			log.Errorf("%v", err)
			return nil
		}
	}
	if err != nil {
		log.Errorf("%v", err)
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
		return nil
	}
	// handle pool settings from policy cr
	if plc != nil {
		if plc.Spec.PoolSettings != (cisapiv1.PoolSettingsSpec{}) {
			err := ctlr.handlePoolResourceConfigForPolicy(rsCfg, plc)
			if err != nil {
				if err != nil {
					log.Errorf("%v", err)
					return nil
				}
			}
		}
	}
	// Add TS resource key to processedNativeResources to mark it as processed
	ctlr.resources.processedNativeResources[resourceRef{
		kind:      TransportServer,
		namespace: virtual.Namespace,
		name:      virtual.Name,
	}] = struct{}{}

	rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)
	rsMap[rsName] = rsCfg
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
		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			allLBServices = append(allLBServices, svc)
		}
	}

	return allLBServices
}

func (ctlr *Controller) processLBServices(
	svc *v1.Service,
	isSVCDeleted bool,
) error {

	ipamLabel, ok := svc.Annotations[LBServiceIPAMLabelAnnotation]
	if !ok {
		log.Debugf("Service %v/%v does not have annotation %v, continuing.",
			svc.Namespace,
			svc.Name,
			LBServiceIPAMLabelAnnotation,
		)
		return nil
	}
	if ctlr.ipamCli == nil {
		warning := "[IPAM] IPAM is not enabled, Unable to process Services of Type LoadBalancer"
		log.Warningf(warning)
		prometheus.ConfigurationWarnings.WithLabelValues(Service, svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, warning).Set(1)
		return nil
	}
	prometheus.ConfigurationWarnings.WithLabelValues(Service, svc.ObjectMeta.Namespace, svc.ObjectMeta.Name, "").Set(0)
	svcKey := svc.Namespace + "/" + svc.Name + "_svc"
	var ip string
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

	if !isSVCDeleted {
		ctlr.setLBServiceIngressStatus(svc, ip)
	} else {
		ctlr.unSetLBServiceIngressStatus(svc, ip)
	}

	for _, portSpec := range svc.Spec.Ports {

		log.Debugf("Processing Service Type LB %s for port %v",
			svc.ObjectMeta.Name, portSpec)

		rsName := AS3NameFormatter(fmt.Sprintf("vs_lb_svc_%s_%s_%s_%v", svc.Namespace, svc.Name, ip, portSpec.Port))
		//TODO: get bigipLabel from route resource or service address cr and get parition from specific bigip agent
		//Phase1 getting partition from bigipconfig index 0
		bigipLabel := BigIPLabel
		partition := ctlr.getPartitionForBIGIP(bigipLabel)
		bigipConfig := ctlr.getBIGIPConfig(bigipLabel)
		if isSVCDeleted {
			rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)
			var hostnames []string
			if _, ok := rsMap[rsName]; ok {
				hostnames = rsMap[rsName].MetaData.hosts
			}
			ctlr.deleteVirtualServer(partition, rsName, bigipConfig)
			if len(hostnames) > 0 {
				ctlr.ProcessAssociatedExternalDNS(hostnames)
			}
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = partition
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

		rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)
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
	if ctlr.managedResources.ManageEDNS == false {
		return
	}
	//TODO: get bigipLabel from route resource or service address cr
	// Phase1 setting bigipLabel to empty string
	bigipLabel := BigIPLabel
	bigipConfig := ctlr.getBIGIPConfig(bigipLabel)
	if bigipConfig != (cisapiv1.BigIpConfig{}) {
		if _, ok := ctlr.resources.bigIpMap[bigipConfig]; ok {
			if gtmPartitionConfig, ok := ctlr.resources.bigIpMap[bigipConfig].gtmConfig[DEFAULT_GTM_PARTITION]; ok {
				if processedWIP, ok := gtmPartitionConfig.WideIPs[edns.Spec.DomainName]; ok {
					if processedWIP.UID != string(edns.UID) {
						log.Errorf("EDNS with same domain name %s present", edns.Spec.DomainName)
						return
					}
				}
			}
		}
	}

	if isDelete {
		if _, ok := ctlr.resources.bigIpMap[bigipConfig].gtmConfig[DEFAULT_GTM_PARTITION]; !ok {
			return
		}

		delete(ctlr.resources.bigIpMap[bigipConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs, edns.Spec.DomainName)
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

	partitions := ctlr.resources.getLTMPartitions(bigipLabel)
	for _, pl := range edns.Spec.Pools {
		UniquePoolName := strings.Replace(edns.Spec.DomainName, "*", "wildcard", -1) + "_" +
			AS3NameFormatter(strings.TrimPrefix(ctlr.AgentMap[BigIpKey{BigIpAddress: bigipConfig.BigIpAddress, BigIpLabel: bigipConfig.BigIpLabel}].PostManager.CMURL, "https://")) + "_" + DEFAULT_GTM_PARTITION
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
			rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)

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
	if _, present := ctlr.resources.bigIpMap[bigipConfig]; !present {
		ctlr.resources.bigIpMap[bigipConfig] = BigIpResourceConfig{
			ltmConfig: make(LTMConfig),
			gtmConfig: make(GTMConfig),
		}

	}
	if _, ok := ctlr.resources.bigIpMap[bigipConfig].gtmConfig[DEFAULT_GTM_PARTITION]; !ok {
		ctlr.resources.bigIpMap[bigipConfig].gtmConfig[DEFAULT_GTM_PARTITION] = GTMPartitionConfig{
			WideIPs: make(map[string]WideIP),
		}
	}

	ctlr.resources.bigIpMap[bigipConfig].gtmConfig[DEFAULT_GTM_PARTITION].WideIPs[wip.DomainName] = wip
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
	if ctlr.managedResources.ManageEDNS == false {
	}
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
func checkCertificateHost(host string, certificate []byte, key []byte) bool {
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
			log.Debugf("Error: Hostname in virtualserver does not match with certificate hostname: %v", ok)
			return false
		}
	} else {
		log.Debugf("Error: SAN is empty on the certificate. So skipping Hostname validation on cert")
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
		if rscKind != "hg" {
			splits := strings.Split(pKey, "/")
			ns = splits[0]
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
				key := vs.Spec.HostGroup + "_hg"
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
				key := ts.Spec.HostGroup + "_hg"
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
				key := vs.Namespace + "/" + vs.Spec.Host + "_host"
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
			item, exists, err := crInf.tsInformer.GetIndexer().GetByKey(pKey[:idx])
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
			item, exists, err := crInf.ilInformer.GetIndexer().GetByKey(pKey[:idx])
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
			item, exists, err := comInf.svcInformer.GetIndexer().GetByKey(pKey[:idx])
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
			warning := fmt.Sprintf("ingressLink %s, is not valid", vkey)
			log.Warningf(warning)
			prometheus.ConfigurationWarnings.WithLabelValues(IngressLink, ingLink.ObjectMeta.Namespace, ingLink.ObjectMeta.Name, warning).Set(1)
			return nil
		}
	}
	prometheus.ConfigurationWarnings.WithLabelValues(IngressLink, ingLink.ObjectMeta.Namespace, ingLink.ObjectMeta.Name, "").Set(0)
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
	partition := ctlr.getCRPartition(ingLink.Spec.Partition)
	key = ingLink.ObjectMeta.Namespace + "/" + ingLink.ObjectMeta.Name + "_il"
	//TODO: get bigipLabel from route resource or service address cr
	// Phase1 setting bigipLabel to empty string
	bigipLabel := BigIPLabel
	bigipConfig := ctlr.getBIGIPConfig(bigipLabel)
	if ctlr.ipamCli != nil {
		if isILDeleted && ingLink.Spec.VirtualServerAddress == "" {
			ip = ctlr.releaseIP(ingLink.Spec.IPAMLabel, "", key)
		} else if ingLink.Spec.VirtualServerAddress != "" {
			ip = ingLink.Spec.VirtualServerAddress
		} else {
			ip, status = ctlr.requestIP(ingLink.Spec.IPAMLabel, "", key)

			switch status {
			case NotEnabled:
				log.Debug("[IPAM] IPAM Custom Resource Not Available")
				return nil
			case InvalidInput:
				log.Debugf("[IPAM] IPAM Invalid IPAM Label: %v for IngressLink: %s/%s",
					ingLink.Spec.IPAMLabel, ingLink.Namespace, ingLink.Name)
				return nil
			case NotRequested:
				return fmt.Errorf("[IPAM] unable to make IPAM Request, will be re-requested soon")
			case Requested:
				log.Debugf("[IPAM] IP address requested for IngressLink: %s/%s", ingLink.Namespace, ingLink.Name)
				return nil
			}
			log.Debugf("[IPAM] requested IP for ingLink %v is: %v", ingLink.ObjectMeta.Name, ip)
			if ip == "" {
				log.Debugf("[IPAM] requested IP for ingLink %v is empty.", ingLink.ObjectMeta.Name)
				return nil
			}
			ctlr.updateIngressLinkStatus(ingLink, ip)
			svc, err := ctlr.getKICServiceOfIngressLink(ingLink)
			if err != nil {
				return err
			}
			if svc == nil {
				return nil
			}
			if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
				ctlr.setLBServiceIngressStatus(svc, ip)
			}
		}
	} else {
		if ingLink.Spec.VirtualServerAddress == "" {
			return fmt.Errorf("No VirtualServer address in ingLink or IPAM found.")
		}
		ip = ingLink.Spec.VirtualServerAddress
	}
	if isILDeleted {
		var delRes []string
		rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)
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
				rsCfg, err := ctlr.resources.getResourceConfig(partition, rsName, BigIPLabel)
				if err == nil {
					hostnames = rsCfg.MetaData.hosts
				}
			}
			ctlr.deleteVirtualServer(partition, rsName, bigipConfig)
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
		return err
	}

	if svc == nil {
		return nil
	}
	targetPort := nginxMonitorPort
	if ctlr.PoolMemberType == NodePort {
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

	rsMap := ctlr.resources.getPartitionResourceMap(partition, bigipConfig)
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
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			port.Port,
		)
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
		}
		// udpating the service cache
		rsRef := resourceRef{
			name:      ingLink.Name,
			namespace: ingLink.Namespace,
			kind:      IngressLink,
		}
		// updating the service cache
		ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, svc.ObjectMeta.Name, "", pool, svcPort, "", bigipLabel)
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

// getIngressLinksForService gets the List of ingressLink which are effected
// by the addition/deletion/updation of service.
func (ctlr *Controller) getIngressLinksForService(svc *v1.Service) []*cisapiv1.IngressLink {
	ingLinks := ctlr.getAllIngressLinks(svc.ObjectMeta.Namespace)
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.IngressLink[svc.ObjectMeta.Namespace] = len(ingLinks)
	ctlr.TeemData.Unlock()
	if nil == ingLinks {
		log.Infof("No IngressLink found in namespace %s",
			svc.ObjectMeta.Namespace)
		return nil
	}
	ingresslinksForService := filterIngressLinkForService(ingLinks, svc)

	if nil == ingresslinksForService {
		log.Debugf("Change in Service %s does not effect any IngressLink",
			svc.ObjectMeta.Name)
		return nil
	}

	// Output list of all IngressLinks Found.
	var targetILNames []string
	for _, il := range ingLinks {
		targetILNames = append(targetILNames, il.ObjectMeta.Name)
	}
	log.Debugf("IngressLinks %v are affected with service %s change",
		targetILNames, svc.ObjectMeta.Name)
	// TODO
	// Remove Duplicate entries in the targetILNames.
	// or Add only Unique entries into the targetILNames.
	return ingresslinksForService
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
	// Set the ingress status to include the virtual IP
	lbIngress := v1.LoadBalancerIngress{IP: ip}
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, lbIngress)
	} else if svc.Status.LoadBalancer.Ingress[0].IP != ip {
		svc.Status.LoadBalancer.Ingress[0] = lbIngress
	}

	_, updateErr := ctlr.clientsets.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
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

		_, updateErr := ctlr.clientsets.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(
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
//	_, updateErr := ctlr.clientsets.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(
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
	//namespace := svc.ObjectMeta.Namespace
	//// Create the event
	//evNotifier := ctlr.eventNotifier.CreateNotifierForNamespace(
	//	namespace, ctlr.clientsets.kubeClient.CoreV1())
	//evNotifier.RecordEvent(svc, eventType, reason, message)
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

// sort BIGIP config by bigip label
func (configs BIGIPConfigs) Len() int {
	return len(configs)
}

func (configs BIGIPConfigs) Less(i, j int) bool {
	return configs[i].BigIpLabel < configs[j].BigIpLabel
}

func (configs BIGIPConfigs) Swap(i, j int) {
	configs[i], configs[j] = configs[j], configs[i]
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
	_, updateErr := ctlr.clientsets.kubeCRClient.CisV1().VirtualServers(vs.ObjectMeta.Namespace).UpdateStatus(context.TODO(), vs, metav1.UpdateOptions{})
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
	_, updateErr := ctlr.clientsets.kubeCRClient.CisV1().TransportServers(ts.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ts, metav1.UpdateOptions{})
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
	_, updateErr := ctlr.clientsets.kubeCRClient.CisV1().IngressLinks(il.ObjectMeta.Namespace).UpdateStatus(context.TODO(), il, metav1.UpdateOptions{})
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
		log.Errorf("Error: Service %v not found", svcKey)
		return nil
	}
	return svc.(*v1.Service)
}

// GetPodsForService returns podList with labels set to svc selector
func (ctlr *Controller) GetPodsForService(namespace, serviceName string, nplAnnotationRequired bool) []*v1.Pod {
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
		log.Errorf("Error: Service %v not found", svcKey)
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
	podList, err := listerscorev1.NewPodLister(comInf.podInformer.GetIndexer()).Pods(namespace).List(pl)
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
			return nil
		}

		if ctlr.matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
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

func (ctlr *Controller) processConfigCR(configCR *cisapiv1.DeployConfig, isDelete bool) (error, bool) {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		key := configCR.Namespace + string('/') + configCR.Name
		if ctlr.CISConfigCRKey == key {
			log.Debugf("Finished syncing global DeployConfig CR: %v/%v (%v)",
				configCR.Namespace, configCR.Name, endTime.Sub(startTime))
		} else {
			log.Debugf("Finished syncing local DeployConfig CR: %v/%v (%v)",
				configCR.Namespace, configCR.Name, endTime.Sub(startTime))
		}

	}()
	// get bigipConfig and start/stop agent if needed
	bigipconfig := configCR.Spec.BigIpConfig
	ctlr.handleBigipConfigUpdates(bigipconfig)
	es := configCR.Spec.ExtendedSpec
	// clusterConfigUpdated, oldClusterRatio and oldClusterAdminState are used for tracking cluster ratio and cluster Admin state updates
	clusterConfigUpdated := false
	oldClusterRatio := make(map[string]int)
	oldClusterAdminState := make(map[string]cisapiv1.AdminState)
	if ctlr.isGlobalExtendedCR(configCR) && ctlr.multiClusterMode != "" {
		// Get Multicluster kube-config
		if isDelete {
			// Handle config CR deletion
			es.HAClusterConfig = cisapiv1.HAClusterConfig{}
		}
		// Check if HA configurations are specified properly
		if ctlr.multiClusterMode != StandAloneCIS && ctlr.multiClusterMode != "" {
			if es.HAClusterConfig == (cisapiv1.HAClusterConfig{}) || es.HAClusterConfig.PrimaryCluster == (cisapiv1.ClusterDetails{}) ||
				es.HAClusterConfig.SecondaryCluster == (cisapiv1.ClusterDetails{}) {
				log.Errorf("[MultiCluster] CIS High availability cluster config not provided properly.")
				os.Exit(1)
			}
		}
		// Read multiCluster mode
		// Set the active-active/active-standby/ratio mode for the HA cluster
		if es.HAMode != "" {
			if es.HAMode == Active || es.HAMode == StandBy || es.HAMode == Ratio {
				ctlr.haModeType = es.HAMode
				//TODO: could each bigip pair will have different HA mode?
				for _, agent := range ctlr.AgentMap {
					agent.PostManager.HAMode = true
				}
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
				es.LocalClusterAdminState == clustermanager.Disable || es.LocalClusterAdminState == clustermanager.Offline {
				ctlr.clusterAdminState[""] = es.LocalClusterAdminState
			} else {
				log.Warningf("[MultiCluster] Invalid cluster adminState: %v specified for local cluster, supported "+
					"values (enable, disable, offline). Defaulting to enable", es.LocalClusterAdminState)
				ctlr.clusterAdminState[""] = clustermanager.Enable
			}
		}
		// Read multi-cluster config from extended CM
		err := ctlr.readMultiClusterConfigFromGlobalCM(es.HAClusterConfig, es.ExternalClustersConfig)
		ctlr.checkSecondaryCISConfig()
		ctlr.stopDeletedGlobalCRMultiClusterInformers()
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
			log.Debugf("[MultiCluster] Cluster ratios:%s", ratioKeyValues)
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
	// Process the routeSpec defined in DeployConfig CR
	if ctlr.managedResources.ManageRoutes {
		if ctlr.isGlobalExtendedCR(configCR) {
			return ctlr.processRouteConfigFromGlobalCM(es, isDelete, clusterConfigUpdated)
		} else if len(es.ExtendedRouteGroupConfigs) > 0 && !ctlr.resourceContext.namespaceLabelMode {
			return ctlr.processRouteConfigFromLocalConfigCR(es, isDelete, configCR.Namespace)
		}
	}
	if ctlr.managedResources.ManageCustomResources {
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
	nodeInf, _ := ctlr.multiClusterNodeInformers[""]
	nodes = nodeInf.nodeInformer.GetIndexer().List()
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
				nodesObj, err := config.KubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: ctlr.resourceSelectorConfig.NodeLabel})
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
	pods := ctlr.GetPodsForService(namespace, svcName, true)
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

func (ctlr *Controller) getResourceServicePort(ns string,
	svcName string,
	svcIndexer cache.Indexer,
	portName string,
	rscType string,
) (int32, error) {
	// GetServicePort returns the port number, for a given port name,
	// else, returns the first port found for a Route's service.
	key := ns + "/" + svcName

	obj, found, err := svcIndexer.GetByKey(key)
	if nil != err {
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
		} else if rscType == Route {
			return svc.Spec.Ports[0].Port, nil
		}
	} else if ctlr.haModeType == Active && ctlr.multiClusterPoolInformers != nil {
		return ctlr.getSvcPortFromHACluster(ns, svcName, portName, rscType)
	}
	return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
}

func (ctlr *Controller) handleBigipConfigUpdates(config []cisapiv1.BigIpConfig) {
	//check if bigip config is existing or not in the bigipMap
	existingBigipConfig := make([]cisapiv1.BigIpConfig, len(ctlr.bigIpMap))
	for bigipConfig, _ := range ctlr.bigIpMap {
		existingBigipConfig = append(existingBigipConfig, bigipConfig)
	}
	sort.Sort(BIGIPConfigs(existingBigipConfig))
	sort.Sort(BIGIPConfigs(config))
	if !reflect.DeepEqual(existingBigipConfig, config) {
		// check if bigip config is removed
		for _, existingConfig := range existingBigipConfig {
			if !slices.Contains(config, existingConfig) {
				// stop agent
				ctlr.stopAgent(existingConfig)
				//remove bigipconfig from bigipMap
				delete(ctlr.bigIpMap, existingConfig)
			}
		}
		// check if bigip config is added
		for _, newConfig := range config {
			if !slices.Contains(existingBigipConfig, newConfig) {
				// start agent
				ctlr.startAgent(newConfig)
				//update bigipMap with new bigipconfig
				ctlr.bigIpMap[newConfig] = BigIpResourceConfig{ltmConfig: make(LTMConfig), gtmConfig: make(GTMConfig)}
			}
		}
	}
}

func (ctlr *Controller) stopAgent(config cisapiv1.BigIpConfig) {
	for _, bigipList := range getBigIpList(config) {
		//stop agent
		agent := ctlr.AgentMap[bigipList]
		if agent != nil {
			//close the channels to stop the requesthandler
			agent.stopAgent()
		}
		//remove bigiplabel from agentmap
		delete(ctlr.AgentMap, bigipList)
	}
	// decrease the Agent Count
	prometheus.AgentCount.Dec()
}

func (ctlr *Controller) startAgent(config cisapiv1.BigIpConfig) {
	for _, bigipList := range getBigIpList(config) {
		//start agent
		ctlr.AgentParams.Partition = config.DefaultPartition
		agent := NewAgent(ctlr.AgentParams, config.BigIpLabel, bigipList.BigIpAddress)
		agent.PostManager.respChan = ctlr.respChan
		agent.PostManager.AS3PostManager.AS3Config = ctlr.AgentParams.PostParams.AS3Config
		agent.PostManager.tokenManager = ctlr.CMTokenManager
		// update agent Map
		ctlr.AgentMap[bigipList] = agent
	}
	// increase the Agent Count
	prometheus.AgentCount.Inc()
}

func (ctlr *Controller) getPartitionForBIGIP(bigipLabel string) string {
	//get partition from bigip
	for bigipconfig, _ := range ctlr.bigIpMap {
		//TODO: get bigipLabel from route resource or service address cr and get parition from specific bigip agent
		//Phase1 getting partition from bigipconfig index 0
		if bigipLabel == "" {
			return bigipconfig.DefaultPartition
		} else {
			if bigipconfig.BigIpLabel == bigipLabel {
				return bigipconfig.DefaultPartition
			}
		}
	}
	return ""
}

func (ctlr *Controller) getBIGIPConfig(bigipLabel string) cisapiv1.BigIpConfig {
	//get partition from bigip
	for bigipconfig, _ := range ctlr.bigIpMap {
		//TODO: get bigipLabel from route resource or service address cr and get parition from specific bigip agent
		//Phase1 getting partition from bigipconfig index 0
		if bigipLabel == "" {
			return bigipconfig
		} else {
			if bigipconfig.BigIpLabel == bigipLabel {
				return bigipconfig
			}
		}
	}
	return cisapiv1.BigIpConfig{}
}
