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
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// customResourceWorker starts the Custom Resource Worker.
func (ctlr *Controller) customResourceWorker() {
	log.Debugf("Starting Custom Resource Worker")
	ctlr.setInitialServiceCount()
	for ctlr.processResource() {
	}
}

func (ctlr *Controller) setInitialServiceCount() {
	var svcCount int
	for _, ns := range ctlr.getWatchingNamespaces() {
		services, err := ctlr.kubeClient.CoreV1().Services(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, svc := range services.Items {
			if _, ok := K8SCoreServices[svc.Name]; ok {
				continue
			}
			if svc.Spec.Type != v1.ServiceTypeExternalName {
				svcCount++
			}
		}
	}
	ctlr.initialSvcCount = svcCount
}

// processResource gets resources from the rscQueue and processes the resource
// depending  on its kind.
func (ctlr *Controller) processResource() bool {

	key, quit := ctlr.rscQueue.Get()
	if quit {
		// The controller is shutting down.
		log.Debugf("Resource Queue is empty, Going to StandBy Mode")
		return false
	}
	var isError bool

	defer ctlr.rscQueue.Done(key)
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)

	// During Init time, just accumulate all the poolMembers by processing only services
	if ctlr.initState && rKey.kind != Namespace {
		if rKey.kind != Service {
			ctlr.rscQueue.AddRateLimited(key)
			return true
		}
		ctlr.initialSvcCount--
		if ctlr.initialSvcCount <= 0 {
			ctlr.initState = false
		}
	}

	// Check the type of resource and process accordingly.
	switch rKey.kind {
	case VirtualServer:
		virtual := rKey.rsc.(*cisapiv1.VirtualServer)
		err := ctlr.processVirtualServers(virtual, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case TLSProfile:
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
				isError = true
			}
		}
	case TransportServer:
		virtual := rKey.rsc.(*cisapiv1.TransportServer)
		err := ctlr.processTransportServers(virtual, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case IngressLink:
		ingLink := rKey.rsc.(*cisapiv1.IngressLink)
		log.Infof("Worker got IngressLink: %v\n", ingLink)
		log.Infof("IngressLink Selector: %v\n", ingLink.Spec.Selector.String())
		err := ctlr.processIngressLink(ingLink, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case ExternalDNS:
		edns := rKey.rsc.(*cisapiv1.ExternalDNS)
		ctlr.processExternalDNS(edns, rKey.rscDelete)
	case IPAM:
		ipam := rKey.rsc.(*ficV1.IPAM)
		virtuals := ctlr.getVirtualServersForIPAM(ipam)
		for _, vs := range virtuals {
			err := ctlr.processVirtualServers(vs, false)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.IPAMVS[rKey.namespace] = len(virtuals)
		ctlr.TeemData.Unlock()
		TSVirtuals := ctlr.getTransportServersForIPAM(ipam)
		for _, ts := range TSVirtuals {
			err := ctlr.processTransportServers(ts, false)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.IPAMTS[rKey.namespace] = len(TSVirtuals)
		ctlr.TeemData.Unlock()
		IngLinks := ctlr.getIngressLinkForIPAM(ipam)
		for _, il := range IngLinks {
			err := ctlr.processIngressLink(il, false)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		services := ctlr.syncAndGetServicesForIPAM(ipam)
		for _, svc := range services {
			err := ctlr.processLBServices(svc, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.IPAMSvcLB[rKey.namespace] = len(services)
		ctlr.TeemData.Unlock()

	case CustomPolicy:
		cp := rKey.rsc.(*cisapiv1.Policy)

		virtuals := ctlr.getVirtualsForCustomPolicy(cp)
		//Sync Custompolicy for Virtual Servers
		for _, virtual := range virtuals {
			err := ctlr.processVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		//Sync Custompolicy for Transport Servers
		tsVirtuals := ctlr.getTransportServersForCustomPolicy(cp)
		for _, virtual := range tsVirtuals {
			err := ctlr.processTransportServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
	case Service:
		svc := rKey.rsc.(*v1.Service)

		_ = ctlr.processService(svc, nil, rKey.rscDelete)

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rKey.rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
			break
		}
		if ctlr.initState {
			break
		}

		virtuals := ctlr.getVirtualServersForService(svc)
		// If nil No Virtuals are effected with the change in service.
		if nil != virtuals {
			for _, virtual := range virtuals {
				err := ctlr.processVirtualServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
		//Sync service for Transport Server virtuals
		tsVirtuals := ctlr.getTransportServersForService(svc)
		if nil != tsVirtuals {
			for _, virtual := range tsVirtuals {
				err := ctlr.processTransportServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
		//Sync service for Ingress Links
		ingLinks := ctlr.getIngressLinksForService(svc)
		if nil != ingLinks {
			for _, ingLink := range ingLinks {
				err := ctlr.processIngressLink(ingLink, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}

	case Endpoints:
		ep := rKey.rsc.(*v1.Endpoints)
		svc := ctlr.getServiceForEndpoints(ep)
		// No Services are effected with the change in service.
		if nil == svc {
			break
		}

		_ = ctlr.processService(svc, ep, rKey.rscDelete)

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rKey.rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
			break
		}

		virtuals := ctlr.getVirtualServersForService(svc)
		for _, virtual := range virtuals {
			err := ctlr.processVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		//Sync service for Transport Server virtuals
		tsVirtuals := ctlr.getTransportServersForService(svc)
		if nil != tsVirtuals {
			for _, virtual := range tsVirtuals {
				err := ctlr.processTransportServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
		//Sync service for Ingress Links
		ingLinks := ctlr.getIngressLinksForService(svc)
		if nil != ingLinks {
			for _, ingLink := range ingLinks {
				err := ctlr.processIngressLink(ingLink, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
	case Namespace:
		ns := rKey.rsc.(*v1.Namespace)
		nsName := ns.ObjectMeta.Name
		if rKey.rscDelete {
			for _, vrt := range ctlr.getAllVirtualServers(nsName) {
				err := ctlr.processVirtualServers(vrt, true)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}

			for _, ts := range ctlr.getAllTransportServers(nsName) {
				err := ctlr.processTransportServers(ts, true)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}

			ctlr.crInformers[nsName].stop()
			delete(ctlr.crInformers, nsName)
			ctlr.namespacesMutex.Lock()
			delete(ctlr.namespaces, nsName)
			ctlr.namespacesMutex.Unlock()
			log.Debugf("Removed Namespace: '%v' from CIS scope", nsName)
		} else {
			ctlr.namespacesMutex.Lock()
			ctlr.namespaces[nsName] = true
			ctlr.namespacesMutex.Unlock()
			_ = ctlr.addNamespacedInformer(nsName)
			ctlr.crInformers[nsName].start()
			log.Debugf("Added Namespace: '%v' to CIS scope", nsName)
		}
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}

	if isError {
		ctlr.rscQueue.AddRateLimited(key)
	} else {
		ctlr.rscQueue.Forget(key)
	}

	if ctlr.rscQueue.Len() == 0 &&
		(!reflect.DeepEqual(ctlr.resources.rsMap, ctlr.resources.oldRsMap) ||
			!reflect.DeepEqual(ctlr.resources.dnsConfig, ctlr.resources.oldDNSConfig)) {
		customProfileStore := NewCustomProfiles()
		for _, rsCfg := range ctlr.resources.rsMap {
			for skey, prof := range rsCfg.customProfiles.Profs {
				customProfileStore.Profs[skey] = prof
			}
		}
		config := ResourceConfigRequest{
			rsCfgs:             ctlr.resources.GetAllResources(),
			customProfiles:     customProfileStore,
			shareNodes:         ctlr.shareNodes,
			dnsConfig:          ctlr.resources.dnsConfig,
			defaultRouteDomain: ctlr.defaultRouteDomain,
			isVSDeleted:        rKey.rscDelete,
		}
		go ctlr.TeemData.PostTeemsData()
		if !config.isVSDeleted {
			ctlr.enqueueReq(config)
		}
		ctlr.Agent.PostConfig(config)
		ctlr.initState = false
		ctlr.resources.updateOldConfig()
	}
	return true
}

// getServiceForEndpoints returns the service associated with endpoints.
func (ctlr *Controller) getServiceForEndpoints(ep *v1.Endpoints) *v1.Service {

	epName := ep.ObjectMeta.Name
	epNamespace := ep.ObjectMeta.Namespace
	svcKey := fmt.Sprintf("%s/%s", epNamespace, epName)

	crInf, ok := ctlr.getNamespacedInformer(epNamespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", epNamespace)
		return nil
	}
	svc, exists, err := crInf.svcInformer.GetIndexer().GetByKey(svcKey)
	if err != nil {
		log.Infof("Error fetching service %v from the store: %v", svcKey, err)
		return nil
	}
	if !exists {
		log.Infof("Service %v doesn't exist", svcKey)
		return nil
	}

	return svc.(*v1.Service)
}

// getVirtualServersForService gets the List of VirtualServers which are effected
// by the addition/deletion/updation of service.
func (ctlr *Controller) getVirtualServersForService(svc *v1.Service) []*cisapiv1.VirtualServer {

	allVirtuals := ctlr.getAllVirtualServers(svc.ObjectMeta.Namespace)
	if nil == allVirtuals {
		log.Infof("No VirtualServers founds in namespace %s",
			svc.ObjectMeta.Namespace)
		return nil
	}

	// find VirtualServers that reference the service
	virtualsForService := filterVirtualServersForService(allVirtuals, svc)
	if nil == virtualsForService {
		log.Debugf("Change in Service %s does not effect any VirtualServer",
			svc.ObjectMeta.Name)
		return nil
	}
	// Output list of all Virtuals Found.
	var targetVirtualNames []string
	for _, vs := range allVirtuals {
		targetVirtualNames = append(targetVirtualNames, vs.ObjectMeta.Name)
	}
	log.Debugf("VirtualServers %v are affected with service %s change",
		targetVirtualNames, svc.ObjectMeta.Name)

	// TODO
	// Remove Duplicate entries in the targetVirutalServers.
	// or Add only Unique entries into the targetVirutalServers.
	return virtualsForService
}

// getVirtualsForTLSProfile gets the List of VirtualServers which are effected
// by the addition/deletion/updation of TLSProfile.
func (ctlr *Controller) getVirtualsForTLSProfile(tls *cisapiv1.TLSProfile) []*cisapiv1.VirtualServer {

	allVirtuals := ctlr.getAllVirtualServers(tls.ObjectMeta.Namespace)
	if nil == allVirtuals {
		log.Infof("No VirtualServers founds in namespace %s",
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
	// Output list of all Virtuals Found.
	var targetVirtualNames []string
	for _, vs := range allVirtuals {
		targetVirtualNames = append(targetVirtualNames, vs.ObjectMeta.Name)
	}
	log.Debugf("VirtualServers %v are affected with TLSProfile %s change",
		targetVirtualNames, tls.ObjectMeta.Name)

	// TODO
	// Remove Duplicate entries in the targetVirutalServers.
	// or Add only Unique entries into the targetVirutalServers.

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

// getAllVirtualServers returns list of all valid VirtualServers in rkey namespace.
func (ctlr *Controller) getAllVirtualServers(namespace string) []*cisapiv1.VirtualServer {
	var allVirtuals []*cisapiv1.VirtualServer

	crInf, ok := ctlr.getNamespacedInformer(namespace)
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

// filterVirtualServersForService returns list of VirtualServers that are
// affected by the service under process.
func filterVirtualServersForService(allVirtuals []*cisapiv1.VirtualServer,
	svc *v1.Service) []*cisapiv1.VirtualServer {

	var result []*cisapiv1.VirtualServer
	svcName := svc.ObjectMeta.Name
	svcNamespace := svc.ObjectMeta.Namespace

	for _, vs := range allVirtuals {
		if vs.ObjectMeta.Namespace != svcNamespace {
			continue
		}

		isValidVirtual := false
		for _, pool := range vs.Spec.Pools {
			if pool.Service == svcName {
				isValidVirtual = true
				break
			}
		}
		if !isValidVirtual {
			continue
		}

		result = append(result, vs)
	}

	return result
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
	crInf, ok := ctlr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
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
		clientSecret, _ := ctlr.kubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), tlsProfile.Spec.TLS.ClientSSL, metav1.GetOptions{})
		//validate clientSSL certificates and hostname
		match := checkCertificateHost(clientSecret, vs.Spec.Host)
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

	allVirtuals := ctlr.getAllVirtualServers(virtual.ObjectMeta.Namespace)
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.VirtualServer[virtual.ObjectMeta.Namespace] = len(allVirtuals)
	ctlr.TeemData.Unlock()

	// Prepare list of associated VirtualServers to be processed
	// In the event of deletion, exclude the deleted VirtualServer
	log.Debugf("Process all the Virtual Servers which share same VirtualServerAddress")

	virtuals := ctlr.getAssociatedVirtualServers(virtual, allVirtuals, isVSDeleted)
	var ip string
	var status int
	if ctlr.ipamCli != nil {
		if isVSDeleted && len(virtuals) == 0 && virtual.Spec.VirtualServerAddress == "" {
			if virtual.Spec.HostGroup != "" {
				key := virtual.ObjectMeta.Namespace + "/" + virtual.Spec.HostGroup
				ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, "", key)
			} else {
				ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, virtual.Spec.Host, "")
			}
		} else if virtual.Spec.VirtualServerAddress != "" {
			// Prioritise VirtualServerAddress specified over IPAMLabel
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ipamLabel := getIPAMLabel(virtuals)
			if virtual.Spec.HostGroup != "" {
				key := virtual.ObjectMeta.Namespace + "/" + virtual.Spec.HostGroup
				ip, status = ctlr.requestIP(ipamLabel, "", key)
			} else {
				ip, status = ctlr.requestIP(ipamLabel, virtual.Spec.Host, "")
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
			virtual.Status.VSAddress = ip
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
			if ip == "" && err == nil{
				ip = virtual.Spec.VirtualServerAddress
			}
			if err != nil {
				log.Errorf("Error in virtualserver address: %s", err.Error())
				return err
			}
		}
	}
	// Depending on the ports defined, TLS type or Unsecured we will populate the resource config.
	portStructs := ctlr.virtualPorts(virtual)

	// vsMap holds Resource Configs of current virtuals temporarily
	vsMap := make(ResourceConfigMap)
	processingError := false
	for _, portStruct := range portStructs {
		// TODO: Add Route Domain
		var rsName string
		if virtual.Spec.VirtualServerName != "" {
			rsName = formatCustomVirtualServerName(
				virtual.Spec.VirtualServerName,
				portStruct.port,
			)
		} else {
			rsName = formatVirtualServerName(
				ip,
				portStruct.port,
			)
		}

		// Delete rsCfg if no corresponding virtuals exist
		// Delete rsCfg if it is HTTP rsCfg and the CR VirtualServer does not handle HTTPTraffic
		if (len(virtuals) == 0) ||
			(portStruct.protocol == "http" && !doesVSHandleHTTP(virtual)) {
			var hostnames []string
			if ctlr.resources.rsMap[rsName] != nil {
				hostnames = ctlr.resources.rsMap[rsName].MetaData.hosts
			}
			ctlr.deleteVirtualServer(rsName)
			if len(hostnames) > 0 {
				ctlr.ProcessAssociatedExternalDNS(hostnames)
			}
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = ctlr.Partition
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, virtual.Spec.Host)
		rsCfg.MetaData.Protocol = portStruct.protocol
		rsCfg.MetaData.httpTraffic = virtual.Spec.HTTPTraffic
		rsCfg.MetaData.namespace = virtual.ObjectMeta.Namespace
		rsCfg.MetaData.rscName = virtual.ObjectMeta.Name
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			portStruct.port,
		)
		rsCfg.IntDgMap = make(InternalDataGroupMap)
		rsCfg.IRulesMap = make(IRulesMap)
		rsCfg.customProfiles.Profs = make(map[SecretKey]CustomProfile)

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
			log.Debugf("Processing Virtual Server %s for port %v",
				vrt.ObjectMeta.Name, portStruct.port)
			err := ctlr.prepareRSConfigFromVirtualServer(
				rsCfg,
				vrt,
			)
			if err != nil {
				processingError = true
				break
			}

			if isTLSVirtualServer(vrt) {
				// Handle TLS configuration for VirtualServer Custom Resource
				tlsProf := ctlr.getTLSProfileForVirtualServer(vrt, vrt.Namespace)
				if tlsProf == nil {
					// Processing failed
					// Stop processing further virtuals
					processingError = true
					break
				}

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
		}

		if processingError {
			log.Errorf("Cannot Publish VirtualServer %s", virtual.ObjectMeta.Name)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, virtual.ObjectMeta.Namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, virtual.ObjectMeta.Namespace)
		}
	}

	if !processingError {
		var hostnames []string
		// Update rsMap with ResourceConfigs created for the current virtuals
		for rsName, rsCfg := range vsMap {
			if _, ok := ctlr.resources.rsMap[rsName]; !ok {
				hostnames = rsCfg.MetaData.hosts
			}
			ctlr.resources.rsMap[rsName] = rsCfg
		}
		if len(hostnames) > 0 {
			ctlr.ProcessAssociatedExternalDNS(hostnames)
		}
	}

	return nil
}

func (ctlr *Controller) getAssociatedVirtualServers(
	currentVS *cisapiv1.VirtualServer,
	allVirtuals []*cisapiv1.VirtualServer,
	isVSDeleted bool,
) []*cisapiv1.VirtualServer {
	// Associated VirutalServers are grouped based on "hostGroup" parameter
	// if hostGroup parameter is not available, they will be grouped on "host" parameter
	// if "host" parameter is not available, they will be grouped on "VirtualServerAddress"

	// The VirtualServers that are being grouped by "hostGroup" or "host" should obey below rules,
	// otherwise the grouping would be treated as invalid and the associatedVirtualServers will be nil.
	//		* all of them should have same "ipamLabel"
	//      * if no "ipamLabel" present, should have same "VirtualServerAddress"
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

	for _, vrt := range allVirtuals {
		// skip the deleted virtual in the event of deletion
		if isVSDeleted && vrt.Name == currentVS.Name {
			continue
		}

		// skip the virtuals in other HostGroups
		if vrt.Spec.HostGroup != currentVS.Spec.HostGroup {
			continue
		}

		if currentVS.Spec.HostGroup == "" {
			// in the absence of HostGroup, skip the virtuals with other host name
			if vrt.Spec.Host != currentVS.Spec.Host {
				continue
			}

			// Same host with different VirtualServerAddress is invalid
			if vrt.Spec.VirtualServerAddress != currentVS.Spec.VirtualServerAddress {
				if vrt.Spec.Host != "" {
					log.Errorf("Same host %v is configured with different VirtualServerAddress : %v ", vrt.Spec.Host, vrt.Spec.VirtualServerName)
					return nil
				}
				// In case of empty host name, skip the virtual with other VirtualServerAddress
				continue
			}
		}

		if ctlr.ipamCli != nil {
			if currentVS.Spec.HostGroup == "" && vrt.Spec.IPAMLabel != currentVS.Spec.IPAMLabel {
				log.Errorf("Same host %v is configured with different IPAM labels: %v, %v. Unable to process %v", vrt.Spec.Host, vrt.Spec.IPAMLabel, currentVS.Spec.IPAMLabel, currentVS.Name)
				return nil
			}
			// Empty host with IPAM label is invalid for a Virtual Server
			if vrt.Spec.IPAMLabel != "" && vrt.Spec.Host == "" {
				log.Errorf("Hostless VS %v is configured with IPAM label: %v", vrt.ObjectMeta.Name, vrt.Spec.IPAMLabel)
				return nil
			}
		}

		// skip the virtuals with different custom HTTP/HTTPS ports
		if vrt.Spec.VirtualServerHTTPPort != currentVS.Spec.VirtualServerHTTPPort ||
			vrt.Spec.VirtualServerHTTPSPort != currentVS.Spec.VirtualServerHTTPSPort {
			log.Debugf("Discarding the VirtualServer %v/%v due to unmatched custom HTTP/HTTPS port",
				currentVS.Namespace, currentVS.Name)
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
	crInf, ok := ctlr.getNamespacedInformer(ns)
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

func (ctlr *Controller) getPolicyFromTransportServers(virtuals []*cisapiv1.TransportServer) (*cisapiv1.Policy, error) {

	if len(virtuals) == 0 {
		log.Errorf("No virtuals to extract policy from")
		return nil, nil
	}
	plcName := ""
	ns := virtuals[0].Namespace
	for _, vrt := range virtuals {
		if plcName != "" && plcName != vrt.Spec.PolicyName {
			log.Errorf("Multiple Policies specified for VirtualServerName: %v", vrt.Spec.VirtualServerName)
			return nil, fmt.Errorf("Multiple Policies specified for VirtualServerName: %v", vrt.Spec.VirtualServerName)
		}
		if vrt.Spec.PolicyName != "" {
			plcName = vrt.Spec.PolicyName
		}
	}
	if plcName == "" {
		return nil, nil
	}
	crInf, ok := ctlr.getNamespacedInformer(ns)
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
		log.Errorf("[ipam] error while retrieving IPAM namespace and name.")
		return nil
	}
	ipamCR, err := ctlr.ipamCli.Get(cr[0], cr[1])
	if err != nil {
		log.Errorf("[ipam] error while retrieving IPAM custom resource.")
		return nil
	}
	return ipamCR
}

//Request IPAM for virtual IP address
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
		log.Errorf("[ipam] Error updating IPAM CR : %v", err)
		return "", NotRequested
	}

	log.Debugf("[ipam] Updated IPAM CR.")
	return "", Requested

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
			ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs[:index], ipamCR.Spec.HostSpecs[index+1:]...)
			ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
			_, err := ctlr.ipamCli.Update(ipamCR)
			if err != nil {
				log.Errorf("[ipam] ipam hostspec update error: %v", err)
				return ""
			}
			log.Debug("[ipam] Updated IPAM CR hostspec while releasing IP.")
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
			}
		}
		if index != -1 {
			ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs[:index], ipamCR.Spec.HostSpecs[index+1:]...)
			ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
			_, err := ctlr.ipamCli.Update(ipamCR)
			if err != nil {
				log.Errorf("[ipam] ipam hostspec update error: %v", err)
				return ""
			}
			log.Debug("[ipam] Updated IPAM CR hostspec while releasing IP.")
		}

	} else {
		log.Debugf("[IPAM] Invalid host and key.")
	}

	return ip
}

// updatePoolMembersForNodePort updates the pool with pool members for a
// service created in nodeport mode.
func (ctlr *Controller) updatePoolMembersForNodePort(
	rsCfg *ResourceConfig,
	namespace string,
) {
	_, ok := ctlr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return
	}

	for index, pool := range rsCfg.Pools {
		svcName := pool.ServiceName
		svcKey := namespace + "/" + svcName

		poolMemInfo := ctlr.resources.poolMemCache[svcKey]

		if !(poolMemInfo.svcType == v1.ServiceTypeNodePort ||
			poolMemInfo.svcType == v1.ServiceTypeLoadBalancer) {
			log.Debugf("Requested service backend %s not of NodePort or LoadBalancer type",
				svcKey)
		}

		for _, svcPort := range poolMemInfo.portSpec {
			if svcPort.TargetPort.IntVal == pool.ServicePort {
				nodePort := svcPort.NodePort
				rsCfg.MetaData.Active = true
				rsCfg.Pools[index].Members =
					ctlr.getEndpointsForNodePort(nodePort, pool.NodeMemberLabel)
			}
		}
	}
}

// updatePoolMembersForCluster updates the pool with pool members for a
// service created in cluster mode.
func (ctlr *Controller) updatePoolMembersForCluster(
	rsCfg *ResourceConfig,
	namespace string,
) {
	for index, pool := range rsCfg.Pools {
		svcName := pool.ServiceName
		svcKey := namespace + "/" + svcName
		poolMemInfo := ctlr.resources.poolMemCache[svcKey]

		for ref, mems := range poolMemInfo.memberMap {
			if ref.port != pool.ServicePort || len(mems) <= 0 {
				continue
			}
			rsCfg.MetaData.Active = true
			rsCfg.Pools[index].Members = mems
		}
	}
}

// getEndpointsForNodePort returns members.
func (ctlr *Controller) getEndpointsForNodePort(
	nodePort int32,
	nodeMemberLabel string,
) []PoolMember {
	var nodes []Node
	if nodeMemberLabel == "" {
		nodes = ctlr.getNodesFromCache()
	} else {
		nodes = ctlr.getNodesWithLabel(nodeMemberLabel)
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
	allVirtuals := ctlr.getAllTransportServers(virtual.ObjectMeta.Namespace)
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.TransportServer[virtual.ObjectMeta.Namespace] = len(allVirtuals)
	ctlr.TeemData.Unlock()
	var virtuals []*cisapiv1.TransportServer

	// Prepare list of associated VirtualServers to be processed
	// In the event of deletion, exclude the deleted VirtualServer
	log.Debugf("Process all the Transport Servers which share same VirtualServerAddress")
	for _, vrt := range allVirtuals {
		if vrt.Spec.VirtualServerAddress == virtual.Spec.VirtualServerAddress && vrt.Spec.VirtualServerPort == virtual.Spec.VirtualServerPort &&
			(!isTSDeleted && vrt.ObjectMeta.Name == virtual.ObjectMeta.Name) {
			virtuals = append(virtuals, vrt)
		}
	}

	if isTSDeleted {
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.TransportServer[virtual.ObjectMeta.Namespace]--
		ctlr.TeemData.Unlock()
		// ctlr.handleVSDeleteForDataGroups(tVirtual)
	}

	var ip string
	var key string
	var status int
	key = virtual.ObjectMeta.Namespace + "/" + virtual.ObjectMeta.Name + "_ts"
	if ctlr.ipamCli != nil {
		if isTSDeleted && len(virtuals) == 0 && virtual.Spec.VirtualServerAddress == "" {
			ip = ctlr.releaseIP(virtual.Spec.IPAMLabel, "", key)
		} else if virtual.Spec.VirtualServerAddress != "" {
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ip, status = ctlr.requestIP(virtual.Spec.IPAMLabel, "", key)

			switch status {
			case NotEnabled:
				log.Debug("IPAM Custom Resource Not Available")
				return nil
			case InvalidInput:
				log.Debugf("IPAM Invalid IPAM Label: %v for Transport Server: %s/%s",
					virtual.Spec.IPAMLabel, virtual.Namespace, virtual.Name)
				return nil
			case NotRequested:
				return fmt.Errorf("unable to make IPAM Request, will be re-requested soon")
			case Requested:
				log.Debugf("IP address requested for Transport Server: %s/%s", virtual.Namespace, virtual.Name)
				return nil
			}
			virtual.Status.VSAddress = ip
		}
	} else {
		if virtual.Spec.VirtualServerAddress == "" {
			return fmt.Errorf("No VirtualServer address in TS or IPAM found.")
		}
		ip = virtual.Spec.VirtualServerAddress
	}

	// vsMap holds Resource Configs of current virtuals temporarily
	vsMap := make(ResourceConfigMap)
	processingError := false
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
	if len(virtuals) == 0 {
		ctlr.resources.deleteVirtualServer(rsName)
		return nil
	}

	rsCfg := &ResourceConfig{}
	rsCfg.Virtual.Partition = ctlr.Partition
	rsCfg.MetaData.ResourceType = TransportServer
	rsCfg.Virtual.Enabled = true
	rsCfg.Virtual.Name = rsName
	rsCfg.Virtual.IpProtocol = virtual.Spec.Type
	rsCfg.MetaData.namespace = virtual.ObjectMeta.Namespace
	rsCfg.MetaData.rscName = virtual.ObjectMeta.Name
	rsCfg.Virtual.SetVirtualAddress(
		ip,
		virtual.Spec.VirtualServerPort,
	)
	plc, err := ctlr.getPolicyFromTransportServers(virtuals)
	if plc != nil {
		err := ctlr.handleTSResourceConfigForPolicy(rsCfg, plc)
		if err != nil {
			processingError = true
		}
	}
	if err != nil {
		processingError = true
		log.Errorf("%v", err)
	}

	for _, vrt := range virtuals {
		log.Debugf("Processing Transport Server %s for port %v",
			vrt.ObjectMeta.Name, vrt.Spec.VirtualServerPort)
		err := ctlr.prepareRSConfigFromTransportServer(
			rsCfg,
			vrt,
		)
		if err != nil {
			processingError = true
			break
		}

		if processingError {
			log.Errorf("Cannot Publish TransportServer %s", virtual.ObjectMeta.Name)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, virtual.ObjectMeta.Namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, virtual.ObjectMeta.Namespace)
		}
	}
	if !processingError {
		// Update rsMap with ResourceConfigs created for the current transport virtuals
		for rsName, rsCfg := range vsMap {
			ctlr.resources.rsMap[rsName] = rsCfg
		}
	}
	return nil

}

// getAllTransportServers returns list of all valid TransportServers in rkey namespace.
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

	crInf, ok := ctlr.getNamespacedInformer(namespace)
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

// getTransportServersForService gets the List of VirtualServers which are effected
// by the addition/deletion/updation of service.
func (ctlr *Controller) getTransportServersForService(svc *v1.Service) []*cisapiv1.TransportServer {

	allVirtuals := ctlr.getAllTransportServers(svc.ObjectMeta.Namespace)
	if nil == allVirtuals {
		log.Infof("No VirtualServers for TransportServer founds in namespace %s",
			svc.ObjectMeta.Namespace)
		return nil
	}

	// find VirtualServers that reference the service
	virtualsForService := filterTransportServersForService(allVirtuals, svc)
	if nil == virtualsForService {
		log.Debugf("Change in Service %s does not effect any VirtualServer for TransportServer",
			svc.ObjectMeta.Name)
		return nil
	}
	// Output list of all Virtuals Found.
	var targetVirtualNames []string
	for _, vs := range allVirtuals {
		targetVirtualNames = append(targetVirtualNames, vs.ObjectMeta.Name)
	}
	log.Debugf("VirtualServers for TransportServer %v are affected with service %s change",
		targetVirtualNames, svc.ObjectMeta.Name)

	// TODO
	// Remove Duplicate entries in the targetVirutalServers.
	// or Add only Unique entries into the targetVirutalServers.
	return virtualsForService
}

// filterTransportServersForService returns list of VirtualServers that are
// affected by the service under process.
func filterTransportServersForService(allVirtuals []*cisapiv1.TransportServer,
	svc *v1.Service) []*cisapiv1.TransportServer {

	var result []*cisapiv1.TransportServer
	svcName := svc.ObjectMeta.Name
	svcNamespace := svc.ObjectMeta.Namespace

	for _, vs := range allVirtuals {
		if vs.ObjectMeta.Namespace != svcNamespace {
			continue
		}

		isValidVirtual := false
		if vs.Spec.Pool.Service == svcName {
			isValidVirtual = true
		}
		if !isValidVirtual {
			continue
		}
		result = append(result, vs)
	}

	return result
}

func (ctlr *Controller) getAllServicesFromMonitoredNamespaces() []*v1.Service {
	var svcList []*v1.Service
	if ctlr.watchingAllNamespaces() {
		objList := ctlr.crInformers[""].svcInformer.GetIndexer().List()
		for _, obj := range objList {
			svcList = append(svcList, obj.(*v1.Service))
		}
		return svcList
	}

	for ns := range ctlr.namespaces {
		objList := ctlr.crInformers[ns].svcInformer.GetIndexer().List()
		for _, obj := range objList {
			svcList = append(svcList, obj.(*v1.Service))
		}
	}

	return svcList
}

// Get List of VirtualServers associated with the IPAM resource
func (ctlr *Controller) getVirtualServersForIPAM(ipam *ficV1.IPAM) []*cisapiv1.VirtualServer {
	log.Debug("[ipam] Syncing IPAM dependent virtual servers")
	var allVS, vss []*cisapiv1.VirtualServer
	allVS = ctlr.getAllVSFromMonitoredNamespaces()
	for _, status := range ipam.Status.IPStatus {
		for _, vs := range allVS {
			key := vs.ObjectMeta.Namespace + "/" + vs.Spec.HostGroup
			if status.Host == vs.Spec.Host || status.Key == key {
				vss = append(vss, vs)
				break
			}
		}
	}
	return vss
}

// Get List of TransportServers associated with the IPAM resource
func (ctlr *Controller) getTransportServersForIPAM(ipam *ficV1.IPAM) []*cisapiv1.TransportServer {
	log.Debug("[ipam] Syncing IPAM dependent transport servers")
	var allTS, tss []*cisapiv1.TransportServer
	allTS = ctlr.getAllTSFromMonitoredNamespaces()
	for _, status := range ipam.Status.IPStatus {
		for _, ts := range allTS {
			key := ts.ObjectMeta.Namespace + "/" + ts.ObjectMeta.Name + "_ts"
			if status.Key == key {
				tss = append(tss, ts)
				break
			}
		}
	}
	return tss
}

//Get List of ingLink associated with the IPAM resource
func (ctlr *Controller) getIngressLinkForIPAM(ipam *ficV1.IPAM) []*cisapiv1.IngressLink {
	var allIngLinks, ils []*cisapiv1.IngressLink
	allIngLinks = ctlr.getAllIngLinkFromMonitoredNamespaces()
	if allIngLinks == nil {
		return nil
	}
	for _, status := range ipam.Status.IPStatus {
		for _, il := range allIngLinks {
			key := il.ObjectMeta.Namespace + "/" + il.ObjectMeta.Name + "_il"
			if status.Key == key {
				ils = append(ils, il)
				break
			}
		}
	}
	return ils
}

func (ctlr *Controller) syncAndGetServicesForIPAM(ipam *ficV1.IPAM) []*v1.Service {

	allServices := ctlr.getAllServicesFromMonitoredNamespaces()
	if allServices == nil {
		return nil
	}
	var svcList []*v1.Service
	var staleSpec []*ficV1.IPSpec
	for _, IPSpec := range ipam.Status.IPStatus {
		for _, svc := range allServices {
			svcKey := svc.Namespace + "/" + svc.Name + "_svc"
			if IPSpec.Key == svcKey {
				if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
					staleSpec = append(staleSpec, IPSpec)
					ctlr.eraseLBServiceIngressStatus(svc)
				} else {
					svcList = append(svcList, svc)
				}
			}
		}
	}

	for _, IPSpec := range staleSpec {
		ctlr.releaseIP(IPSpec.IPAMLabel, "", IPSpec.Key)
	}

	return svcList
}

func (ctlr *Controller) processLBServices(
	svc *v1.Service,
	isSVCDeleted bool,
) error {
	if ctlr.ipamCli == nil {
		log.Error("IPAM is not enabled, Unable to process Services of Type LoadBalancer")
		return nil
	}

	ipamLabel, ok := svc.Annotations[LBServiceIPAMLabelAnnotation]
	if !ok {
		log.Errorf("Not found %v in %v/%v. Unable to process.",
			LBServiceIPAMLabelAnnotation,
			svc.Namespace,
			svc.Name,
		)
		return nil
	}

	svcKey := svc.Namespace + "/" + svc.Name + "_svc"

	ip, status := ctlr.requestIP(ipamLabel, "", svcKey)

	switch status {
	case NotEnabled:
		log.Debug("IPAM Custom Resource Not Available")
		return nil
	case InvalidInput:
		log.Debugf("IPAM Invalid IPAM Label: %v for service: %s/%s", ipamLabel, svc.Namespace, svc.Name)
		return nil
	case NotRequested:
		return fmt.Errorf("unable to make IPAM Request, will be re-requested soon")
	case Requested:
		log.Debugf("IP address requested for service: %s/%s", svc.Namespace, svc.Name)
		return nil
	}

	if !isSVCDeleted {
		ctlr.setLBServiceIngressStatus(svc, ip)
	} else {
		ctlr.releaseIP(ipamLabel, "", svcKey)
		ctlr.unSetLBServiceIngressStatus(svc, ip)
	}

	for _, portSpec := range svc.Spec.Ports {

		rsName := AS3NameFormatter(fmt.Sprintf("vs_lb_svc_%s_%s_%s_%v", svc.Namespace, svc.Name, ip, portSpec.Port))
		if isSVCDeleted {
			delete(ctlr.resources.rsMap, rsName)
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = ctlr.Partition
		rsCfg.Virtual.IpProtocol = strings.ToLower(string(portSpec.Protocol))
		rsCfg.MetaData.ResourceType = TransportServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			portSpec.Port,
		)

		_ = ctlr.prepareRSConfigFromLBService(rsCfg, svc, portSpec)

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, svc.Namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, svc.Namespace)
		}

		ctlr.resources.rsMap[rsName] = rsCfg

	}

	return nil
}

func (ctlr *Controller) processService(
	svc *v1.Service,
	eps *v1.Endpoints,
	isSVCDeleted bool,
) error {
	namespace := svc.Namespace
	svcKey := svc.Namespace + "/" + svc.Name

	if isSVCDeleted {
		delete(ctlr.resources.poolMemCache, svcKey)
		return nil
	}

	if eps == nil {
		crInf, ok := ctlr.getNamespacedInformer(namespace)
		if !ok {
			log.Errorf("Informer not found for namespace: %v", namespace)
			return fmt.Errorf("unable to process Service: %v", svcKey)
		}

		item, found, _ := crInf.epsInformer.GetIndexer().GetByKey(svcKey)
		if !found {
			return fmt.Errorf("Endpoints for service '%v' not found!", svcKey)
		}
		eps, _ = item.(*v1.Endpoints)
	}

	pmi := poolMembersInfo{
		svcType:   svc.Spec.Type,
		portSpec:  svc.Spec.Ports,
		memberMap: make(map[portRef][]PoolMember),
	}

	nodes := ctlr.getNodesFromCache()

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

	ctlr.resources.poolMemCache[svcKey] = pmi

	return nil
}

func (ctlr *Controller) processExternalDNS(edns *cisapiv1.ExternalDNS, isDelete bool) {

	if isDelete {
		delete(ctlr.resources.dnsConfig, edns.Spec.DomainName)
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.ExternalDNS[edns.Namespace]--
		ctlr.TeemData.Unlock()
		return
	}
	ctlr.TeemData.Lock()
	ctlr.TeemData.ResourceType.ExternalDNS[edns.Namespace] = len(ctlr.getAllExternalDNS(edns.Namespace))
	ctlr.TeemData.Unlock()
	wip := WideIP{
		DomainName: edns.Spec.DomainName,
		RecordType: edns.Spec.DNSRecordType,
		LBMethod:   edns.Spec.LoadBalanceMethod,
	}
	if edns.Spec.DNSRecordType == "" {
		wip.RecordType = "A"
	}
	if edns.Spec.LoadBalanceMethod == "" {
		wip.LBMethod = "round-robin"
	}

	log.Debugf("Processing WideIP: %v", edns.Spec.DomainName)

	for _, pl := range edns.Spec.Pools {
		UniquePoolName := edns.Spec.DomainName + "_" + strings.ReplaceAll(edns.GetCreationTimestamp().Format(time.RFC3339Nano), ":", "-")
		log.Debugf("Processing WideIP Pool: %v", UniquePoolName)
		pool := GSLBPool{
			Name:       UniquePoolName,
			RecordType: pl.DNSRecordType,
			LBMethod:   pl.LoadBalanceMethod,
		}

		if pl.DNSRecordType == "" {
			pool.RecordType = "A"
		}
		if pl.LoadBalanceMethod == "" {
			pool.LBMethod = "round-robin"
		}
		for vsName, vs := range ctlr.resources.rsMap {
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
				log.Debugf("Adding WideIP Pool Member: %v", fmt.Sprintf("%v:/%v/Shared/%v",
					pl.DataServerName, DEFAULT_PARTITION, vsName))
				pool.Members = append(
					pool.Members,
					fmt.Sprintf("%v:/%v/Shared/%v",
						pl.DataServerName, DEFAULT_PARTITION, vsName),
				)
			}
		}
		if pl.Monitor.Type != "" {
			// TODO: Need to change to DEFAULT_PARTITION from Common, once Agent starts to support DEFAULT_PARTITION
			if pl.Monitor.Type == "http" || pl.Monitor.Type == "https" {
				pool.Monitor = &Monitor{
					Name:      UniquePoolName + "_monitor",
					Partition: "Common",
					Type:      pl.Monitor.Type,
					Interval:  pl.Monitor.Interval,
					Send:      pl.Monitor.Send,
					Recv:      pl.Monitor.Recv,
					Timeout:   pl.Monitor.Timeout,
				}
			} else {
				pool.Monitor = &Monitor{
					Name:      UniquePoolName + "_monitor",
					Partition: "Common",
					Type:      pl.Monitor.Type,
					Interval:  pl.Monitor.Interval,
					Timeout:   pl.Monitor.Timeout,
				}
			}
		}
		wip.Pools = append(wip.Pools, pool)
	}

	ctlr.resources.dnsConfig[wip.DomainName] = wip
	return
}

func (ctlr *Controller) getAllExternalDNS(namespace string) []*cisapiv1.ExternalDNS {
	var allEDNS []*cisapiv1.ExternalDNS
	crInf, ok := ctlr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	var orderedEDNSs []interface{}
	var err error

	if namespace == "" {
		orderedEDNSs = crInf.ednsInformer.GetIndexer().List()
	} else {
		orderedEDNSs, err = crInf.ednsInformer.GetIndexer().ByIndex("namespace", namespace)
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

//Validate certificate hostname
func checkCertificateHost(res *v1.Secret, host string) bool {
	cert, certErr := tls.X509KeyPair(res.Data["tls.crt"], res.Data["tls.key"])
	if certErr != nil {
		log.Errorf("Failed to validate TLS cert and key: %v", certErr)
		return false
	}
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Errorf("failed to parse certificate; %s", err)
		return false
	}
	ok := x509cert.VerifyHostname(host)
	if ok != nil {
		log.Debugf("Error: Hostname in virtualserver does not match with certificate hostname: %v", ok)
	}
	return true
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
	var ip string
	var key string
	var status int
	key = ingLink.ObjectMeta.Namespace + "/" + ingLink.ObjectMeta.Name + "_il"
	if ctlr.ipamCli != nil {
		if isILDeleted && ingLink.Spec.VirtualServerAddress == "" {
			ip = ctlr.releaseIP(ingLink.Spec.IPAMLabel, "", key)
		} else if ingLink.Spec.VirtualServerAddress != "" {
			ip = ingLink.Spec.VirtualServerAddress
		} else {
			ip, status = ctlr.requestIP(ingLink.Spec.IPAMLabel, "", key)

			switch status {
			case NotEnabled:
				log.Debug("IPAM Custom Resource Not Available")
				return nil
			case InvalidInput:
				log.Debugf("IPAM Invalid IPAM Label: %v for IngressLink: %s/%s",
					ingLink.Spec.IPAMLabel, ingLink.Namespace, ingLink.Name)
				return nil
			case NotRequested:
				return fmt.Errorf("unable to make IPAM Request, will be re-requested soon")
			case Requested:
				log.Debugf("IP address requested for IngressLink: %s/%s", ingLink.Namespace, ingLink.Name)
				return nil
			}
			log.Debugf("[ipam] requested IP for ingLink %v is: %v", ingLink.ObjectMeta.Name, ip)
			if ip == "" {
				log.Debugf("[ipam] requested IP for ingLink %v is empty.", ingLink.ObjectMeta.Name)
				return nil
			}
			ctlr.updateIngressLinkStatus(ingLink, ip)
		}
	} else {
		if ingLink.Spec.VirtualServerAddress == "" {
			return fmt.Errorf("No VirtualServer address in ingLink or IPAM found.")
		}
		ip = ingLink.Spec.VirtualServerAddress
	}
	if isILDeleted {
		var delRes []string
		for k := range ctlr.resources.rsMap {
			rsName := "ingress_link_" + formatVirtualServerName(
				ip,
				0,
			)
			if strings.HasPrefix(k, rsName[:len(rsName)-1]) {
				delRes = append(delRes, k)
			}
		}
		for _, rsname := range delRes {
			delete(ctlr.resources.rsMap, rsname)
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
	}
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
		rsCfg.Virtual.Partition = ctlr.Partition
		rsCfg.MetaData.ResourceType = "TransportServer"
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

		pool := Pool{
			Name: formatVirtualServerPoolName(
				svc.ObjectMeta.Namespace,
				svc.ObjectMeta.Name,
				port.Port,
				"",
			),
			Partition:   rsCfg.Virtual.Partition,
			ServiceName: svc.ObjectMeta.Name,
			ServicePort: port.Port,
		}
		monitorName := fmt.Sprintf("%s_monitor", pool.Name)
		rsCfg.Monitors = append(
			rsCfg.Monitors,
			Monitor{Name: monitorName, Partition: rsCfg.Virtual.Partition, Interval: 20,
				Type: "http", Send: "GET /nginx-ready HTTP/1.1\r\n", Recv: "", Timeout: 10, TargetPort: targetPort})
		pool.MonitorNames = append(pool.MonitorNames, monitorName)
		rsCfg.Virtual.PoolName = pool.Name
		rsCfg.Pools = append(rsCfg.Pools, pool)
		ctlr.resources.rsMap[rsName] = rsCfg

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, ingLink.ObjectMeta.Namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, ingLink.ObjectMeta.Namespace)
		}
	}

	return nil
}

func (ctlr *Controller) getAllIngressLinks(namespace string) []*cisapiv1.IngressLink {
	var allIngLinks []*cisapiv1.IngressLink

	crInf, ok := ctlr.getNamespacedInformer(namespace)
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
		log.Infof("No IngressLink founds in namespace %s",
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

	svcListOptions := metav1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matches the given label
	serviceList, err := ctlr.kubeClient.CoreV1().Services(ingLink.ObjectMeta.Namespace).List(context.TODO(), svcListOptions)

	if err != nil {
		log.Errorf("Error getting service list From IngressLink. Error: %v", err)
		return nil, err
	}

	if len(serviceList.Items) == 0 {
		log.Infof("No services for with labels : %v", ingLink.Spec.Selector.MatchLabels)
		return nil, nil
	}

	if len(serviceList.Items) == 1 {
		return &serviceList.Items[0], nil
	}

	sort.Sort(Services(serviceList.Items))
	return &serviceList.Items[0], nil
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
	svc, err := ctlr.kubeClient.CoreV1().Services(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Unable to Update Status of Service: %v due to unavailability", svcName)
		return
	}

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
				log.Debugf("Error while updating service: %v. %v", svcName, updateErr.Error())
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

func (ctlr *Controller) eraseLBServiceIngressStatus(
	svc *v1.Service,
) {
	svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{}

	_, updateErr := ctlr.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(
		context.TODO(), svc, metav1.UpdateOptions{})
	if nil != updateErr {
		// Multi-service causes the controller to try to update the status multiple times
		// at once. Ignore this error.
		if strings.Contains(updateErr.Error(), "object has been modified") {
			log.Debugf("Error while updating service: %v/%v. %v", svc.Namespace, svc.Name, updateErr.Error())
			return
		}
		warning := fmt.Sprintf(
			"Error when erasing Service LB Ingress status IP: %v", updateErr)
		log.Warning(warning)
		ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeWarning, "StatusIPError", warning)
	} else {
		message := fmt.Sprintf("F5 CIS erased LoadBalancer IP in Status")
		ctlr.recordLBServiceIngressEvent(svc, v1.EventTypeNormal, "ExternalIP", message)
	}
}

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

//sort services by timestamp
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

func getNodeport(svc *v1.Service, servicePort int32) int32 {
	for _, port := range svc.Spec.Ports {
		if port.Port == servicePort {
			return port.NodePort
		}
	}
	return 0
}

//Update virtual server status with virtual server address
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

//Update Transport server status with virtual server address
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

//Update ingresslink status with virtual server address
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
