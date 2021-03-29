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

package crmanager

import (
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

// customResourceWorker starts the Custom Resource Worker.
func (crMgr *CRManager) customResourceWorker() {
	log.Debugf("Starting Custom Resource Worker")
	for crMgr.processResource() {
	}
}

// processResource gets resources from the rscQueue and processes the resource
// depending  on its kind.
func (crMgr *CRManager) processResource() bool {

	key, quit := crMgr.rscQueue.Get()
	if quit {
		// The controller is shutting down.
		log.Debugf("Resource Queue is empty, Going to StandBy Mode")
		return false
	}
	var isError bool

	defer crMgr.rscQueue.Done(key)
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)

	// Check the type of resource and process accordingly.
	switch rKey.kind {
	case VirtualServer:
		virtual := rKey.rsc.(*cisapiv1.VirtualServer)
		err := crMgr.processVirtualServers(virtual, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case TLSProfile:
		if crMgr.initState {
			break
		}
		tls := rKey.rsc.(*cisapiv1.TLSProfile)
		virtuals := crMgr.getVirtualsForTLSProfile(tls)
		// No Virtuals are effected with the change in TLSProfile.
		if nil == virtuals {
			break
		}
		for _, virtual := range virtuals {
			err := crMgr.processVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
	case TransportServer:
		virtual := rKey.rsc.(*cisapiv1.TransportServer)
		err := crMgr.processTransportServers(virtual, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case IngressLink:
		ingLink := rKey.rsc.(*cisapiv1.IngressLink)
		log.Infof("Worker got IngressLink: %v\n", ingLink)
		log.Infof("IngressLink Selector: %v\n", ingLink.Spec.Selector.String())
		err := crMgr.processIngressLink(ingLink, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case ExternalDNS:
		edns := rKey.rsc.(*cisapiv1.ExternalDNS)
		crMgr.processExternalDNS(edns, rKey.rscDelete)
	case IPAM:
		ipam := rKey.rsc.(*ficV1.F5IPAM)
		virtuals := crMgr.getVirtualServersForIPAM(ipam)
		for _, vs := range virtuals {
			crMgr.processVirtualServers(vs, false)
		}
		TSVirtuals := crMgr.getTransportServersForIPAM(ipam)
		for _, ts := range TSVirtuals {
			crMgr.processTransportServers(ts, false)
		}
	case Service:
		if crMgr.initState {
			break
		}
		svc := rKey.rsc.(*v1.Service)
		virtuals := crMgr.getVirtualServersForService(svc)
		// If nil No Virtuals are effected with the change in service.
		if nil != virtuals {
			for _, virtual := range virtuals {
				err := crMgr.processVirtualServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
		//Sync service for Transport Server virtuals
		tsVirtuals := crMgr.getTransportServersForService(svc)
		if nil != tsVirtuals {
			for _, virtual := range tsVirtuals {
				err := crMgr.processTransportServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
		//Sync service for Ingress Links
		ingLinks := crMgr.getIngressLinksForService(svc)
		if nil != ingLinks {
			for _, ingLink := range ingLinks {
				err := crMgr.processIngressLink(ingLink, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}

	case Endpoints:
		if crMgr.initState {
			break
		}
		ep := rKey.rsc.(*v1.Endpoints)
		svc := crMgr.getServiceForEndpoints(ep)
		// No Services are effected with the change in service.
		if nil == svc {
			break
		}
		virtuals := crMgr.getVirtualServersForService(svc)
		for _, virtual := range virtuals {
			err := crMgr.processVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
		//Sync service for Transport Server virtuals
		tsVirtuals := crMgr.getTransportServersForService(svc)
		if nil != tsVirtuals {
			for _, virtual := range tsVirtuals {
				err := crMgr.processTransportServers(virtual, false)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}
		}
		//Sync service for Ingress Links
		ingLinks := crMgr.getIngressLinksForService(svc)
		if nil != ingLinks {
			for _, ingLink := range ingLinks {
				err := crMgr.processIngressLink(ingLink, false)
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
			for _, vrt := range crMgr.getAllVirtualServers(nsName) {
				err := crMgr.processVirtualServers(vrt, true)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}

			for _, ts := range crMgr.getAllTransportServers(nsName) {
				err := crMgr.processTransportServers(ts, true)
				if err != nil {
					// TODO
					utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
					isError = true
				}
			}

			crMgr.crInformers[nsName].stop()
			delete(crMgr.crInformers, nsName)
			crMgr.namespacesMutex.Lock()
			delete(crMgr.namespaces, nsName)
			crMgr.namespacesMutex.Unlock()
			log.Debugf("Removed Namespace: '%v' from CIS scope", nsName)
		} else {
			crMgr.namespacesMutex.Lock()
			crMgr.namespaces[nsName] = true
			crMgr.namespacesMutex.Unlock()
			_ = crMgr.addNamespacedInformer(nsName)
			crMgr.crInformers[nsName].start()
			log.Debugf("Added Namespace: '%v' to CIS scope", nsName)
		}
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}

	if isError {
		crMgr.rscQueue.AddRateLimited(key)
	} else {
		crMgr.rscQueue.Forget(key)
	}

	if crMgr.rscQueue.Len() == 0 &&
		(!reflect.DeepEqual(crMgr.resources.rsMap, crMgr.resources.oldRsMap) ||
			!reflect.DeepEqual(crMgr.resources.dnsConfig, crMgr.resources.oldDNSConfig)) {

		config := ResourceConfigWrapper{
			rsCfgs:         crMgr.resources.GetAllResources(),
			customProfiles: crMgr.customProfiles,
			shareNodes:     crMgr.shareNodes,
			dnsConfig:      crMgr.resources.dnsConfig,
		}
		crMgr.Agent.PostConfig(config)
		crMgr.initState = false
		crMgr.resources.updateOldConfig()
	}
	return true
}

// getServiceForEndpoints returns the service associated with endpoints.
func (crMgr *CRManager) getServiceForEndpoints(ep *v1.Endpoints) *v1.Service {

	epName := ep.ObjectMeta.Name
	epNamespace := ep.ObjectMeta.Namespace
	svcKey := fmt.Sprintf("%s/%s", epNamespace, epName)

	crInf, ok := crMgr.getNamespacedInformer(epNamespace)
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
func (crMgr *CRManager) getVirtualServersForService(svc *v1.Service) []*cisapiv1.VirtualServer {

	allVirtuals := crMgr.getAllVirtualServers(svc.ObjectMeta.Namespace)
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
func (crMgr *CRManager) getVirtualsForTLSProfile(tls *cisapiv1.TLSProfile) []*cisapiv1.VirtualServer {

	allVirtuals := crMgr.getAllVirtualServers(tls.ObjectMeta.Namespace)
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

// getAllVirtualServers returns list of all valid VirtualServers in rkey namespace.
func (crMgr *CRManager) getAllVirtualServers(namespace string) []*cisapiv1.VirtualServer {
	var allVirtuals []*cisapiv1.VirtualServer

	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	// Get list of VirtualServers and process them.
	orderedVSs, err := crInf.vsInformer.GetIndexer().ByIndex("namespace", namespace)
	if err != nil {
		log.Errorf("Unable to get list of VirtualServers for namespace '%v': %v",
			namespace, err)
		return nil
	}

	for _, obj := range orderedVSs {
		vs := obj.(*cisapiv1.VirtualServer)
		// TODO
		// Validate the VirtualServers List to check if all the vs are valid.

		allVirtuals = append(allVirtuals, vs)
	}

	return allVirtuals
}

// getAllVirtualServers returns list of all valid VirtualServers in rkey namespace.
func (crMgr *CRManager) getAllVSFromAllNamespaces() []*cisapiv1.VirtualServer {
	var allVirtuals []*cisapiv1.VirtualServer

	crInf, ok := crMgr.getNamespacedInformer("")
	if !ok {
		log.Errorf("Informer not found all namespace.")
		return allVirtuals
	}
	// Get list of VirtualServers and process them.
	objs := crInf.vsInformer.GetIndexer().List()

	for _, obj := range objs {
		vs := obj.(*cisapiv1.VirtualServer)
		// TODO
		// Validate the VirtualServers List to check if all the vs are valid.

		allVirtuals = append(allVirtuals, vs)
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

func (crMgr *CRManager) getTLSProfileForVirtualServer(
	vs *cisapiv1.VirtualServer,
	namespace string) *cisapiv1.TLSProfile {
	tlsName := vs.Spec.TLSProfileName
	tlsKey := fmt.Sprintf("%s/%s", namespace, tlsName)

	// Initialize CustomResource Informer for required namespace
	crInf, ok := crMgr.getNamespacedInformer(namespace)
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
		clientSecret, _ := crMgr.kubeClient.CoreV1().Secrets(namespace).Get(tlsProfile.Spec.TLS.ClientSSL, metav1.GetOptions{})
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
func (crMgr *CRManager) processVirtualServers(
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
		valid := crMgr.checkValidVirtualServer(virtual)
		if false == valid {
			log.Infof("VirtualServer %s, invalid configuration or not valid",
				vkey)
			return nil
		}
	}

	allVirtuals := crMgr.getAllVirtualServers(virtual.ObjectMeta.Namespace)

	var virtuals []*cisapiv1.VirtualServer

	// Prepare list of associated VirtualServers to be processed
	// In the event of deletion, exclude the deleted VirtualServer
	log.Debugf("Process all the Virtual Servers which share same VirtualServerAddress")

	uniqueHostPath := make(map[string][]string)
	var ipamLabel string
	for _, vrt := range allVirtuals {
		if vrt.Spec.Host == virtual.Spec.Host &&
			!(isVSDeleted && vrt.ObjectMeta.Name == virtual.ObjectMeta.Name) {
			if crMgr.ipamCli != nil && vrt.Spec.IPAMLabel != virtual.Spec.IPAMLabel {
				log.Debugf("Same host is configured with different ipma label : , %v ", vrt.Spec.Host)
				return nil
			} else if vrt.Spec.VirtualServerAddress != virtual.Spec.VirtualServerAddress {
				log.Debugf("Same host is configured with different VirtualServerAddress : %v ", vrt.Spec.VirtualServerName)
				return nil
			}
			isUnique := true
		op:
			for _, pool := range vrt.Spec.Pools {
				uniquePaths := uniqueHostPath[virtual.Spec.Host]
				if len(uniquePaths) > 0 {
					for _, path := range uniquePaths {
						//check if path already exists in host map
						if pool.Path == path {
							isUnique = false
							log.Errorf("Discarding the virtual server : %v in Namespace %v : %v  due to duplicate path",
								virtual.Spec.VirtualServerAddress, virtual.ObjectMeta.Namespace, virtual.ObjectMeta.Name)
							break op
						} else {
							uniqueHostPath[virtual.Spec.Host] = append(uniqueHostPath[virtual.Spec.Host], pool.Path)
						}
					}
				} else {
					uniqueHostPath[virtual.Spec.Host] = append(uniqueHostPath[virtual.Spec.Host], pool.Path)
				}
			}
			if isUnique {
				virtuals = append(virtuals, vrt)
				if vrt.Spec.IPAMLabel != "" {
					ipamLabel = vrt.Spec.IPAMLabel
				}
			}
		}
	}

	var ip string
	if crMgr.ipamCli != nil {
		if isVSDeleted && len(virtuals) == 0 && virtual.Spec.VirtualServerAddress == "" {
			ip = crMgr.releaseIP(virtual.Spec.IPAMLabel, virtual.Spec.Host, "")
		} else if virtual.Spec.VirtualServerAddress != "" {
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ip = crMgr.requestIP(ipamLabel, virtual.Spec.Host, "")
			log.Debugf("[ipam] requested IP for host %v is: %v", virtual.Spec.Host, ip)
			if ip == "" {
				log.Debugf("[ipam] requested IP for host %v is empty.", virtual.Spec.Host)
				return nil
			}
		}
	} else {
		if virtual.Spec.VirtualServerAddress == "" {
			return fmt.Errorf("No VirtualServer address or IPAM found.")
		}
		ip = virtual.Spec.VirtualServerAddress
	}
	// Depending on the ports defined, TLS type or Unsecured we will populate the resource config.
	portStructs := crMgr.virtualPorts(virtual)

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
			crMgr.deleteVirtualServer(rsName)
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = crMgr.Partition
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, virtual.Spec.Host)
		rsCfg.Virtual.SetVirtualAddress(
			ip,
			portStruct.port,
		)
		rsCfg.IntDgMap = make(InternalDataGroupMap)
		rsCfg.IRulesMap = make(IRulesMap)

		for _, vrt := range virtuals {
			log.Debugf("Processing Virtual Server %s for port %v",
				vrt.ObjectMeta.Name, portStruct.port)
			err := crMgr.prepareRSConfigFromVirtualServer(
				rsCfg,
				vrt,
			)
			if err != nil {
				processingError = true
				break
			}

			if isTLSVirtualServer(vrt) {
				// Handle TLS configuration for VirtualServer Custom Resource
				processed := crMgr.handleVirtualServerTLS(rsCfg, vrt, ip)
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

		if crMgr.ControllerMode == NodePortMode {
			crMgr.updatePoolMembersForNodePort(rsCfg, virtual.ObjectMeta.Namespace)
		} else {
			crMgr.updatePoolMembersForCluster(rsCfg, virtual.ObjectMeta.Namespace)
		}
	}

	if !processingError {
		var newVSCreated bool
		// Update rsMap with ResourceConfigs created for the current virtuals
		for rsName, rsCfg := range vsMap {
			if _, ok := crMgr.resources.rsMap[rsName]; !ok {
				newVSCreated = true
			}
			crMgr.resources.rsMap[rsName] = rsCfg
		}
		if newVSCreated {
			// TODO: Need to improve the algorithm by taking "host" as a factor
			crMgr.ProcessAllExternalDNS()
		}
	}

	return nil
}

func (crMgr *CRManager) getIPAMCR() *ficV1.F5IPAM {
	cr := strings.Split(crMgr.ipamCR, "/")
	if len(cr) != 2 {
		log.Errorf("[ipam] error while retriving IPAM namespace and name.")
		return nil
	}
	ipamCR, err := crMgr.ipamCli.Get(cr[0], cr[1])
	if err != nil {
		log.Errorf("[ipam] error while retriving IPAM custom resource.")
		return nil
	}
	return ipamCR
}

//Request IPAM for virtual IP address
func (crMgr *CRManager) requestIP(ipamLabel string, host string, key string) string {
	ipamCR := crMgr.getIPAMCR()
	if ipamCR == nil || ipamLabel == "" {
		return ""
	}

	if host != "" {
		//For VS server
		for _, ipst := range ipamCR.Status.IPStatus {
			if ipst.IPAMLabel == ipamLabel && ipst.Host == host {
				return ipst.IP
			}
		}

		for _, hst := range ipamCR.Spec.HostSpecs {
			if hst.Host == host {
				if hst.IPAMLabel == ipamLabel {
					//Check if HostSpec is already updated with IPAMLabel and Host
					return ""
				} else {
					//Check this for key and host both
					crMgr.releaseIP(hst.IPAMLabel, hst.Host, "")
					break
				}
			}
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
				return ipst.IP
			}
		}

		for _, hst := range ipamCR.Spec.HostSpecs {
			if hst.Key == key {
				if hst.IPAMLabel == ipamLabel {
					//Check if HostSpec is already updated with IPAMLabel and Key
					return ""
				} else {
					//Check this for key and host both
					crMgr.releaseIP(hst.IPAMLabel, "", hst.Key)
					break
				}
			}
		}

		ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
		ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs, &ficV1.HostSpec{
			Key:       key,
			IPAMLabel: ipamLabel,
		})

	} else {
		log.Debugf("[IPAM] Invalid host and key.")
		return ""
	}

	crMgr.ipamCli.Update(IPAMNamespace, ipamCR)
	log.Debugf("[ipam] Updated IPAM CR.")
	return ""

}

func (crMgr *CRManager) releaseIP(ipamLabel string, host string, key string) string {
	ipamCR := crMgr.getIPAMCR()
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
			_, err := crMgr.ipamCli.Update(IPAMNamespace, ipamCR)
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
			_, err := crMgr.ipamCli.Update(IPAMNamespace, ipamCR)
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
func (crMgr *CRManager) updatePoolMembersForNodePort(
	rsCfg *ResourceConfig,
	namespace string,
) {
	// TODO: Can we get rid of counter? and use something better.
	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return
	}

	for index, pool := range rsCfg.Pools {
		svcName := pool.ServiceName
		svcKey := namespace + "/" + svcName

		// TODO: Too Many API calls?
		service, exist, _ := crInf.svcInformer.GetIndexer().GetByKey(svcKey)
		if !exist {
			log.Debugf("Service not found %s", svcKey)
			// Update the pool with empty members
			var member []Member
			rsCfg.Pools[index].Members = member
			continue
		}
		svc := service.(*v1.Service)
		// Traverse for all the pools in the Resource Config
		if svc.Spec.Type == v1.ServiceTypeNodePort ||
			svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			// TODO: Instead of looping over Spec Ports, get the port from the pool itself
			for _, portSpec := range svc.Spec.Ports {
				if portSpec.Port == pool.ServicePort {
					rsCfg.MetaData.Active = true
					rsCfg.Pools[index].Members =
						crMgr.getEndpointsForNodePort(portSpec.NodePort, pool.NodeMemberLabel)
				}
			}
		} else {
			log.Debugf("Requested service backend %s not of NodePort or LoadBalancer type",
				svcName)
		}
	}
}

// updatePoolMembersForCluster updates the pool with pool members for a
// service created in cluster mode.
func (crMgr *CRManager) updatePoolMembersForCluster(
	rsCfg *ResourceConfig,
	namespace string,
) {

	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return
	}

	for index, pool := range rsCfg.Pools {
		svcName := pool.ServiceName
		svcKey := namespace + "/" + svcName

		// TODO: Too Many API calls?
		item, found, _ := crInf.epsInformer.GetIndexer().GetByKey(svcKey)
		if !found {
			log.Debugf("Endpoints for service '%v' not found!", svcKey)
			continue
		}
		eps, _ := item.(*v1.Endpoints)
		// TODO: Too Many API calls?
		// Get Service
		service, exist, _ := crInf.svcInformer.GetIndexer().GetByKey(svcKey)
		if !exist {
			log.Debugf("Service not found %s", svcKey)
			// Update the pool with empty members
			var member []Member
			rsCfg.Pools[index].Members = member
			continue
		}
		svc := service.(*v1.Service)

		// TODO: Instead of looping over Spec Ports, get the port from the pool itself
		for _, portSpec := range svc.Spec.Ports {
			ipPorts := crMgr.getEndpointsForCluster(portSpec.Name, eps, pool.ServicePort)
			log.Debugf("Found endpoints for backend %+v: %v", svcKey, ipPorts)
			rsCfg.MetaData.Active = true
			if len(ipPorts) > 0 {
				rsCfg.Pools[index].Members = ipPorts
			}
		}
	}
}

// getEndpointsForNodePort returns members.
func (crMgr *CRManager) getEndpointsForNodePort(
	nodePort int32,
	nodeMemberLabel string,
) []Member {
	var nodes []Node
	if nodeMemberLabel == "" {
		nodes = crMgr.getNodesFromCache()
	} else {
		nodes = crMgr.getNodesWithLabel(nodeMemberLabel)
	}
	var members []Member
	for _, v := range nodes {
		member := Member{
			Address: v.Addr,
			Port:    nodePort,
			Session: "user-enabled",
		}
		members = append(members, member)
	}

	return members
}

// getEndpointsForCluster returns members.
func (crMgr *CRManager) getEndpointsForCluster(
	portName string,
	eps *v1.Endpoints,
	servicePort int32,
) []Member {
	nodes := crMgr.getNodesFromCache()
	var members []Member

	if eps == nil {
		return members
	}

	for _, subset := range eps.Subsets {
		for _, p := range subset.Ports {
			if portName == p.Name && servicePort == p.Port {
				for _, addr := range subset.Addresses {
					if containsNode(nodes, *addr.NodeName) {
						member := Member{
							Address: addr.IP,
							Port:    p.Port,
							Session: "user-enabled",
						}
						members = append(members, member)
					}
				}
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
func (crMgr *CRManager) processTransportServers(
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
		valid := crMgr.checkValidTransportServer(virtual)
		if false == valid {
			log.Infof("TransportServer %s, invalid configuration or not valid",
				vkey)
			return nil
		}
	}
	allVirtuals := crMgr.getAllTransportServers(virtual.ObjectMeta.Namespace)

	var virtuals []*cisapiv1.TransportServer

	// Prepare list of associated VirtualServers to be processed
	// In the event of deletion, exclude the deleted VirtualServer
	log.Debugf("Process all the Transport Servers which share same VirtualServerAddress")
	for _, vrt := range allVirtuals {
		if vrt.Spec.VirtualServerAddress == virtual.Spec.VirtualServerAddress && vrt.Spec.VirtualServerPort == virtual.Spec.VirtualServerPort &&
			!isTSDeleted {
			virtuals = append(virtuals, vrt)
		}
	}

	if isTSDeleted {
		// crMgr.handleVSDeleteForDataGroups(tVirtual)
	}

	var ip string
	var key string
	key = virtual.ObjectMeta.Namespace + "/" + virtual.ObjectMeta.Name + "_ts"
	if crMgr.ipamCli != nil {
		if isTSDeleted && len(virtuals) == 0 && virtual.Spec.VirtualServerAddress == "" {
			ip = crMgr.releaseIP(virtual.Spec.IPAMLabel, "", key)
		} else if virtual.Spec.VirtualServerAddress != "" {
			ip = virtual.Spec.VirtualServerAddress
		} else {
			ip = crMgr.requestIP(virtual.Spec.IPAMLabel, "", key)
			log.Debugf("[ipam] requested IP for TS %v is: %v", virtual.ObjectMeta.Name, ip)
			if ip == "" {
				log.Debugf("[ipam] requested IP for TS %v is empty.", virtual.ObjectMeta.Name)
				return nil
			}
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
		crMgr.resources.deleteVirtualServer(rsName)
		return nil
	}

	rsCfg := &ResourceConfig{}
	rsCfg.Virtual.Partition = crMgr.Partition
	rsCfg.MetaData.ResourceType = TransportServer
	rsCfg.Virtual.Enabled = true
	rsCfg.Virtual.Name = rsName
	rsCfg.Virtual.IpProtocol = virtual.Spec.Type
	rsCfg.Virtual.SetVirtualAddress(
		ip,
		virtual.Spec.VirtualServerPort,
	)

	for _, vrt := range virtuals {
		log.Debugf("Processing Transport Server %s for port %v",
			vrt.ObjectMeta.Name, vrt.Spec.VirtualServerPort)
		err := crMgr.prepareRSConfigFromTransportServer(
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

		if crMgr.ControllerMode == NodePortMode {
			crMgr.updatePoolMembersForNodePort(rsCfg, virtual.ObjectMeta.Namespace)
		} else {
			crMgr.updatePoolMembersForCluster(rsCfg, virtual.ObjectMeta.Namespace)
		}
	}
	if !processingError {
		// Update rsMap with ResourceConfigs created for the current transport virtuals
		for rsName, rsCfg := range vsMap {
			crMgr.resources.rsMap[rsName] = rsCfg
		}
	}
	return nil

}

// getAllTransportServers returns list of all valid TransportServers in rkey namespace.
func (crMgr *CRManager) getAllTSFromAllNamespaces() []*cisapiv1.TransportServer {
	var allVirtuals []*cisapiv1.TransportServer

	crInf, ok := crMgr.getNamespacedInformer("")
	if !ok {
		log.Errorf("Informer not found for all namespace.")
		return allVirtuals
	}
	// Get list of VirtualServers and process them.
	orderedVSs := crInf.tsInformer.GetIndexer().List()
	for _, obj := range orderedVSs {
		vs := obj.(*cisapiv1.TransportServer)
		// TODO
		// Validate the TransportServers List to check if all the vs are valid.

		allVirtuals = append(allVirtuals, vs)
	}

	return allVirtuals
}

// getAllTransportServers returns list of all valid TransportServers in rkey namespace.
func (crMgr *CRManager) getAllTransportServers(namespace string) []*cisapiv1.TransportServer {
	var allVirtuals []*cisapiv1.TransportServer

	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	// Get list of VirtualServers and process them.
	orderedVSs, err := crInf.tsInformer.GetIndexer().ByIndex("namespace", namespace)
	if err != nil {
		log.Errorf("Unable to get list of TransportServers for namespace '%v': %v",
			namespace, err)
		return nil
	}

	for _, obj := range orderedVSs {
		vs := obj.(*cisapiv1.TransportServer)
		// TODO
		// Validate the TransportServers List to check if all the vs are valid.

		allVirtuals = append(allVirtuals, vs)
	}

	return allVirtuals
}

// getTransportServersForService gets the List of VirtualServers which are effected
// by the addition/deletion/updation of service.
func (crMgr *CRManager) getTransportServersForService(svc *v1.Service) []*cisapiv1.TransportServer {

	allVirtuals := crMgr.getAllTransportServers(svc.ObjectMeta.Namespace)
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

// Get List of VirtualServers associated with the IPAM resource
func (crMgr *CRManager) getVirtualServersForIPAM(ipam *ficV1.F5IPAM) []*cisapiv1.VirtualServer {
	log.Debug("[ipam] sync ipam starting...")
	var allVS, vss []*cisapiv1.VirtualServer
	allVS = crMgr.getAllVSFromAllNamespaces()
	for _, status := range ipam.Status.IPStatus {
		for _, vs := range allVS {
			if status.Host == vs.Spec.Host {
				vss = append(vss, vs)
				break
			}
		}
	}
	return vss
}

// Get List of TransportServers associated with the IPAM resource
func (crMgr *CRManager) getTransportServersForIPAM(ipam *ficV1.F5IPAM) []*cisapiv1.TransportServer {
	var allTS, tss []*cisapiv1.TransportServer
	allTS = crMgr.getAllTSFromAllNamespaces()
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

func (crMgr *CRManager) processExternalDNS(edns *cisapiv1.ExternalDNS, isDelete bool) {

	if isDelete {
		delete(crMgr.resources.dnsConfig, edns.Spec.DomainName)
		return
	}
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
		log.Debugf("Processing WideIP Pool: %v", pl.Name)
		pool := GSLBPool{
			Name:       pl.Name,
			RecordType: pl.DNSRecordType,
			LBMethod:   pl.LoadBalanceMethod,
		}

		if pl.DNSRecordType == "" {
			pool.RecordType = "A"
		}
		if pl.LoadBalanceMethod == "" {
			pool.LBMethod = "round-robin"
		}

		for vsName, vs := range crMgr.resources.rsMap {
			var found bool
			for _, host := range vs.MetaData.hosts {
				if host == edns.Spec.DomainName {
					found = true
					break
				}
			}
			if found {
				log.Debugf("Adding WideIP Pool Member: %v", fmt.Sprintf("%v:/%v/Shared/%v",
					pl.DataServerName, DEFAULT_PARTITION, vsName))
				pool.Members = append(
					pool.Members,
					fmt.Sprintf("%v:/%v/Shared/%v",
						pl.DataServerName, DEFAULT_PARTITION, vsName),
				)
			}
		}
		if pl.Monitor.Send != "" && pl.Monitor.Type != "" {
			// TODO: Need to change to DEFAULT_PARTITION from Common, once Agent starts to support DEFAULT_PARTITION
			pool.Monitor = &Monitor{
				Name:      pl.Name + "_monitor",
				Partition: "Common",
				Type:      pl.Monitor.Type,
				Interval:  pl.Monitor.Interval,
				Send:      pl.Monitor.Send,
				Recv:      pl.Monitor.Recv,
				Timeout:   pl.Monitor.Timeout,
			}
		}
		wip.Pools = append(wip.Pools, pool)
	}

	crMgr.resources.dnsConfig[wip.DomainName] = wip
	return
}

func (crMgr *CRManager) ProcessAllExternalDNS() {
	for ns, crInf := range crMgr.crInformers {
		// TODO: It does not support the case of all namespaces (""). Need to Fix.
		nsEDNSs, err := crInf.ednsInformer.GetIndexer().ByIndex("namespace", ns)
		if err != nil {
			log.Errorf("Unable to get list of ExternalDNSs for namespace '%v': %v",
				ns, err)
			continue
		}
		log.Debugf("Processing all ExternalDNS: %v, Namespace: %v.", len(nsEDNSs), ns)

		for _, obj := range nsEDNSs {
			edns := obj.(*cisapiv1.ExternalDNS)
			crMgr.processExternalDNS(edns, false)
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

func (crMgr *CRManager) processIngressLink(
	ingLink *cisapiv1.IngressLink,
	isILDeleted bool,
) error {

	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing Ingress Links %+v (%v)",
			ingLink, endTime.Sub(startTime))
	}()

	if isILDeleted {
		var delRes []string
		for k, _ := range crMgr.resources.rsMap {
			rsName := "ingress_link_" + formatVirtualServerName(
				ingLink.Spec.VirtualServerAddress,
				0,
			)
			if strings.HasPrefix(k, rsName[:len(rsName)-1]) {
				delRes = append(delRes, k)
			}
		}
		for _, rsname := range delRes {
			delete(crMgr.resources.rsMap, rsname)
		}
		return nil
	}

	svc, err := crMgr.getKICServiceOfIngressLink(ingLink)
	if err != nil {
		return err
	}

	if svc == nil {
		return nil
	}

	for _, port := range svc.Spec.Ports {
		rsName := "ingress_link_" + formatVirtualServerName(
			ingLink.Spec.VirtualServerAddress,
			port.Port,
		)

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = crMgr.Partition
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
			ingLink.Spec.VirtualServerAddress,
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
		rsCfg.Monitors = append(rsCfg.Monitors, Monitor{Name: monitorName, Partition: rsCfg.Virtual.Partition, Interval: 20, Type: "http", Send: "GET /nginx-ready HTTP/1.1\r\n", Recv: "", Timeout: 10, TargetPort: 8081})
		pool.MonitorNames = append(pool.MonitorNames, monitorName)
		rsCfg.Virtual.PoolName = pool.Name
		rsCfg.Pools = append(rsCfg.Pools, pool)
		crMgr.resources.rsMap[rsName] = rsCfg

		if crMgr.ControllerMode == NodePortMode {
			crMgr.updatePoolMembersForNodePort(rsCfg, ingLink.ObjectMeta.Namespace)
		} else {
			crMgr.updatePoolMembersForCluster(rsCfg, ingLink.ObjectMeta.Namespace)
		}
	}

	return nil
}

func (crMgr *CRManager) getAllIngressLinks(namespace string) []*cisapiv1.IngressLink {
	var allIngLinks []*cisapiv1.IngressLink

	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	// Get list of VirtualServers and process them.
	orderedIngLinks, err := crInf.ilInformer.GetIndexer().ByIndex("namespace", namespace)
	if err != nil {
		log.Errorf("Unable to get list of VirtualServers for namespace '%v': %v",
			namespace, err)
		return nil
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
func (crMgr *CRManager) getIngressLinksForService(svc *v1.Service) []*cisapiv1.IngressLink {
	ingLinks := crMgr.getAllIngressLinks(svc.ObjectMeta.Namespace)
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

func (crMgr *CRManager) getKICServiceOfIngressLink(ingLink *cisapiv1.IngressLink) (*v1.Service, error) {
	selector := ""
	for k, v := range ingLink.Spec.Selector.MatchLabels {
		selector += fmt.Sprintf("%v=%v,", k, v)
	}
	selector = selector[:len(selector)-1]

	svcListOptions := metav1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matches the given label
	serviceList, err := crMgr.kubeClient.CoreV1().Services(ingLink.ObjectMeta.Namespace).List(svcListOptions)

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

func (crMgr *CRManager) setLBServiceIngressStatus(
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

	_, updateErr := crMgr.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(svc)
	if nil != updateErr {
		// Multi-service causes the controller to try to update the status multiple times
		// at once. Ignore this error.
		if strings.Contains(updateErr.Error(), "object has been modified") {
			return
		}
		warning := fmt.Sprintf(
			"Error when setting Service LB Ingress status IP: %v", updateErr)
		log.Warning(warning)
		crMgr.recordLBServiceIngressEvent(svc, v1.EventTypeWarning, "StatusIPError", warning)
	} else {
		message := fmt.Sprintf("F5 CIS assigned LoadBalancer IP: %v", ip)
		crMgr.recordLBServiceIngressEvent(svc, v1.EventTypeNormal, "ExternalIP", message)
	}
}

func (crMgr *CRManager) unSetLBServiceIngressStatus(
	svc *v1.Service,
	ip string,
) {
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

		_, updateErr := crMgr.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(svc)
		if nil != updateErr {
			// Multi-service causes the controller to try to update the status multiple times
			// at once. Ignore this error.
			if strings.Contains(updateErr.Error(), "object has been modified") {
				return
			}
			warning := fmt.Sprintf(
				"Error when unsetting Service LB Ingress status IP: %v", updateErr)
			log.Warning(warning)
			crMgr.recordLBServiceIngressEvent(svc, v1.EventTypeWarning, "StatusIPError", warning)
		} else {
			message := fmt.Sprintf("F5 CIS unassigned LoadBalancer IP: %v", ip)
			crMgr.recordLBServiceIngressEvent(svc, v1.EventTypeNormal, "ExternalIP", message)
		}
	}
}

func (crMgr *CRManager) recordLBServiceIngressEvent(
	svc *v1.Service,
	eventType string,
	reason string,
	message string,
) {
	namespace := svc.ObjectMeta.Namespace
	// Create the event
	evNotifier := crMgr.eventNotifier.CreateNotifierForNamespace(
		namespace, crMgr.kubeClient.CoreV1())
	evNotifier.RecordEvent(svc, eventType, reason, message)
}

type Services []v1.Service

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
