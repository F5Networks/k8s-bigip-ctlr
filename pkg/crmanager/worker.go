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
	"reflect"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
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
	var isLastInQueue, isError bool

	if crMgr.rscQueue.Len() == 0 {
		isLastInQueue = true
	}
	defer crMgr.rscQueue.Done(key)
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)

	// Check the type of resource and process accordingly.
	switch rKey.kind {
	case VirtualServer:
		virtual := rKey.rsc.(*cisapiv1.VirtualServer)
		err := crMgr.syncVirtualServers(virtual, rKey.rscDelete)
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
		virtuals := crMgr.syncTLSProfile(tls)
		// No Virtuals are effected with the change in TLSProfile.
		if nil == virtuals {
			break
		}
		for _, virtual := range virtuals {
			err := crMgr.syncVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
	case Service:
		if crMgr.initState {
			break
		}
		svc := rKey.rsc.(*v1.Service)
		virtuals := crMgr.syncService(svc)
		// No Virtuals are effected with the change in service.
		if nil == virtuals {
			break
		}
		for _, virtual := range virtuals {
			err := crMgr.syncVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
	case Endpoints:
		if crMgr.initState {
			break
		}
		ep := rKey.rsc.(*v1.Endpoints)
		svc := crMgr.syncEndpoints(ep)
		// No Services are effected with the change in service.
		if nil == svc {
			break
		}
		virtuals := crMgr.syncService(svc)
		for _, virtual := range virtuals {
			err := crMgr.syncVirtualServers(virtual, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}

	if isError {
		crMgr.rscQueue.AddRateLimited(key)
	} else {
		crMgr.rscQueue.Forget(key)
	}

	if isLastInQueue && !reflect.DeepEqual(
		crMgr.resources.rsMap,
		crMgr.resources.oldRsMap,
	) {

		config := ResourceConfigWrapper{
			rsCfgs:         crMgr.resources.GetAllResources(),
			iRuleMap:       crMgr.irulesMap,
			intDgMap:       crMgr.intDgMap,
			customProfiles: crMgr.customProfiles,
		}

		crMgr.Agent.PostConfig(config)
		crMgr.initState = false
		crMgr.resources.updateOldConfig()
	}
	return true
}

// syncEndpoints returns the service associated with endpoints.
func (crMgr *CRManager) syncEndpoints(ep *v1.Endpoints) *v1.Service {

	epName := ep.ObjectMeta.Name
	epNamespace := ep.ObjectMeta.Namespace
	svcKey := fmt.Sprintf("%s/%s", epNamespace, epName)

	crInf, ok := crMgr.getNamespaceInformer(epNamespace)
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

// syncService gets the List of VirtualServers which are effected
// by the addition/deletion/updation of service.
func (crMgr *CRManager) syncService(svc *v1.Service) []*cisapiv1.VirtualServer {

	allVirtuals := crMgr.getAllVirtualServers(svc.ObjectMeta.Namespace)
	if nil == allVirtuals {
		log.Infof("No VirtualServers founds in namespace %s",
			svc.ObjectMeta.Namespace)
		return nil
	}

	// find VirtualServers that reference the service
	virtualsForService := getVirtualServersForService(allVirtuals, svc)
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

// syncTLSProfile gets the List of VirtualServers which are effected
// by the addition/deletion/updation of TLSProfile.
func (crMgr *CRManager) syncTLSProfile(tls *cisapiv1.TLSProfile) []*cisapiv1.VirtualServer {

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

	crInf, ok := crMgr.getNamespaceInformer(namespace)
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

// getVirtualServersForService returns list of VirtualServers that are
// affected by the service under process.
func getVirtualServersForService(allVirtuals []*cisapiv1.VirtualServer,
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

func (crMgr *CRManager) getTLSProfileForVirtualServer(vs *cisapiv1.VirtualServer) *cisapiv1.TLSProfile {
	tlsName := vs.Spec.TLSProfileName
	namespace := vs.ObjectMeta.Namespace
	tlsKey := fmt.Sprintf("%s/%s", namespace, tlsName)

	// Initialize CustomResource Informer for required namespace
	crInf, ok := crMgr.getNamespaceInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}

	// TODO: Create Internal Structure to hold TLSProfiles. Make API call only for a new TLSProfile
	// Check if the TLSProfile exists and valid for us.
	obj, tlsFound, _ := crInf.tsInformer.GetIndexer().GetByKey(tlsKey)
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
	for _, host := range tlsProfile.Spec.Hosts {
		if host == vs.Spec.Host {
			// TLSProfile Object
			return tlsProfile
		}
	}
	log.Errorf("TLSProfile %s with host %s does not match with virtual server %s host.", tlsName, vs.Spec.Host, vs.ObjectMeta.Name)
	return nil

}

// syncVirtualServers takes the Virtual Server as input and processes all
// associated VirtualServers to create a resource config(Internal DataStructure)
// or to update if exists already.
func (crMgr *CRManager) syncVirtualServers(
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
	for _, v := range allVirtuals {
		if v.Spec.VirtualServerAddress == virtual.Spec.VirtualServerAddress &&
			v.Spec.Host == virtual.Spec.Host &&
			!(isVSDeleted && v.ObjectMeta.Name == virtual.ObjectMeta.Name) {
			virtuals = append(virtuals, v)
		}
	}

	if isVSDeleted {
		crMgr.handleVSDeleteForDataGroups(virtual)
	}
	// Depending on the ports defined, TLS type or Unsecured we will populate the resource config.
	portStructs := crMgr.virtualPorts(virtual)

	// vsMap holds Resource Configs of current virtuals temporarily
	vsMap := make(ResourceConfigMap)
	processingError := false

	for _, portStruct := range portStructs {
		// TODO: Add Route Domain
		rsName := formatVirtualServerName(
			virtual.Spec.VirtualServerAddress,
			portStruct.port,
		)
		if len(virtuals) == 0 {
			crMgr.resources.deleteVirtualServer(rsName)
			continue
		}
		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = crMgr.Partition
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.SetVirtualAddress(
			virtual.Spec.VirtualServerAddress,
			portStruct.port,
		)

		for _, vrt := range virtuals {
			log.Debugf("Processing Virtual Server %s for port %v",
				vrt.ObjectMeta.Name, portStruct.port)
			crMgr.prepareRSConfigFromVirtualServer(
				rsCfg,
				vrt,
			)

			if len(vrt.Spec.TLSProfileName) != 0 {
				// Handle TLS configuration for VirtualServer Custom Resource
				processed := crMgr.handleVirtualServerTLS(rsCfg, vrt)
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
		// Update rsMap with ResourceConfigs created for the current virtuals
		for rsName, rsCfg := range vsMap {
			crMgr.resources.rsMap[rsName] = rsCfg
		}
	}

	return nil
}

// updatePoolMembersForNodePort updates the pool with pool members for a
// service created in nodeport mode.
func (crMgr *CRManager) updatePoolMembersForNodePort(
	rsCfg *ResourceConfig,
	namespace string,
) {
	// TODO: Can we get rid of counter? and use something better.
	crInf, ok := crMgr.getNamespaceInformer(namespace)
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
				rsCfg.MetaData.Active = true
				rsCfg.Pools[index].Members =
					crMgr.getEndpointsForNodePort(portSpec.NodePort, pool.NodeMemberLabel)
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

	crInf, ok := crMgr.getNamespaceInformer(namespace)
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
			ipPorts := crMgr.getEndpointsForCluster(portSpec.Name, eps)
			log.Debugf("Found endpoints for backend %+v: %v", svcKey, ipPorts)
			rsCfg.MetaData.Active = true
			rsCfg.Pools[index].Members = ipPorts
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
) []Member {
	nodes := crMgr.getNodesFromCache()
	var members []Member

	if eps == nil {
		return members
	}

	for _, subset := range eps.Subsets {
		for _, p := range subset.Ports {
			if portName == p.Name {
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
