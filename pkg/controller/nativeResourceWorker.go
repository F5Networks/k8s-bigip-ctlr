package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	routeapi "github.com/openshift/api/route/v1"

	"reflect"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// nativeResourceWorker starts the Custom Resource Worker.
func (ctlr *Controller) nativeResourceWorker() {
	log.Debugf("Starting Native Resource Worker")
	ctlr.setInitialServiceCount()
	ctlr.initialiseExtendedRouteConfig()
	for ctlr.processNativeResource() {
	}
}

// processNativeResource gets resources from the nativeResourceQueue and processes the resource
// depending  on its kind.
func (ctlr *Controller) processNativeResource() bool {
	key, quit := ctlr.nativeResourceQueue.Get()
	if quit {
		// The controller is shutting down.
		log.Debugf("Resource Queue is empty, Going to StandBy Mode")
		return false
	}
	var isRetryableError bool

	defer ctlr.nativeResourceQueue.Done(key)
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)

	// During Init time, just accumulate all the poolMembers by processing only services
	if ctlr.initState && rKey.kind != Namespace {
		if rKey.kind != Service {
			ctlr.nativeResourceQueue.AddRateLimited(key)
			return true
		}
		ctlr.initialSvcCount--
		if ctlr.initialSvcCount <= 0 {
			ctlr.initState = false
		}
	}

	rscDelete := false
	if rKey.event == Delete {
		rscDelete = true
	}

	// Check the type of resource and process accordingly.
	switch rKey.kind {

	case Route:
		route := rKey.rsc.(*routeapi.Route)
		// processRoutes knows when to delete a VS (in the event of global config update and route delete)
		// so should not trigger delete from here
		if rKey.event == Create {
			if _, ok := ctlr.resources.processedNativeResources[resourceRef{
				kind:      Route,
				name:      route.Name,
				namespace: route.Namespace,
			}]; ok {
				break
			}
		}
		err := ctlr.processRoutes(route.Namespace, false)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isRetryableError = true
		}
	case ConfigMap:
		cm := rKey.rsc.(*v1.ConfigMap)
		err, ok := ctlr.processConfigMap(cm, rscDelete)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			break
		}

		if !ok {
			isRetryableError = true
		}

	case Service:
		svc := rKey.rsc.(*v1.Service)

		_ = ctlr.processService(svc, nil, rscDelete)

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
			break
		}
		if ctlr.initState {
			break
		}
		for _, rg := range getAffectedRouteGroups(svc) {
			ctlr.updatePoolMembersForRoutes(rg)
		}
	case Endpoints:
		ep := rKey.rsc.(*v1.Endpoints)
		svc := ctlr.getServiceForEndpoints(ep)
		// No Services are effected with the change in service.
		if nil == svc {
			break
		}

		_ = ctlr.processService(svc, ep, rscDelete)

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
			break
		}
		for _, rg := range getAffectedRouteGroups(svc) {
			ctlr.updatePoolMembersForRoutes(rg)
		}

	case Namespace:
		ns := rKey.rsc.(*v1.Namespace)
		nsName := ns.ObjectMeta.Name
		if rscDelete {
			// TODO: Delete all the resource configs from the store

			ctlr.nrInformers[nsName].stop()
			ctlr.esInformers[nsName].stop()
			delete(ctlr.nrInformers, nsName)
			delete(ctlr.esInformers, nsName)
			ctlr.namespacesMutex.Lock()
			delete(ctlr.namespaces, nsName)
			ctlr.namespacesMutex.Unlock()
			log.Debugf("Removed Namespace: '%v' from CIS scope", nsName)
		} else {
			ctlr.namespacesMutex.Lock()
			ctlr.namespaces[nsName] = true
			ctlr.namespacesMutex.Unlock()
			_ = ctlr.addNamespacedInformers(nsName)
			ctlr.nrInformers[nsName].start()
			ctlr.esInformers[nsName].start()
			log.Debugf("Added Namespace: '%v' to CIS scope", nsName)
		}
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}
	if isRetryableError {
		ctlr.nativeResourceQueue.AddRateLimited(key)
	} else {
		ctlr.nativeResourceQueue.Forget(key)
	}

	if ctlr.nativeResourceQueue.Len() == 0 && ctlr.resources.isConfigUpdated() {
		config := ResourceConfigRequest{
			ltmConfig:          ctlr.resources.getLTMConfigDeepCopy(),
			shareNodes:         ctlr.shareNodes,
			dnsConfig:          ctlr.resources.getGTMConfigCopy(),
			defaultRouteDomain: ctlr.defaultRouteDomain,
		}
		go ctlr.TeemData.PostTeemsData()
		config.reqId = ctlr.enqueueReq(config)
		ctlr.Agent.PostConfig(config)
		ctlr.initState = false
		ctlr.resources.updateCaches()
	}
	return true
}

func (ctlr *Controller) processRoutes(routeGroup string, triggerDelete bool) error {
	startTime := time.Now()
	namespace := routeGroup
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing RouteGroup/Namespace %v (%v)",
			routeGroup, endTime.Sub(startTime))
	}()

	extdSpec := ctlr.resources.getExtendedRouteSpec(routeGroup)
	if extdSpec == nil {
		return fmt.Errorf("extended Route Spec not available for RouteGroup/Namespace: %v", routeGroup)
	}

	routes := ctlr.getGroupedRoutes(routeGroup)

	if triggerDelete || len(routes) == 0 {
		// Delete all possible virtuals for this route group
		for _, portStruct := range getBasicVirtualPorts() {
			rsName := frameRouteVSName(routeGroup, extdSpec, portStruct)
			if ctlr.getVirtualServer(namespace, rsName) != nil {
				log.Debugf("Removing virtual %v belongs to RouteGroup: %v from Namespace: %v",
					rsName, routeGroup, namespace)
				ctlr.deleteVirtualServer(namespace, rsName)
			}
		}
		return nil
	}

	portStructs := getVirtualPortsForRoutes(routes)
	vsMap := make(ResourceMap)
	processingError := false

	for _, portStruct := range portStructs {
		rsName := frameRouteVSName(routeGroup, extdSpec, portStruct)

		// Delete rsCfg if it is HTTP port and the Route does not handle HTTPTraffic
		if portStruct.protocol == "http" && !doRoutesHandleHTTP(routes) {
			ctlr.deleteVirtualServer(routeGroup, rsName)
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = routeGroup
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.MetaData.Protocol = portStruct.protocol
		rsCfg.Virtual.SetVirtualAddress(
			extdSpec.VServerAddr,
			portStruct.port,
		)
		rsCfg.MetaData.baseResources = make(map[string]string)
		rsCfg.IntDgMap = make(InternalDataGroupMap)
		rsCfg.IRulesMap = make(IRulesMap)
		rsCfg.customProfiles = make(map[SecretKey]CustomProfile)
		// deletion ; update /health /app/path1

		err := ctlr.handleRouteGroupExtendedSpec(rsCfg, extdSpec)

		if err != nil {
			processingError = true
			log.Errorf("%v", err)
			break
		}

		for _, rt := range routes {
			rsCfg.MetaData.baseResources[rt.Namespace+"/"+rt.Name] = Route
			_, servicePort := ctlr.getServicePort(rt)
			if err != nil {
				processingError = true
				log.Errorf("%v", err)
				break
			}
			err = ctlr.prepareResourceConfigFromRoute(rsCfg, rt, routeGroup, servicePort, isPassthroughRoute(rt), portStruct)
			if err != nil {
				processingError = true
				log.Errorf("%v", err)
				break
			}

			if isSecureRoute(rt) {
				//TLS Logic
				processed := ctlr.handleRouteTLS(rsCfg, rt, extdSpec, servicePort)
				if !processed {
					// Processing failed
					// Stop processing further routes
					processingError = true
					break
				}

				log.Debugf("Updated Route %s with TLSProfile", rt.ObjectMeta.Name)
			}

			ctlr.resources.processedNativeResources[resourceRef{
				kind:      Route,
				namespace: rt.Namespace,
				name:      rt.Name,
			}] = struct{}{}
		}
		ctlr.removeUnusedHealthMonitors(rsCfg)

		if processingError {
			log.Errorf("Unable to Process Route Group %s", routeGroup)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, namespace)
		}
	}

	if !processingError {
		for name, rscfg := range vsMap {
			rsMap := ctlr.resources.getPartitionResourceMap(routeGroup)
			rsMap[name] = rscfg
		}
	}

	return nil
}

func (ctlr *Controller) removeUnusedHealthMonitors(rsCfg *ResourceConfig) {
	monitorLen := len(rsCfg.Monitors)
	i := 0
	for i < monitorLen {
		if !rsCfg.Monitors[i].InUse {
			log.Warningf("Discarding monitor %v with path %v as it is unused", rsCfg.Monitors[i].Name, rsCfg.Monitors[i].Path)
			if i == len(rsCfg.Monitors)-1 {
				rsCfg.Monitors = rsCfg.Monitors[:i]
			} else {
				rsCfg.Monitors = append(rsCfg.Monitors[:i], rsCfg.Monitors[i+1:]...)
			}
			monitorLen -= 1
		} else {
			i++
		}
	}
}

func (ctlr *Controller) getGroupedRoutes(routeGroup string) []*routeapi.Route {
	// Get the route group
	orderedRoutes := ctlr.getOrderedRoutes(routeGroup)
	var assocRoutes []*routeapi.Route
	for _, route := range orderedRoutes {
		// TODO: add combinations for a/b - svc weight ; valid svcs or not
		if ctlr.checkValidRoute(route) {
			ctlr.updateHostPathMap(route)
			go ctlr.removeDeletedRouteFromHostPathMap()
			assocRoutes = append(assocRoutes, route)
		}
	}
	return assocRoutes
}

func (ctlr *Controller) handleRouteGroupExtendedSpec(rsCfg *ResourceConfig, extdSpec *ExtendedRouteGroupSpec) error {
	if extdSpec.SNAT == "" {
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
	} else {
		rsCfg.Virtual.SNAT = extdSpec.SNAT
	}
	rsCfg.Virtual.WAF = extdSpec.WAF
	rsCfg.Virtual.IRules = extdSpec.IRules

	for _, hm := range extdSpec.HealthMonitors {
		if hm.Type == "" {
			hm.Type = "http"
		}
		rsCfg.Monitors = append(
			rsCfg.Monitors,
			Monitor{
				Name:      AS3NameFormatter(hm.Path) + "_monitor",
				Partition: rsCfg.Virtual.Partition,
				Interval:  hm.Interval,
				Type:      hm.Type,
				Send:      hm.Send,
				Recv:      hm.Recv,
				Timeout:   hm.Timeout,
				Path:      hm.Path,
			})
	}
	return nil
}

// gets the target port for the route
// if targetPort is set to IntVal, it's used directly
// otherwise the port is fetched from the associated service
func (ctlr *Controller) getServicePort(
	route *routeapi.Route,
) (error, int32) {
	log.Debugf("Finding port for route %v", route.Name)
	var err error
	var port int32
	nrInf, ok := ctlr.getNamespacedEssentialInformer(route.Namespace)
	if !ok {
		return fmt.Errorf("Informer not found for namespace: %v", route.Namespace), port
	}
	svcIndexer := nrInf.svcInformer.GetIndexer()
	svcName := route.Spec.To.Name
	if route.Spec.Port != nil {
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			port = route.Spec.Port.TargetPort.IntVal
		} else {
			port, err = resource.GetServicePort(route.Namespace, svcName, svcIndexer, strVal, resource.ResourceTypeRoute)
			if nil != err {
				return fmt.Errorf("Error while processing port for route %s: %v", route.Name, err), port
			}
		}
	} else {
		port, err = resource.GetServicePort(route.Namespace, svcName, svcIndexer, "", resource.ResourceTypeRoute)
		if nil != err {
			return fmt.Errorf("Error while processing port for route %s: %v", route.Name, err), port

		}
	}
	log.Debugf("Port %v found for route %s", port, route.Name)
	return nil, port

}

func (ctlr *Controller) prepareResourceConfigFromRoute(
	rsCfg *ResourceConfig,
	route *routeapi.Route,
	routeGroup string,
	servicePort int32,
	passthroughRoute bool,
	portStruct portStruct,
) error {

	// Skip adding the host, pool and forwarding policy rule to the resource config
	// if it's an HTTP virtual server and the route doesn't allow insecure traffic
	if portStruct.protocol == HTTP && route.Spec.TLS != nil &&
		(route.Spec.TLS.InsecureEdgeTerminationPolicy == "" || route.Spec.TLS.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyNone) {
		return nil
	}

	rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, route.Spec.Host)

	pool := Pool{
		Name: formatPoolName(
			route.Namespace,
			route.Spec.To.Name,
			servicePort,
			"",
		),
		Partition:       rsCfg.Virtual.Partition,
		ServiceName:     route.Spec.To.Name,
		ServicePort:     servicePort,
		NodeMemberLabel: "",
	}

	for index, monitor := range rsCfg.Monitors {
		if strings.HasPrefix(monitor.Path, route.Spec.Host+route.Spec.Path) {
			// Remove unused health monitors
			rsCfg.Monitors[index].InUse = true
			pool.MonitorNames = append(pool.MonitorNames, monitor.Name)
			break
		}
	}

	rsCfg.Pools = append(rsCfg.Pools, pool)
	// skip the policy creation for passthrough termination
	if !passthroughRoute {
		rules := ctlr.prepareRouteLTMRules(route, routeGroup, pool.Name)
		if rules == nil {
			return fmt.Errorf("failed to create LTM Rules")
		}

		policyName := formatPolicyName(route.Spec.Host, routeGroup, rsCfg.Virtual.Name)

		rsCfg.AddRuleToPolicy(policyName, routeGroup, rules)
	}

	return nil
}

// prepareRouteLTMRules prepares LTM Policy rules for VirtualServer
func (ctlr *Controller) prepareRouteLTMRules(
	route *routeapi.Route,
	routeGroup string,
	poolName string,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)

	uri := route.Spec.Host + route.Spec.Path
	path := route.Spec.Path

	ruleName := formatVirtualServerRuleName(route.Spec.Host, routeGroup, path, poolName)

	rl, err := createRule(uri, poolName, ruleName)
	if nil != err {
		log.Errorf("Error configuring rule: %v", err)
		return nil
	}

	if strings.HasPrefix(uri, "*.") == true {
		wildcards[uri] = rl
	} else {
		rlMap[uri] = rl
	}

	var wg sync.WaitGroup
	wg.Add(2)

	sortrules := func(r ruleMap, rls *Rules, ordinal int) {
		for _, v := range r {
			*rls = append(*rls, v)
		}
		//sort.Sort(sort.Reverse(*rls))
		for _, v := range *rls {
			v.Ordinal = ordinal
			ordinal++
		}
		wg.Done()
	}

	rls := Rules{}
	go sortrules(rlMap, &rls, 0)

	w := Rules{}
	go sortrules(wildcards, &w, len(rlMap))

	wg.Wait()

	rls = append(rls, w...)
	sort.Sort(rls)

	return &rls
}

func (ctlr *Controller) updatePoolMembersForRoutes(routeGroup string) {
	extdSpec := ctlr.resources.getExtendedRouteSpec(routeGroup)
	if extdSpec == nil {
		//log.Debugf("extended Route Spec not available for RouteGroup/Namespace: %v", routeGroup)
		return
	}
	namespace := routeGroup
	for _, portStruct := range getBasicVirtualPorts() {
		rsName := frameRouteVSName(routeGroup, extdSpec, portStruct)
		rsCfg := ctlr.getVirtualServer(namespace, rsName)
		if rsCfg == nil {
			continue
		}
		freshRsCfg := &ResourceConfig{}
		freshRsCfg.copyConfig(rsCfg)
		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(freshRsCfg, namespace)
		} else {
			ctlr.updatePoolMembersForCluster(freshRsCfg, namespace)
		}
		_ = ctlr.resources.setResourceConfig(namespace, rsName, freshRsCfg)
	}
}

func (ctlr *Controller) initialiseExtendedRouteConfig() {
	splits := strings.Split(ctlr.routeSpecCMKey, "/")
	ns, cmName := splits[0], splits[1]
	cm, err := ctlr.kubeClient.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Unable to Get Extended Route Spec Config Map: %v, %v", ctlr.routeSpecCMKey, err)
	}
	err, _ = ctlr.processConfigMap(cm, false)
	if err != nil {
		log.Errorf("Unable to Process Extended Route Spec Config Map: %v, %v", ctlr.routeSpecCMKey, err)
	}
}

func (ctlr *Controller) processConfigMap(cm *v1.ConfigMap, isDelete bool) (error, bool) {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing local extended spec configmap: %v/%v (%v)",
			cm.Namespace, cm.Name, endTime.Sub(startTime))
	}()

	ersData := cm.Data
	es := extendedSpec{}

	//log.Debugf("GCM: %v", cm.Data)

	err := yaml.UnmarshalStrict([]byte(ersData["extendedSpec"]), &es)
	if err != nil {
		return fmt.Errorf("invalid extended route spec in configmap: %v/%v", cm.Namespace, cm.Name), false
	}

	newExtdSpecMap := make(extendedSpecMap, len(ctlr.resources.extdSpecMap))

	if ctlr.isGlobalExtendedRouteSpec(cm) {
		for rg := range es.ExtendedRouteGroupConfigs {
			// ergc needs to be created at every iteration, as we are using address inside this container

			// if this were used as an iteration variable, on every loop we just use the same container instead of creating one
			// using the same container overrides the previous iteration contents, which is not desired
			ergc := es.ExtendedRouteGroupConfigs[rg]
			newExtdSpecMap[ergc.Namespace] = &extendedParsedSpec{
				override: ergc.AllowOverride,
				local:    nil,
				global:   &ergc.ExtendedRouteGroupSpec,
			}
		}

		// Global configmap once gets processed even before processing other native resources
		if ctlr.initState {
			ctlr.resources.extdSpecMap = newExtdSpecMap
			return nil, true
		}

		// deletedSpecs: the spec blocks are deleted from the configmap
		// modifiedSpecs: specific params of spec entry are changed because of which virutals need to be deleted and framed again
		// updatedSpecs: parameters are updated, so just reprocess the resources
		// createSpecs: new spec blocks are added to the configmap
		var deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs []string

		if isDelete {
			for ns := range newExtdSpecMap {
				deletedSpecs = append(deletedSpecs, ns)
			}
		} else {
			for ns, spec := range ctlr.resources.extdSpecMap {
				newSpec, ok := newExtdSpecMap[ns]
				if !ok {
					deletedSpecs = append(deletedSpecs, ns)
					continue
				}
				if !reflect.DeepEqual(spec, newExtdSpecMap[ns]) {
					if spec.global.VServerName != newSpec.global.VServerName || spec.override != newSpec.override {
						// Update to VServerName or override should trigger delete and recreation of object
						modifiedSpecs = append(deletedSpecs, ns)
					} else {
						updatedSpecs = append(modifiedSpecs, ns)
					}
				}
			}
			for ns, _ := range newExtdSpecMap {
				_, ok := ctlr.resources.extdSpecMap[ns]
				if !ok {
					createdSpecs = append(createdSpecs, ns)
				}
			}
		}

		for _, ns := range deletedSpecs {
			_ = ctlr.processRoutes(ns, true)
			if ctlr.resources.extdSpecMap[ns].local == nil {
				delete(ctlr.resources.extdSpecMap, ns)
			} else {
				ctlr.resources.extdSpecMap[ns].global = nil
				ctlr.resources.extdSpecMap[ns].override = false
			}
		}

		for _, ns := range modifiedSpecs {
			_ = ctlr.processRoutes(ns, true)
			ctlr.resources.extdSpecMap[ns].override = newExtdSpecMap[ns].override
			ctlr.resources.extdSpecMap[ns].global = newExtdSpecMap[ns].global
			err := ctlr.processRoutes(ns, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v with modified extended spec", ns)
			}
		}

		for _, ns := range updatedSpecs {
			ctlr.resources.extdSpecMap[ns].override = newExtdSpecMap[ns].override
			ctlr.resources.extdSpecMap[ns].global = newExtdSpecMap[ns].global
			err := ctlr.processRoutes(ns, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v with updated extended spec", ns)
			}
		}

		for _, ns := range createdSpecs {
			ctlr.resources.extdSpecMap[ns] = &extendedParsedSpec{}
			ctlr.resources.extdSpecMap[ns].override = newExtdSpecMap[ns].override
			ctlr.resources.extdSpecMap[ns].global = newExtdSpecMap[ns].global
			err := ctlr.processRoutes(ns, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v on addition of extended spec", ns)
			}
		}

	} else if len(es.ExtendedRouteGroupConfigs) > 0 {
		ergc := es.ExtendedRouteGroupConfigs[0]
		if ergc.Namespace != cm.Namespace {
			return fmt.Errorf("Invalid Extended Route Spec Block in configmap: %v/%v", cm.Namespace, cm.Name), true
		}
		if spec, ok := ctlr.resources.extdSpecMap[ergc.Namespace]; ok {
			if isDelete {
				if !spec.override {
					spec.local = nil
					return nil, true
				}
				_ = ctlr.processRoutes(ergc.Namespace, true)
				spec.local = nil
				// process routes again, this time routes get processed along with global config
				err := ctlr.processRoutes(ergc.Namespace, false)
				if err != nil {
					log.Errorf("Failed to process RouteGroup: %v on with global extended spec after deletion of local extended spec", ergc.Namespace)
				}
				return nil, true
			}

			if !spec.override || spec.global == nil {
				spec.local = &ergc.ExtendedRouteGroupSpec
				return nil, true
			}
			// creation event
			if spec.local == nil {
				if !reflect.DeepEqual(*(spec.global), ergc.ExtendedRouteGroupSpec) {
					if spec.global.VServerName != ergc.ExtendedRouteGroupSpec.VServerName {
						// Delete existing virtual that was framed with globla config
						// later build new virtual with local config
						_ = ctlr.processRoutes(ergc.Namespace, true)
					}
					spec.local = &ergc.ExtendedRouteGroupSpec
					err := ctlr.processRoutes(ergc.Namespace, false)
					if err != nil {
						log.Errorf("Failed to process RouteGroup: %v on addition of extended spec", ergc.Namespace)
					}
				}
				return nil, true
			}

			// update event
			if !reflect.DeepEqual(*(spec.local), ergc.ExtendedRouteGroupSpec) {
				// if update event, update to VServerName should trigger delete and recreation of object
				if spec.local.VServerName != ergc.ExtendedRouteGroupSpec.VServerName {
					_ = ctlr.processRoutes(ergc.Namespace, true)
				}
				spec.local = &ergc.ExtendedRouteGroupSpec
				err := ctlr.processRoutes(ergc.Namespace, false)
				if err != nil {
					log.Errorf("Failed to process RouteGroup: %v on addition of extended spec", ergc.Namespace)
				}
				return nil, true
			}

		} else {
			// Need not process routes as there is no confirmation of override yet
			ctlr.resources.extdSpecMap[ergc.Namespace] = &extendedParsedSpec{
				override: false,
				local:    &ergc.ExtendedRouteGroupSpec,
				global:   nil,
			}
			return nil, false
		}
	}

	return nil, true
}

func (ctlr *Controller) isGlobalExtendedRouteSpec(cm *v1.ConfigMap) bool {
	cmKey := cm.Namespace + "/" + cm.Name

	if cmKey == ctlr.routeSpecCMKey {
		return true
	}

	return false
}

func (ctlr *Controller) getOrderedRoutes(namespace string) []*routeapi.Route {
	var resources []interface{}
	var err error
	var allRoutes []*routeapi.Route

	nrInf, ok := ctlr.getNamespacedNativeInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}

	if namespace == "" {
		resources = nrInf.routeInformer.GetIndexer().List()
	} else {
		// Get list of Routes and process them.
		resources, err = nrInf.routeInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("Unable to get list of Routes for namespace '%v': %v",
				namespace, err)
			return nil
		}
	}

	for _, obj := range resources {
		rt := obj.(*routeapi.Route)
		allRoutes = append(allRoutes, rt)
	}
	sort.Slice(allRoutes, func(i, j int) bool {
		if allRoutes[i].Spec.Host == allRoutes[j].Spec.Host {
			if (len(allRoutes[i].Spec.Path) == 0 || len(allRoutes[j].Spec.Path) == 0) && (allRoutes[i].Spec.Path == "/" || allRoutes[j].Spec.Path == "/") {
				return allRoutes[i].CreationTimestamp.Before(&allRoutes[j].CreationTimestamp)
			}
		}
		return (allRoutes[i].Spec.Host < allRoutes[j].Spec.Host) ||
			(allRoutes[i].Spec.Host == allRoutes[j].Spec.Host &&
				allRoutes[i].Spec.Path == allRoutes[j].Spec.Path &&
				allRoutes[i].CreationTimestamp.Before(&allRoutes[j].CreationTimestamp)) ||
			(allRoutes[i].Spec.Host == allRoutes[j].Spec.Host &&
				allRoutes[i].Spec.Path < allRoutes[j].Spec.Path)
	})

	return allRoutes
}

func doRoutesHandleHTTP(routes []*routeapi.Route) bool {
	for _, route := range routes {
		if !isSecureRoute(route) {
			// If it is not TLS VirtualServer(HTTPS), then it is HTTP server
			return true
		}

		// If Allow or Redirect happens then HTTP Traffic is being handled.
		if route.Spec.TLS.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyAllow ||
			route.Spec.TLS.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyRedirect {
			return true
		}
	}

	return false
}

func isSecureRoute(route *routeapi.Route) bool {
	return route.Spec.TLS != nil
}

func isPassthroughRoute(route *routeapi.Route) bool {
	if route.Spec.TLS != nil {
		return route.Spec.TLS.Termination == TLSPassthrough
	}
	return false
}

func getAffectedRouteGroups(svc *v1.Service) []string {
	return []string{svc.Namespace}
}

func getBasicVirtualPorts() []portStruct {
	return []portStruct{
		{
			protocol: "http",
			port:     DEFAULT_HTTP_PORT,
		},
		{
			protocol: "https",
			port:     DEFAULT_HTTPS_PORT,
		},
	}
}

func getVirtualPortsForRoutes(routes []*routeapi.Route) []portStruct {
	ports := []portStruct{
		{
			protocol: "http",
			port:     DEFAULT_HTTP_PORT,
		},
	}

	for _, rt := range routes {
		if isSecureRoute(rt) {
			return getBasicVirtualPorts()
		}
	}
	return ports
}

func frameRouteVSName(routeGroup string,
	extdSpec *ExtendedRouteGroupSpec,
	portStruct portStruct,
) string {
	var rsName string
	if extdSpec.VServerName != "" {
		rsName = formatCustomVirtualServerName(
			extdSpec.VServerName,
			portStruct.port,
		)
	} else {
		rsName = formatCustomVirtualServerName(
			"routes_"+routeGroup,
			portStruct.port,
		)
	}
	return rsName
}

// update route admit status
func (ctlr *Controller) updateRouteAdmitStatus(
	rscKey string,
	reason string,
	message string,
	status v1.ConditionStatus,
) {
	route := ctlr.fetchRoute(rscKey)
	if route == nil {
		return
	}
	Admitted := false
	for _, routeIngress := range route.Status.Ingress {
		if routeIngress.RouterName == F5RouterName {
			for _, condition := range routeIngress.Conditions {
				if condition.Status == status {
					Admitted = true
				} else {
					// remove all multiple route admit status submitted earlier
					ctlr.eraseRouteAdmitStatus(rscKey)
				}
			}
		}
	}
	retryCount := 0
	for !Admitted && retryCount < 3 {
		now := metaV1.Now().Rfc3339Copy()
		route.Status.Ingress = append(route.Status.Ingress, routeapi.RouteIngress{
			RouterName: F5RouterName,
			Host:       route.Spec.Host,
			Conditions: []routeapi.RouteIngressCondition{{
				Type:               routeapi.RouteAdmitted,
				Status:             status,
				Reason:             reason,
				Message:            message,
				LastTransitionTime: &now,
			}},
		})
		_, err := ctlr.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(), route, metaV1.UpdateOptions{})
		if err != nil {
			retryCount++
			log.Errorf("Error while Updating Route Admit Status: %v\n", err)
			// Fetching the latest copy of route
			route = ctlr.fetchRoute(rscKey)
			if route == nil {
				return
			}
		} else {
			Admitted = true
			log.Debugf("Admitted Route -  %v", route.ObjectMeta.Name)
		}
	}
	// remove the route admit status for routes which are not monitored by CIS anymore
	ctlr.eraseAllRouteAdmitStatus()
}

// remove the route admit status for routes which are not monitored by CIS anymore
func (ctlr *Controller) eraseAllRouteAdmitStatus() {
	// Get the list of all unwatched Routes from all NS.
	unmonitoredOptions := metaV1.ListOptions{
		LabelSelector: strings.ReplaceAll(ctlr.routeLabel, " in ", " notin "),
	}
	unmonitoredRoutes, err := ctlr.routeClientV1.Routes("").List(context.TODO(), unmonitoredOptions)
	if err != nil {
		log.Errorf("[CORE] Error listing all Routes: %v", err)
		return
	}
	for _, route := range unmonitoredRoutes.Items {
		ctlr.eraseRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name))
	}
}

func (ctlr *Controller) eraseRouteAdmitStatus(rscKey string) {
	// Fetching the latest copy of route
	route := ctlr.fetchRoute(rscKey)
	if route == nil {
		return
	}
	for i := 0; i < len(route.Status.Ingress); i++ {
		if route.Status.Ingress[i].RouterName == F5RouterName {
			route.Status.Ingress = append(route.Status.Ingress[:i], route.Status.Ingress[i+1:]...)
			erased := false
			retryCount := 0
			for !erased && retryCount < 3 {
				_, err := ctlr.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(), route, metaV1.UpdateOptions{})
				if err != nil {
					log.Errorf("[CORE] Error while Erasing Route Admit Status: %v\n", err)
					retryCount++
					route = ctlr.fetchRoute(rscKey)
					if route == nil {
						return
					}
				} else {
					erased = true
					log.Debugf("[CORE] Admit Status Erased for Route - %v\n", route.ObjectMeta.Name)
				}
			}
			i-- // Since we just deleted a[i], we must redo that index
		}
	}
}

func (ctlr *Controller) fetchRoute(rscKey string) *routeapi.Route {
	ns := strings.Split(rscKey, "/")[0]
	nrInf, ok := ctlr.getNamespacedNativeInformer(ns)
	if !ok {
		return nil
	}
	obj, exist, err := nrInf.routeInformer.GetIndexer().GetByKey(rscKey)
	if err != nil {
		log.Debugf("Error while fetching Route: %v: %v",
			rscKey, err)
		return nil
	}
	if !exist {
		log.Debugf("Route Not Found: %v", rscKey)
		return nil
	}
	return obj.(*routeapi.Route)
}

func (ctlr *Controller) checkValidRoute(route *routeapi.Route) bool {
	// Validate the hostpath
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	if processedRoute, found := ctlr.processedHostPath.processedHostPathMap[route.Spec.Host+route.Spec.Path]; found {
		// update the status if different route
		if processedRoute != fmt.Sprintf("%v/%v", route.Namespace, route.Name) {
			message := fmt.Sprintf("Discarding route %v as route %v already exposes URI %v%v and is older ", route.Name, processedRoute, route.Spec.Host, route.Spec.Path)
			log.Errorf(message)
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "HostAlreadyClaimed", message, v1.ConditionFalse)
			return false
		}
	}
	// Validate hostname if certificate is not provided in SSL annotations
	if nil != route.Spec.TLS && route.Spec.TLS.Termination != routeapi.TLSTerminationPassthrough {
		ok := checkCertificateHost(route.Spec.Host, []byte(route.Spec.TLS.Certificate), []byte(route.Spec.TLS.Key))
		if !ok {
			//Invalid certificate and key
			message := fmt.Sprintf("Invalid certificate and key for route: %v", route.ObjectMeta.Name)
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	}
	// Validate the route service exists or not
	err, _ := ctlr.getServicePort(route)
	if err != nil {
		message := fmt.Sprintf("Discarding route %s as service associated with it doesn't exist",
			route.Name)
		log.Errorf(message)
		go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%s/%s", route.Namespace, route.Name),
			"ServiceNotFound", message, v1.ConditionFalse)
		return false
	}
	return true
}

func (ctlr *Controller) updateHostPathMap(route *routeapi.Route) {
	// This function updates the processedHostPathMap
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	for hostPath, routeKey := range ctlr.processedHostPath.processedHostPathMap {
		if routeKey == fmt.Sprintf("%v/%v", route.Namespace, route.Name) && hostPath != route.Spec.Host+route.Spec.Path {
			// Deleting the ProcessedHostPath map if route's path is changed
			delete(ctlr.processedHostPath.processedHostPathMap, hostPath)
		}
	}
	// adding the ProcessedHostPath map entry
	ctlr.processedHostPath.processedHostPathMap[route.Spec.Host+route.Spec.Path] = fmt.Sprintf("%v/%v", route.Namespace, route.Name)
}

func (ctlr *Controller) removeDeletedRouteFromHostPathMap() {
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	// This function removes the deleted route's entry from host-path map
	for hostPath, routeKey := range ctlr.processedHostPath.processedHostPathMap {
		route := ctlr.fetchRoute(routeKey)
		if route == nil {
			delete(ctlr.processedHostPath.processedHostPathMap, hostPath)
		}
	}
}
