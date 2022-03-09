package controller

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sort"
	"strings"
	"sync"
	"time"

	routeapi "github.com/openshift/api/route/v1"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"reflect"
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

	// Check the type of resource and process accordingly.
	switch rKey.kind {

	case Route:
		route := rKey.rsc.(*routeapi.Route)
		err := ctlr.processRoutes(route, route.Namespace, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isRetryableError = true
		}
	case ConfigMap:
		cm := rKey.rsc.(*v1.ConfigMap)
		err, ok := ctlr.processConfigMap(cm, rKey.rscDelete)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			break
		}

		if !ok {
			isRetryableError = true
		}

	case Service:
		svc := rKey.rsc.(*v1.Service)

		_ = ctlr.processService(svc, nil, rKey.rscDelete)

		if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
			err := ctlr.processLBServices(svc, rKey.rscDelete)
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
			err := ctlr.processRoutes(nil, rg, rKey.rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
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
				isRetryableError = true
			}
			break
		}
		for _, rg := range getAffectedRouteGroups(svc) {
			err := ctlr.processRoutes(nil, rg, rKey.rscDelete)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isRetryableError = true
			}
		}

	case Namespace:
		ns := rKey.rsc.(*v1.Namespace)
		nsName := ns.ObjectMeta.Name
		if rKey.rscDelete {
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
			ltmConfig:          ctlr.resources.getLTMConfigCopy(),
			shareNodes:         ctlr.shareNodes,
			dnsConfig:          ctlr.resources.getGTMConfigCopy(),
			defaultRouteDomain: ctlr.defaultRouteDomain,
		}
		go ctlr.TeemData.PostTeemsData()
		ctlr.enqueueReq(config)
		ctlr.Agent.PostConfig(config)
		ctlr.initState = false
		ctlr.resources.updateCaches()
	}
	return true
}

func (ctlr *Controller) processRoutes(route *routeapi.Route, routeGroup string, isDelete bool) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing RouteGroup/Namespace %v (%v)",
			routeGroup, endTime.Sub(startTime))
	}()

	routes := ctlr.getGroupedRoutes(routeGroup)
	if len(routes) == 0 && route == nil {
		log.Debugf("No routes in the RouteGroup/namespace: %v to process", routeGroup)
		return nil
	}
	if route == nil {
		route = routes[0]
	}

	extdSpec := ctlr.resources.getExtendedRouteSpec(routeGroup)
	if extdSpec == nil {
		return fmt.Errorf("extended Route Spec not available for RouteGroup/Namespace: %v", routeGroup)
	}

	portStructs := ctlr.virtualPorts(route)
	vsMap := make(ResourceMap)
	processingError := false

	for _, portStruct := range portStructs {
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

		// Delete rsCfg if no corresponding virtuals exist
		// Delete rsCfg if it is HTTP rsCfg and the CR VirtualServer does not handle HTTPTraffic
		if (len(routes) == 0) || isDelete ||
			(portStruct.protocol == "http" && !doesRouteHandleHTTP(route)) {

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

		err := ctlr.handleRouteGroupExtendedSpec(rsCfg, extdSpec)

		if err != nil {
			processingError = true
			log.Errorf("%v", err)
			break
		}

		for _, rt := range routes {
			err = ctlr.prepareResourceConfigFromRoute(rsCfg, rt, routeGroup, portStruct.port)
			if err != nil {
				processingError = true
				log.Errorf("%v", err)
				break
			}
			if isSecureRoute(rt) {
				//TLS Logic
			}
		}

		if processingError {
			log.Errorf("Unable to Process Route Group %s", routeGroup)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, route.Namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, route.Namespace)
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

func (ctlr *Controller) getGroupedRoutes(routeGroup string) []*routeapi.Route {
	// Get the route group
	allRoutes := ctlr.getAllResources(Route, routeGroup)
	var assocRoutes []*routeapi.Route
	uniqueHostPathMap := map[string]struct{}{}
	for _, route := range allRoutes {

		// TODO: add combinations for a/b - svc weight ; valid svcs or not
		if _, found := uniqueHostPathMap[route.Spec.Host+route.Spec.Path]; found {
			log.Errorf(" Discarding route %v due to duplicate host %v, path %v combination", route.Name, route.Spec.Host, route.Spec.To)
			continue
		} else {
			uniqueHostPathMap[route.Spec.Host+route.Spec.Path] = struct{}{}
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
	return nil
}

func (ctlr *Controller) prepareResourceConfigFromRoute(
	rsCfg *ResourceConfig,
	route *routeapi.Route,
	routeGroup string,
	port int32,
) error {

	rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, route.Spec.Host)

	if route.Spec.Port != nil {
		port = route.Spec.Port.TargetPort.IntVal
	}

	pool := Pool{
		Name: formatPoolName(
			route.Namespace,
			route.Spec.To.Name,
			port,
			"",
		),
		Partition:       rsCfg.Virtual.Partition,
		ServiceName:     route.Spec.To.Name,
		ServicePort:     port,
		NodeMemberLabel: "",
	}

	rsCfg.Pools = append(rsCfg.Pools, pool)

	rules := ctlr.prepareRouteLTMRules(route, routeGroup, pool.Name)
	if rules == nil {
		return fmt.Errorf("failed to create LTM Rules")
	}

	policyName := formatPolicyName(route.Spec.Host, routeGroup, rsCfg.Virtual.Name)

	rsCfg.AddRuleToPolicy(policyName, routeGroup, rules)

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

	event := HTTPRequest

	rl, err := createRule(uri, poolName, ruleName, event)
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
	ersData := cm.Data

	es := extendedSpec{}

	//log.Debugf("GCM: %v", cm.Data)

	err := yaml.UnmarshalStrict([]byte(ersData["extendedSpec"]), &es)

	if err != nil {
		return fmt.Errorf("invalid extended route spec in configmap: %v/%v", cm.Namespace, cm.Name), false
	}

	var modifiedExtendedSpecs []string

	if ctlr.isGlobalExtendedRouteSpec(cm) {
		for _, ergc := range es.ExtendedRouteGroupConfigs {
			if spec, ok := ctlr.resources.extdSpecMap[ergc.Namespace]; ok {
				if *spec.override && spec.local != nil {
					continue
				}
				if reflect.DeepEqual(*(spec.global), ergc.ExtendedRouteGroupSpec) {
					continue
				}
				if spec.global.VServerName != ergc.ExtendedRouteGroupSpec.VServerName {
					_ = ctlr.processRoutes(nil, ergc.Namespace, true)
				}
				spec.global = &ergc.ExtendedRouteGroupSpec
			} else {
				ctlr.resources.extdSpecMap[ergc.Namespace] = &extendedParsedSpec{
					override: &ergc.AllowOverride,
					local:    nil,
					global:   &ergc.ExtendedRouteGroupSpec,
				}
			}
			modifiedExtendedSpecs = append(modifiedExtendedSpecs, ergc.Namespace)
		}
	} else if len(es.ExtendedRouteGroupConfigs) > 0 {
		ergc := es.ExtendedRouteGroupConfigs[0]
		if spec, ok := ctlr.resources.extdSpecMap[ergc.Namespace]; ok {
			if !*spec.override {
				return nil, true
			}
			if reflect.DeepEqual(*(spec.local), ergc.ExtendedRouteGroupSpec) {
				return nil, true
			}
			spec.local = &ergc.ExtendedRouteGroupSpec
		} else {
			return nil, false
		}

		modifiedExtendedSpecs = append(modifiedExtendedSpecs, ergc.Namespace)
	}

	for _, mes := range modifiedExtendedSpecs {
		_ = ctlr.processRoutes(nil, mes, false)
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

func (ctlr *Controller) getAllResources(resourceType string, namespace string) []*routeapi.Route {

	var orderedResources []interface{}
	var err error
	var allRoutes []*routeapi.Route

	switch resourceType {
	case Route:
		nrInf, ok := ctlr.nrInformers[namespace]
		if !ok {
			log.Errorf("Informer not found for namespace: %v", namespace)
			return nil
		}

		if namespace == "" {
			orderedResources = nrInf.routeInformer.GetIndexer().List()
		} else {
			// Get list of Routes and process them.
			orderedResources, err = nrInf.routeInformer.GetIndexer().ByIndex("namespace", namespace)
			if err != nil {
				log.Errorf("Unable to get list of Routes for namespace '%v': %v",
					namespace, err)
				return nil
			}
		}

		for _, obj := range orderedResources {
			rt := obj.(*routeapi.Route)
			allRoutes = append(allRoutes, rt)
		}
	}
	return allRoutes

}

func doesRouteHandleHTTP(route *routeapi.Route) bool {
	if !isSecureRoute(route) {
		// If it is not TLS VirtualServer(HTTPS), then it is HTTP server
		return true
	}
	// If Allow or Redirect happens then HTTP Traffic is being handled.
	return route.Spec.TLS.InsecureEdgeTerminationPolicy == TLSAllowInsecure ||
		route.Spec.TLS.InsecureEdgeTerminationPolicy == TLSRedirectInsecure
}

func isSecureRoute(route *routeapi.Route) bool {
	return route.Spec.TLS != nil
}

func getAffectedRouteGroups(svc *v1.Service) []string {
	return []string{svc.Namespace}
}
