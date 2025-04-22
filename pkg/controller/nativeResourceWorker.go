package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	routeapi "github.com/openshift/api/route/v1"

	"reflect"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

func (ctlr *Controller) processRoutes(routeGroup string, triggerDelete bool) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing RouteGroup/Namespace %v (%v)",
			routeGroup, endTime.Sub(startTime))
	}()
	if ctlr.multiClusterMode != "" && ctlr.discoveryMode == DefaultMode {
		log.Errorf("%v default mode is currently not supported for Routes, please use active-active/active-standby/ratio mode", ctlr.getMultiClusterLog())
		return nil
	}
	var extdSpec *ExtendedRouteGroupSpec
	var partition string
	if routeGroup == defaultRouteGroupName {
		defaultrgspec := ctlr.resources.extdSpecMap[routeGroup]
		extdSpec = defaultrgspec.defaultrg
		partition = defaultrgspec.partition
	} else {
		extdSpec, partition = ctlr.resources.getExtendedRouteSpec(routeGroup)
		if extdSpec == nil {
			// Log error and return, if user adds the extended route spec then routes will be processed again
			log.Errorf("extended Route Spec not available for RouteGroup/Namespace: %v", routeGroup)
			return nil
		}
	}
	annotationsUsed := &AnnotationsUsed{}
	var policySSLProfiles rgPlcSSLProfiles
	plc, policyErr := ctlr.getRouteGroupPolicy(extdSpec)

	if plc != nil && len(plc.Spec.Profiles.SSLProfiles.ClientProfiles) > 0 {
		policySSLProfiles.clientSSLs = plc.Spec.Profiles.SSLProfiles.ClientProfiles
		policySSLProfiles.serverSSLs = plc.Spec.Profiles.SSLProfiles.ServerProfiles
		plcName := strings.Split(extdSpec.Policy, "/")
		if len(plcName) == 2 {
			policySSLProfiles.plcNamespace = plcName[0]
			policySSLProfiles.plcName = plcName[1]
		}
	}

	routes := ctlr.getGroupedRoutes(routeGroup, annotationsUsed, policySSLProfiles)

	if triggerDelete || len(routes) == 0 {
		// Delete all possible virtuals for this route group
		for _, portStruct := range getBasicVirtualPorts() {
			rsName := frameRouteVSName(extdSpec.VServerName, extdSpec.VServerAddr, portStruct)
			vs := ctlr.getVirtualServer(partition, rsName)
			if vs != nil {
				log.Debugf("Removing virtual %v belongs to RouteGroup: %v",
					rsName, routeGroup)
				ctlr.deleteVirtualServer(partition, rsName)
				ctlr.ProcessRouteEDNS(vs.MetaData.hosts)
			}
		}
		return nil
	}

	// Delayed handling policyErr to ensure VS deletion is not missed in case resources related to VS have been deleted
	if policyErr != nil {
		return policyErr
	}

	portStructs := getVirtualPortsForRoutes(routes)
	vsMap := make(ResourceMap)
	processingError := false

	for _, portStruct := range portStructs {
		rsName := frameRouteVSName(extdSpec.VServerName, extdSpec.VServerAddr, portStruct)

		// Delete rsCfg if it is HTTP port and the Route does not handle HTTPTraffic
		if portStruct.protocol == "http" && !doRoutesHandleHTTP(routes) {
			ctlr.deleteVirtualServer(partition, rsName)
			continue
		}

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = partition
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
		if rsCfg.MetaData.Protocol == "http" {
			// for unsecured vs, disable mrf router always
			enabled := false
			rsCfg.Virtual.HttpMrfRoutingEnabled = &enabled
		}

		// deletion ; update /health /app/path1

		err := ctlr.handleRouteGroupExtendedSpec(rsCfg, plc, annotationsUsed, extdSpec)

		if err != nil {
			processingError = true
			log.Errorf("%v", err)
			break
		}

		// iterate over routes
		passthroughVSGrp := true
		for _, rt := range routes {
			if isSecureRoute(rt) {
				if rt.Spec.TLS.Termination != TLSPassthrough {
					passthroughVSGrp = false
					break
				}
			}
		}

		for _, rt := range routes {
			rsCfg.MetaData.baseResources[rt.Namespace+"/"+rt.Name] = Route
			_, port := ctlr.getServicePort(rt)
			servicePort := intstr.IntOrString{IntVal: port}
			err = ctlr.prepareResourceConfigFromRoute(rsCfg, rt, servicePort, portStruct)
			if err != nil {
				processingError = true
				log.Errorf("%v", err)
				break
			}
			// handle pool settings from policy if defined
			policy, err := ctlr.getPolicyForRoute(rsCfg, plc, extdSpec)
			if err != nil {
				processingError = true
				log.Errorf("%v", err)
				break
			}
			if policy != nil {
				if policy.Spec.PoolSettings != (cisapiv1.PoolSettingsSpec{}) {
					err := ctlr.handlePoolResourceConfigForPolicy(rsCfg, policy)
					if err != nil {
						processingError = true
						log.Errorf("%v", err)
						break
					}
				}
				if !reflect.DeepEqual(plc.Spec.DefaultPool, cisapiv1.DefaultPool{}) {
					rsRef := resourceRef{
						name:      rt.Name,
						namespace: rt.Namespace,
						kind:      Route,
					}
					var httpTraffic string
					if isSecureRoute(rt) {
						if rt.Spec.TLS.InsecureEdgeTerminationPolicy != "" {
							httpTraffic = strings.ToLower(string(rt.Spec.TLS.InsecureEdgeTerminationPolicy))
						}
					}
					ctlr.handleDefaultPoolForPolicy(rsCfg, plc, rsRef, "", httpTraffic, isSecureRoute(rt))
				}
			}
			if isSecureRoute(rt) {
				//TLS Logic
				processed := ctlr.handleRouteTLS(rsCfg, rt, extdSpec.VServerAddr, servicePort, policySSLProfiles, passthroughVSGrp)
				if !processed {
					// Processing failed
					// Stop processing further routes
					processingError = true
					break
				}

				log.Debugf("Updated Route %s with TLS", rt.ObjectMeta.Name)
			} else {
				// handle ab deployment for insecure routes
				if isRouteABDeployment(rt) || ctlr.discoveryMode == Ratio {
					ctlr.handleInsecureABRoute(rsCfg, rt, servicePort)
				}
			}

			ctlr.resources.processedNativeResources[resourceRef{
				kind:      Route,
				namespace: rt.Namespace,
				name:      rt.Name,
			}] = struct{}{}
		}

		// Add default WAF disable rule if WAF annotation is used
		if annotationsUsed.WAF && rsCfg.Virtual.WAF == "" {
			ctlr.addDefaultWAFDisableRule(rsCfg, "openshift_route_waf_disable")
		}

		if processingError {
			log.Errorf("Unable to Process Route Group %s", routeGroup)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg
	}

	if !processingError {
		var hosts []string
		for name, rscfg := range vsMap {
			rsMap := ctlr.resources.getPartitionResourceMap(partition)
			rsMap[name] = rscfg

			if len(rscfg.MetaData.hosts) > 0 {
				hosts = rscfg.MetaData.hosts
			}
		}
		ctlr.ProcessRouteEDNS(hosts)
	}

	return nil
}

// addDefaultWAFDisableRule adds WAF disable action for rules without WAF and a default WAF disable rule
func (ctlr *Controller) addDefaultWAFDisableRule(rsCfg *ResourceConfig, wafDisableRuleName string) {
	wafDisableAction := &action{
		WAF:     true,
		Enabled: false,
	}
	wafDropAction := &action{
		Drop:    true,
		Request: true,
	}
	wafDisableRule := &Rule{
		Name:    wafDisableRuleName,
		Actions: []*action{wafDropAction, wafDisableAction},
	}
	for index, pol := range rsCfg.Policies {
		for _, rule := range pol.Rules {
			isRuleWithWAF := false
			for _, action := range rule.Actions {
				if action.WAF {
					isRuleWithWAF = true
					break
				}
			}
			// Add a default WAF disable action to all non-WAF rules
			if !isRuleWithWAF {
				rule.Actions = append(rule.Actions, wafDisableAction)
			}
		}
		// BigIP requires a default WAF disable rule doesn't require WAF
		rsCfg.Policies[index].Rules = append(rsCfg.Policies[index].Rules, wafDisableRule)
	}
}

func (ctlr *Controller) getGroupedRoutes(routeGroup string,
	annotationsUsed *AnnotationsUsed, policySSLProfiles rgPlcSSLProfiles) []*routeapi.Route {
	var assocRoutes []*routeapi.Route
	// Get the route group
	for namespace, _ := range ctlr.resources.extdSpecMap[routeGroup].namespaces {
		orderedRoutes := ctlr.getOrderedRoutes(namespace)
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.NativeRoutes[namespace] = len(orderedRoutes)
		ctlr.TeemData.Unlock()
		for _, route := range orderedRoutes {
			// TODO: add combinations for a/b - svc weight ; valid svcs or not
			if ctlr.checkValidRoute(route, policySSLProfiles) {
				var key string
				if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
					key = route.Spec.Host + "/"
				} else {
					key = route.Spec.Host + route.Spec.Path
				}
				ctlr.updateHostPathMap(route.ObjectMeta.CreationTimestamp, key)
				assocRoutes = append(assocRoutes, route)
				if _, ok := route.Annotations[resource.F5VsWAFPolicy]; ok {
					annotationsUsed.WAF = true
				}
				if _, ok := route.Annotations[resource.F5VsAllowSourceRangeAnnotation]; ok {
					annotationsUsed.AllowSourceRange = true
				}
			}
		}
	}
	return assocRoutes
}

func (ctlr *Controller) handleInsecureABRoute(rsCfg *ResourceConfig, route *routeapi.Route, servicePort intstr.IntOrString) {
	// add the AB deployment data group
	ctlr.updateDataGroupForABRoute(route,
		getRSCfgResName(rsCfg.Virtual.Name, AbDeploymentDgName),
		rsCfg.Virtual.Partition,
		route.Namespace,
		rsCfg.IntDgMap,
		servicePort,
	)
	// add the path based AB irule
	rsCfg.addIRule(
		getRSCfgResName(rsCfg.Virtual.Name, ABPathIRuleName), rsCfg.Virtual.Partition,
		ctlr.getPathBasedABDeployIRule(rsCfg.Virtual.Name, rsCfg.Virtual.Partition, rsCfg.Virtual.MultiPoolPersistence))
	abPathIRule := JoinBigipPath(rsCfg.Virtual.Partition,
		getRSCfgResName(rsCfg.Virtual.Name, ABPathIRuleName))
	rsCfg.Virtual.AddIRule(abPathIRule)
}

func (ctlr *Controller) handleRouteGroupExtendedSpec(rsCfg *ResourceConfig, plc *cisapiv1.Policy,
	au *AnnotationsUsed, extdSpec *ExtendedRouteGroupSpec) error {
	policy, err := ctlr.getPolicyForRoute(rsCfg, plc, extdSpec)
	if err != nil {
		return err
	}
	if policy != nil {
		err := ctlr.handleVSResourceConfigForPolicy(rsCfg, policy)
		if err != nil {
			return err
		}

		// If allowOverride is true and routes use WAF annotation then WAF specified in policy CR is deprioritized
		if allowOverride, err := strconv.ParseBool(extdSpec.AllowOverride); err == nil && allowOverride && au.WAF {
			rsCfg.Virtual.WAF = ""
		}

		// If allowOverride is true and routes use allow-source-range annotation then allow-source-range specified
		// in policy CR is deprioritized
		if allowOverride, err := strconv.ParseBool(extdSpec.AllowOverride); err == nil && allowOverride &&
			au.AllowSourceRange {
			rsCfg.Virtual.AllowSourceRange = nil
		}
	}
	return nil
}

func (ctlr *Controller) getRouteGroupPolicy(extdSpec *ExtendedRouteGroupSpec) (*cisapiv1.Policy, error) {
	policy := extdSpec.Policy
	if policy != "" {
		splits := strings.Split(policy, "/")
		if len(splits) != 2 {
			return nil, fmt.Errorf("Policy %v not in the format <namespace>/<policy-name>", policy)
		}
		return ctlr.getPolicy(splits[0], splits[1])
	}
	return nil, nil
}

func (ctlr *Controller) getPolicyForRoute(rsCfg *ResourceConfig, plc *cisapiv1.Policy,
	extdSpec *ExtendedRouteGroupSpec) (*cisapiv1.Policy, error) {
	var policy *cisapiv1.Policy
	if extdSpec.HTTPServerPolicyCR != "" && rsCfg.MetaData.Protocol == HTTP {
		// GetPolicy
		splits := strings.Split(extdSpec.HTTPServerPolicyCR, "/")
		if len(splits) != 2 {
			return nil, fmt.Errorf("Policy %s not in the format <namespace>/<policy-name>", extdSpec.HTTPServerPolicyCR)
		}
		var err error
		policy, err = ctlr.getPolicy(splits[0], splits[1])
		if err != nil {
			return nil, err
		}
	} else {
		policy = plc
	}
	return policy, nil
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
	nrInf, ok := ctlr.getNamespacedCommonInformer(ctlr.multiClusterHandler.LocalClusterName, route.Namespace)
	if !ok {
		return fmt.Errorf("Informer not found for namespace: %v", route.Namespace), port
	}
	svcIndexer := nrInf.svcInformer.GetIndexer()
	port, err = ctlr.getResourceServicePortForRoute(svcIndexer, route)
	if nil != err {
		return fmt.Errorf("Error while processing port for route %s: %v", route.Name, err), port
	}
	log.Debugf("Port %v found for route %s", port, route.Name)
	return nil, port

}

func (ctlr *Controller) prepareResourceConfigFromRoute(
	rsCfg *ResourceConfig,
	route *routeapi.Route,
	servicePort intstr.IntOrString,
	portStruct portStruct,
) error {

	// Skip adding the host, pool and forwarding policy rule to the resource config
	// if it's an HTTP virtual server and the route doesn't allow insecure traffic
	if portStruct.protocol == HTTP && route.Spec.TLS != nil &&
		(route.Spec.TLS.InsecureEdgeTerminationPolicy == "" || route.Spec.TLS.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyNone) {
		return nil
	}

	rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, route.Spec.Host)

	// Use default SNAT if not provided by user
	if rsCfg.Virtual.SNAT == "" {
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
	}

	// If not using WAF from policy CR, use WAF from route annotations
	wafPolicy := ""
	if rsCfg.Virtual.WAF == "" {
		wafPolicy, _ = route.Annotations[resource.F5VsWAFPolicy]
	}

	// If not using AllowSourceRange from policy CR, use it from route annotations
	var allowSourceRange []string
	if rsCfg.Virtual.AllowSourceRange == nil {
		sourceRange, ok := route.Annotations[resource.F5VsAllowSourceRangeAnnotation]
		if ok {
			allowSourceRange = resource.ParseWhitelistSourceRangeAnnotations(sourceRange)
		}
	} else {
		allowSourceRange = rsCfg.Virtual.AllowSourceRange
	}
	rsRef := resourceRef{
		name:      route.Name,
		namespace: route.Namespace,
		kind:      Route,
	}

	var clusterSvcs []cisapiv1.MultiClusterServiceReference

	if ctlr.multiClusterMode != "" {
		//check for external service reference annotation
		if annotation := route.Annotations[resource.MultiClusterServicesAnnotation]; annotation != "" {
			// only process if route key is not present. else skip the processing
			// on route update we are clearing the resource service
			// if event comes from route then we will read and populate data, else we will skip processing
			// However, unmarshal the multiClusterServices annotation as it is needed for GetRouteBackends
			err := json.Unmarshal([]byte(annotation), &clusterSvcs)
			if err != nil {
				log.Warningf("[MultiCluster] unable to read extended service mapping for resource %v, error: %v",
					rsRef, err)
			}
			if _, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; !ok {
				if err == nil {
					ctlr.processResourceExternalClusterServices(rsRef, clusterSvcs)
				}
			}
		}
	}

	backendSvcs := ctlr.GetRouteBackends(route, clusterSvcs)

	for _, bs := range backendSvcs {
		svcNamespace := route.Namespace
		if bs.SvcNamespace != "" {
			svcNamespace = bs.SvcNamespace
		}
		pool := Pool{
			Name: ctlr.formatPoolName(
				svcNamespace,
				bs.Name,
				servicePort,
				"",
				"",
				bs.Cluster,
			),
			Partition:        rsCfg.Virtual.Partition,
			ServiceName:      bs.Name,
			ServiceNamespace: svcNamespace,
			ServicePort:      servicePort,
			NodeMemberLabel:  "",
			Balance:          route.ObjectMeta.Annotations[resource.F5VsBalanceAnnotation],
			Cluster:          bs.Cluster, // In all modes other than ratio, the cluster is ""
		}

		if ctlr.multiClusterMode != "" {
			if ctlr.discoveryMode != Ratio {
				var multiClusterServices []cisapiv1.MultiClusterServiceReference
				if svcs, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; ok {
					for svc, config := range svcs {
						// if service port not specified for the multiCluster service then use the route's servicePort
						if config.svcPort == (intstr.IntOrString{}) {
							config.svcPort = servicePort
						}
						multiClusterServices = append(multiClusterServices, cisapiv1.MultiClusterServiceReference{
							ClusterName: svc.clusterName,
							SvcName:     svc.serviceName,
							Namespace:   svc.namespace,
							ServicePort: config.svcPort,
						})
						// update the clusterSvcMap
						ctlr.updatePoolIdentifierForService(svc, rsRef, config.svcPort, pool.Name, pool.Partition, rsCfg.Virtual.Name, route.Spec.Path)
					}
					pool.MultiClusterServices = multiClusterServices
				}
				// update the multicluster resource serviceMap with local cluster services
				ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, bs.Name, route.Spec.Path, pool, servicePort, ctlr.multiClusterHandler.LocalClusterName)
				// update the multicluster resource serviceMap with HA pair cluster services
				if ctlr.discoveryMode == Active && ctlr.multiClusterHandler.HAPairClusterName != "" {
					ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, bs.Name, route.Spec.Path, pool, servicePort,
						ctlr.multiClusterHandler.HAPairClusterName)
				}
			} else {
				// Update the multiCluster resource service map for each pool which constitutes a service in case of ratio mode
				ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, bs.Name, route.Spec.Path, pool, servicePort, bs.Cluster)
			}
		} else {
			ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, bs.Name, route.Spec.Path, pool, servicePort, "")
		}
		// Handle Route pod concurrent connections
		podConnections, ok := route.ObjectMeta.Annotations[PodConcurrentConnectionsAnnotation]
		if ok {
			p, _ := strconv.ParseInt(podConnections, 10, 32)
			connections := int32(p)
			pool.ConnectionLimit = connections
		}
		// Update the pool Members
		ctlr.updatePoolMembersForResources(&pool)
		if len(pool.Members) > 0 {
			rsCfg.MetaData.Active = true
		}

		// Handle Route health monitors
		hmStr, exists := route.ObjectMeta.Annotations[LegacyHealthMonitorAnnotation]
		if exists {
			var monitors Monitors
			err := json.Unmarshal([]byte(hmStr), &monitors)
			if err != nil {
				log.Errorf("Unable to parse health monitor JSON array '%v': %v",
					hmStr, err)
			} else {
				for _, hm := range monitors {
					if hm.Type == "" {
						hm.Type = "http"
					}
					monitor := Monitor{
						Name:       pool.Name + "_monitor",
						Partition:  rsCfg.Virtual.Partition,
						Interval:   hm.Interval,
						Type:       hm.Type,
						Send:       hm.Send,
						Recv:       hm.Recv,
						Timeout:    hm.Timeout,
						Path:       hm.Path,
						TargetPort: hm.TargetPort,
						SSLProfile: hm.SSLProfile,
					}
					rsCfg.Monitors = append(
						rsCfg.Monitors,
						monitor,
					)
					pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitor.Name})

				}
			}
		} else if ctlr.resources.baseRouteConfig.AutoMonitor != None {
			// handle auto-monitor for route
			monitor := ctlr.handleAutoMonitor(rsCfg, route.Namespace, bs.Name, bs.Cluster, &pool)
			if monitor != (Monitor{}) {
				rsCfg.Monitors = append(
					rsCfg.Monitors,
					monitor,
				)
				pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitor.Name})
			}
		}
		rsCfg.Pools = append(rsCfg.Pools, pool)
	}
	poolName := ctlr.formatPoolName(
		route.Namespace,
		route.Spec.To.Name,
		servicePort,
		"",
		"",
		"",
	)
	// skip the policy creation for passthrough termination
	if !isPassthroughRoute(route) {
		var rules *Rules
		if isRouteABDeployment(route) || ctlr.discoveryMode == Ratio {
			rules = ctlr.prepareABRouteLTMRules(route, poolName, allowSourceRange, wafPolicy)
		} else {
			rules = ctlr.prepareRouteLTMRules(route, poolName, allowSourceRange, wafPolicy)
		}
		if rules == nil {
			return fmt.Errorf("failed to create LTM Rules")
		}
		if *rules != nil && len(*rules) > 0 {
			policyName := formatPolicyName(route.Spec.Host, route.Namespace, rsCfg.Virtual.Name)
			rsCfg.AddRuleToPolicy(policyName, rsCfg.Virtual.Partition, rules)
		}
	}
	return nil
}

func (ctlr *Controller) prepareABRouteLTMRules(
	route *routeapi.Route,
	poolName string,
	allowSourceRange []string,
	wafPolicy string,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)
	var redirects []*Rule
	uri := route.Spec.Host + route.Spec.Path
	path := route.Spec.Path
	appRoot := "/"
	ruleName := formatVirtualServerRuleName(route.Spec.Host, route.Namespace, path, poolName, false)
	rl, err := createRule(uri, poolName, ruleName, allowSourceRange, wafPolicy, true)
	if nil != err {
		log.Errorf("Error configuring rule: %v", err)
		return nil
	}

	if route.Spec.Path == appRoot || route.Spec.Path == "" {
		redirects = append(redirects, rl)
	} else if strings.HasPrefix(uri, "*.") == true {
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
	rls = append(redirects, rls...)
	return &rls
}

// prepareRouteLTMRules prepares LTM Policy rules for VirtualServer
func (ctlr *Controller) prepareRouteLTMRules(
	route *routeapi.Route,
	poolName string,
	allowSourceRange []string,
	wafPolicy string,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)
	var redirects []*Rule
	uri := route.Spec.Host + route.Spec.Path
	path := route.Spec.Path
	appRoot := "/"
	// Handle app-root annotation
	appRootPath, appRootOk := route.Annotations[resource.F5VsAppRootAnnotation]
	if appRootOk {
		ruleName := formatVirtualServerRuleName(route.Spec.Host, "", "redirectto", appRootPath, false)
		rl, err := createRedirectRule(route.Spec.Host+appRoot, appRootPath, ruleName, allowSourceRange)
		if nil != err {
			log.Errorf("Error configuring redirect rule: %v", err)
			return nil
		}
		redirects = append(redirects, rl)
		if path == appRoot || path == "" {
			uri = route.Spec.Host + appRootPath
			path = appRootPath
		}
	}

	ruleName := formatVirtualServerRuleName(route.Spec.Host, route.Namespace, path, poolName, false)
	rl, err := createRule(uri, poolName, ruleName, allowSourceRange, wafPolicy, false)
	if nil != err {
		log.Errorf("Error configuring rule: %v", err)
		return nil
	}

	// Handle url-rewrite annotation
	if rewritePath, ok := route.Annotations[resource.F5VsURLRewriteAnnotation]; ok {
		rewriteActions, err := getRewriteActions(
			path,
			rewritePath,
			len(rl.Actions),
		)
		if nil != err {
			log.Errorf("Error configuring rule: %v", err)
			return nil
		}
		rl.Actions = append(rl.Actions, rewriteActions...)
	}

	if route.Spec.Path == appRoot || route.Spec.Path == "" {
		redirects = append(redirects, rl)
	} else if strings.HasPrefix(uri, "*.") == true {
		wildcards[uri] = rl
	} else {
		rlMap[uri] = rl
	}

	if appRootOk && len(redirects) != 2 {
		log.Error("AppRoot path not found for rewriting")
		return nil
	}

	if rlMap[route.Spec.Host] == nil && len(redirects) == 2 {
		rl := &Rule{
			Name:    formatVirtualServerRuleName(route.Spec.Host, route.Namespace, "", redirects[1].Actions[0].Pool, false),
			FullURI: route.Spec.Host,
			Actions: redirects[1].Actions,
			Conditions: []*condition{
				redirects[1].Conditions[0],
			},
		}
		redirects = append(redirects, rl)
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
	rls = append(redirects, rls...)
	return &rls
}

// UpdatePoolHealthMonitors we need to call this method on update of pod/ pool members update
func (ctlr *Controller) UpdatePoolHealthMonitors(svcKey MultiClusterServiceKey) {

	//Get routes for service
	route := ctlr.GetServiceRouteWithoutHealthAnnotation(svcKey)
	if route == nil {
		return
	}

	err, port := ctlr.getServicePort(route)
	if err != nil {
		return
	}

	servicePort := intstr.IntOrString{IntVal: port}
	poolName := ctlr.formatPoolName(
		svcKey.namespace,
		svcKey.serviceName,
		servicePort,
		"",
		"",
		"",
	)
	// for each cluster -> referred svcs -> for each svc -> port info and bigip vs and dependant resource(route)
	if serviceKeys, ok := ctlr.multiClusterResources.clusterSvcMap[svcKey.clusterName]; ok {
		if svcPorts, ok2 := serviceKeys[svcKey]; ok2 {
			for _, poolIds := range svcPorts {
				for poolId := range poolIds {
					rsCfg := ctlr.getVirtualServer(poolId.partition, poolId.rsName)
					if rsCfg == nil {
						continue
					}
					freshRsCfg := &ResourceConfig{}
					freshRsCfg.copyConfig(rsCfg)
					for _, pool := range freshRsCfg.Pools {
						if pool.Name == poolId.poolName && pool.Partition == poolId.partition && pool.Name == poolName {
							if poolId.rsKey.kind == Route {
								podMonitor := ctlr.handleAutoMonitor(rsCfg, svcKey.namespace, svcKey.serviceName, svcKey.clusterName, &pool)

								// update the monitor name in the config
								for monitorInd, mon := range freshRsCfg.Monitors {
									if mon.Name == poolName+"_monitor" {
										//If readiness probe spec is not modified, return
										if reflect.DeepEqual(mon, podMonitor) {
											return
										} else {
											//If readiness probe spec is modified/removed, remove the monitor from the config
											if len(freshRsCfg.Monitors) == 1 {
												freshRsCfg.Monitors = make([]Monitor, 0)
											} else if monitorInd == len(freshRsCfg.Monitors)-1 {
												freshRsCfg.Monitors = freshRsCfg.Monitors[:monitorInd]
											} else if monitorInd == 0 {
												freshRsCfg.Monitors = freshRsCfg.Monitors[1:]
											} else {
												freshRsCfg.Monitors = append(freshRsCfg.Monitors[:monitorInd], freshRsCfg.Monitors[monitorInd+1:]...)
											}
										}
										break
									}
								}
								//Add monitor if autoMonitor is present in config
								if podMonitor != (Monitor{}) {
									freshRsCfg.Monitors = append(
										freshRsCfg.Monitors,
										podMonitor,
									)
								}
								// update the pool's monitor name
								for poolInd, pool := range freshRsCfg.Pools {
									if pool.Name == poolName {
										for monInd, monitorName := range pool.MonitorNames {
											if monitorName.Name == poolName+"_monitor" {
												//If readiness spec is modified/removed,Remove the monitor name from the pool
												if len(pool.MonitorNames) == 1 {
													freshRsCfg.Pools[poolInd].MonitorNames = make([]MonitorName, 0)
												} else if monInd == len(pool.MonitorNames)-1 {
													freshRsCfg.Pools[poolInd].MonitorNames = pool.MonitorNames[:monInd]
												} else if monInd == 0 {
													freshRsCfg.Pools[poolInd].MonitorNames = pool.MonitorNames[1:]
												} else {
													freshRsCfg.Pools[poolInd].MonitorNames = append(pool.MonitorNames[:monInd], pool.MonitorNames[monInd+1:]...)
												}
												break
											}
										}
										//Add monitor name to the pool if readinessProbe is present in pod
										if podMonitor != (Monitor{}) {
											freshRsCfg.Pools[poolInd].MonitorNames = append(freshRsCfg.Pools[poolInd].MonitorNames, MonitorName{Name: podMonitor.Name})
										}
										break
									}
								}
								_ = ctlr.resources.setResourceConfig(poolId.partition, poolId.rsName, freshRsCfg)
							}
						}
					}
				}
			}
		}
	}
}

func (ctlr *Controller) GetServiceRouteWithoutHealthAnnotation(svcKey MultiClusterServiceKey) *routeapi.Route {
	natvInf, ok := ctlr.getNamespacedNativeInformer(svcKey.namespace)
	if !ok {
		log.Errorf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), svcKey.namespace)
		return nil
	}
	routes, _ := natvInf.routeInformer.GetIndexer().ByIndex("namespace", svcKey.namespace)
	routeMatched := false
	for _, obj := range routes {
		route := obj.(*routeapi.Route)
		if route.Spec.To.Name == svcKey.serviceName {
			routeMatched = true
		} else {
			for _, altBEnd := range route.Spec.AlternateBackends {
				if altBEnd.Name == svcKey.serviceName {
					routeMatched = true
				}
			}
		}
		_, exists := route.ObjectMeta.Annotations[LegacyHealthMonitorAnnotation]
		//If LegacyHealthMonitorAnnotation annotation found, ignore route
		if exists && routeMatched {
			return nil
		} else if routeMatched {
			return route
		}
	}
	return nil
}

func (ctlr *Controller) processGlobalExtendedConfigMap() {
	splits := strings.Split(ctlr.globalExtendedCMKey, "/")
	ns, cmName := splits[0], splits[1]
	var cm *v1.ConfigMap
	var err error
	var obj interface{}
	var exist bool
	cnInf, found := ctlr.getNamespacedCommonInformer(ctlr.multiClusterHandler.LocalClusterName, ns)
	if found {
		obj, exist, err = cnInf.cmInformer.GetIndexer().GetByKey(fmt.Sprintf("%s/%s", ns, cmName))
		cm, _ = obj.(*v1.ConfigMap)
	}
	if !exist || cm == nil || err != nil {
		log.Warningf("Ensure Global Extended Configmap is created in CIS monitored namespace")
		// If informer fails to fetch configmap which may occur if cis just started which means informers may not have
		// synced properly then try to fetch using kubeClient
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		cm, err = clusterConfig.kubeClient.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmName, metav1.GetOptions{})
	}
	// Exit gracefully if Extended configmap is not found
	if err != nil || cm == nil {
		log.Errorf("%v Unable to Get Extended Route Spec Config Map: %v, %v", ctlr.getMultiClusterLog(), ctlr.globalExtendedCMKey, err)
		os.Exit(1)
	}
	if ctlr.mode == OpenShiftMode {
		err = ctlr.setNamespaceLabelMode(cm)
		if err != nil {
			log.Errorf("%v invalid configuration: %v", ctlr.getMultiClusterLog(), ctlr.globalExtendedCMKey, err)
			os.Exit(1)
		}
	}
	err, _ = ctlr.processConfigMap(cm, false)
	if err != nil {
		log.Errorf("%v Unable to Process Extended Config Map: %v, %v", ctlr.getMultiClusterLog(), ctlr.globalExtendedCMKey, err)
		os.Exit(1)
	}
}

func (ctlr *Controller) setNamespaceLabelMode(cm *v1.ConfigMap) error {
	ersData := cm.Data
	es := extendedSpec{}
	//log.Debugf("GCM: %v", cm.Data)
	err := yaml.UnmarshalStrict([]byte(ersData["extendedSpec"]), &es)
	if err != nil {
		return fmt.Errorf("%v invalid extended route spec in configmap: %v/%v error: %v", ctlr.getMultiClusterLog(), cm.Namespace, cm.Name, err)
	}
	namespace, namespaceLabel := false, false
	//Either defaultRouteGroup or ExtendedRouteGroupConfigs are allowed
	if es.BaseRouteConfig.DefaultRouteGroupConfig != (DefaultRouteGroupConfig{}) && len(es.ExtendedRouteGroupConfigs) > 0 {
		return fmt.Errorf("can not specify both defaultRouteGroup and ExtendedRouteGroupConfigs in extended configmap %v/%v", cm.Namespace, cm.Name)
	}
	for rg := range es.ExtendedRouteGroupConfigs {
		// ergc needs to be created at every iteration, as we are using address inside this container

		// if this were used as an iteration variable, on every loop we just use the same container instead of creating one
		// using the same container overrides the previous iteration contents, which is not desired
		ergc := es.ExtendedRouteGroupConfigs[rg]
		if len(ergc.Namespace) > 0 {
			namespace = true
		}
		if len(ergc.NamespaceLabel) > 0 {
			namespaceLabel = true
			ctlr.resourceContext.namespaceLabelMode = true
		}
	}
	if namespace && namespaceLabel {
		return fmt.Errorf("can not specify both namespace and namespace-label in extended configmap %v/%v", cm.Namespace, cm.Name)
	}
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	if clusterConfig.namespaceLabel == "" && namespaceLabel {
		return fmt.Errorf("--namespace-label deployment parameter is required with namespace-label in extended configmap")
	}
	// set namespaceLabel informers
	if ctlr.namespaceLabelMode {
		for rg := range es.ExtendedRouteGroupConfigs {
			// ergc needs to be created at every iteration, as we are using address inside this container

			// if this were used as an iteration variable, on every loop we just use the same container instead of creating one
			// using the same container overrides the previous iteration contents, which is not desired
			ergc := es.ExtendedRouteGroupConfigs[rg]
			// setting up the namespace nsLabel informer
			nsLabel := fmt.Sprintf("%v,%v", clusterConfig.namespaceLabel, ergc.NamespaceLabel)
			if _, ok := clusterConfig.nsInformers[nsLabel]; !ok {
				err := ctlr.createNamespaceLabeledInformerForCluster(nsLabel, ctlr.multiClusterHandler.LocalClusterName)
				if err != nil {
					log.Errorf("%v %v", ctlr.getMultiClusterLog(), err)
					clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
					if clusterConfig != nil {
						for _, nsInf := range clusterConfig.nsInformers {
							for _, v := range nsInf.nsInformer.GetIndexer().List() {
								ns := v.(*v1.Namespace)
								clusterConfig.namespaces[ns.ObjectMeta.Name] = struct{}{}
							}
						}
					}
				} else {
					log.Infof("%v Added namespace label informer: %v", ctlr.getMultiClusterLog(), nsLabel)
					clusterConfig.nsInformers[nsLabel].start()
				}
			}
		}
	}
	return nil
}

// process the routeConfigFromGlobalConfigMap
func (ctlr *Controller) processRouteConfigFromGlobalCM(es extendedSpec, isDelete bool, clusterConfigUpdate bool) (error, bool) {

	newExtdSpecMap := make(extendedSpecMap, len(ctlr.resources.extdSpecMap))
	routeGroupsToBeProcessed := make(map[string]struct{})
	// Get the base route config from the Global ConfigMap
	oldBaseRouteConfig := ctlr.resources.baseRouteConfig
	ctlr.readBaseRouteConfigFromGlobalCM(es.BaseRouteConfig)
	baseRouteConfigUpdated := !reflect.DeepEqual(oldBaseRouteConfig, ctlr.resources.baseRouteConfig)
	var partition string
	if len(es.BaseRouteConfig.DefaultRouteGroupConfig.BigIpPartition) > 0 {
		partition = es.BaseRouteConfig.DefaultRouteGroupConfig.BigIpPartition
	} else {
		partition = ctlr.Partition
	}

	if es.BaseRouteConfig.DefaultRouteGroupConfig != (DefaultRouteGroupConfig{}) {
		newExtdSpecMap[defaultRouteGroupName] = &extendedParsedSpec{
			override:   false,
			local:      nil,
			global:     nil,
			defaultrg:  &es.BaseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec,
			namespaces: ctlr.getNamespacesForRouteGroup(defaultRouteGroupName),
			partition:  partition,
		}
	}
	for rg := range es.ExtendedRouteGroupConfigs {
		// ergc needs to be created at every iteration, as we are using address inside this container

		// if this were used as an iteration variable, on every loop we just use the same container instead of creating one
		// using the same container overrides the previous iteration contents, which is not desired
		ergc := es.ExtendedRouteGroupConfigs[rg]
		var allowOverride bool
		var err error
		if ctlr.namespaceLabelMode || len(ergc.AllowOverride) == 0 {
			// specifically setting allow override as false in case of namespaceLabel Mode
			// Defaulted to false in case AllowOverride is not set.( in both namespaceLabel and namespace Mode)
			allowOverride = false
		} else if allowOverride, err = strconv.ParseBool(ergc.AllowOverride); err != nil {
			return fmt.Errorf("invalid allowOverride value in configmap: %v error: %v", ctlr.globalExtendedCMKey, err), false
		}

		var routeGroup string
		if len(ergc.Namespace) > 0 {
			routeGroup = ergc.Namespace
		}
		if len(ergc.NamespaceLabel) > 0 {
			routeGroup = ergc.NamespaceLabel
		}
		var partition string
		if len(ergc.BigIpPartition) > 0 {
			if ergc.BigIpPartition != CommonPartition {
				partition = ergc.BigIpPartition
			} else {
				return fmt.Errorf("partition Common is not allowed in RouteGroup, "+
					"skipping RouteGroup: %s processing", routeGroup), false
			}
		} else {
			partition = ctlr.Partition
		}
		newExtdSpecMap[routeGroup] = &extendedParsedSpec{
			override:   allowOverride,
			local:      nil,
			global:     &ergc.ExtendedRouteGroupSpec,
			namespaces: ctlr.getNamespacesForRouteGroup(routeGroup),
			partition:  partition,
		}
		if len(newExtdSpecMap[routeGroup].namespaces) > 0 {
			ctlr.TeemData.Lock()
			ctlr.TeemData.ResourceType.RouteGroups[routeGroup] = 1
			ctlr.TeemData.Unlock()
		}
	}

	// Global configmap once gets processed even before processing other native resources
	if ctlr.initState {
		ctlr.resources.extdSpecMap = newExtdSpecMap
		for rg := range newExtdSpecMap {
			if !ctlr.namespaceLabelMode {
				// check for alternative local configmaps (pick latest)
				// process if one is available
				localCM := ctlr.getLatestLocalConfigMap(rg)
				if localCM != nil {
					err, _ := ctlr.processConfigMap(localCM, false)
					if err != nil {
						log.Errorf("%v Could not process local configmap for routeGroup : %v error: %v", ctlr.getMultiClusterLog(), rg, err)
					}
				}

			}
		}
		return nil, true
	}
	deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs := getOperationalExtendedConfigMapSpecs(
		ctlr.resources.extdSpecMap, newExtdSpecMap, isDelete,
	)
	for _, routeGroupKey := range deletedSpecs {
		routeGroupsToBeProcessed[routeGroupKey] = struct{}{}
		_ = ctlr.processRoutes(routeGroupKey, true)
		if ctlr.resources.extdSpecMap[routeGroupKey].local == nil {
			delete(ctlr.resources.extdSpecMap, routeGroupKey)
			if ctlr.namespaceLabelMode {
				clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
				// deleting and stopping the namespaceLabel informers if a routeGroupKey is modified or deleted
				nsLabel := fmt.Sprintf("%v,%v", clusterConfig.namespaceLabel, routeGroupKey)
				if nsInf, ok := clusterConfig.nsInformers[nsLabel]; ok {
					log.Debugf("%v Removed namespace label informer: %v", ctlr.getMultiClusterLog(), nsLabel)
					nsInf.stop()
					delete(clusterConfig.nsInformers, nsLabel)
				}
			}
		} else {
			ctlr.resources.extdSpecMap[routeGroupKey].global = nil
			ctlr.resources.extdSpecMap[routeGroupKey].override = false
			ctlr.resources.extdSpecMap[routeGroupKey].partition = ""
			ctlr.resources.extdSpecMap[routeGroupKey].namespaces = make(map[string]string)

		}

	}

	for _, routeGroupKey := range modifiedSpecs {
		routeGroupsToBeProcessed[routeGroupKey] = struct{}{}
		_ = ctlr.processRoutes(routeGroupKey, true)
		// deleting the bigip partition when partition is changes
		if ctlr.resources.extdSpecMap[routeGroupKey].partition != newExtdSpecMap[routeGroupKey].partition {
			if _, ok := ctlr.resources.ltmConfig[ctlr.resources.extdSpecMap[routeGroupKey].partition]; ok {
				ctlr.resources.updatePartitionPriority(ctlr.resources.extdSpecMap[routeGroupKey].partition, 1)
			}
		}
		ctlr.resources.extdSpecMap[routeGroupKey].override = newExtdSpecMap[routeGroupKey].override
		ctlr.resources.extdSpecMap[routeGroupKey].global = newExtdSpecMap[routeGroupKey].global
		ctlr.resources.extdSpecMap[routeGroupKey].partition = newExtdSpecMap[routeGroupKey].partition
		ctlr.resources.extdSpecMap[routeGroupKey].defaultrg = newExtdSpecMap[routeGroupKey].defaultrg
		ctlr.resources.extdSpecMap[routeGroupKey].namespaces = newExtdSpecMap[routeGroupKey].namespaces
		err := ctlr.processRoutes(routeGroupKey, false)
		if err != nil {
			log.Errorf("Failed to process RouteGroup: %v with modified extended spec", routeGroupKey)
		}
	}

	for _, routeGroupKey := range updatedSpecs {
		routeGroupsToBeProcessed[routeGroupKey] = struct{}{}
		ctlr.resources.extdSpecMap[routeGroupKey].override = newExtdSpecMap[routeGroupKey].override
		ctlr.resources.extdSpecMap[routeGroupKey].global = newExtdSpecMap[routeGroupKey].global
		ctlr.resources.extdSpecMap[routeGroupKey].partition = newExtdSpecMap[routeGroupKey].partition
		ctlr.resources.extdSpecMap[routeGroupKey].namespaces = newExtdSpecMap[routeGroupKey].namespaces
		ctlr.resources.extdSpecMap[routeGroupKey].defaultrg = newExtdSpecMap[routeGroupKey].defaultrg
		err := ctlr.processRoutes(routeGroupKey, false)
		if err != nil {
			log.Errorf("Failed to process RouteGroup: %v with updated extended spec", routeGroupKey)
		}
	}

	for _, routeGroupKey := range createdSpecs {
		routeGroupsToBeProcessed[routeGroupKey] = struct{}{}
		ctlr.resources.extdSpecMap[routeGroupKey] = &extendedParsedSpec{}
		ctlr.resources.extdSpecMap[routeGroupKey].override = newExtdSpecMap[routeGroupKey].override
		ctlr.resources.extdSpecMap[routeGroupKey].global = newExtdSpecMap[routeGroupKey].global
		ctlr.resources.extdSpecMap[routeGroupKey].partition = newExtdSpecMap[routeGroupKey].partition
		ctlr.resources.extdSpecMap[routeGroupKey].namespaces = newExtdSpecMap[routeGroupKey].namespaces
		ctlr.resources.extdSpecMap[routeGroupKey].defaultrg = newExtdSpecMap[routeGroupKey].defaultrg
		err := ctlr.processRoutes(routeGroupKey, false)
		if err != nil {
			log.Errorf("%v Failed to process RouteGroup: %v on addition of extended spec", ctlr.getMultiClusterLog(), routeGroupKey)
		}
	}
	// Reprocess all route groups except the ones which are already reprocessed
	if (clusterConfigUpdate || baseRouteConfigUpdated) && !isDelete {
		log.Debugf("%s Re-processing all route groups as baseRouteConfig/cluster ratio/cluster AdminState is updated", ctlr.getMultiClusterLog())
		for routeGroupKey := range ctlr.resources.extdSpecMap {
			if _, ok := routeGroupsToBeProcessed[routeGroupKey]; ok {
				continue
			}
			err := ctlr.processRoutes(routeGroupKey, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v on addition of extended spec", routeGroupKey)
			}

		}
	}
	return nil, true
}

func (ctlr *Controller) processRouteConfigFromLocalCM(es extendedSpec, isDelete bool, namespace string) (error, bool) {
	//local configmap processing.
	ergc := es.ExtendedRouteGroupConfigs[0]
	if ergc.Namespace != namespace {
		return fmt.Errorf("Invalid Extended Route Spec Block in configmap: Mismatching namespace found at index 0 in %v", ctlr.globalExtendedCMKey), true
	}
	routeGroup, ok := ctlr.resources.routeGroupNamespaceMap[ergc.Namespace]
	if !ok {
		return fmt.Errorf("RouteGroup not found"), true
	}
	if spec, ok := ctlr.resources.extdSpecMap[ergc.Namespace]; ok {
		if isDelete {
			if !spec.override {
				spec.local = nil
				return nil, true
			}

			// check for alternative local configmaps (pick latest)
			// process if one is available
			localCM := ctlr.getLatestLocalConfigMap(ergc.Namespace)
			if localCM != nil {
				err, _ := ctlr.processConfigMap(localCM, false)
				if err == nil {
					return nil, true
				}
			}

			_ = ctlr.processRoutes(routeGroup, true)
			spec.local = nil
			// process routes again, this time routes get processed along with global config
			err := ctlr.processRoutes(routeGroup, false)
			if err != nil {
				log.Errorf("%v Failed to process RouteGroup: %v on with global extended spec after deletion of local extended spec", ctlr.getMultiClusterLog(), ergc.Namespace)
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
				if ctlr.initState {
					spec.local = &ergc.ExtendedRouteGroupSpec
					return nil, true
				}
				if spec.global.VServerName != ergc.ExtendedRouteGroupSpec.VServerName {
					// Delete existing virtual that was framed with globla config
					// later build new virtual with local config
					_ = ctlr.processRoutes(routeGroup, true)
				}
				spec.local = &ergc.ExtendedRouteGroupSpec
				err := ctlr.processRoutes(routeGroup, false)
				if err != nil {
					log.Errorf("%v Failed to process RouteGroup: %v on addition of extended spec", ctlr.getMultiClusterLog(), ergc.Namespace)
				}
			}
			return nil, true
		}

		// update event
		if !reflect.DeepEqual(*(spec.local), ergc.ExtendedRouteGroupSpec) {
			// if update event, update to VServerName should trigger delete and recreation of object
			if spec.local.VServerName != ergc.ExtendedRouteGroupSpec.VServerName {
				_ = ctlr.processRoutes(routeGroup, true)
			}
			spec.local = &ergc.ExtendedRouteGroupSpec
			err := ctlr.processRoutes(routeGroup, false)
			if err != nil {
				log.Errorf("%v Failed to process RouteGroup: %v on addition of extended spec", ctlr.getMultiClusterLog(), ergc.Namespace)
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
	return nil, true
}

func (ctlr *Controller) readBaseRouteConfigFromGlobalCM(baseRouteConfig BaseRouteConfig) {

	//declare default configuration for TLS Ciphers
	ctlr.resources.baseRouteConfig.TLSCipher = TLSCipher{
		"1.2",
		"DEFAULT",
		"/Common/f5-default",
		[]string{},
	}
	ctlr.resources.baseRouteConfig.DefaultTLS = DefaultSSLProfile{}
	ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig = DefaultRouteGroupConfig{}
	if !reflect.DeepEqual(baseRouteConfig, BaseRouteConfig{}) {
		if baseRouteConfig.TLSCipher.TLSVersion != "" {
			ctlr.resources.baseRouteConfig.TLSCipher.TLSVersion = baseRouteConfig.TLSCipher.TLSVersion
		}

		if baseRouteConfig.TLSCipher.Ciphers != "" {
			ctlr.resources.baseRouteConfig.TLSCipher.Ciphers = baseRouteConfig.TLSCipher.Ciphers
		}
		if baseRouteConfig.TLSCipher.CipherGroup != "" {
			ctlr.resources.baseRouteConfig.TLSCipher.CipherGroup = baseRouteConfig.TLSCipher.CipherGroup
		}
		ctlr.resources.baseRouteConfig.TLSCipher.DisableTLSVersions = baseRouteConfig.TLSCipher.DisableTLSVersions
	}
	if baseRouteConfig.DefaultTLS != (DefaultSSLProfile{}) {
		ctlr.resources.baseRouteConfig.DefaultTLS.ClientSSL = baseRouteConfig.DefaultTLS.ClientSSL
		ctlr.resources.baseRouteConfig.DefaultTLS.ServerSSL = baseRouteConfig.DefaultTLS.ServerSSL
		ctlr.resources.baseRouteConfig.DefaultTLS.Reference = baseRouteConfig.DefaultTLS.Reference
	}
	if baseRouteConfig.DefaultRouteGroupConfig != (DefaultRouteGroupConfig{}) {
		ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec.VServerName = baseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec.VServerName
		ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec.VServerAddr = baseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec.VServerAddr
		ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec.Policy = baseRouteConfig.DefaultRouteGroupConfig.DefaultRouteGroupSpec.Policy
		ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig.BigIpPartition = baseRouteConfig.DefaultRouteGroupConfig.BigIpPartition
	}

	// check for valid autoMonitor value
	if baseRouteConfig.AutoMonitor == None || baseRouteConfig.AutoMonitor == ReadinessProbe ||
		baseRouteConfig.AutoMonitor == ServiceEndpoint {
		ctlr.resources.baseRouteConfig.AutoMonitor = baseRouteConfig.AutoMonitor
	} else {
		log.Warningf("AutoMonitor value %v is not defined or not supported. Defaulting to %v", baseRouteConfig.AutoMonitor, None)
		ctlr.resources.baseRouteConfig.AutoMonitor = None
	}

	// check for autoMonitorTimeout value
	if baseRouteConfig.AutoMonitorTimeout != 0 {
		ctlr.resources.baseRouteConfig.AutoMonitorTimeout = baseRouteConfig.AutoMonitorTimeout
	} else {
		ctlr.resources.baseRouteConfig.AutoMonitorTimeout = 0
	}

}

func (ctlr *Controller) isGlobalExtendedCM(cm *v1.ConfigMap) bool {
	cmKey := cm.Namespace + "/" + cm.Name

	if cmKey == ctlr.globalExtendedCMKey {
		return true
	}

	return false
}

func (ctlr *Controller) getLatestLocalConfigMap(ns string) *v1.ConfigMap {
	inf, ok := ctlr.getNamespacedCommonInformer(ctlr.multiClusterHandler.LocalClusterName, ns)

	if !ok {
		return nil
	}

	objList, err := inf.cmInformer.GetIndexer().ByIndex("namespace", ns)

	if err != nil {
		log.Errorf("Unable to fetch local config map from namespace: %v ", ns)
		return nil
	}

	if len(objList) == 0 {
		return nil
	}

	cm := objList[0].(*v1.ConfigMap)
	for _, obj := range objList {
		c := obj.(*v1.ConfigMap)
		if cm.CreationTimestamp.Before(&c.CreationTimestamp) {
			cm = c
		}
	}
	return cm
}

// deletedSpecs: the spec blocks are deleted from the configmap
// modifiedSpecs: specific params of spec entry are changed because of which virutals need to be deleted and framed again
// updatedSpecs: parameters are updated, so just reprocess the resources
// createSpecs: new spec blocks are added to the configmap
func getOperationalExtendedConfigMapSpecs(
	cachedMap, newMap extendedSpecMap, isDelete bool,
) (
	deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs []string,
) {
	if isDelete {
		for routeGroupKey := range newMap {
			deletedSpecs = append(deletedSpecs, routeGroupKey)
		}
		return
	}
	updateMap := make(map[string]bool)
	for routeGroupKey, spec := range cachedMap {
		newSpec, ok := newMap[routeGroupKey]
		if !ok {
			deletedSpecs = append(deletedSpecs, routeGroupKey)
			continue
		}
		if !reflect.DeepEqual(spec, newMap[routeGroupKey]) {
			if routeGroupKey == defaultRouteGroupName {
				//handle update to vserverName or partition in defaultRouteGroup
				if spec.defaultrg.VServerName != newSpec.defaultrg.VServerName || spec.partition != newSpec.partition {
					// Update to VServerName or override should trigger delete and recreation of object
					modifiedSpecs = append(modifiedSpecs, routeGroupKey)
				} else {
					updatedSpecs = append(updatedSpecs, routeGroupKey)
					updateMap[routeGroupKey] = true
				}
			} else {
				if spec.global.VServerName != newSpec.global.VServerName || spec.override != newSpec.override || spec.partition != newSpec.partition {
					// Update to VServerName or override should trigger delete and recreation of object
					modifiedSpecs = append(modifiedSpecs, routeGroupKey)
				} else {
					updatedSpecs = append(updatedSpecs, routeGroupKey)
					updateMap[routeGroupKey] = true
				}
			}
		}
	}
	for routeGroupKey, spec := range cachedMap {
		//check defaultTLS set
		var checkTLS bool
		if routeGroupKey == defaultRouteGroupName {
			checkTLS = spec.defaultrg.Meta.DependsOnTLS
		} else {
			checkTLS = spec.global.Meta.DependsOnTLS
		}
		if checkTLS {
			if _, ok := newMap[routeGroupKey]; !ok {
				continue
			}
			if _, ok := updateMap[routeGroupKey]; !ok {
				updatedSpecs = append(updatedSpecs, routeGroupKey)
			}
		}
	}

	for routeGroupKey := range newMap {
		_, ok := cachedMap[routeGroupKey]
		if !ok {
			createdSpecs = append(createdSpecs, routeGroupKey)
		}
	}
	return
}
func (ctlr *Controller) getMultiClusterLog() string {
	if ctlr.multiClusterMode != "" {
		return "[MultiCluster]"
	}
	return ""
}
func (ctlr *Controller) getOrderedRoutes(namespace string) []*routeapi.Route {
	var resources []interface{}
	var err error
	var allRoutes []*routeapi.Route

	nrInf, ok := ctlr.getNamespacedNativeInformer(namespace)
	if !ok {
		log.Errorf("%v Informer not found for namespace: %v", ctlr.getMultiClusterLog(), namespace)
		return nil
	}

	if namespace == "" {
		resources = nrInf.routeInformer.GetIndexer().List()
	} else {
		// Get list of Routes and process them.
		resources, err = nrInf.routeInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("%v Unable to get list of Routes for namespace '%v': %v",
				ctlr.getMultiClusterLog(), namespace, err)
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

func frameRouteVSName(vServerName string,
	vServerAddr string,
	portStruct portStruct,
) string {
	var rsName string
	if vServerName != "" {
		rsName = formatCustomVirtualServerName(
			vServerName,
			portStruct.port,
		)
	} else {
		vServerAddr = AS3NameFormatter(vServerAddr)
		rsName = formatCustomVirtualServerName(
			"routes_"+vServerAddr,
			portStruct.port,
		)
	}
	return rsName
}

func (ctlr *Controller) GetHostFromHostPath(hostPath string) string {
	if strings.Contains(hostPath, "/") {
		return strings.Split(hostPath, "/")[0]
	}
	return hostPath
}

func (ctlr *Controller) checkValidRoute(route *routeapi.Route, plcSSLProfiles rgPlcSSLProfiles) bool {
	// Validate the hostpath
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	var key string
	routeKey := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
		key = route.Spec.Host + "/"
	} else {
		key = route.Spec.Host + route.Spec.Path
	}
	if processedRouteTimestamp, found := ctlr.processedHostPath.processedHostPathMap[key]; found {
		// update the status if different route
		if processedRouteTimestamp.Before(&route.ObjectMeta.CreationTimestamp) {
			message := fmt.Sprintf("Discarding route %v as other route already exposes URI %v%v and is older ", route.Name, route.Spec.Host, route.Spec.Path)
			log.Errorf(message)
			go ctlr.updateRouteAdmitStatus(routeKey, "HostAlreadyClaimed", message, v1.ConditionFalse)
			return false
		}
	}
	sslProfileOption := ctlr.getSSLProfileOption(route, plcSSLProfiles)
	switch sslProfileOption {
	case "":
		break
	case PolicySSLOption:
		if len(plcSSLProfiles.serverSSLs) == 0 && route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
			message := fmt.Sprintf("Missing server SSL profile in the policy %v/%v", plcSSLProfiles.plcNamespace, plcSSLProfiles.plcName)
			ctlr.updateRouteAdmitStatus(routeKey, "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	case AnnotationSSLOption:
		if _, ok := route.ObjectMeta.Annotations[resource.F5ServerSslProfileAnnotation]; !ok && route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
			message := fmt.Sprintf("Missing server SSL profile in the annotation")
			ctlr.updateRouteAdmitStatus(routeKey, "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	case RouteCertificateSSLOption:
		// Validate vsHostname if certificate is not provided in SSL annotations
		ok := checkCertificateHost(route.Spec.Host, Route, routeKey, []byte(route.Spec.TLS.Certificate), []byte(route.Spec.TLS.Key))
		if !ok {
			//Invalid certificate and key
			message := fmt.Sprintf("Invalid certificate or key for %v in route: %v", route.Spec.Host, route.ObjectMeta.Name)
			ctlr.updateRouteAdmitStatus(routeKey, "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	case DefaultSSLOption:
		if ctlr.resources.baseRouteConfig.DefaultTLS.ClientSSL == "" {
			message := fmt.Sprintf("Missing client SSL profile %s reference in the ConfigMap - BaseRouteSpec", ctlr.resources.baseRouteConfig.DefaultTLS.Reference)
			ctlr.updateRouteAdmitStatus(routeKey, "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
		if ctlr.resources.baseRouteConfig.DefaultTLS.ServerSSL == "" && route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
			message := fmt.Sprintf("Missing server SSL profile %s reference in the ConfigMap - BaseRouteSpec", ctlr.resources.baseRouteConfig.DefaultTLS.Reference)
			ctlr.updateRouteAdmitStatus(routeKey, "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	default:
		message := fmt.Sprintf("Missing certificate/key/SSL profile annotation/defaultSSL for route: %v", route.ObjectMeta.Name)
		ctlr.updateRouteAdmitStatus(routeKey, "ExtendedValidationFailed", message, v1.ConditionFalse)
		return false
	}

	// Validate appRoot Rewrite annotation
	if appRootPath, ok := route.Annotations[resource.F5VsAppRootAnnotation]; ok {
		if appRootPath == "" {
			message := fmt.Sprintf("Discarding route %v as annotation %v is empty", route.Name, resource.F5VsAppRootAnnotation)
			log.Errorf(message)
			ctlr.updateRouteAdmitStatus(routeKey, "InvalidAnnotation", message, v1.ConditionFalse)
			return false
		}
		if route.Spec.Path != "" && route.Spec.Path != "/" {
			message := fmt.Sprintf("Invalid annotation: %v=%v can not target path for app-root annotation for route %v, skipping", resource.F5VsAppRootAnnotation, appRootPath, route.Name)
			log.Errorf(message)
			ctlr.updateRouteAdmitStatus(routeKey, "InvalidAnnotation", message, v1.ConditionFalse)
			return false
		}
	}

	// Validate WAF annotation
	if wafPolicy, ok := route.Annotations[resource.F5VsWAFPolicy]; ok {
		if wafPolicy == "" {
			message := fmt.Sprintf("Discarding route %v as annotation %v is empty", route.Name, resource.F5VsWAFPolicy)
			log.Errorf(message)
			ctlr.updateRouteAdmitStatus(routeKey, "InvalidAnnotation", message, v1.ConditionFalse)
			return false
		}
	}

	// Validate AllowSourceRange annotation
	if sourceRange, ok := route.Annotations[resource.F5VsAllowSourceRangeAnnotation]; ok {
		invalidAllowSourceRange := false
		if sourceRange == "" {
			invalidAllowSourceRange = true
		} else {
			allowSourceRange := resource.ParseWhitelistSourceRangeAnnotations(sourceRange)
			if allowSourceRange == nil && len(allowSourceRange) == 0 {
				invalidAllowSourceRange = true
			}
		}
		if invalidAllowSourceRange {
			message := fmt.Sprintf("Discarding route %v as annotation %v is empty", route.Name,
				resource.F5VsAllowSourceRangeAnnotation)
			log.Errorf(message)
			ctlr.updateRouteAdmitStatus(routeKey, "InvalidAnnotation", message, v1.ConditionFalse)
			return false
		}
	}
	// Validate multiCluster service annotation has valid cluster names
	if ctlr.multiClusterMode != "" {
		if annotation := route.Annotations[resource.MultiClusterServicesAnnotation]; annotation != "" {
			var clusterSvcs []cisapiv1.MultiClusterServiceReference
			err := json.Unmarshal([]byte(annotation), &clusterSvcs)
			if err == nil {
				ctlr.multiClusterResources.Lock()
				defer ctlr.multiClusterResources.Unlock()
				for _, svc := range clusterSvcs {
					err := ctlr.checkValidMultiClusterService(svc, true)
					if err != nil {
						// In case of invalid extendedServiceReference, just log the error and proceed
						log.Errorf("[MultiCluster] invalid extendedServiceReference: %v for Route: %s: %v", svc, route.Name, err)
						continue
					}
				}
			} else {
				message := fmt.Sprintf("unable to parse annotation %v for route %v/%v", resource.MultiClusterServicesAnnotation, route.Name, route.Namespace)
				log.Errorf(message)
				ctlr.updateRouteAdmitStatus(routeKey, "InvalidAnnotation", message, v1.ConditionFalse)
				return false
			}
		}
	} else {
		// Validate the route service exists or not
		err, _ := ctlr.getServicePort(route)
		if err != nil {
			message := fmt.Sprintf("Discarding route %s as service associated with it doesn't exist",
				route.Name)
			log.Errorf(message)
			ctlr.updateRouteAdmitStatus(routeKey, "ServiceNotFound", message, v1.ConditionFalse)
			return false
		}
	}

	return true
}

func (ctlr *Controller) updateHostPathMap(timestamp metav1.Time, key string) {
	// This function updates the processedHostPathMap
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	for hostPath, routeTimestamp := range ctlr.processedHostPath.processedHostPathMap {
		if routeTimestamp == timestamp && hostPath != key {
			// Deleting the ProcessedHostPath map if route's path is changed
			delete(ctlr.processedHostPath.processedHostPathMap, hostPath)
			//track removed/modified hosts for EDNS processing
			ctlr.processedHostPath.removedHosts = append(ctlr.processedHostPath.removedHosts, ctlr.GetHostFromHostPath(hostPath))
		}
	}
	// adding the ProcessedHostPath map entry
	ctlr.processedHostPath.processedHostPathMap[key] = timestamp
}

func (ctlr *Controller) deleteHostPathMapEntry(route *routeapi.Route) {
	// This function deletes the route entry from processedHostPath
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	for hostPath, routeTimestamp := range ctlr.processedHostPath.processedHostPathMap {
		var key string
		if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
			key = route.Spec.Host + "/"
		} else {
			key = route.Spec.Host + route.Spec.Path
		}
		if routeTimestamp == route.CreationTimestamp && hostPath == key {
			// Deleting the ProcessedHostPath map if route's path is changed
			delete(ctlr.processedHostPath.processedHostPathMap, hostPath)
			//track removed/modified hosts for EDNS processing
			ctlr.processedHostPath.removedHosts = append(ctlr.processedHostPath.removedHosts, ctlr.GetHostFromHostPath(key))
		}
	}
}

func (ctlr *Controller) getNamespacesForRouteGroup(namespaceGroup string) map[string]string {
	namespaces := make(map[string]string)
	//check for defaultRouteGroup
	if namespaceGroup == defaultRouteGroupName {
		watchedNs := ctlr.getWatchingNamespaces(ctlr.multiClusterHandler.LocalClusterName)
		for _, ns := range watchedNs {
			namespaces[ns] = namespaceGroup
			ctlr.resources.routeGroupNamespaceMap[ns] = namespaceGroup
		}
	} else {
		if !ctlr.namespaceLabelMode {
			namespaces[namespaceGroup] = namespaceGroup
			ctlr.resources.routeGroupNamespaceMap[namespaceGroup] = namespaceGroup
		} else {
			clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
			nsLabel := fmt.Sprintf("%v,%v", clusterConfig.namespaceLabel, namespaceGroup)
			nss, err := clusterConfig.kubeClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{LabelSelector: nsLabel})
			if err != nil {
				log.Errorf("%v Unable to Fetch Namespaces: %v", ctlr.getMultiClusterLog(), err)
				return nil
			}
			for _, ns := range nss.Items {
				namespaces[ns.Name] = namespaceGroup
				ctlr.resources.routeGroupNamespaceMap[ns.Name] = namespaceGroup
			}
		}
	}
	return namespaces
}

// fetch routeGroup for given policyCR.
func (ctlr *Controller) getRouteGroupForCustomPolicy(policy string) []string {
	var routeGroups []string
	for rg, extdSpec := range ctlr.resources.extdSpecMap {
		if extdSpec.override {
			// continue if extended spec is not set
			if extdSpec.local == nil {
				if extdSpec.global != nil && (extdSpec.global.Policy == policy || extdSpec.global.HTTPServerPolicyCR == policy) {
					routeGroups = append(routeGroups, rg)
				}
				continue
			}
			if extdSpec.local.Policy == policy || extdSpec.local.HTTPServerPolicyCR == policy {
				routeGroups = append(routeGroups, rg)
			}
			if extdSpec.local.Policy == "" && (extdSpec.global.Policy == policy || extdSpec.global.HTTPServerPolicyCR == policy) {
				routeGroups = append(routeGroups, rg)
			} else {
				continue
			}
		} else {
			//handle policycr for defaultRouteGroup
			if rg == defaultRouteGroupName {
				if extdSpec.defaultrg.Policy == policy || extdSpec.defaultrg.HTTPServerPolicyCR == policy {
					routeGroups = append(routeGroups, rg)
				}
			} else {
				if extdSpec.global.Policy == policy || extdSpec.global.HTTPServerPolicyCR == policy {
					routeGroups = append(routeGroups, rg)
				}
			}
		}
	}
	return routeGroups
}

// fetch routeGroup for given secret.
func (ctlr *Controller) getRouteGroupForNamespace(ns string) string {
	for rg, extdSpec := range ctlr.resources.extdSpecMap {
		// Skip local extended configmaps for TLS secret update processing
		if extdSpec == nil || extdSpec.global == nil {
			continue
		}
		// Check if namespace of the secret matches with the namespace of the routes defined in a route group
		if ctlr.resources.routeGroupNamespaceMap[ns] == rg {
			return rg
		}
	}
	return ""
}

// readMultiClusterConfigFromGlobalCM reads the configuration for multiple kubernetes clusters
func (ctlr *Controller) readMultiClusterConfigFromGlobalCM(haClusterConfig HAClusterConfig, externalClusterConfigs []ClusterDetails) error {
	primaryClusterName := ""
	secondaryClusterName := ""
	// Handle cluster configs for HA CIS
	if ctlr.multiClusterMode != StandAloneCIS && ctlr.multiClusterMode != "" && haClusterConfig != (HAClusterConfig{}) {
		// If HA mode not set use default mode
		if ctlr.discoveryMode == "" {
			ctlr.discoveryMode = DefaultMode
		}
		// Get the primary and secondary cluster names and store the ratio if operating in ratio mode
		if haClusterConfig.PrimaryCluster != (ClusterDetails{}) {
			primaryClusterName = haClusterConfig.PrimaryCluster.ClusterName
			if ctlr.discoveryMode == Ratio {
				if haClusterConfig.PrimaryCluster.Ratio != nil {
					ctlr.clusterRatio[haClusterConfig.PrimaryCluster.ClusterName] = haClusterConfig.PrimaryCluster.Ratio
				} else {
					one := 1
					ctlr.clusterRatio[haClusterConfig.PrimaryCluster.ClusterName] = &one
				}
				ctlr.clusterRatio[ctlr.multiClusterHandler.LocalClusterName] = ctlr.clusterRatio[haClusterConfig.PrimaryCluster.ClusterName]
			}
			ctlr.readAndUpdateClusterAdminState(haClusterConfig.PrimaryCluster, ctlr.multiClusterMode == PrimaryCIS)
		}
		if haClusterConfig.SecondaryCluster != (ClusterDetails{}) {
			secondaryClusterName = haClusterConfig.SecondaryCluster.ClusterName
			if ctlr.discoveryMode == Ratio {
				if haClusterConfig.SecondaryCluster.Ratio != nil {
					ctlr.clusterRatio[haClusterConfig.SecondaryCluster.ClusterName] = haClusterConfig.SecondaryCluster.Ratio
				} else {
					one := 1
					ctlr.clusterRatio[haClusterConfig.SecondaryCluster.ClusterName] = &one
				}
			}
			ctlr.readAndUpdateClusterAdminState(haClusterConfig.SecondaryCluster, ctlr.multiClusterMode == SecondaryCIS)
		}
		// Set up health probe
		if ctlr.multiClusterMode == SecondaryCIS {
			if haClusterConfig.PrimaryClusterEndPoint == "" {
				// cis in secondary mode, primary cluster health check endpoint is required
				// if endpoint is missing exit
				log.Debugf("[MultiCluster] error: cis running in secondary mode and missing primaryEndPoint parameter")
				os.Exit(1)
			} else {
				// process only the updated healthProbe config params
				ctlr.updateHealthProbeConfig(haClusterConfig)
			}
		}

		// Set up the informers for the HA clusters
		if ctlr.multiClusterMode == PrimaryCIS && haClusterConfig.SecondaryCluster != (ClusterDetails{}) {
			// Both cluster name and secret are mandatory
			if haClusterConfig.SecondaryCluster.ClusterName == "" || haClusterConfig.SecondaryCluster.Secret == "" {
				log.Errorf("[MultiCluster] Secondary clusterName or secret not provided in highAvailabilityCIS section: %v",
					haClusterConfig.SecondaryCluster)
				os.Exit(1)
			}
			kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(haClusterConfig.SecondaryCluster.Secret,
				haClusterConfig.SecondaryCluster.ClusterName)
			if err != nil {
				log.Errorf("[MultiCluster]  %v", err.Error())
				os.Exit(1)
			}
			err = ctlr.updateClusterConfigStore(kubeConfigSecret,
				ClusterDetails{
					ClusterName:            haClusterConfig.SecondaryCluster.ClusterName,
					Secret:                 haClusterConfig.SecondaryCluster.Secret,
					ServiceTypeLBDiscovery: haClusterConfig.SecondaryCluster.ServiceTypeLBDiscovery,
				},
				false)
			if err != nil {
				log.Errorf("[MultiCluster]  %v", err.Error())
				os.Exit(1)
			}

			// Setup and start informers for secondary cluster in case of active-active/ratio/default mode HA cluster
			// Note: in case of default mode check if the serviceTypeLBDiscovery is set to true for this cluster
			if ctlr.discoveryMode != StandBy && (ctlr.discoveryMode != DefaultMode ||
				haClusterConfig.SecondaryCluster.ServiceTypeLBDiscovery) {
				err := ctlr.setupAndStartExternalClusterInformers(haClusterConfig.SecondaryCluster.ClusterName)
				if err != nil {
					return err
				}
			}
			ctlr.multiClusterHandler.HAPairClusterName = haClusterConfig.SecondaryCluster.ClusterName
		}
		if ctlr.multiClusterMode == SecondaryCIS && haClusterConfig.PrimaryCluster != (ClusterDetails{}) {
			// Both cluster name and secret are mandatory
			if haClusterConfig.PrimaryCluster.ClusterName == "" || haClusterConfig.PrimaryCluster.Secret == "" {
				log.Errorf("[MultiCluster] Primary clusterName or secret not provided in highAvailabilityCIS section: %v",
					haClusterConfig.PrimaryCluster)
				os.Exit(1)
			}
			kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(haClusterConfig.PrimaryCluster.Secret,
				haClusterConfig.PrimaryCluster.ClusterName)
			if err != nil {
				log.Errorf("[MultiCluster]  %v", err.Error())
				os.Exit(1)
			}
			err = ctlr.updateClusterConfigStore(kubeConfigSecret,
				ClusterDetails{
					ClusterName:            haClusterConfig.PrimaryCluster.ClusterName,
					Secret:                 haClusterConfig.PrimaryCluster.Secret,
					ServiceTypeLBDiscovery: haClusterConfig.SecondaryCluster.ServiceTypeLBDiscovery,
				},
				false)
			if err != nil {
				log.Errorf("[MultiCluster]  %v", err.Error())
				os.Exit(1)
			}

			// Setup and start informers for primary cluster in case of active-active/ratio/default mode HA cluster
			// Note: in case of default mode check if the serviceTypeLBDiscovery is set to true for this cluster
			if ctlr.discoveryMode != StandBy && (ctlr.discoveryMode != DefaultMode ||
				haClusterConfig.PrimaryCluster.ServiceTypeLBDiscovery) {
				err := ctlr.setupAndStartExternalClusterInformers(haClusterConfig.PrimaryCluster.ClusterName)
				if err != nil {
					return err
				}
			}

			ctlr.multiClusterHandler.HAPairClusterName = haClusterConfig.PrimaryCluster.ClusterName
			//ctlr.multiClusterHandler.LocalClusterName = secondaryClusterName
		}
		if ctlr.discoveryMode != DefaultMode {
			// start the informers for external Cluster on the CIS start up
			if len(externalClusterConfigs) > 0 {
				for _, config := range externalClusterConfigs {
					kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(config.Secret,
						config.ClusterName)
					if err != nil {
						log.Errorf("[MultiCluster]  %v", err.Error())
						os.Exit(1)
					}
					err = ctlr.updateClusterConfigStore(kubeConfigSecret,
						ClusterDetails{
							ClusterName:            config.ClusterName,
							Secret:                 config.Secret,
							ServiceTypeLBDiscovery: config.ServiceTypeLBDiscovery,
						},
						false)
					if err != nil {
						log.Errorf("[MultiCluster]  %v", err.Error())
						os.Exit(1)
					}

					err = ctlr.setupAndStartExternalClusterInformers(config.ClusterName)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	currentClusterSecretKeys := make(map[string]bool)

	// Check if externalClustersConfig are specified for external clusters
	// If externalClustersConfig is not specified, then clean up any old external cluster related config in case user had
	// specified externalClusterConfigs earlier and now removed those configs
	if externalClusterConfigs == nil || len(externalClusterConfigs) == 0 {
		// Clean up the clusterConfigs
		ctlr.multiClusterHandler.cleanClusterCache(primaryClusterName, secondaryClusterName, currentClusterSecretKeys)
		for clusterName := range ctlr.clusterRatio {
			// Avoid deleting HA cluster related configs
			if clusterName == primaryClusterName || clusterName == secondaryClusterName || clusterName == ctlr.multiClusterHandler.LocalClusterName {
				continue
			}
			// Delete cluster ratio
			if _, ok := ctlr.clusterRatio[clusterName]; ok {
				delete(ctlr.clusterRatio, clusterName)
			}
		}
		return nil
	}

	for _, mcc := range externalClusterConfigs {

		// Store the cluster keys which will be used to detect deletion of a cluster later
		currentClusterSecretKeys[mcc.ClusterName] = mcc.ServiceTypeLBDiscovery

		// Both cluster name and secret are mandatory
		if mcc.ClusterName == "" || mcc.Secret == "" {
			log.Warningf("[MultiCluster] clusterName or secret not provided in externalClustersConfig section")
			continue
		}

		// Check and discard multiCluster config if an HA cluster is used as external cluster
		if mcc.ClusterName == primaryClusterName || mcc.ClusterName == secondaryClusterName || mcc.ClusterName == ctlr.multiClusterHandler.LocalClusterName {
			log.Warningf("[MultiCluster] Discarding usage of cluster %s as external cluster, as HA/Local cluster can't be used as external cluster in externalClustersConfig section.", mcc.ClusterName)
			continue
		}

		// Update cluster admin state so that admin state updates are not missed
		ctlr.readAndUpdateClusterAdminState(mcc, false)

		// Fetch the secret containing kubeconfig creds
		kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(mcc.Secret, mcc.ClusterName)

		if err != nil {
			log.Warningf("[MultiCluster]  %v", err.Error())
			continue
		}
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(mcc.ClusterName)
		// If cluster config has been processed already and kubeclient has been created then skip it
		if clusterConfig != nil {
			// Skip processing the cluster config as it's already processed
			// TODO: handle scenarios when cluster names are swapped in the extended config, may be the key should be a
			// combination of cluster name and secret name
			// Before continuing set cluster ratio to ensure any update in ratio of an external cluster isn't missed
			if ctlr.discoveryMode == Ratio {
				if mcc.Ratio != nil {
					ctlr.clusterRatio[mcc.ClusterName] = mcc.Ratio
				} else {
					one := 1
					ctlr.clusterRatio[mcc.ClusterName] = &one
				}
			}

			if ctlr.discoveryMode == DefaultMode {
				// check if serviceTypeLB is updated and handle informer creation/deletion
				//update serviceTypeLB discovery in externalConfig cache
				clusterConfig.clusterDetails.ServiceTypeLBDiscovery = mcc.ServiceTypeLBDiscovery
				if mcc.ServiceTypeLBDiscovery {
					if clusterConfig.InformerStore == nil || clusterConfig.InformerStore.comInformers == nil || len(clusterConfig.InformerStore.comInformers) == 0 {
						err = ctlr.setupAndStartExternalClusterInformers(mcc.ClusterName)
						if err != nil {
							return err
						}
					}
				}
			}
			continue
		}

		// Update the clusterKubeConfig
		err = ctlr.updateClusterConfigStore(kubeConfigSecret, mcc, false)
		if err != nil {
			log.Warningf("[MultiCluster] %v", err.Error())
			continue
		}
		// Set cluster ratio
		if ctlr.discoveryMode == Ratio {
			if mcc.Ratio != nil {
				ctlr.clusterRatio[mcc.ClusterName] = mcc.Ratio
			} else {
				one := 1
				ctlr.clusterRatio[mcc.ClusterName] = &one
			}
		}
		ctlr.readAndUpdateClusterAdminState(mcc, false)

		switch ctlr.discoveryMode {
		case DefaultMode:
			//Setup and start pool informers for external cluster in case of default mode and serviceTypeLBDiscovery set to true
			if mcc.ServiceTypeLBDiscovery {
				err := ctlr.setupAndStartExternalClusterInformers(mcc.ClusterName)
				if err != nil {
					return err
				}
			}
			// Check if a cluster config has been removed then remove the data associated with it from the externalClustersConfig store
			ctlr.multiClusterHandler.cleanClusterCache(primaryClusterName, secondaryClusterName, currentClusterSecretKeys)
		default:
			// Setup and start pool informers for external cluster in case of standalone and started in non-default mode.
			// For all other modes except default mode implicit service discovery is required.
			// So starting pool informers for external clusters on startup
			if ctlr.multiClusterMode == StandAloneCIS {
				err := ctlr.setupAndStartExternalClusterInformers(mcc.ClusterName)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// updateClusterConfigStore updates the clusterKubeConfigs store with the latest config and updated kubeclient for the cluster
func (ctlr *Controller) updateClusterConfigStore(kubeConfigSecret *v1.Secret, mcc ClusterDetails, deleted bool) error {
	if !deleted && (kubeConfigSecret == nil || mcc == (ClusterDetails{})) {
		return fmt.Errorf("[MultiCluster] no secret or externalClustersConfig specified")
	}
	// if secret associated with a cluster kubeconfig is deleted then stop all informers for the cluster
	if deleted {
		log.Debugf("kubeconfig deleted for cluster %s.Informers are stopped", mcc.ClusterName)
		ctlr.stopMultiClusterPoolInformers(mcc.ClusterName, true)
		ctlr.stopMultiClusterNodeInformer(mcc.ClusterName)
		return nil
	}
	// Extract the kubeconfig from the secret
	kubeConfig, ok := kubeConfigSecret.Data["kubeconfig"]
	if !ok {
		return fmt.Errorf("no kubeconfig data found in the secret: %s for the cluster: %s", mcc.Secret,
			mcc.ClusterName)
	}
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeConfig)
	if err != nil {
		return err
	}
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(mcc.ClusterName)
	if clusterConfig == nil {
		clusterConfig = newClusterConfig()
	}
	// Create clientset using the provided kubeconfig for the respective cluster
	err = ctlr.setupClientsforCluster(config, false, false, mcc.ClusterName, clusterConfig)
	// update externalclusterconfig in clusterconfig
	clusterConfig.clusterDetails = mcc
	// Update the clusterConfig in the externalClustersConfig store
	ctlr.multiClusterHandler.addClusterConfig(mcc.ClusterName, clusterConfig)
	if err != nil {
		return fmt.Errorf("Failed to create clients for cluster %s with kube-config fetched from secret %s: %v", mcc.ClusterName, mcc.Secret, err)
	}
	return nil
}

// updateMultiClusterResourceServiceMap updates the multiCluster rscSvcMap and clusterSvcMap
func (ctlr *Controller) updateMultiClusterResourceServiceMap(rsCfg *ResourceConfig, rsRef resourceRef, serviceName, path string,
	pool Pool, servicePort intstr.IntOrString, clusterName string) {
	if _, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; !ok {
		ctlr.multiClusterResources.rscSvcMap[rsRef] = make(map[MultiClusterServiceKey]MultiClusterServiceConfig)
	}
	svcKey := MultiClusterServiceKey{
		clusterName: clusterName,
		serviceName: serviceName,
		namespace:   pool.ServiceNamespace,
	}
	ctlr.multiClusterResources.rscSvcMap[rsRef][svcKey] = MultiClusterServiceConfig{svcPort: servicePort}
	// update the clusterSvcMap
	ctlr.updatePoolIdentifierForService(svcKey, rsRef, pool.ServicePort, pool.Name, pool.Partition, rsCfg.Virtual.Name, path)
}

// fetchKubeConfigSecret fetches the kubeConfig secret associated with a cluster
func (ctlr *Controller) fetchKubeConfigSecret(secret string, clusterName string) (*v1.Secret, error) {

	// Check if secret is in the desired format of <namespace>/<secret name>
	splits := strings.Split(secret, "/")
	if len(splits) != 2 {
		return nil, fmt.Errorf("[MultiCluster] secret: %s for cluster: %v should be in the format <namespace/secret-name>", secret, clusterName)
	}
	secretNamespace := splits[0]
	secretName := splits[1]

	comInf, ok := ctlr.getNamespacedCommonInformer(ctlr.multiClusterHandler.LocalClusterName, secretNamespace)
	if !ok {
		log.Warningf("[MultiCluster] informer not found for namespace: %v while fetching secret for cluster %v", secretNamespace, clusterName)
	}
	var obj interface{}
	var exist bool
	var err error
	var kubeConfigSecret *v1.Secret
	if comInf != nil && comInf.secretsInformer != nil {
		obj, exist, err = comInf.secretsInformer.GetIndexer().GetByKey(secret)
		if err != nil {
			log.Warningf("[MultiCluster] error occurred while fetching Secret: %s for the cluster: %s, Error: %v",
				secretName, clusterName, err)
		}
	}
	if !exist {
		log.Debugf("[MultiCluster] Fetching secret: %s for cluster: %s using kubeclient", secretName, clusterName)
		// During start up the informers may not be updated so, try to fetch secret using kubeClient
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		kubeConfigSecret, err = clusterConfig.kubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName,
			metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("[MultiCluster] error occurred while fetching Secret: %s for the cluster: %s, Error: %v",
				secretName, clusterName, err)
		} else {
			log.Debugf("[MultiCluster] Successfully fetched secret: %s for cluster: %s using kubeclient", secretName, clusterName)
		}
	}
	// Fetch the kubeconfig data from the secret
	if kubeConfigSecret == nil {
		kubeConfigSecret = obj.(*v1.Secret)
	}
	return kubeConfigSecret, nil
}

// updateHealthProbeConfig checks for any healthProbe config update and updates the respective healthProbe parameters
func (ctlr *Controller) updateHealthProbeConfig(haClusterConfig HAClusterConfig) {
	// Initialize PrimaryClusterHealthProbeParams if it's the first time
	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams == nil {
		ctlr.RequestHandler.PrimaryClusterHealthProbeParams = &PrimaryClusterHealthProbeParams{
			paramLock: sync.RWMutex{},
		}
	}
	ctlr.RequestHandler.PrimaryClusterHealthProbeParams.paramLock.Lock()
	defer ctlr.RequestHandler.PrimaryClusterHealthProbeParams.paramLock.Unlock()
	// Check if primary cluster health probe endpoint has been updated and set the endpoint type
	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint != haClusterConfig.PrimaryClusterEndPoint {
		ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint = haClusterConfig.PrimaryClusterEndPoint
		ctlr.RequestHandler.setPrimaryClusterHealthCheckEndPointType()
	}
	// Check if probe interval has been updated
	if haClusterConfig.ProbeInterval == 0 {
		if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval != DefaultProbeInterval {
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval = DefaultProbeInterval
		}
	} else if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval != haClusterConfig.ProbeInterval {
		ctlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval = haClusterConfig.ProbeInterval
	}
	// Check if retry interval has been updated
	if haClusterConfig.RetryInterval == 0 {
		if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval != DefaultRetryInterval {
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval = DefaultRetryInterval
		}
	} else if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval != haClusterConfig.RetryInterval {
		ctlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval = haClusterConfig.RetryInterval
	}
}

func (ctlr *Controller) handleAutoMonitor(rsCfg *ResourceConfig, svcNamespace, svcName, clusterName string, pool *Pool) Monitor {
	// Create health monitor if AutoMonitor is not set to None, which means either create pod readiness-probe  based HTTP monitor or default TCP monitor based on the autoMonitor value
	// Skip NPL Annotation check on service
	svcPods := ctlr.GetPodsForService(svcNamespace, svcName, clusterName, false)
	var interval int            // interval for health monitor
	var initialDelaySeconds int // initial delay for health monitor
	var monitor Monitor
	if svcPods != nil && len(svcPods) > 0 {
		port := pool.ServicePort.IntVal
		var pod *v1.Pod
		for _, svcPod := range svcPods {
			if pod == nil {
				pod = svcPod
			} else {
				// In case of update, use the latest pod as there might be a chance that there is two pod instances,
				// one in terminating state and other in running state
				if pod.ObjectMeta.CreationTimestamp.Before(&svcPod.ObjectMeta.CreationTimestamp) {
					pod = svcPod
				}
			}
		}
	out:
		for _, container := range pod.Spec.Containers {
			if container.ReadinessProbe == nil {
				continue
			}
			if container.ReadinessProbe.HTTPGet != nil || container.ReadinessProbe.TCPSocket != nil {
				for _, cPort := range container.Ports {
					if cPort.ContainerPort == port {
						interval = int(container.ReadinessProbe.PeriodSeconds)
						initialDelaySeconds = int(container.ReadinessProbe.InitialDelaySeconds)
						// in case of serviceEndpoint, create a default TCP monitor hence break out of the loop
						if ctlr.resources.baseRouteConfig.AutoMonitor == ServiceEndpoint {
							break out
						}

						var timeout int
						// Use AutoMonitorTimeout as timeout if it is specified, else set timeout to 3*interval + 1 (BIG-IP recommended)
						if ctlr.resources.baseRouteConfig.AutoMonitorTimeout != 0 {
							timeout = ctlr.resources.baseRouteConfig.AutoMonitorTimeout
						} else {
							timeout = 3*interval + 1
						}
						var targetPort int32
						if container.ReadinessProbe.HTTPGet != nil {
							var scheme v1.URIScheme
							switch container.ReadinessProbe.HTTPGet.Scheme {
							case v1.URISchemeHTTPS:
								scheme = v1.URISchemeHTTPS
							case v1.URISchemeHTTP:
								scheme = v1.URISchemeHTTP
							default:
								scheme = v1.URISchemeHTTP
							}
							targetPort = int32(container.ReadinessProbe.HTTPGet.Port.IntValue())
							path := container.ReadinessProbe.HTTPGet.Path
							if path == "" {
								path = "/"
							}
							monitor = Monitor{
								Name:        pool.Name + "_monitor",
								Partition:   rsCfg.Virtual.Partition,
								Interval:    interval,
								Type:        strings.ToLower(string(scheme)),
								Send:        fmt.Sprintf("GET %s HTTP/1.0\r\n", path), // Request conforming to the HTTP/1.0 protocol
								Recv:        "HTTP/1\\.[01] [23][0-9][0-9]",           // Any code greater than or equal to 200 and less than 400 indicates success
								Timeout:     timeout,
								Path:        path,
								TimeUntilUp: &initialDelaySeconds,
								TargetPort:  targetPort,
							}
						} else {
							targetPort = int32(container.ReadinessProbe.TCPSocket.Port.IntValue())
							monitor = Monitor{
								Name:        pool.Name + "_monitor",
								Partition:   rsCfg.Virtual.Partition,
								Interval:    interval,
								Type:        "tcp",
								Timeout:     timeout,
								TimeUntilUp: &initialDelaySeconds,
								TargetPort:  targetPort,
							}
						}
						break out
					}
				}
			}
		}
	}
	// If autoMonitor is set as service-endpoint, create a default TCP monitor
	if ctlr.resources.baseRouteConfig.AutoMonitor == ServiceEndpoint {
		var timeout int
		if ctlr.resources.baseRouteConfig.AutoMonitorTimeout != 0 {
			timeout = ctlr.resources.baseRouteConfig.AutoMonitorTimeout
		} else if interval == 0 {
			interval = 5
			timeout = 16 // default values used by BIG-IP
		} else {
			timeout = 3*interval + 1 // recommended by BIG-IP
		}
		monitor = Monitor{
			Type:        "tcp",
			Name:        pool.Name + "_monitor",
			Partition:   rsCfg.Virtual.Partition,
			Timeout:     timeout,
			Interval:    interval,
			TimeUntilUp: &initialDelaySeconds,
		}
	}
	return monitor
}

func (ctlr *Controller) readAndUpdateClusterAdminState(cluster interface{}, localCluster bool) {
	// read cluster admin state and update the cluster config
	if cluster == nil {
		return
	}
	if clusterData, ok := cluster.(ClusterDetails); ok {
		// For HA cluster config
		clusterNameKey := ctlr.multiClusterHandler.LocalClusterName
		if !localCluster {
			clusterNameKey = clusterData.ClusterName
		}
		if clusterData.AdminState != "" {
			if clusterData.AdminState == clustermanager.Enable || clusterData.AdminState == clustermanager.Disable ||
				clusterData.AdminState == clustermanager.Offline || clusterData.AdminState == clustermanager.NoPool {
				ctlr.clusterAdminState[clusterNameKey] = clusterData.AdminState
			} else {
				log.Warningf("[MultiCluster] Invalid cluster adminState: %v specified for cluster: %v, supported "+
					"values (enable, disable, offline, no-pool). Defaulting to enable", clusterData.AdminState, clusterData.ClusterName)
				ctlr.clusterAdminState[clusterNameKey] = clustermanager.Enable
			}
		} else {
			ctlr.clusterAdminState[clusterNameKey] = clustermanager.Enable
		}
	}
}

func (ch *ClusterHandler) fetchClusterNames() []string {
	var clusterNames []string
	ch.RWMutex.RLock()
	defer ch.RWMutex.RUnlock()
	for clusterName, _ := range ch.ClusterConfigs {
		clusterNames = append(clusterNames, clusterName)
	}
	return clusterNames
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
