package controller

import (
	"context"
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"os"
	"sort"
	"strconv"
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
)

func (ctlr *Controller) processRoutes(routeGroup string, triggerDelete bool) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing RouteGroup/Namespace %v (%v)",
			routeGroup, endTime.Sub(startTime))
	}()

	extdSpec, partition := ctlr.resources.getExtendedRouteSpec(routeGroup)

	if extdSpec == nil {
		return fmt.Errorf("extended Route Spec not available for RouteGroup/Namespace: %v", routeGroup)
	}

	routes := ctlr.getGroupedRoutes(routeGroup, extdSpec)

	if triggerDelete || len(routes) == 0 {
		// Delete all possible virtuals for this route group
		for _, portStruct := range getBasicVirtualPorts() {
			rsName := frameRouteVSName(extdSpec.VServerName, extdSpec.VServerAddr, portStruct)
			if ctlr.getVirtualServer(partition, rsName) != nil {
				log.Debugf("Removing virtual %v belongs to RouteGroup: %v",
					rsName, routeGroup)
				ctlr.deleteVirtualServer(partition, rsName)
			}
		}
		return nil
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

		// deletion ; update /health /app/path1

		err := ctlr.handleRouteGroupExtendedSpec(rsCfg, extdSpec)

		if err != nil {
			processingError = true
			log.Errorf("%v", err)
			break
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

			if isSecureRoute(rt) {
				//TLS Logic
				processed := ctlr.handleRouteTLS(rsCfg, rt, extdSpec.VServerAddr, servicePort, extdSpec)
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

		if processingError {
			log.Errorf("Unable to Process Route Group %s", routeGroup)
			break
		}

		// Save ResourceConfig in temporary Map
		vsMap[rsName] = rsCfg
		for _, namespace := range ctlr.resources.extdSpecMap[routeGroup].namespaces {
			if ctlr.PoolMemberType == NodePort {
				ctlr.updatePoolMembersForNodePort(rsCfg, namespace)
			} else {
				ctlr.updatePoolMembersForCluster(rsCfg, namespace)
			}
		}
	}

	if !processingError {
		for name, rscfg := range vsMap {
			rsMap := ctlr.resources.getPartitionResourceMap(partition)
			rsMap[name] = rscfg
		}
	}

	return nil
}

func (ctlr *Controller) getGroupedRoutes(routeGroup string, extdSpec *ExtendedRouteGroupSpec) []*routeapi.Route {
	var assocRoutes []*routeapi.Route
	// Get the route group
	for _, namespace := range ctlr.resources.extdSpecMap[routeGroup].namespaces {
		orderedRoutes := ctlr.getOrderedRoutes(namespace)
		ctlr.TeemData.Lock()
		ctlr.TeemData.ResourceType.NativeRoutes[namespace] = len(orderedRoutes)
		ctlr.TeemData.Unlock()
		for _, route := range orderedRoutes {
			// TODO: add combinations for a/b - svc weight ; valid svcs or not
			if ctlr.checkValidRoute(route, extdSpec) {
				var key string
				if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
					key = route.Spec.Host + "/"
				} else {
					key = route.Spec.Host + route.Spec.Path
				}
				ctlr.updateHostPathMap(route.ObjectMeta.CreationTimestamp, key)
				assocRoutes = append(assocRoutes, route)
			}
		}
	}
	return assocRoutes
}

func (ctlr *Controller) handleRouteGroupExtendedSpec(rsCfg *ResourceConfig, extdSpec *ExtendedRouteGroupSpec) error {
	policy := extdSpec.Policy
	if policy != "" {
		splits := strings.Split(policy, "/")
		policyNamespace := splits[0]
		comInf, ok := ctlr.getNamespacedCommonInformer(policyNamespace)
		if !ok {
			return fmt.Errorf("Informer not found for namespace: %v", policyNamespace)
		}
		obj, exist, err := comInf.plcInformer.GetIndexer().GetByKey(policy)
		if err != nil {
			return fmt.Errorf("Error while fetching Policy: %v: %v", policy, err)
		}
		if !exist {
			return fmt.Errorf("Policy Not Found: %v", policy)
		}
		plc := obj.(*cisapiv1.Policy)
		if plc != nil {
			err := ctlr.handleVSResourceConfigForPolicy(rsCfg, plc)
			if err != nil {
				return err
			}
		}
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
	nrInf, ok := ctlr.getNamespacedCommonInformer(route.Namespace)
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

	backendSvcs := GetRouteBackends(route)

	for _, bs := range backendSvcs {
		pool := Pool{
			Name: formatPoolName(
				route.Namespace,
				bs.Name,
				servicePort,
				"",
				"",
			),
			Partition:        rsCfg.Virtual.Partition,
			ServiceName:      bs.Name,
			ServiceNamespace: route.Namespace,
			ServicePort:      servicePort,
			NodeMemberLabel:  "",
			Balance:          route.ObjectMeta.Annotations[resource.F5VsBalanceAnnotation],
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
						Name:      pool.Name + "_monitor",
						Partition: rsCfg.Virtual.Partition,
						Interval:  hm.Interval,
						Type:      hm.Type,
						Send:      hm.Send,
						Recv:      hm.Recv,
						Timeout:   hm.Timeout,
						Path:      hm.Path,
					}
					rsCfg.Monitors = append(
						rsCfg.Monitors,
						monitor,
					)
					pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitor.Name})
				}
			}
		} else {
			// Skip NPL Annotation check on service
			svcPods := ctlr.GetPodsForService(route.Namespace, bs.Name, false)

			if svcPods != nil {
				port := pool.ServicePort.IntVal
				pod := svcPods.Items[0]

			out:
				for _, container := range pod.Spec.Containers {
					if container.LivenessProbe == nil {
						continue
					}
					for _, cPort := range container.Ports {
						if cPort.ContainerPort == port {
							var scheme v1.URIScheme
							switch container.LivenessProbe.HTTPGet.Scheme {
							case v1.URISchemeHTTPS:
								scheme = v1.URISchemeHTTPS
							case v1.URISchemeHTTP:
								scheme = v1.URISchemeHTTP
							default:
								scheme = v1.URISchemeHTTP
							}

							monitor := Monitor{
								Name:      pool.Name + "_monitor",
								Partition: rsCfg.Virtual.Partition,
								Interval:  int(container.LivenessProbe.PeriodSeconds),
								Type:      strings.ToLower(string(scheme)),
								Send:      "GET /\r\n",
								Recv:      "",
								Timeout:   int(container.LivenessProbe.TimeoutSeconds),
								Path:      container.LivenessProbe.HTTPGet.Path,
							}
							rsCfg.Monitors = append(
								rsCfg.Monitors,
								monitor,
							)
							pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitor.Name})
							break out
						}
					}
				}
			}
		}

		rsCfg.Pools = append(rsCfg.Pools, pool)
		// skip the policy creation for passthrough termination
		// skip the policy creation for A/B Deployment
		if !isPassthroughRoute(route) && !IsRouteABDeployment(route) {
			rules := ctlr.prepareRouteLTMRules(route, pool.Name, rsCfg.Virtual.AllowSourceRange)
			if rules == nil {
				return fmt.Errorf("failed to create LTM Rules")
			}

			policyName := formatPolicyName(route.Spec.Host, route.Namespace, rsCfg.Virtual.Name)

			rsCfg.AddRuleToPolicy(policyName, rsCfg.Virtual.Partition, rules)
		}
	}

	return nil
}

// prepareRouteLTMRules prepares LTM Policy rules for VirtualServer
func (ctlr *Controller) prepareRouteLTMRules(
	route *routeapi.Route,
	poolName string,
	allowSourceRange []string,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)

	uri := route.Spec.Host + route.Spec.Path
	path := route.Spec.Path

	ruleName := formatVirtualServerRuleName(route.Spec.Host, route.Namespace, path, poolName)

	rl, err := createRule(uri, poolName, ruleName, allowSourceRange)
	if nil != err {
		log.Errorf("Error configuring rule: %v", err)
		return nil
	}

	if rewritePath, ok := route.Annotations[string(URLRewriteAnnotation)]; ok {
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

func (ctlr *Controller) UpdatePoolHealthMonitors(service *v1.Service, freshRsCfg *ResourceConfig) {

	//Get routes for service
	route := ctlr.GetServiceRouteWithoutHealthAnnotation(service)
	if route == nil {
		return
	}

	err, port := ctlr.getServicePort(route)
	if err != nil {
		return
	}
	servicePort := intstr.IntOrString{IntVal: port}
	poolName := formatPoolName(
		service.Namespace,
		service.Name,
		servicePort,
		"",
		"",
	)
	svcPods := ctlr.GetPodsForService(service.Namespace, service.Name, false)
	if svcPods != nil {
		//Pick any one of the pod
		pod := svcPods.Items[0]

		var podMonitor Monitor
	out:
		for _, container := range pod.Spec.Containers {
			for _, cPort := range container.Ports {
				if cPort.ContainerPort == servicePort.IntVal {
					if container.LivenessProbe == nil {
						break out
					} else {
						var scheme v1.URIScheme
						switch container.LivenessProbe.HTTPGet.Scheme {
						case v1.URISchemeHTTPS:
							scheme = v1.URISchemeHTTPS
						case v1.URISchemeHTTP:
							scheme = v1.URISchemeHTTP
						default:
							scheme = v1.URISchemeHTTP
						}

						podMonitor = Monitor{
							Name:      poolName + "_monitor",
							Partition: freshRsCfg.Virtual.Partition,
							Interval:  int(container.LivenessProbe.PeriodSeconds),
							Type:      strings.ToLower(string(scheme)),
							Send:      "GET /\r\n",
							Recv:      "",
							Timeout:   int(container.LivenessProbe.TimeoutSeconds),
							Path:      container.LivenessProbe.HTTPGet.Path,
						}

						break out
					}
				}
			}
		}

		for monitorInd, mon := range freshRsCfg.Monitors {
			if mon.Name == poolName+"_monitor" {
				//If liveness spec is not modified, return
				if reflect.DeepEqual(mon, podMonitor) {
					return
				} else {
					//If liveness spec is modified/removed, remove the monitor from the config
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
		//Add monitor if LivenessProbe is present in pod
		if podMonitor != (Monitor{}) {
			freshRsCfg.Monitors = append(
				freshRsCfg.Monitors,
				podMonitor,
			)
		}

		for poolInd, pool := range freshRsCfg.Pools {
			if pool.Name == poolName {
				for monInd, monitorName := range pool.MonitorNames {
					if monitorName.Name == poolName+"_monitor" {
						//If liveness spec is modified/removed,Remove the monitor name from the pool
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
				//Add monitor name to the pool if LivenessProbe is present in pod
				if podMonitor != (Monitor{}) {
					freshRsCfg.Pools[poolInd].MonitorNames = append(freshRsCfg.Pools[poolInd].MonitorNames, MonitorName{Name: podMonitor.Name})
				}
				break
			}
		}
	}
}

func (ctlr *Controller) GetServiceRouteWithoutHealthAnnotation(service *v1.Service) *routeapi.Route {
	natvInf, ok := ctlr.getNamespacedNativeInformer(service.Namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", service.Namespace)
		return nil
	}
	routes, _ := natvInf.routeInformer.GetIndexer().ByIndex("namespace", service.Namespace)
	routeMatched := false
	for _, obj := range routes {
		route := obj.(*routeapi.Route)
		if route.Spec.To.Name == service.Name {
			routeMatched = true
		} else {
			for _, altBEnd := range route.Spec.AlternateBackends {
				if altBEnd.Name == service.Name {
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

func (ctlr *Controller) updatePoolMembersForRoutes(svc *v1.Service, updatePoolHealthMon bool) {
	namespace := svc.Namespace
	for _, portStruct := range getBasicVirtualPorts() {
		routeGroup, ok := ctlr.resources.invertedNamespaceLabelMap[namespace]
		if !ok {
			continue
		}
		extdSpec, partition := ctlr.resources.getExtendedRouteSpec(routeGroup)
		if extdSpec == nil {
			continue
		}
		rsName := frameRouteVSName(extdSpec.VServerName, extdSpec.VServerAddr, portStruct)
		rsCfg := ctlr.getVirtualServer(partition, rsName)
		if rsCfg == nil {
			continue
		}
		freshRsCfg := &ResourceConfig{}
		freshRsCfg.copyConfig(rsCfg)

		for _, ns := range ctlr.getNamespacesForRouteGroup(routeGroup) {
			if ctlr.PoolMemberType == NodePort {
				ctlr.updatePoolMembersForNodePort(freshRsCfg, ns)
			} else {
				ctlr.updatePoolMembersForCluster(freshRsCfg, ns)
			}
		}
		if updatePoolHealthMon {
			// If service route has no healthMonitor annotation and route pod has LivenessProbe spec
			ctlr.UpdatePoolHealthMonitors(svc, freshRsCfg)
		}
		_ = ctlr.resources.setResourceConfig(partition, rsName, freshRsCfg)
	}
}

func (ctlr *Controller) processGlobalExtendedRouteConfig() {
	splits := strings.Split(ctlr.routeSpecCMKey, "/")
	ns, cmName := splits[0], splits[1]
	cm, err := ctlr.kubeClient.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Unable to Get Extended Route Spec Config Map: %v, %v", ctlr.routeSpecCMKey, err)
	}
	err = ctlr.setNamespaceLabelMode(cm)
	if err != nil {
		log.Errorf("invalid configuration: %v", ctlr.routeSpecCMKey, err)
		os.Exit(1)
	}
	err, _ = ctlr.processConfigMap(cm, false)
	if err != nil {
		log.Errorf("Unable to Process Extended Route Spec Config Map: %v, %v", ctlr.routeSpecCMKey, err)
	}
}

func (ctlr *Controller) setNamespaceLabelMode(cm *v1.ConfigMap) error {
	ersData := cm.Data
	es := extendedSpec{}
	//log.Debugf("GCM: %v", cm.Data)
	err := yaml.UnmarshalStrict([]byte(ersData["extendedSpec"]), &es)
	if err != nil {
		return fmt.Errorf("invalid extended route spec in configmap: %v/%v error: %v", cm.Namespace, cm.Name, err)
	}
	namespace, namespaceLabel := false, false
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
	if ctlr.namespaceLabel == "" && namespaceLabel {
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
			nsLabel := fmt.Sprintf("%v,%v", ctlr.namespaceLabel, ergc.NamespaceLabel)
			if _, ok := ctlr.nsInformers[nsLabel]; !ok {
				err := ctlr.createNamespaceLabeledInformer(nsLabel)
				if err != nil {
					log.Errorf("%v", err)
					for _, nsInf := range ctlr.nsInformers {
						for _, v := range nsInf.nsInformer.GetIndexer().List() {
							ns := v.(*v1.Namespace)
							ctlr.namespaces[ns.ObjectMeta.Name] = true
						}
					}
				} else {
					log.Debugf("Added namespace label informer: %v", nsLabel)
					ctlr.nsInformers[nsLabel].start()
				}
			}
		}
	}
	return nil
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
		return fmt.Errorf("invalid extended route spec in configmap: %v/%v error: %v", cm.Namespace, cm.Name, err), false
	}

	newExtdSpecMap := make(extendedSpecMap, len(ctlr.resources.extdSpecMap))

	if ctlr.isGlobalExtendedRouteSpec(cm) {

		// Get the base route config from the Global ConfigMap
		ctlr.readBaseRouteConfigFromGlobalCM(es.BaseRouteConfig)

		for rg := range es.ExtendedRouteGroupConfigs {
			// ergc needs to be created at every iteration, as we are using address inside this container

			// if this were used as an iteration variable, on every loop we just use the same container instead of creating one
			// using the same container overrides the previous iteration contents, which is not desired
			ergc := es.ExtendedRouteGroupConfigs[rg]
			var allowOverride bool

			if ctlr.namespaceLabelMode {
				// specifically setting the allow override as false in case of namespaceLabel Mode
				allowOverride = false
			} else if allowOverride, err = strconv.ParseBool(ergc.AllowOverride); err != nil {
				return fmt.Errorf("invalid allowOverride value in configmap: %v/%v error: %v", cm.Namespace, cm.Name, err), false
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
				partition = ergc.BigIpPartition
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
			return nil, true
		}

		deletedSpecs, modifiedSpecs, updatedSpecs, createdSpecs := getOperationalExtendedConfigMapSpecs(
			ctlr.resources.extdSpecMap, newExtdSpecMap, isDelete,
		)

		for _, routeGroupKey := range deletedSpecs {
			_ = ctlr.processRoutes(routeGroupKey, true)
			if ctlr.resources.extdSpecMap[routeGroupKey].local == nil {
				delete(ctlr.resources.extdSpecMap, routeGroupKey)
				if ctlr.namespaceLabelMode {
					// deleting and stopping the namespaceLabel informers if a routeGroupKey is modified or deleted
					nsLabel := fmt.Sprintf("%v,%v", ctlr.namespaceLabel, routeGroupKey)
					if nsInf, ok := ctlr.nsInformers[nsLabel]; ok {
						log.Debugf("Removed namespace label informer: %v", nsLabel)
						nsInf.stop()
						delete(ctlr.nsInformers, nsLabel)
					}
				}
			} else {
				ctlr.resources.extdSpecMap[routeGroupKey].global = nil
				ctlr.resources.extdSpecMap[routeGroupKey].override = false
				ctlr.resources.extdSpecMap[routeGroupKey].partition = ""
				ctlr.resources.extdSpecMap[routeGroupKey].namespaces = []string{}

			}

		}

		for _, routeGroupKey := range modifiedSpecs {
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
			ctlr.resources.extdSpecMap[routeGroupKey].namespaces = newExtdSpecMap[routeGroupKey].namespaces
			err := ctlr.processRoutes(routeGroupKey, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v with modified extended spec", routeGroupKey)
			}
		}

		for _, routeGroupKey := range updatedSpecs {
			ctlr.resources.extdSpecMap[routeGroupKey].override = newExtdSpecMap[routeGroupKey].override
			ctlr.resources.extdSpecMap[routeGroupKey].global = newExtdSpecMap[routeGroupKey].global
			ctlr.resources.extdSpecMap[routeGroupKey].partition = newExtdSpecMap[routeGroupKey].partition
			ctlr.resources.extdSpecMap[routeGroupKey].namespaces = newExtdSpecMap[routeGroupKey].namespaces
			err := ctlr.processRoutes(routeGroupKey, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v with updated extended spec", routeGroupKey)
			}
		}

		for _, routeGroupKey := range createdSpecs {
			ctlr.resources.extdSpecMap[routeGroupKey] = &extendedParsedSpec{}
			ctlr.resources.extdSpecMap[routeGroupKey].override = newExtdSpecMap[routeGroupKey].override
			ctlr.resources.extdSpecMap[routeGroupKey].global = newExtdSpecMap[routeGroupKey].global
			ctlr.resources.extdSpecMap[routeGroupKey].partition = newExtdSpecMap[routeGroupKey].partition
			ctlr.resources.extdSpecMap[routeGroupKey].namespaces = newExtdSpecMap[routeGroupKey].namespaces
			err := ctlr.processRoutes(routeGroupKey, false)
			if err != nil {
				log.Errorf("Failed to process RouteGroup: %v on addition of extended spec", routeGroupKey)
			}
		}

	} else if len(es.ExtendedRouteGroupConfigs) > 0 && !ctlr.resourceContext.namespaceLabelMode {
		ergc := es.ExtendedRouteGroupConfigs[0]
		if ergc.Namespace != cm.Namespace {
			return fmt.Errorf("Invalid Extended Route Spec Block in configmap: Mismatching namespace found at index 0 in %v/%v", cm.Namespace, cm.Name), true
		}
		routeGroup, ok := ctlr.resources.invertedNamespaceLabelMap[ergc.Namespace]
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
					err, _ = ctlr.processConfigMap(localCM, false)
					if err == nil {
						return nil, true
					}
				}

				_ = ctlr.processRoutes(routeGroup, true)
				spec.local = nil
				// process routes again, this time routes get processed along with global config
				err := ctlr.processRoutes(routeGroup, false)
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
						_ = ctlr.processRoutes(routeGroup, true)
					}
					spec.local = &ergc.ExtendedRouteGroupSpec
					err := ctlr.processRoutes(routeGroup, false)
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
					_ = ctlr.processRoutes(routeGroup, true)
				}
				spec.local = &ergc.ExtendedRouteGroupSpec
				err := ctlr.processRoutes(routeGroup, false)
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

func (ctlr *Controller) readBaseRouteConfigFromGlobalCM(baseRouteConfig BaseRouteConfig) {

	//declare default configuration for TLS Ciphers
	ctlr.resources.baseRouteConfig.TLSCipher = TLSCipher{
		"1.2",
		"DEFAULT",
		"/Common/f5-default",
	}
	ctlr.resources.baseRouteConfig.DefaultTLS = DefaultSSLProfile{}

	if (baseRouteConfig != BaseRouteConfig{}) {
		if baseRouteConfig.TLSCipher.TLSVersion != "" {
			ctlr.resources.baseRouteConfig.TLSCipher.TLSVersion = baseRouteConfig.TLSCipher.TLSVersion
		}

		if baseRouteConfig.TLSCipher.Ciphers != "" {
			ctlr.resources.baseRouteConfig.TLSCipher.Ciphers = baseRouteConfig.TLSCipher.Ciphers
		}
		if baseRouteConfig.TLSCipher.CipherGroup != "" {
			ctlr.resources.baseRouteConfig.TLSCipher.CipherGroup = baseRouteConfig.TLSCipher.CipherGroup
		}
	}
	if baseRouteConfig.DefaultTLS != (DefaultSSLProfile{}) {
		ctlr.resources.baseRouteConfig.DefaultTLS.ClientSSL = baseRouteConfig.DefaultTLS.ClientSSL
		ctlr.resources.baseRouteConfig.DefaultTLS.ServerSSL = baseRouteConfig.DefaultTLS.ServerSSL
		ctlr.resources.baseRouteConfig.DefaultTLS.Reference = baseRouteConfig.DefaultTLS.Reference
	}
}

func (ctlr *Controller) isGlobalExtendedRouteSpec(cm *v1.ConfigMap) bool {
	cmKey := cm.Namespace + "/" + cm.Name

	if cmKey == ctlr.routeSpecCMKey {
		return true
	}

	return false
}

func (ctlr *Controller) getLatestLocalConfigMap(ns string) *v1.ConfigMap {
	inf, ok := ctlr.getNamespacedNativeInformer(ns)

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
			if spec.global.VServerName != newSpec.global.VServerName || spec.override != newSpec.override || spec.partition != newSpec.partition {
				// Update to VServerName or override should trigger delete and recreation of object
				modifiedSpecs = append(modifiedSpecs, routeGroupKey)
			} else {
				updatedSpecs = append(updatedSpecs, routeGroupKey)
				updateMap[routeGroupKey] = true
			}
		}
	}
	for routeGroupKey, spec := range cachedMap {
		if spec.global.Meta.DependsOnTLS {
			if _, ok := newMap[routeGroupKey]; !ok {
				continue
			}
			if _, ok := updateMap[routeGroupKey]; !ok {
				updatedSpecs = append(updatedSpecs, routeGroupKey)
			}
		}
	}

	for routeGroupKey, _ := range newMap {
		_, ok := cachedMap[routeGroupKey]
		if !ok {
			createdSpecs = append(createdSpecs, routeGroupKey)
		}
	}
	return
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
		rsName = formatCustomVirtualServerName(
			"routes_"+vServerAddr,
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
	for retryCount := 0; retryCount < 3; retryCount++ {
		route := ctlr.fetchRoute(rscKey)
		if route == nil {
			return
		}
		Admitted := false
		now := metaV1.Now().Rfc3339Copy()
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
		if Admitted {
			return
		}
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
		if err == nil {
			log.Debugf("Admitted Route -  %v", route.ObjectMeta.Name)
			return
		}
		log.Errorf("Error while Updating Route Admit Status: %v\n", err)
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
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	for _, route := range unmonitoredRoutes.Items {
		ctlr.eraseRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name))
		// This removes the deleted route's entry from host-path map
		// update the processedHostPathMap if the route is deleted
		var key string
		if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
			key = route.Spec.Host
		} else {
			key = route.Spec.Host + route.Spec.Path
		}
		ctlr.processedHostPath.Lock()
		if timestamp, ok := ctlr.processedHostPath.processedHostPathMap[key]; ok && timestamp == route.ObjectMeta.CreationTimestamp {
			delete(ctlr.processedHostPath.processedHostPathMap, key)
		}
		ctlr.processedHostPath.Unlock()
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

func (ctlr *Controller) checkValidRoute(route *routeapi.Route, extdSpec *ExtendedRouteGroupSpec) bool {
	// Validate the hostpath
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	var key string
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
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "HostAlreadyClaimed", message, v1.ConditionFalse)
			return false
		}
	}

	// If TLS reference of type BigIP/Secret is configured in ConfigMap, fetch Client and Server SSL profile references
	if extdSpec != nil && extdSpec.TLS != (TLS{}) && (extdSpec.TLS.Reference == BIGIP || extdSpec.TLS.Reference == Secret) &&
		route.Spec.TLS.Termination != routeapi.TLSTerminationPassthrough {
		if extdSpec.TLS.ClientSSL == "" {
			message := fmt.Sprintf("Missing client SSL profile %s reference in the ConfigMap", extdSpec.TLS.Reference)
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
		if extdSpec.TLS.ServerSSL == "" && route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
			message := fmt.Sprintf("Missing server SSL profile %s reference in the ConfigMap", extdSpec.TLS.Reference)
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	} else if ctlr.resources.baseRouteConfig != (BaseRouteConfig{}) && ctlr.resources.baseRouteConfig.DefaultTLS != (DefaultSSLProfile{}) &&
		ctlr.resources.baseRouteConfig.DefaultTLS.Reference == BIGIP && route.Spec.TLS.Termination != routeapi.TLSTerminationPassthrough {
		if ctlr.resources.baseRouteConfig.DefaultTLS.ClientSSL == "" {
			message := fmt.Sprintf("Missing client SSL profile %s reference in the ConfigMap - BaseRouteSpec", ctlr.resources.baseRouteConfig.DefaultTLS.Reference)
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
		if ctlr.resources.baseRouteConfig.DefaultTLS.ServerSSL == "" && route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
			message := fmt.Sprintf("Missing server SSL profile %s reference in the ConfigMap - BaseRouteSpec", ctlr.resources.baseRouteConfig.DefaultTLS.Reference)
			go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "ExtendedValidationFailed", message, v1.ConditionFalse)
			return false
		}
	} else if nil != route.Spec.TLS && route.Spec.TLS.Termination != routeapi.TLSTerminationPassthrough {
		if route.Spec.TLS.Certificate != "" && route.Spec.TLS.Key != "" {
			// Validate hostname if certificate is not provided in SSL annotations
			ok := checkCertificateHost(route.Spec.Host, []byte(route.Spec.TLS.Certificate), []byte(route.Spec.TLS.Key))
			if !ok {
				//Invalid certificate and key
				message := fmt.Sprintf("Invalid certificate and key for route: %v", route.ObjectMeta.Name)
				go ctlr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "ExtendedValidationFailed", message, v1.ConditionFalse)
				return false
			}
		} else {
			message := fmt.Sprintf("Missing certificate/key for route: %v", route.ObjectMeta.Name)
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

func (ctlr *Controller) updateHostPathMap(timestamp metav1.Time, key string) {
	// This function updates the processedHostPathMap
	ctlr.processedHostPath.Lock()
	defer ctlr.processedHostPath.Unlock()
	for hostPath, routeTimestamp := range ctlr.processedHostPath.processedHostPathMap {
		if routeTimestamp == timestamp && hostPath != key {
			// Deleting the ProcessedHostPath map if route's path is changed
			delete(ctlr.processedHostPath.processedHostPathMap, hostPath)
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
		}
	}
}

func (ctlr *Controller) getNamespacesForRouteGroup(namespaceGroup string) []string {
	var namespaces []string
	if !ctlr.namespaceLabelMode {
		namespaces = append(namespaces, namespaceGroup)
		ctlr.resources.invertedNamespaceLabelMap[namespaceGroup] = namespaceGroup
	} else {
		nsLabel := fmt.Sprintf("%v,%v", ctlr.namespaceLabel, namespaceGroup)
		nss, err := ctlr.kubeClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{LabelSelector: nsLabel})
		if err != nil {
			log.Errorf("Unable to Fetch Namespaces: %v", err)
			return nil
		}
		for _, ns := range nss.Items {
			namespaces = append(namespaces, ns.Name)
			ctlr.resources.invertedNamespaceLabelMap[ns.Name] = namespaceGroup
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
				if extdSpec.global != nil && extdSpec.global.Policy == policy {
					routeGroups = append(routeGroups, rg)
				}
				continue
			}
			if extdSpec.local.Policy == policy {
				routeGroups = append(routeGroups, rg)
			}
			if extdSpec.local.Policy == "" && extdSpec.global.Policy == policy {
				routeGroups = append(routeGroups, rg)
			} else {
				continue
			}
		} else {
			if extdSpec.global.Policy == policy {
				routeGroups = append(routeGroups, rg)
			}
		}
	}
	return routeGroups
}

// fetch routeGroup for given secret.
func (ctlr *Controller) getRouteGroupForSecret(secret *v1.Secret) string {
	for rg, extdSpec := range ctlr.resources.extdSpecMap {
		// Skip local extended configmaps for TLS secret update processing
		if extdSpec == nil || extdSpec.global == nil {
			continue
		}
		// Skip routeGroups with no TLS and TLS with reference other than secret
		if extdSpec.global.TLS == (TLS{}) || extdSpec.global.TLS.Reference != Secret {
			continue
		}
		// Check if the updated secret is used in any RouteGroup and, belongs to the same namespace as the RouteGroup
		if extdSpec.global.TLS.ServerSSL == secret.Name || extdSpec.global.TLS.ClientSSL == secret.Name {
			if ctlr.resources.invertedNamespaceLabelMap[secret.Namespace] == rg {
				return rg
			}
		}
	}
	return ""
}
