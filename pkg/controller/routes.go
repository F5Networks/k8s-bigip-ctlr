package controller

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"

	v1 "k8s.io/api/core/v1"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
)

func (ctlr *Controller) processRoutes(route *routeapi.Route, isDeleted bool) error {
	// TODO : multiparition case think how to leverage
	// TODO : how to use config amp cache to read and update values

	allRoutes := ctlr.getAllResources(Route, route.Namespace)

	depRoutes := ctlr.validateAssociatedRoutes(route, allRoutes, isDeleted)

	portStructs := ctlr.virtualPorts(route)
	processingError := false
	vsMap := make(ResourceMap)
	for _, portStruct := range portStructs {
		rsCfg := &ResourceConfig{}
		if isDeleted && len(allRoutes) == 0 {
			// Clean resources in partition
			ctlr.deleteVirtualServer(route.Namespace, "", Route)

			return nil
		}

		for _, rt := range depRoutes {
			log.Debugf("Processing Route %s for port %v",
				rt.ObjectMeta.Name, portStruct.port)
			err := ctlr.createRSConfig(rt, rsCfg, portStruct)
			if err != nil {
				processingError = true
				break
			}
			if isSecureRoute(rt) {
				//TLS Logic
			}
		}

		if processingError {
			log.Errorf("Cannot Publish Route %s", route.Name)
			break
		}

		if ctlr.PoolMemberType == NodePort {
			ctlr.updatePoolMembersForNodePort(rsCfg, route.Namespace)
		} else {
			ctlr.updatePoolMembersForCluster(rsCfg, route.Namespace)
		}

		vsMap[rsCfg.Virtual.Partition+"_"+rsCfg.Virtual.Name] = rsCfg

	}
	if !processingError {
		for name, rscfg := range vsMap {
			rsMap := ctlr.resources.getPartitionResourceMap(route.Namespace)
			rsMap[name] = rscfg
		}
	}

	return nil
}

func isSecureRoute(route *routeapi.Route) bool {
	return route.Spec.TLS != nil
}

func (rsCfg *ResourceConfig) processRouteHealthMonitor(route *routeapi.Route) {
	hmStr, exists := route.ObjectMeta.Annotations[HealthMonitorAnnotation]
	if exists {
		var monitors Monitors
		err := json.Unmarshal([]byte(hmStr), &monitors)
		if err != nil {
			log.Errorf("[CORE] Unable to parse health monitor JSON array '%v': %v",
				hmStr, err)
		} else {
			for _, monitor := range monitors {
				if monitor.Send == "" || monitor.Interval == 0 || monitor.Path == "" {
					log.Errorf("Ignoring route %v health monitor %v", route.Name, monitor)
					continue
				}
				monitor.Name = formatMonitorName(rsCfg.Virtual.Partition, route.Spec.To.Name, monitor.Path, 0)
				monitor.Partition = rsCfg.Virtual.Partition
				rsCfg.Monitors = append(rsCfg.Monitors, monitor)
			}
		}
	}

}

func (ctlr *Controller) prepareRoutePool(rsCfg *ResourceConfig, route *routeapi.Route) error {
	var backendPort int32
	var err error
	if route.Spec.Port != nil {
		// Check whether TargetPort in a named service port
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			backendPort = route.Spec.Port.TargetPort.IntVal
		} else {
			backendPort, err = ctlr.GetServicePort(route.Namespace, route.Spec.To.Name, strVal, Route)
			if nil != err {
				return err
			}
		}
	} else {
		backendPort, err = ctlr.GetServicePort(route.Namespace, route.Spec.To.Name, "", Route)
		if nil != err {
			return err
		}
	}

	//Frame pool
	var balance string
	var ok bool
	if balance, ok = route.ObjectMeta.Annotations[F5VsBalanceAnnotation]; !ok {
		balance = DEFAULT_BALANCE
	}

	pool := Pool{
		Name:        formatPoolName(rsCfg.Virtual.Partition, route.Spec.To.Name, backendPort, ""),
		Partition:   rsCfg.Virtual.Partition,
		Balance:     balance,
		ServiceName: route.Spec.To.Name,
		ServicePort: backendPort,
	}
	var found bool
	for _, existingPool := range rsCfg.Pools {
		if existingPool.Name == pool.Name {
			found = true
		}
	}
	if !found {
		rsCfg.Pools = append(rsCfg.Pools, pool)
	}
	return nil
}

func (ctlr *Controller) createRSConfig(route *routeapi.Route, rsCfg *ResourceConfig, pStruct portStruct) error {
	var rsName string

	// TODO: update this from cmap spec
	partition := route.Namespace

	rsCfg.Virtual.Partition = partition

	if pStruct.protocol == "http" {
		//	policyName = "openshift_insecure_routes"
		rsName = ctlr.RouteConfig.HttpVs
	} else {
		//	policyName = "openshift_secure_routes"
		rsName = ctlr.RouteConfig.HttpsVs
	}

	err := ctlr.prepareRoutePool(rsCfg, route)
	if err != nil {
		return err
	}

	rule, urlRewriteRule, appRootRules := rsCfg.prepareRouteRules(route)

	ctlr.prepareRoutePolicies(route, rule, urlRewriteRule, appRootRules, pStruct.protocol, rsCfg)

	rsCfg.processRouteHealthMonitor(route)

	rsCfg.MetaData.ResourceType = ROUTE
	rsCfg.Virtual.Name = rsName
	rsCfg.Virtual.Enabled = true
	SetProfilesForMode("http", rsCfg)
	rsCfg.Virtual.SourceAddrTranslation = SetSourceAddrTranslation(ctlr.VsSnatPoolName)

	bindAddr := ""

	if ctlr.RouteConfig.RouteVSAddr != "" {
		bindAddr = ctlr.RouteConfig.RouteVSAddr
	}
	rsCfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)

	return nil
}

func SetProfilesForMode(mode string, cfg *ResourceConfig) {
	tcpProf := ProfileRef{
		Partition: "Common",
		Name:      "tcp",
		Context:   CustomProfileAll,
	}
	switch mode {
	case "http":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "http",
				Context:   CustomProfileAll,
			})
		cfg.Virtual.AddOrUpdateProfile(tcpProf)
	case "tcp":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(tcpProf)
	case "udp":
		cfg.Virtual.IpProtocol = "udp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "udp",
				Context:   CustomProfileAll,
			})
	}
}
func SetSourceAddrTranslation(snatPoolName string) SourceAddrTranslation {
	if snatPoolName == "" {
		return SourceAddrTranslation{
			Type: DefaultSourceAddrTranslation,
		}
	}
	return SourceAddrTranslation{
		Type: SnatSourceAddrTranslation,
		Pool: snatPoolName,
	}
}

func IsRouteABDeployment(route *routeapi.Route) bool {
	return route.Spec.AlternateBackends != nil && len(route.Spec.AlternateBackends) > 0
}

func ParseAppRootURLRewriteAnnotations(annotation string) map[string]string {
	annotationValMap := make(map[string]string)

	numSeps := strings.Count(annotation, ",")
	numReps := strings.Count(annotation, "=")
	if numSeps > 0 {
		splits := strings.Split(annotation, ",")
		for _, val := range splits {
			if strings.Count(val, "=") != 1 {
				log.Warningf("[RESOURCE] Annotation: %s value: %s not properly formatted should be replace-val=target-val, skipping", annotation, val)
				continue
			}
			split := strings.Split(val, "=")
			annotationValMap[split[0]] = split[1]
		}
	} else if numSeps == 0 && numReps == 1 {
		split := strings.Split(annotation, "=")
		annotationValMap[split[0]] = split[1]
	} else if numSeps == 0 && numReps == 0 {
		annotationValMap["single"] = annotation
	} else {
		log.Warningf("[RESOURCE] Annotation: %s improperly formatted should be single value or comma separated values, not processing", annotation)
	}

	return annotationValMap
}

func ParseAnnotationURL(urlString string) *url.URL {
	if !(strings.HasPrefix(urlString, "http://") || strings.HasPrefix(urlString, "https://")) {
		urlString = "http://" + urlString
	}

	u, err := url.Parse(urlString)
	if err != nil {
		log.Warningf("[RESOURCE] Error parsing url-rewrite url: %s, Error: %v, skipping", urlString, err)
		return nil
	}

	return u
}

func ProcessURLRewrite(target, value string, rsType string) *Rule {
	var actions []*action
	var conditions []*condition

	targetURL := ParseAnnotationURL(target)
	valueURL := ParseAnnotationURL(value)

	if rsType == Route && targetURL.Path == "" && valueURL.Path != "" {
		return nil
	}
	if rsType == Route && targetURL.Host == "" && valueURL.Host != "" {
		return nil
	}
	if valueURL.Host == "" && valueURL.Path == "" {
		return nil
	}

	if targetURL.Host != "" {
		conditions = append(conditions, &condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{targetURL.Host},
		})
	}
	if 0 != len(targetURL.EscapedPath()) {
		conditions = append(conditions, createPathSegmentConditions(targetURL)...)
	}

	actionName := 0
	if valueURL.Host != "" {
		actions = append(actions, &action{
			Name:     fmt.Sprintf("%d", actionName),
			HTTPHost: true,
			Replace:  true,
			Request:  true,
			Value:    valueURL.Host,
		})
		actionName++
	}
	if valueURL.Path != "" {
		if targetURL != nil && targetURL.Path != "" {
			actions = append(actions, &action{
				Name:    fmt.Sprintf("%d", actionName),
				HTTPURI: true,
				Path:    targetURL.Path,
				Replace: true,
				Request: true,
				Value:   ParseRewriteAction(targetURL.Path, valueURL.Path),
			})
		} else {
			actions = append(actions, &action{
				Name:    fmt.Sprintf("%d", actionName),
				HTTPURI: true,
				Replace: true,
				Request: true,
				Value:   valueURL.Path,
			})
		}
	}

	if len(actions) == 0 {
		log.Warningf("[RESOURCE] No actions were processed for url-rewrite value %s, skipping", value)
		return nil
	}

	nameEnd := target + "-" + value
	nameEnd = strings.Replace(nameEnd, "/", "_", -1)
	return &Rule{
		Name:       urlRewriteRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    actions,
		Conditions: conditions,
	}
}

func ParseRewriteAction(targetUrlPath, valueUrlPath string) string {
	var action string
	if valueUrlPath == "/" {
		action = fmt.Sprintf("tcl:[ expr {[string match [HTTP::uri] %s ] ? [regsub %s [HTTP::uri] / ] : [regsub %s [HTTP::uri] \"\" ] }]", targetUrlPath,
			targetUrlPath, targetUrlPath)
	} else {
		action = fmt.Sprintf("tcl:[regsub %s [HTTP::uri] %s ]", targetUrlPath, valueUrlPath)
	}
	return action
}

func ProcessAppRoot(target, value, poolName string, rsType string) Rules {
	var rules []*Rule
	var redirectConditions []*condition
	var forwardConditions []*condition

	targetURL := ParseAnnotationURL(target)
	valueURL := ParseAnnotationURL(value)

	if rsType == Route && targetURL.Path != "" {
		return rules
	}
	if valueURL.Host != "" {
		return rules
	}
	if valueURL.Path == "" {
		return rules
	}

	rootCondition := &condition{
		Name:    "0",
		Equals:  true,
		HTTPURI: true,
		Index:   0,
		Path:    true,
		Request: true,
		Values:  []string{"/"},
	}

	if targetURL.Host != "" {
		redirectConditions = append(redirectConditions, &condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{targetURL.Host},
		})
		rootCondition.Name = "1"
	}
	redirectConditions = append(redirectConditions, rootCondition)
	redirectAction := &action{
		Name:      "0",
		HttpReply: true,
		Location:  valueURL.Path,
		Redirect:  true,
		Request:   true,
	}
	nameEnd := target

	nameEnd = strings.Replace(nameEnd, "/", "_", -1)
	rules = append(rules, &Rule{
		Name:       appRootRedirectRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    []*action{redirectAction},
		Conditions: redirectConditions,
	})

	pathCondition := &condition{
		Name:    "0",
		Equals:  true,
		HTTPURI: true,
		Index:   0,
		Path:    true,
		Request: true,
		Values:  []string{valueURL.Path},
	}

	if targetURL.Host != "" {
		forwardConditions = append(forwardConditions, &condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{targetURL.Host},
		})
		pathCondition.Name = "1"
	}
	forwardConditions = append(forwardConditions, pathCondition)
	forwardAction := &action{
		Forward: true,
		Name:    "0",
		Pool:    poolName,
		Request: true,
	}

	rules = append(rules, &Rule{
		Name:       appRootForwardRulePrefix + nameEnd,
		FullURI:    target,
		Actions:    []*action{forwardAction},
		Conditions: forwardConditions,
	})

	return rules
}

func (rsCfg *ResourceConfig) prepareRouteRules(route *routeapi.Route) (rule, urlRewriteRule *Rule, appRootRules []*Rule) {

	uri := route.Spec.Host + route.Spec.Path
	var err error
	poolName := rsCfg.Pools[0].Name

	rule, err = createRule(uri, poolName, FormatRouteRuleName(route, route.Spec.Path), HTTPRequest)
	if nil != err {
		log.Errorf("Error configuring rule for Route: %v %v", route.Name, err)
		return
	}
	// todo : optimise this logic
	// Handle url-rewrite annotation
	if urlRewrite, ok := route.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {

		urlRewriteMap := ParseAppRootURLRewriteAnnotations(urlRewrite)
		if len(urlRewriteMap) == 1 {
			if urlRewriteVal, ok := urlRewriteMap["single"]; ok {
				urlRewriteRule = ProcessURLRewrite(uri, urlRewriteVal, Route)
			}
		}
	}

	// Handle app-root annotation
	if appRoot, ok := route.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {

		ruleName := FormatRouteRuleName(route, appRoot)
		appRootRule, err := createRedirectRule(uri, appRoot, ruleName)
		if nil != err {
			log.Errorf("Error configuring redirect rule: %v", err)
			return
		}
		appRootRules = append(appRootRules, appRootRule)
	}
	return rule, urlRewriteRule, appRootRules

}

func (ctlr *Controller) prepareRoutePolicies(
	route *routeapi.Route,
	rule *Rule,
	urlRewriteRule *Rule,
	appRootRules Rules,
	protocol string,
	rsCfg *ResourceConfig,
) {
	tls := route.Spec.TLS
	partition := rsCfg.Virtual.Partition

	var policyName string

	if protocol == "http" {
		policyName = InsecureRoutesPolicyName
	} else {
		policyName = SecureRoutesPolicyName
	}

	if protocol == "http" {
		if nil == tls || len(tls.Termination) == 0 {
			rsCfg.AddRuleToPolicy(policyName, rsCfg.Virtual.Partition, &Rules{rule})
			SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rsCfg, false)

		} else {
			// Handle redirect policy for edge. Reencrypt and passthrough do not
			// support redirect policies, despite what the OpenShift docs say.
			if tls.Termination == routeapi.TLSTerminationEdge {
				// edge supports 'allow' and 'redirect'
				switch tls.InsecureEdgeTerminationPolicy {
				case routeapi.InsecureEdgeTerminationPolicyAllow:
					rsCfg.AddRuleToPolicy(policyName, rsCfg.Virtual.Partition, &Rules{rule})
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rsCfg, false)

				case routeapi.InsecureEdgeTerminationPolicyRedirect:
					redirectIRuleName := JoinBigipPath(partition,
						HttpRedirectIRuleName)
					rsCfg.addIRule(HttpRedirectIRuleName, partition,
						httpRedirectRouteIRule(DEFAULT_HTTPS_PORT, partition, ctlr.Agent.userAgent))
					rsCfg.addInternalDataGroup(HttpsRedirectDgName, partition)
					rsCfg.Virtual.AddIRule(redirectIRuleName)
					// TLS config indicates to forward http to https.
					//TODO: revisit if svcFwdRulesMap is needed
					//path := "/"
					//if route.Spec.Path != "" {
					//	path = route.Spec.Path
					//}
					//svcFwdRulesMap.AddEntry(route.ObjectMeta.Namespace, route.Spec.To.Name,
					//	route.Spec.Host, path)
					rsCfg.AddRuleToPolicy(policyName, rsCfg.Virtual.Partition, &Rules{rule})
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rsCfg, true)
				}
			}
		}
	} else {
		// https
		if nil != tls {
			//passThroughIRuleName := JoinBigipPath(partition,
			//	SslPassthroughIRuleName)
			//switch tls.Termination {
			//case routeapi.TLSTerminationEdge:
			//	if abDeployment {
			//		appMgr.addIRule(
			//			AbDeploymentPathIRuleName, partition, appMgr.abDeploymentPathIRule())
			//		appMgr.addInternalDataGroup(AbDeploymentDgName, partition)
			//		rc.Virtual.AddIRule(abPathIRuleName)
			//	} else {
			//		appMgr.addIRule(
			//			SslPassthroughIRuleName, partition, appMgr.sslPassthroughIRule())
			//		appMgr.addInternalDataGroup(EdgeHostsDgName, partition)
			//		appMgr.addInternalDataGroup(EdgeServerSslDgName, partition)
			//		rc.Virtual.AddIRule(passThroughIRuleName)
			//		rc.AddRuleToPolicy(policyName, rule)
			//		SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, false)
			//	}
			//case routeapi.TLSTerminationPassthrough:
			//	appMgr.addIRule(
			//		SslPassthroughIRuleName, partition, appMgr.sslPassthroughIRule())
			//	appMgr.addInternalDataGroup(PassthroughHostsDgName, DEFAULT_PARTITION)
			//	rc.Virtual.AddIRule(passThroughIRuleName)
			//case routeapi.TLSTerminationReencrypt:
			//	appMgr.addIRule(
			//		SslPassthroughIRuleName, partition, appMgr.sslPassthroughIRule())
			//	appMgr.addInternalDataGroup(ReencryptHostsDgName, partition)
			//	appMgr.addInternalDataGroup(ReencryptServerSslDgName, partition)
			//	rc.Virtual.AddIRule(passThroughIRuleName)
			//	if !abDeployment {
			//		rc.AddRuleToPolicy(policyName, rule)
			//		SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, false)
			//	}
			//}
		}
	}

	// Add whitelist or allow source condition
	var whitelistSourceRanges []string
	if sourceRange, ok := route.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	} else if sourceRange, ok := route.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	}
	if len(whitelistSourceRanges) > 0 {
		for _, pol := range rsCfg.Policies {
			if pol.Name == policyName {
				for i, rl := range pol.Rules {
					if rl.FullURI == rule.FullURI && !strings.HasSuffix(rl.Name, "-reset") {
						origCond := make([]*condition, len(rl.Conditions))
						copy(origCond, rl.Conditions)
						cond := condition{
							Tcp:     true,
							Address: true,
							Matches: true,
							Name:    "0",
							Values:  whitelistSourceRanges,
						}
						var found bool
						for _, existingCond := range origCond {
							if reflect.DeepEqual(existingCond, cond) {
								found = true
								break
							}
						}

						if !found {
							rl.Conditions = append(rl.Conditions, &cond)
						}

						// Add reset traffic rule immediately after this rule
						if (len(pol.Rules) > i+1 && pol.Rules[i+1].Name != rl.Name+"-reset") ||
							i == len(pol.Rules)-1 {
							reset := &Rule{
								Name:    rl.Name + "-reset",
								FullURI: rl.FullURI,
								Actions: []*action{{
									Name:    "0",
									Forward: true,
									Request: true,
									Reset:   true,
								}},
								Conditions: origCond,
							}
							if i == len(pol.Rules)-1 {
								pol.Rules = append(pol.Rules, reset)
							} else {
								pol.Rules = append(pol.Rules, &Rule{})
								copy(pol.Rules[i+2:], pol.Rules[i+1:])
								pol.Rules[i+1] = reset
							}
						}
					}
				}
				var found bool
				for _, val := range pol.Requires {
					if val == "tcp" {
						found = true
						break
					}
				}
				if !found {
					pol.Requires = append(pol.Requires, "tcp")
				}
				rsCfg.SetPolicy(pol)
				break
			}
		}
	}
}

func ParseWhitelistSourceRangeAnnotations(annotation string) []string {
	var annotationVals []string

	numSeps := strings.Count(annotation, ",")
	if numSeps > 0 {
		splits := strings.Split(annotation, ",")
		for _, val := range splits {
			val = strings.TrimSpace(val)
			_, _, err := net.ParseCIDR(val)
			if err != nil {
				log.Infof("[RESOURCE] Annotation: %s value: %s not properly formatted should be in CIDR format, skipping", annotation, val)
			}
			annotationVals = append(annotationVals, val)
		}
	} else if numSeps == 0 {
		annotationVals = append(annotationVals, annotation)
	} else {
		log.Warningf("[RESOURCE] Annotation: %s improperly formatted should be single value or comma separated values, not processing", annotation)
	}

	return annotationVals
}

// todo : check if httpRedirectIrule can be modified a little
func httpRedirectRouteIRule(port int32, partition string, agent string) string {
	// The key in the data group is the host name or * to match all.
	// The data is a list of paths for the host delimited by '|' or '/' for all.
	dgName := "/" + partition
	if agent == "as3" {
		dgName += "/Shared"
	}
	dgName += "/https_redirect_dg"
	iRuleCode := fmt.Sprintf(`
		when HTTP_REQUEST {
			
			# check if there is an entry in data-groups to accept requests from all domains.
			# */ represents [* -> Any host / -> default path]
			set allHosts [class match -value "*/" equals %[1]s]
			if {$allHosts != ""} {
				HTTP::redirect https://[getfield [HTTP::host] ":" 1]:443[HTTP::uri]
				return
			}
			set host [HTTP::host]
			set path [HTTP::path]
			# Check for the combination of host and path.
			append host $path
			# Find the number of "/" in the hostpath
			set rc 0
			foreach x [split $host {}] {
			    if {$x eq "/"} {
					   incr rc
				   }
			}
			# Compares the hostpath with the entries in %[1]s
			for {set i $rc} {$i >= 0} {incr i -1} {
				set paths [class match -value $host equals %[1]s] 
				# Check if host with combination of "/" matches %[1]s
				if {$paths == ""} {
					set hosts ""
					append hosts $host "/"
					set paths [class match -value $hosts equals %[1]s] 
				}
				# Trim the uri to last slash
				if {$paths == ""} {
					set host [
						string range $host 0 [
							expr {[string last "/" $host]-1}
						]
					]
				}
				else {
					break
				}
			}
			if {$paths != ""} {
				set redir 0
				set prefix ""
				foreach s [split $paths "|"] {
					# See if the request path starts with the prefix
					append prefix "^" $s "($|/*)"
					if {[HTTP::path] matches_regex $prefix} {
						set redir 1
						break
					}
				}
				if {$redir == 1} {
					HTTP::redirect https://[getfield [HTTP::host] ":" 1]:%[2]d[HTTP::uri]
				}
			}
		}`, dgName, port)

	return iRuleCode
}

func SetAnnotationRulesForRoute(
	policyName string,
	urlRewriteRule *Rule,
	appRootRules Rules,
	rc *ResourceConfig,
	skipUrlRewriteRule bool,
) {
	if len(appRootRules) == 2 {
		rc.AddRuleToPolicy(policyName, rc.Virtual.Partition, &appRootRules)
	}
	if urlRewriteRule != nil && skipUrlRewriteRule != true {
		rc.AddRuleToPolicy(policyName, rc.Virtual.Partition, &Rules{urlRewriteRule})
	}
}

// GetServicePort returns the port number, for a given port name,
// else, returns the first port found for a Route's service.
func (ctlr *Controller) GetServicePort(
	ns string,
	svcName string,
	portName string,
	rscType string,
) (int32, error) {
	key := ns + "/" + svcName
	svcIndexer := ctlr.esInformers[ns].svcInformer.GetIndexer()
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
	}
	return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
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

func (ctlr *Controller) validateAssociatedRoutes(currentRoute *routeapi.Route, allRoutes []*routeapi.Route, isDeleted bool) []*routeapi.Route {
	var depRoutes []*routeapi.Route
	uniqueHostPathMap := map[string]struct{}{}
	for _, route := range allRoutes {
		// skip the deleted virtual in the event of deletion
		if isDeleted && route.Name == currentRoute.Name {
			continue
		}
		// TODO: add combinations for a/b - svc weight ; valid svcs or not
		if _, found := uniqueHostPathMap[route.Spec.Host+route.Spec.Path]; found {
			log.Errorf(" Discarding route %v due to duplicate host %v, path %v combination", route.Name, route.Spec.Host, route.Spec.To)
			continue
		} else {
			uniqueHostPathMap[route.Spec.Host+route.Spec.Path] = struct{}{}
			depRoutes = append(depRoutes, route)
		}
	}
	return depRoutes
}

// return the services associated with a route (names + weight)
func GetRouteServices(route *routeapi.Route) []RouteService {
	numOfSvcs := 1
	if route.Spec.AlternateBackends != nil {
		numOfSvcs += len(route.Spec.AlternateBackends)
	}
	svcs := make([]RouteService, numOfSvcs)

	svcIndex := 0
	if route.Spec.AlternateBackends != nil {
		for _, svc := range route.Spec.AlternateBackends {
			svcs[svcIndex].Name = svc.Name
			svcs[svcIndex].Weight = int(*(svc.Weight))
			svcIndex = svcIndex + 1
		}
	}
	svcs[svcIndex].Name = route.Spec.To.Name
	if route.Spec.To.Weight != nil {
		svcs[svcIndex].Weight = int(*(route.Spec.To.Weight))
	} else {
		// Older versions of openshift do not have a weight field
		// so we will basically ignore it.
		svcs[svcIndex].Weight = 0
	}

	return svcs
}

// Verify if the service is associated with the route as AlternateBackend
func IsABServiceOfRoute(route *routeapi.Route, expSvcName string) bool {
	for _, svc := range route.Spec.AlternateBackends {
		if expSvcName == svc.Name {
			return true
		}
	}
	return false
}

// format the Rule name for a Route
func FormatRouteRuleName(route *routeapi.Route, path string) string {
	ruleName := fmt.Sprintf("openshift_route_%s_%s", route.ObjectMeta.Namespace,
		route.Spec.Host)
	if path != "" {
		ruleName = ruleName + path
	}
	return AS3NameFormatter(ruleName)
}

// format the pool name for a Route
func FormatRoutePoolName(route *routeapi.Route) string {
	svcName := route.Spec.To.Name
	return fmt.Sprintf("openshift_%s_%s", route.Namespace, svcName)
}
