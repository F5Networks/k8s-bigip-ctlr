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

package appmanager

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	routeapi "github.com/openshift/api/route/v1"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
)

// Create a ResourceConfig based on an Ingress resource config
func (appMgr *Manager) createRSConfigFromIngress(
	ing *v1beta1.Ingress,
	resources *Resources,
	ns string,
	svcIndexer cache.Indexer,
	pStruct portStruct,
	defaultIP,
	snatPoolName string,
) *ResourceConfig {
	if class, ok := ing.ObjectMeta.Annotations[K8sIngressClass]; ok == true {
		if class != appMgr.ingressClass {
			return nil
		}
	} else {
		// at this point we dont have k8sIngressClass defined in Ingress definition.
		// So check whether we need to process those ingress or not.
		if appMgr.manageIngressClassOnly {
			return nil
		}
	}
	var cfg ResourceConfig
	var balance string
	if bal, ok := ing.ObjectMeta.Annotations[F5VsBalanceAnnotation]; ok == true {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	if partition, ok := ing.ObjectMeta.Annotations[F5VsPartitionAnnotation]; ok == true {
		cfg.Virtual.Partition = partition
	} else {
		cfg.Virtual.Partition = DEFAULT_PARTITION
	}

	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok == true {
		if addr == "controller-default" {
			bindAddr = defaultIP
		} else {
			bindAddr = addr
		}
	} else {
		// if no annotation is provided, take the IP from controller config.
		if defaultIP != "" && defaultIP != "0.0.0.0" {
			bindAddr = defaultIP
		} else {
			// Ingress IP is not given in either as controller deployment option or in annotation, exit with error log.
			log.Error("Ingress IP Address is not provided. Unable to process ingress resources. " +
				"Either configure controller with 'default-ingress-ip' or Ingress with annotation 'virtual-server.f5.com/ip'.")
		}
	}

	cfg.Virtual.Name = FormatIngressVSName(bindAddr, pStruct.port)

	// Handle url-rewrite annotation
	var urlRewriteMap map[string]string
	if urlRewrite, ok := ing.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
		urlRewriteMap = ParseAppRootURLRewriteAnnotations(urlRewrite)
	}

	// Handle whitelist-source-range annotation
	// Handle allow-source-range annotation
	var whitelistSourceRanges []string
	if sourceRange, ok := ing.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	} else if sourceRange, ok := ing.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	}

	// Handle app-root annotation
	var appRootMap map[string]string
	if appRoot, ok := ing.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
		appRootMap = ParseAppRootURLRewriteAnnotations(appRoot)
	}

	// Create our pools and policy/rules based on the Ingress
	var pools Pools
	var plcy *Policy
	var rules *Rules
	var ssPoolName string

	urlRewriteRefs := make(map[string]string)
	appRootRefs := make(map[string][]string)
	if nil != ing.Spec.Rules { //multi-service
		for _, rule := range ing.Spec.Rules {
			if nil != rule.IngressRuleValue.HTTP {
				for _, path := range rule.IngressRuleValue.HTTP.Paths {
					exists := false
					for _, pl := range pools {
						if pl.ServiceName == path.Backend.ServiceName &&
							pl.ServicePort == path.Backend.ServicePort.IntVal {
							exists = true
						}
					}
					if exists {
						continue
					}
					// If service doesn't exist, don't create a pool for it
					sKey := ns + "/" + path.Backend.ServiceName
					_, svcFound, _ := svcIndexer.GetByKey(sKey)
					if !svcFound {
						continue
					}
					pool := Pool{
						Name: FormatIngressPoolName(
							ing.ObjectMeta.Namespace,
							path.Backend.ServiceName,
						),
						Partition:   cfg.Virtual.Partition,
						Balance:     balance,
						ServiceName: path.Backend.ServiceName,
						ServicePort: path.Backend.ServicePort.IntVal,
					}
					pools = append(pools, pool)
				}
			}
		}

		rules, urlRewriteRefs, appRootRefs = processIngressRules(
			&ing.Spec,
			urlRewriteMap,
			whitelistSourceRanges,
			appRootMap,
			pools,
			cfg.Virtual.Partition,
		)
		plcy = CreatePolicy(*rules, cfg.Virtual.Name, cfg.Virtual.Partition)
	} else { // single-service
		pool := Pool{
			Name: FormatIngressPoolName(
				ing.ObjectMeta.Namespace,
				ing.Spec.Backend.ServiceName,
			),
			Partition:   cfg.Virtual.Partition,
			Balance:     balance,
			ServiceName: ing.Spec.Backend.ServiceName,
			ServicePort: ing.Spec.Backend.ServicePort.IntVal,
		}
		ssPoolName = pool.Name
		pools = append(pools, pool)
		cfg.Virtual.PoolName = JoinBigipPath(cfg.Virtual.Partition, ssPoolName)

		// Process app root annotation
		if len(appRootMap) == 1 {
			if appRootVal, ok := appRootMap["single"]; ok == true {
				appRootRules := ProcessAppRoot("", appRootVal, fmt.Sprintf("/%s/%s", pool.Partition, pool.Name), SingleServiceIngressType)
				rules = &appRootRules
				if len(appRootRules) == 2 {
					plcy = CreatePolicy(appRootRules, cfg.Virtual.Name, cfg.Virtual.Partition)
					appRootRefs[pool.Name] = append(appRootRefs[pool.Name], appRootRules[0].Name)
					appRootRefs[pool.Name] = append(appRootRefs[pool.Name], appRootRules[1].Name)
				}
			}
		}
	}
	cfg.MetaData.IngName = ing.ObjectMeta.Name

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we already have any Ingresses for this IP:Port
	if oldCfg, exists := resources.GetByName(cfg.Virtual.Name); exists {
		// If we do, use an existing config
		cfg.CopyConfig(oldCfg)

		// If any of the new pools don't already exist, add them
		for _, newPool := range pools {
			found := false
			for i, pl := range cfg.Pools {
				if pl.Name == newPool.Name {
					found = true
					if pl.Balance != newPool.Balance {
						cfg.Pools[i].Balance = newPool.Balance
					}
					break
				}
			}
			if !found {
				cfg.Pools = append(cfg.Pools, newPool)
			}
		}
		if len(cfg.Pools) > 1 && nil != ing.Spec.Rules {
			cfg.Virtual.PoolName = ""
		} else if nil == ing.Spec.Rules {
			// If updating an Ingress from multi-service to single-service, we need to
			// reset the virtual's default pool
			cfg.Virtual.PoolName = JoinBigipPath(cfg.Virtual.Partition, ssPoolName)
		}

		// If any of the new rules already exist, update them; else add them
		if len(cfg.Policies) > 0 && rules != nil {
			policy := cfg.Policies[0]
			for _, newRule := range *rules {
				found := false
				for i, rl := range policy.Rules {
					if rl.Name == newRule.Name || (!IsAnnotationRule(rl.Name) &&
						!IsAnnotationRule(newRule.Name) && rl.FullURI == newRule.FullURI) {
						found = true
						policy.Rules[i] = newRule
						break
					}
				}
				if !found {
					cfg.AddRuleToPolicy(policy.Name, newRule)
				}
			}
		} else if len(cfg.Policies) == 0 && plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	} else { // This is a new VS for an Ingress
		cfg.MetaData.ResourceType = "ingress"
		cfg.Virtual.Enabled = true
		SetProfilesForMode("http", &cfg)
		cfg.Virtual.SourceAddrTranslation = SetSourceAddrTranslation(snatPoolName)
		cfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		cfg.Pools = append(cfg.Pools, pools...)
		if plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	}

	if len(urlRewriteRefs) > 0 || len(appRootRefs) > 0 {
		cfg.MergeRules(appMgr.mergedRulesMap)
	}
	// Sort the rules
	for _, policy := range cfg.Policies {
		sort.Sort(sort.Reverse(&policy.Rules))
	}
	return &cfg
}

// Return value is whether or not a custom profile was updated
func (appMgr *Manager) handleIngressTls(
	rsCfg *ResourceConfig,
	ing *v1beta1.Ingress,
	svcFwdRulesMap ServiceFwdRuleMap,
) bool {
	if 0 == len(ing.Spec.TLS) {
		// Nothing to do if no TLS section
		return false
	}
	if nil == rsCfg.Virtual.VirtualAddress ||
		rsCfg.Virtual.VirtualAddress.BindAddr == "" {
		// Nothing to do for pool-only mode
		return false
	}

	var httpsPort int32
	if port, ok :=
		ing.ObjectMeta.Annotations[F5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// If we are processing the HTTPS server,
	// then we don't need a redirect policy, only profiles
	if rsCfg.Virtual.VirtualAddress.Port == httpsPort {
		var cpUpdated, updateState bool
		for _, tls := range ing.Spec.TLS {
			// Check if profile is contained in a Secret
			if appMgr.useSecrets {
				secret := appMgr.rsrcSSLCtxt[tls.SecretName]
				if secret == nil {
					// No secret, so we assume the profile is a BIG-IP default
					log.Debugf("[CORE] No Secret with name '%s' in namespace '%s', "+
						"parsing secretName as path instead.",
						tls.SecretName, ing.ObjectMeta.Namespace)
					profRef := ConvertStringToProfileRef(
						tls.SecretName, CustomProfileClient, ing.ObjectMeta.Namespace)
					rsCfg.Virtual.AddOrUpdateProfile(profRef)
					continue
				}
				var err error
				err, cpUpdated = appMgr.createSecretSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("[CORE] %v", err)
					continue
				}
				updateState = updateState || cpUpdated
				profRef := ProfileRef{
					Partition: rsCfg.Virtual.Partition,
					Name:      tls.SecretName,
					Context:   CustomProfileClient,
					Namespace: ing.ObjectMeta.Namespace,
				}
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				secretName := FormatIngressSslProfileName(tls.SecretName)
				profRef := ConvertStringToProfileRef(
					secretName, CustomProfileClient, ing.ObjectMeta.Namespace)
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			}
		}
		if serverProfile, ok :=
			ing.ObjectMeta.Annotations[F5ServerSslProfileAnnotation]; ok == true {
			secretName := FormatIngressSslProfileName(serverProfile)
			profRef := ConvertStringToProfileRef(
				secretName, CustomProfileServer, ing.ObjectMeta.Namespace)
			rsCfg.Virtual.AddOrUpdateProfile(profRef)
		}
		return cpUpdated
	}

	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressAllowHttp, false)
	// -----------------------------------------------------------------
	// | State | sslRedirect | allowHttp | Description                 |
	// -----------------------------------------------------------------
	// |   1   |     F       |    F      | Just HTTPS, nothing on HTTP |
	// -----------------------------------------------------------------
	// |   2   |     T       |    F      | HTTP redirects to HTTPS     |
	// -----------------------------------------------------------------
	// |   2   |     T       |    T      | Honor sslRedirect == true   |
	// -----------------------------------------------------------------
	// |   3   |     F       |    T      | Both HTTP and HTTPS         |
	// -----------------------------------------------------------------
	if sslRedirect {
		// State 2, set HTTP redirect iRule
		log.Debugf("[CORE] TLS: Applying HTTP redirect iRule.")
		ruleName := fmt.Sprintf("%s_%d", HttpRedirectIRuleName, httpsPort)
		appMgr.addIRule(ruleName, DEFAULT_PARTITION,
			httpRedirectIRule(httpsPort))
		appMgr.addInternalDataGroup(HttpsRedirectDgName, DEFAULT_PARTITION)
		ruleName = JoinBigipPath(DEFAULT_PARTITION, ruleName)
		rsCfg.Virtual.AddIRule(ruleName)
		if nil != ing.Spec.Backend {
			svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
				ing.Spec.Backend.ServiceName, "\\*", "/")
		}
		for _, rul := range ing.Spec.Rules {
			if nil != rul.HTTP {
				host := rul.Host
				for _, path := range rul.HTTP.Paths {
					svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
						path.Backend.ServiceName, host, path.Path)
				}
			}
		}
	} else if allowHttp {
		// State 3, do not apply any policy
		log.Debugf("[CORE] TLS: Not applying any policies.")
	}
	return false
}

func (appMgr *Manager) createRSConfigFromRoute(
	route *routeapi.Route,
	svcName string,
	resources *Resources,
	routeConfig RouteConfig,
	pStruct portStruct,
	svcIndexer cache.Indexer,
	svcFwdRulesMap ServiceFwdRuleMap,
	snatPoolName string,
) (*ResourceConfig, error, Pool) {
	var rsCfg ResourceConfig
	rsCfg.MetaData.RouteProfs = make(map[RouteKey]string)
	var policyName, rsName string

	if pStruct.protocol == "http" {
		policyName = "openshift_insecure_routes"
		rsName = routeConfig.HttpVs
	} else {
		policyName = "openshift_secure_routes"
		rsName = routeConfig.HttpsVs
	}

	var backendPort int32
	var err error
	if route.Spec.Port != nil {
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			backendPort = route.Spec.Port.TargetPort.IntVal
		} else {
			backendPort, err = GetServicePort(route, svcName, svcIndexer, strVal)
			if nil != err {
				return &rsCfg, err, Pool{}
			}
		}
	} else {
		backendPort, err = GetServicePort(route, svcName, svcIndexer, "")
		if nil != err {
			return &rsCfg, err, Pool{}
		}
	}
	var balance string
	if bal, ok := route.ObjectMeta.Annotations[F5VsBalanceAnnotation]; ok {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	// Create the pool
	pool := Pool{
		Name:        FormatRoutePoolName(route.ObjectMeta.Namespace, svcName),
		Partition:   DEFAULT_PARTITION,
		Balance:     balance,
		ServiceName: svcName,
		ServicePort: backendPort,
	}
	// Create the rule
	uri := route.Spec.Host + route.Spec.Path

	var rule *Rule
	if IsABServiceOfRoute(route, svcName) {
		poolName := FormatRoutePoolName(route.ObjectMeta.Namespace, route.Spec.To.Name)
		rule, err = CreateRule(uri, poolName, pool.Partition, FormatRouteRuleName(route))
	} else {
		rule, err = CreateRule(uri, pool.Name, pool.Partition, FormatRouteRuleName(route))
	}

	if nil != err {
		err = fmt.Errorf("Error configuring rule for Route %s: %v", route.ObjectMeta.Name, err)
		return &rsCfg, err, Pool{}
	}

	// Handle url-rewrite annotation
	var urlRewriteRule *Rule
	if urlRewrite, ok := route.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
		urlRewriteMap := ParseAppRootURLRewriteAnnotations(urlRewrite)
		if len(urlRewriteMap) == 1 {
			if urlRewriteVal, ok := urlRewriteMap["single"]; ok == true {
				urlRewriteRule = ProcessURLRewrite(uri, urlRewriteVal, RouteType)
			}
		}
	}

	// Handle app-root annotation
	var appRootRules []*Rule
	if appRoot, ok := route.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
		appRootMap := ParseAppRootURLRewriteAnnotations(appRoot)
		if len(appRootMap) == 1 {
			if appRootVal, ok := appRootMap["single"]; ok == true {
				appRootRules = ProcessAppRoot(uri, appRootVal, fmt.Sprintf("/%s/%s", pool.Partition, pool.Name), RouteType)
			}
		}
	}

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we have any Routes already saved for this VS type
	if oldCfg, exists := resources.GetByName(rsName); exists {
		// If we do, use an existing config
		rsCfg.CopyConfig(oldCfg)

		// If this pool doesn't already exist, add it
		var found bool
		for i, pl := range rsCfg.Pools {
			if pl.Name == pool.Name {
				// If port has changed, update it
				if pl.ServicePort != pool.ServicePort {
					rsCfg.Pools[i].ServicePort = pool.ServicePort
				}
				if pl.Balance != pool.Balance {
					rsCfg.Pools[i].Balance = pool.Balance
				}
				found = true
				break
			}
		}
		if !found {
			rsCfg.Pools = append(rsCfg.Pools, pool)
		}
	} else { // This is a new VS for a Route
		rsCfg.MetaData.ResourceType = "route"
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.Enabled = true
		SetProfilesForMode("http", &rsCfg)
		rsCfg.Virtual.SourceAddrTranslation = SetSourceAddrTranslation(snatPoolName)
		rsCfg.Virtual.Partition = DEFAULT_PARTITION
		bindAddr := ""
		if routeConfig.RouteVSAddr != "" {
			bindAddr = routeConfig.RouteVSAddr
		}
		rsCfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		rsCfg.Pools = append(rsCfg.Pools, pool)
	}

	abDeployment := IsRouteABDeployment(route)
	appMgr.handleRouteRules(&rsCfg,
		route,
		pStruct.protocol,
		policyName,
		rsName,
		pool.Name,
		rule,
		urlRewriteRule,
		appRootRules,
		svcFwdRulesMap,
		abDeployment)

	return &rsCfg, nil, pool
}

func (appMgr *Manager) handleRouteRules(
	rc *ResourceConfig,
	route *routeapi.Route,
	protocol string,
	policyName string,
	virtualName string,
	poolName string,
	rule *Rule,
	urlRewriteRule *Rule,
	appRootRules []*Rule,
	svcFwdRulesMap ServiceFwdRuleMap,
	abDeployment bool,
) {
	tls := route.Spec.TLS
	abPathIRuleName := JoinBigipPath(DEFAULT_PARTITION, AbDeploymentPathIRuleName)

	if abDeployment {
		rc.DeleteRuleFromPolicy(policyName, rule, appMgr.mergedRulesMap)
	}

	if protocol == "http" {
		if nil == tls || len(tls.Termination) == 0 {
			if abDeployment {
				appMgr.addIRule(
					AbDeploymentPathIRuleName, DEFAULT_PARTITION, appMgr.abDeploymentPathIRule())
				appMgr.addInternalDataGroup(AbDeploymentDgName, DEFAULT_PARTITION)
				rc.Virtual.AddIRule(abPathIRuleName)
			} else {
				rc.AddRuleToPolicy(policyName, rule)
				SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc)
			}
		} else {
			// Handle redirect policy for edge. Reencrypt and passthrough do not
			// support redirect policies, despite what the OpenShift docs say.
			if tls.Termination == routeapi.TLSTerminationEdge {
				// edge supports 'allow' and 'redirect'
				switch tls.InsecureEdgeTerminationPolicy {
				case routeapi.InsecureEdgeTerminationPolicyAllow:
					if abDeployment {
						rc.Virtual.AddIRule(abPathIRuleName)
					} else {
						rc.AddRuleToPolicy(policyName, rule)
						SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc)
					}
				case routeapi.InsecureEdgeTerminationPolicyRedirect:
					redirectIRuleName := JoinBigipPath(DEFAULT_PARTITION,
						HttpRedirectIRuleName)
					appMgr.addIRule(HttpRedirectIRuleName, DEFAULT_PARTITION,
						httpRedirectIRule(DEFAULT_HTTPS_PORT))
					appMgr.addInternalDataGroup(HttpsRedirectDgName, DEFAULT_PARTITION)
					rc.Virtual.AddIRule(redirectIRuleName)
					// TLS config indicates to forward http to https.
					path := "/"
					if route.Spec.Path != "" {
						path = route.Spec.Path
					}
					svcFwdRulesMap.AddEntry(route.ObjectMeta.Namespace, route.Spec.To.Name,
						route.Spec.Host, path)
					rc.AddRuleToPolicy(policyName, rule)
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc)
				}
			}
		}
	} else {
		// https
		if nil != tls {
			passThroughIRuleName := JoinBigipPath(DEFAULT_PARTITION,
				SslPassthroughIRuleName)
			switch tls.Termination {
			case routeapi.TLSTerminationEdge:
				if abDeployment {
					appMgr.addIRule(
						AbDeploymentPathIRuleName, DEFAULT_PARTITION, appMgr.abDeploymentPathIRule())
					appMgr.addInternalDataGroup(AbDeploymentDgName, DEFAULT_PARTITION)
					rc.Virtual.AddIRule(abPathIRuleName)
				} else {
					appMgr.addIRule(
						SslPassthroughIRuleName, DEFAULT_PARTITION, appMgr.sslPassthroughIRule())
					appMgr.addInternalDataGroup(EdgeHostsDgName, DEFAULT_PARTITION)
					appMgr.addInternalDataGroup(EdgeServerSslDgName, DEFAULT_PARTITION)
					rc.Virtual.AddIRule(passThroughIRuleName)
					rc.AddRuleToPolicy(policyName, rule)
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc)
				}
			case routeapi.TLSTerminationPassthrough:
				appMgr.addIRule(
					SslPassthroughIRuleName, DEFAULT_PARTITION, appMgr.sslPassthroughIRule())
				appMgr.addInternalDataGroup(PassthroughHostsDgName, DEFAULT_PARTITION)
				rc.Virtual.AddIRule(passThroughIRuleName)
			case routeapi.TLSTerminationReencrypt:
				appMgr.addIRule(
					SslPassthroughIRuleName, DEFAULT_PARTITION, appMgr.sslPassthroughIRule())
				appMgr.addInternalDataGroup(ReencryptHostsDgName, DEFAULT_PARTITION)
				appMgr.addInternalDataGroup(ReencryptServerSslDgName, DEFAULT_PARTITION)
				rc.Virtual.AddIRule(passThroughIRuleName)
				if !abDeployment {
					rc.AddRuleToPolicy(policyName, rule)
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc)
				}
			}
		}
	}
	if urlRewriteRule != nil || len(appRootRules) != 0 {
		rc.MergeRules(appMgr.mergedRulesMap)
	}

	// Add whitelist or allow source condition
	var whitelistSourceRanges []string
	if sourceRange, ok := route.ObjectMeta.Annotations[F5VsWhitelistSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	} else if sourceRange, ok := route.ObjectMeta.Annotations[F5VsAllowSourceRangeAnnotation]; ok {
		whitelistSourceRanges = ParseWhitelistSourceRangeAnnotations(sourceRange)
	}
	if len(whitelistSourceRanges) > 0 {
		for _, pol := range rc.Policies {
			if pol.Name == policyName {
				for i, rl := range pol.Rules {
					if rl.FullURI == rule.FullURI && !strings.HasSuffix(rl.Name, "-reset") {
						origCond := make([]*Condition, len(rl.Conditions))
						copy(origCond, rl.Conditions)
						cond := Condition{
							Tcp:     true,
							Address: true,
							Matches: true,
							Name:    "0",
							Values:  whitelistSourceRanges,
						}
						if !Contains(rl.Conditions, cond) {
							rl.Conditions = append(rl.Conditions, &cond)
						}

						// Add reset traffic rule immediately after this rule
						if (len(pol.Rules) > i+1 && pol.Rules[i+1].Name != rl.Name+"-reset") ||
							i == len(pol.Rules)-1 {
							reset := &Rule{
								Name:    rl.Name + "-reset",
								FullURI: rl.FullURI,
								Actions: []*Action{{
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
				if !Contains(pol.Requires, "tcp") {
					pol.Requires = append(pol.Requires, "tcp")
				}
				rc.SetPolicy(pol)
				break
			}
		}
	}
}

// Creates an IRule if it doesn't already exist
func (appMgr *Manager) addIRule(name, partition, rule string) {
	appMgr.irulesMutex.Lock()
	defer appMgr.irulesMutex.Unlock()

	key := NameRef{
		Name:      name,
		Partition: partition,
	}
	if _, found := appMgr.irulesMap[key]; !found {
		appMgr.irulesMap[key] = NewIRule(name, partition, rule)
	}
}

// Creates an InternalDataGroup if it doesn't already exist
func (appMgr *Manager) addInternalDataGroup(name, partition string) {
	appMgr.intDgMutex.Lock()
	defer appMgr.intDgMutex.Unlock()

	key := NameRef{
		Name:      name,
		Partition: partition,
	}
	if _, found := appMgr.intDgMap[key]; !found {
		appMgr.intDgMap[key] = make(DataGroupNamespaceMap)
	}
}
