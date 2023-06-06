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
	"strconv"
	"strings"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	routeapi "github.com/openshift/api/route/v1"
	"k8s.io/client-go/tools/cache"
)

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
		policyName = InsecurePolicyName
		rsName = routeConfig.HttpVs
	} else {
		policyName = SecurePolicyName
		rsName = routeConfig.HttpsVs
	}

	var backendPort int32
	var err error
	if route.Spec.Port != nil {
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			backendPort = route.Spec.Port.TargetPort.IntVal
		} else {
			backendPort, err = GetServicePort(route.Namespace, svcName, svcIndexer, strVal, ResourceTypeRoute)
			if nil != err {
				return &rsCfg, err, Pool{}
			}
		}
	} else {
		backendPort, err = GetServicePort(route.Namespace, svcName, svcIndexer, "", ResourceTypeRoute)
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
	if oldCfg, exists := resources.GetByName(NameRef{Name: rsName, Partition: DEFAULT_PARTITION}); exists {
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
		rsCfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port, true)
		rsCfg.Pools = append(rsCfg.Pools, pool)
	}

	abDeployment := IsRouteABDeployment(route)
	appMgr.handleRouteRules(&rsCfg,
		route,
		pStruct.protocol,
		policyName,
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
				SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, false)
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
						SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, false)
					}
				case routeapi.InsecureEdgeTerminationPolicyRedirect:
					redirectIRuleName := JoinBigipPath(DEFAULT_PARTITION,
						HttpRedirectIRuleName)
					appMgr.addIRule(HttpRedirectIRuleName, DEFAULT_PARTITION,
						httpRedirectIRule(DEFAULT_HTTPS_PORT, DEFAULT_PARTITION, appMgr.TeemData.Agent))
					appMgr.addInternalDataGroup(HttpsRedirectDgName, DEFAULT_PARTITION)
					rc.Virtual.AddIRule(redirectIRuleName)
					// TLS config indicates to forward http to https.
					path := "/"
					if route.Spec.Path != "" {
						path = route.Spec.Path
					}
					svcFwdRulesMap.AddEntry(route.ObjectMeta.Namespace, route.Spec.To.Name,
						route.Spec.Host, path)
					// Add redirect datagroup support for host header match as host and host:port
					hostPort := route.Spec.Host + ":" + strconv.Itoa(int(DEFAULT_HTTP_PORT))
					svcFwdRulesMap.AddEntry(route.ObjectMeta.Namespace, route.Spec.To.Name,
						hostPort, path)
					rc.AddRuleToPolicy(policyName, rule)
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, true)
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
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, false)
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
					SetAnnotationRulesForRoute(policyName, urlRewriteRule, appRootRules, rc, false)
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
