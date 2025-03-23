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
	"fmt"

	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

// prepareVirtualServerRules prepares LTM Policy rules for VirtualServer
func (ctlr *Controller) prepareVirtualServerRules(
	vs *cisapiv1.VirtualServer,
	rsCfg *ResourceConfig,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)
	var redirects []*Rule

	appRoot := "/"

	// Consider the primary host as well as the host aliases
	hosts := getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)
	hostAliasesUsed := false
	if len(vs.Spec.HostAliases) > 0 {
		hostAliasesUsed = true
	}
	if vs.Spec.RewriteAppRoot != "" {
		for _, host := range hosts {
			ruleName := formatVirtualServerRuleName(host, vs.Spec.HostGroup, "redirectto", vs.Spec.RewriteAppRoot, hostAliasesUsed)
			rl, err := createRedirectRule(host+appRoot, vs.Spec.RewriteAppRoot, ruleName, rsCfg.Virtual.AllowSourceRange)
			if nil != err {
				log.Errorf("Error configuring redirect rule: %v", err)
				return nil
			}
			redirects = append(redirects, rl)
		}

	}

	for _, pl := range vs.Spec.Pools {
		// Create a rule for each host including host aliases and path combination
		for _, host := range hosts {
			// Service cannot be empty
			if pl.Service == "" {
				continue
			}
			// If not using WAF from policy CR, use Pool Based WAF from VS
			wafPolicy := ""
			if rsCfg.Virtual.WAF == "" {
				wafPolicy = pl.WAF
			}

			uri := host + pl.Path

			path := pl.Path

			if pl.Path == "/" {
				uri = host + vs.Spec.RewriteAppRoot
				path = vs.Spec.RewriteAppRoot
			}
			poolBackends := ctlr.GetPoolBackendsForVS(&pl, vs.ObjectMeta.Namespace)
			skipPool := false
			if (pl.AlternateBackends != nil && len(pl.AlternateBackends) > 0) || ctlr.discoveryMode == Ratio || ctlr.discoveryMode == DefaultMode {
				skipPool = true
			}
			for _, backend := range poolBackends {
				poolName := ctlr.framePoolNameForVS(
					vs.ObjectMeta.Namespace,
					pl,
					vs.Spec.Host,
					backend,
				)
				ruleName := formatVirtualServerRuleName(host, vs.Spec.HostGroup, path, poolName, hostAliasesUsed)
				var err error
				rl, err := createRule(uri, poolName, ruleName, rsCfg.Virtual.AllowSourceRange, wafPolicy, skipPool)
				if nil != err {
					log.Errorf("Error configuring rule: %v", err)
					return nil
				}
				if pl.HostRewrite != "" {
					hostRewriteActions, err := getHostRewriteActions(
						pl.HostRewrite,
						len(rl.Actions),
					)
					if nil != err {
						log.Errorf("Error configuring rule: %v", err)
						return nil
					}
					rl.Actions = append(rl.Actions, hostRewriteActions...)
				}
				if pl.Rewrite != "" {
					rewriteActions, err := getRewriteActions(
						path,
						pl.Rewrite,
						len(rl.Actions),
					)
					if nil != err {
						log.Errorf("Error configuring rule: %v", err)
						return nil
					}
					rl.Actions = append(rl.Actions, rewriteActions...)
				}

				if vs.Spec.HostPersistence.Method != "" {
					if host == "" {
						log.Warning("Host Persistence cannot be configured without hosts")
					} else {
						rewriteActions, err := getHostPersistActions(vs.Spec.HostPersistence)
						if nil != err {
							log.Errorf("Error while configuring host persistence: %v", err)
							return nil
						}
						rl.Actions = append(rl.Actions, rewriteActions...)
					}
				}

				if pl.Path == "/" {
					redirects = append(redirects, rl)
				} else if true == strings.HasPrefix(uri, "*.") {
					wildcards[uri] = rl
				} else {
					rlMap[uri] = rl
				}
			}
		}
	}

	if vs.Spec.RewriteAppRoot != "" && len(redirects) != len(hosts)*2 {
		log.Error("AppRoot path not found for rewriting")
		return nil
	}

	if rlMap[vs.Spec.Host] == nil && len(hosts) != 0 && len(redirects) == 2*len(hosts) {
		rl := &Rule{
			Name:    formatVirtualServerRuleName(vs.Spec.Host, vs.Spec.HostGroup, "", redirects[1].Actions[0].Pool, hostAliasesUsed),
			FullURI: vs.Spec.Host,
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

// format the rule name for VirtualServer
func formatVirtualServerRuleName(hostname, hostGroup, path, pool string, hostAliases bool) string {
	var rule string
	host := hostname
	//if wildcard vs
	if strings.HasPrefix(host, "*") {
		host = strings.Replace(host, "*", "wildcard", 1)
	}
	if hostGroup != "" {
		if !hostAliases {
			host = hostGroup
		} else {
			host = hostGroup + "_" + host
		}
	}
	if path == "" {
		rule = fmt.Sprintf("vs_%s_%s", host, pool)
	} else {
		// Remove the first slash, then replace any subsequent slashes with '_'
		path = strings.TrimPrefix(path, "/")
		path = strings.Replace(path, "/", "_", -1)
		rule = fmt.Sprintf("vs_%s_%s_%s", host, path, pool)
	}

	rule = AS3NameFormatter(rule)
	return rule
}

// Create LTM policy rules
func createRule(uri, poolName, ruleName string, allowSourceRange []string, wafPolicy string, skipPool bool) (*Rule, error) {
	_u := "scheme://" + uri
	_u = strings.TrimSuffix(_u, "/")
	u, err := url.Parse(_u)
	if nil != err {
		return nil, err
	}

	var actions []*action
	var conditions []*condition
	var cond *condition
	if true == strings.HasPrefix(uri, "*.") {
		cond = &condition{
			EndsWith: true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Values:   []string{strings.TrimPrefix(u.Host, "*")},
		}
	} else if u.Host != "" {
		cond = &condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Values:   []string{u.Host},
		}
	}
	if cond != nil {
		cond.Request = true
		conditions = append(conditions, cond)
	}
	if 0 != len(u.EscapedPath()) {
		conditions = append(conditions, createPathSegmentConditions(u)...)
	}
	if len(allowSourceRange) > 0 {
		cond = &condition{
			Tcp:     true,
			Address: true,
			Values:  allowSourceRange,
		}
		conditions = append(conditions, cond)
	}

	// for a/b enabled resource pool will be skipped
	var a action
	if !skipPool {
		a = action{
			Forward: true,
			Name:    "0",
			Pool:    poolName,
			Request: true,
		}
		actions = append(actions, &a)
	} else if wafPolicy == "" {
		// add dummy action
		a = action{
			Log:     true,
			Message: "a/b pool",
			Name:    "0",
			Request: true,
		}
		actions = append(actions, &a)
	}

	// Add WAF rule
	if wafPolicy != "" {
		wafAction := &action{
			WAF:     true,
			Policy:  wafPolicy,
			Request: true,
		}
		actions = append(actions, wafAction)
	}

	rl := Rule{
		Name:       ruleName,
		FullURI:    uri,
		Actions:    actions,
		Conditions: conditions,
	}

	log.Debugf("Configured rule: %v", rl)
	return &rl, nil
}

func createPathSegmentConditions(u *url.URL) []*condition {

	var c []*condition
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	segments := strings.Split(path, "/")

	// Incase of a No-Host Virtual Server Custom Resource with path as "/"
	// Example: vs.Spec.Host = ""  && vs.Spec.Pools[0].path = "/"
	// Create an empty condition(no condition). This will forward the traffic
	// to pool(referred at path "/") when no other conditions are matched.
	if segments[0] == "" {
		return c
	}
	for i, v := range segments {
		c = append(c, &condition{
			Equals:      true,
			HTTPURI:     true,
			PathSegment: true,
			Name:        strconv.Itoa(i + 1),
			Index:       i + 1,
			Request:     true,
			Values:      []string{v},
		})
	}
	return c
}

func createPolicy(rls Rules, policyName, partition string) *Policy {
	plcy := Policy{
		Controls:  []string{PolicyControlForward},
		Legacy:    true,
		Name:      policyName,
		Partition: partition,
		Requires:  []string{"http"},
		Rules:     Rules{},
		Strategy:  "/Common/first-match",
	}

	plcy.AddRules(&rls)

	log.Debugf("Configured policy: %v", plcy)
	return &plcy
}

func getHostPersistActions(hostPersistence cisapiv1.HostPersistence) ([]*action, error) {
	switch hostPersistence.Method {
	case SourceAddress:
		if hostPersistence.PersistMetaData.Netmask == "" || hostPersistence.PersistMetaData.Timeout == 0 {
			return nil, fmt.Errorf("netmask and timeout are required for Source Address persist method")
		}
	case DestinationAddress:
		if hostPersistence.PersistMetaData.Netmask == "" || hostPersistence.PersistMetaData.Timeout == 0 {
			return nil, fmt.Errorf("netmask and timeout are required for Destination Address persist method")
		}
	case CookieInsert:
		if hostPersistence.PersistMetaData.Name == "" || hostPersistence.PersistMetaData.Expiry == "" {
			return nil, fmt.Errorf("name and expiry are required for Cookie Insert persist method")
		}
	case CookieRewrite:
		if hostPersistence.PersistMetaData.Name == "" || hostPersistence.PersistMetaData.Expiry == "" {
			return nil, fmt.Errorf("name and expiry are required for Cookie Rewrite persist methods")
		}
	case CookiePassive:
		if hostPersistence.PersistMetaData.Name == "" {
			return nil, fmt.Errorf("name is required for Cookie Passive persist method")
		}
	case CookieHash:
		if hostPersistence.PersistMetaData.Name == "" || hostPersistence.PersistMetaData.Timeout == 0 || hostPersistence.PersistMetaData.Offset == 0 || hostPersistence.PersistMetaData.Length == 0 {
			return nil, fmt.Errorf("name, timeout, offset, and length are required for Cookie Hash persist method")
		}
	case Universal:
		if hostPersistence.PersistMetaData.Key == "" || hostPersistence.PersistMetaData.Timeout == 0 {
			return nil, fmt.Errorf("key and timeout are required for Universal persist method")
		}
	case Carp:
		if hostPersistence.PersistMetaData.Key == "" || hostPersistence.PersistMetaData.Timeout == 0 {
			return nil, fmt.Errorf("key and timeout are required for Carp persist method")
		}
	case Hash:
		if hostPersistence.PersistMetaData.Key == "" || hostPersistence.PersistMetaData.Timeout == 0 {
			return nil, fmt.Errorf("key and timeout are required for Hash persist method")
		}
	case Disable:
		if hostPersistence.PersistMetaData != (cisapiv1.PersistMetaData{}) {
			return nil, fmt.Errorf("Metadata is not required for none method")
		}
	default:
		return nil, fmt.Errorf("provide a persist method value from sourceAddress, destinationAddress, cookieInsert, cookieRewrite, cookiePassive, cookieHash, universal, hash, and carp")
	}

	return []*action{{
		PersistMethod: hostPersistence.Method,
		Name:          hostPersistence.PersistMetaData.Name,
		Key:           hostPersistence.PersistMetaData.Key,
		Netmask:       hostPersistence.PersistMetaData.Netmask,
		Timeout:       hostPersistence.PersistMetaData.Timeout,
		Length:        hostPersistence.PersistMetaData.Length,
		Offset:        hostPersistence.PersistMetaData.Offset,
		Expiry:        hostPersistence.PersistMetaData.Expiry,
	}}, nil
}

func getRewriteActions(path, rwPath string, actionNameIndex int) ([]*action, error) {

	if rwPath == "" {
		return nil, fmt.Errorf("Empty Path")
	}

	var actions []*action

	if rwPath != "" {
		if path != "" {
			actions = append(actions, &action{
				Name:    fmt.Sprintf("%d", actionNameIndex),
				HTTPURI: true,
				Path:    path,
				Replace: true,
				Request: true,
				Value:   resource.ParseRewriteAction(path, rwPath),
			})
		} else {
			actions = append(actions, &action{
				Name:    fmt.Sprintf("%d", actionNameIndex),
				HTTPURI: true,
				Replace: true,
				Request: true,
				Value:   rwPath,
			})
		}
	}
	return actions, nil
}

func getHostRewriteActions(rwHost string, actionNameIndex int) ([]*action, error) {
	if rwHost == "" {
		return nil, fmt.Errorf("empty host")
	}
	return []*action{{
		Name:     fmt.Sprintf("%d", actionNameIndex),
		HTTPHost: true,
		Replace:  true,
		Request:  true,
		Value:    rwHost,
	}}, nil
}

func createRedirectRule(source, target, ruleName string, allowSourceRange []string) (*Rule, error) {
	_u := "scheme://" + source
	_u = strings.TrimSuffix(_u, "/")
	u, err := url.Parse(_u)
	if nil != err {
		return nil, err
	}

	redirectAction := action{
		Name:      "0",
		HttpReply: true,
		Location:  target,
		Redirect:  true,
		Request:   true,
	}

	var conds []*condition
	if true == strings.HasPrefix(source, "*.") {
		conds = append(conds, &condition{
			EndsWith: true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{strings.TrimPrefix(u.Host, "*")},
		})
	} else if u.Host != "" {
		conds = append(conds, &condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{u.Host},
		})
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
	conds = append(conds, rootCondition)

	if len(allowSourceRange) > 0 {
		conds = append(conds, &condition{
			Tcp:     true,
			Address: true,
			Values:  allowSourceRange,
		})
	}

	rl := Rule{
		Name:       ruleName,
		FullURI:    source,
		Ordinal:    0,
		Actions:    []*action{&redirectAction},
		Conditions: conds,
	}

	log.Debugf("Configured rule: %v", rl)
	return &rl, nil
}

func (rules Rules) Len() int {
	return len(rules)
}

func (rules Rules) Less(i, j int) bool {
	ruleI := rules[i]
	ruleJ := rules[j]
	// Strategy 1: Rule with Highest number of conditions
	l1 := len(ruleI.Conditions)
	l2 := len(ruleJ.Conditions)
	if l1 != l2 {
		return l1 > l2
	}

	// Strategy 2: Rule with highest priority sequence of condition types
	// TODO
	pathExists := func(rule *Rule) bool {
		for _, cnd := range rule.Conditions {
			if cnd.Path {
				return true
			}
		}
		return false
	}
	if pathExists(ruleI) {
		return true
	}
	if pathExists(ruleJ) {
		return true
	}

	// Strategy 3: "equal" match type takes more priority than others
	// such as "starts-with", "ends-with", "contains"
	// TODO: And "start-with" and "ends-with" takes same priority and take
	// more priority than "contains"
	getConditionCounters := func(rule *Rule) (int, int) {
		var (
			eqCount  int
			endCount int
		)
		for _, cnd := range rule.Conditions {
			if cnd.Equals {
				eqCount++
			}
			if cnd.EndsWith {
				endCount++
			}
		}
		return eqCount, endCount
	}
	eqCountI, endCountI := getConditionCounters(ruleI)
	eqCountJ, endCountJ := getConditionCounters(ruleJ)
	if eqCountI != eqCountJ {
		return eqCountI > eqCountJ
	}
	if endCountI != endCountJ {
		return endCountI > endCountJ
	}

	if ruleI.Ordinal != ruleJ.Ordinal {
		// Strategy 4: Lowest Ordinal
		return ruleI.Ordinal < ruleJ.Ordinal
	}
	// Strategy 5: Lexicographic Order
	return ruleI.Name < ruleJ.Name

}

func (rules Rules) Swap(i, j int) {
	rules[i], rules[j] = rules[j], rules[i]
}

// httpRedirectIRuleNoHost redirects traffic to BIG-IP https vs
// for hostLess CRDs.
func httpRedirectIRuleNoHost(port int32) string {
	// The key in the data group is the host name or * to match all.
	// The data is a list of paths for the host delimited by '|' or '/' for all.
	iRuleCode := fmt.Sprintf(`
		when HTTP_REQUEST {
			HTTP::redirect https://[getfield [HTTP::host] ":" 1]:%d[HTTP::uri]	
		}`, port)
	return iRuleCode
}

// httpRedirectIRule redirects traffic to BIG-IP https vs
// except for the hostLess CRDs.
func httpRedirectIRule(port int32, rsVSName string, partition string) string {
	// The key in the data group is the host name or * to match all.
	// The data is a list of paths for the host delimited by '|' or '/' for all.
	dgName := "/" + partition + "/" + Shared + "/" + rsVSName + "_https_redirect_dg"
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
			# Compares the hostpath with the entries in https_redirect_dg
			for {set i $rc} {$i >= 0} {incr i -1} {
				set paths [class match -value $host equals %[1]s]
                # Check if host has wildcard match to https_redirect_dg
                if {$paths == ""} {
                    if { [class match $host ends_with %[1]s] } {
                        set paths [class match -value $host ends_with %[1]s]
                    }
                }
				# Check if host with combination of "/" matches https_redirect_dg
				if {$paths == ""} {
					set hosts ""
					append hosts $host "/"
					set paths [class match -value $hosts equals %[1]s]
                    if {$paths == ""} {
                        # Check if host with combination of "/" has wildcard
                        # match with https_redirect_dg
                        if { [class match $hosts ends_with %[1]s] } {
                            set paths [class match -value $hosts ends_with %[1]s]
                        }
                    }
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

func (ctlr *Controller) getABDeployIruleForTS(rsVSName string, partition string, tsType string) string {
	dgPath := strings.Join([]string{partition, Shared}, "/")

	return fmt.Sprintf(`when CLIENT_ACCEPTED {
    	set ab_class "/%[1]s/%[2]s_ab_deployment_dg"
		set ab_rule [class match -value "/" equals $ab_class]
		if {$ab_rule != ""} then {
	    	set weight_selection [expr {rand()}]
			set service_rules [split $ab_rule ";"]
        	set active_pool ""
			foreach service_rule $service_rules {
		    	set fields [split $service_rule ","]
				set pool_name [lindex $fields 0]
				if { [active_members $pool_name] >= 1 } {
			    	set active_pool $pool_name
				}
				set weight [expr {double([lindex $fields 1])}]
				if {$weight_selection <= $weight} then {
			    	#check if active pool members are available
					if { [active_members $pool_name] >= 1 } {
				    	pool $pool_name
						return
					} else {
                    	# select other pool with active members
						if {$active_pool!= ""} then {
					    	pool $active_pool
							return
						}
					}
				}
			}
		}
		# If we had a match, but all weights were 0 then
		# retrun a 503 (Service Unavailable)
		%[3]s::respond 503
		return
	}`, dgPath, rsVSName, strings.ToUpper(tsType))
}

func (ctlr *Controller) getPathBasedABDeployIRule(rsVSName string, partition string, multiPoolPersistence MultiPoolPersistence) string {
	dgPath := strings.Join([]string{partition, Shared}, "/")

	iRule := fmt.Sprintf(`proc select_ab_pool {path default_pool } {
			set last_slash [string length $path]
			set ab_class "/%[1]s/%[2]s_ab_deployment_dg"
			while {$last_slash >= 0} {
				if {[class match $path equals $ab_class]} then {
					break
				}
				set last_slash [string last "/" $path $last_slash]
				incr last_slash -1
				set path [string range $path 0 $last_slash]
			}
			if {$last_slash >= 0} {
				set ab_rule [class match -value $path equals $ab_class]
				if {$ab_rule != ""} then {
					set weight_selection [expr {rand()}]
					set service_rules [split $ab_rule ";"]
                    set active_pool ""
					foreach service_rule $service_rules {
						set fields [split $service_rule ","]
						set pool_name [lindex $fields 0]
                        if { [active_members $pool_name] >= 1 } {
						    set active_pool $pool_name
						}
						set weight [expr {double([lindex $fields 1])}]
						if {$weight_selection <= $weight} then {
							#check if active pool members are available
						    if { [active_members $pool_name] >= 1 } {
							    return $pool_name
						    } else {
                                  # select other pool with active members
						          if {$active_pool!= ""} then {
						              return $active_pool
						          }    
						    }
						}
					}
				}
				# If we had a match, but all weights were 0 then
				# retrun a 503 (Service Unavailable)
				HTTP::respond 503
			}
			return $default_pool
		}`, dgPath, rsVSName)

	persistenceType := getPersistenceType(multiPoolPersistence.Method)
	if persistenceType != "" {
		iRule += fmt.Sprintf(`
			when HTTP_REQUEST priority 200 {
			   set path [string tolower [HTTP::host]][HTTP::path]
			   set persist_key "[IP::client_addr]:$path"
			   set persist_record [linsert [persist lookup %v [list $persist_key any pool] ] 1 member]
			   
			   if {$persist_record ne "member"} then {
							pool [lindex $persist_record 0] member [lindex $persist_record 2] [lindex $persist_record 3]
							event disable
				} else {
				   set selected_pool [call select_ab_pool $path ""]
				   if {$selected_pool != ""} then {
						pool $selected_pool
						persist %v $persist_key %v
						return
					}
				}
}`, persistenceType, persistenceType, multiPoolPersistence.TimeOut)
	} else {
		iRule += fmt.Sprintf(`
			when HTTP_REQUEST priority 200 {
			set path [string tolower [HTTP::host]][HTTP::path]
			set selected_pool [call select_ab_pool $path ""]
			if {$selected_pool != ""} then {
				pool $selected_pool
				return
			}
		}`)
	}

	return iRule
}

func getPersistenceType(key string) string {
	if key == "" {
		return key
	}
	// supported persistence types
	// the keys should be in sync with the supported values of multiPoolPersistence in policy
	// any change to the multiPoolPersistence def should be reflected here
	persisMap := map[string]string{
		"uieSourceAddress":  "uie",
		"hashSourceAddress": "hash",
	}
	if val, ok := persisMap[key]; ok {
		return val
	} else {
		return ""
	}
}

func (ctlr *Controller) getTLSIRule(rsVSName string, partition string, allowSourceRange []string,
	multiPoolPersistence MultiPoolPersistence, passthroughVSGrp bool) string {
	dgPath := strings.Join([]string{partition, Shared}, "/")

	clientSSL := "\n" + fmt.Sprintf(`
		 when CLIENTSSL_HANDSHAKE {
					SSL::collect
				}

		 when CLIENTSSL_DATA {
			if { [llength [split [SSL::payload]]] < 1 }{
				reject ; event disable all; return;
				}
			set sslpath [lindex [split [SSL::payload]] 1]
			# for http2 protocol we receive the sslpath as '*', hence replacing it with root path,
			# however it will not handle the http2 path based routing for now.
			# for http2 currently only host based routing is supported.
			if { $sslpath equals "*" } { 
				set sslpath "/"
			}
			set domainpath $sslpath
			set routepath ""
			set wc_routepath ""
			
			if { [info exists tls_servername] } {
				set servername_lower [string tolower $tls_servername]
				set domain_length [llength [split $servername_lower "."]]
				set domain_wc [domain $servername_lower [expr {$domain_length - 1}] ]
				set wc_host ".$domain_wc"
				# Set routepath as combination of servername and url path
				append routepath $servername_lower $sslpath
				append wc_routepath $wc_host $sslpath
				set routepath [string tolower $routepath]
				set wc_routepath [string tolower $wc_routepath]
				set sslpath $routepath
				# Find the number of "/" in the routepath
				set rc 0
				foreach x [split $routepath {}] {
				   if {$x eq "/"} {
					   incr rc
				   }
				}

				set reencrypt_class "/%[1]s/%[2]s_ssl_reencrypt_servername_dg"
				set edge_class "/%[1]s/%[2]s_ssl_edge_servername_dg"
				if { [class exists $reencrypt_class] || [class exists $edge_class] } {
					# Compares the routepath with the entries in ssl_reencrypt_servername_dg and
					# ssl_edge_servername_dg.
					for {set i $rc} {$i >= 0} {incr i -1} {
						if { [class exists $reencrypt_class] } {
							set reen_pool [class match -value $routepath equals $reencrypt_class]
							# Check for wildcard domain
							if { $reen_pool equals "" } {
								if { [class match $wc_routepath equals $reencrypt_class] } {
									set reen_pool [class match -value $wc_routepath equals $reencrypt_class]
								}
							}
							# Disable serverside ssl and enable only for reencrypt routes with valid pool
							if { not ($reen_pool equals "") } {
								set dflt_pool $reen_pool
								SSL::enable serverside
							}
						}
						if { [class exists $edge_class] } {
							set edge_pool [class match -value $routepath equals $edge_class]
							# Check for wildcard domain
							if { $edge_pool equals "" } {
								if { [class match $wc_routepath equals $edge_class] } {
									set edge_pool [class match -value $wc_routepath equals $edge_class]
								}
							}
							if { not ($edge_pool equals "") } {
								# Disable serverside ssl for edge routes
								SSL::disable serverside
								set dflt_pool $edge_pool
							}
						}
						if { not [info exists dflt_pool] } {
							set routepath [
								string range $routepath 0 [
									expr {[string last "/" $routepath]-1}
								]
							]
							set wc_routepath [
								string range $wc_routepath 0 [
									expr {[string last "/" $wc_routepath]-1}
								]
							]
						}
						else {
							break
						}
					}
				}
				else {
					# Disable serverside ssl for passthrough routes as well
					SSL::disable serverside
				}
				# handle the default pool for virtual server
				set default_class "/%[1]s/%[2]s_default_pool_servername_dg"
				 if { [class exists $default_class] } { 
					set dflt_pool [class match -value "defaultPool" equals $default_class]
				 }
				
				# Handle requests sent to unknown hosts.
				# For valid hosts, Send the request to respective pool.
				if { not [info exists dflt_pool] } then {
					 # Allowing HTTP2 traffic to be handled by policies and closing the connection for HTTP/1.1 unknown hosts.
					 if { not ([SSL::payload] starts_with "PRI * HTTP/2.0") } {
						reject ; event disable all;
						log local0.debug "Failed to find pool for $servername_lower"
						return;
					}
				} else {
					pool $dflt_pool
				}
				set ab_class "/%[1]s/%[2]s_ab_deployment_dg"
				if { [class exists $ab_class] } {
					set selected_pool [call select_ab_pool $servername_lower $dflt_pool $domainpath]
					if { $selected_pool == "" } then {
						log local0.debug "Unable to find pool for $servername_lower"
					} else {
						pool $selected_pool
					}
				}
			}
			SSL::release
		}

	`, dgPath, rsVSName)

	sslDisable := "SSL::disable"

	httpRequest := "\n" + fmt.Sprintf(`
		when HTTP_REQUEST {
			if { [info exists static::http_status_503] && $static::http_status_503 == 1 } {
        		# Respond with 503
       			HTTP::respond 503

        		# Unset the variable
        		unset static::http_status_503
    		}
		}
	`)

	if ctlr.Agent.bigIPAS3Version >= 3.52 && passthroughVSGrp {
		clientSSL = ""
		sslDisable = ""
	}

	iRule := fmt.Sprintf(`
		when CLIENT_DATA {
			# Byte 0 is the content type.
			# Bytes 1-2 are the TLS version.
			# Bytes 3-4 are the TLS payload length.
			# Bytes 5-$tls_payload_len are the TLS payload.
			set payload [TCP::payload]
           set payloadlen [TCP::payload length]

           if {![info exists payloadscan]} {
               set payloadscan [binary scan $payload cSS tls_content_type tls_version tls_payload_len ]
           }
		   
	       if {($payloadscan == 3)} {
               if {($tls_payload_len < 0 || $tls_payload_len > 16389)} {  
                   log local0.warn "[IP::remote_addr] : parsed SSL/TLS record length ${tls_payload_len} outside of handled length (0..16389)"
                   reject
                   return
               } elseif {($payloadlen < $tls_payload_len+5)} {
                   TCP::collect [expr {$tls_payload_len +5 - $payloadlen}]
                   return
               }
				if { ! [ expr { [info exists tls_content_type] && [string is integer -strict $tls_content_type] } ] }  { reject ; event disable all; return; }
				if { ! [ expr { [info exists tls_version] && [string is integer -strict $tls_version] } ] }  { reject ; event disable all; return; }
				switch -exact $tls_version {
					"769" -
					"770" -
					"771" {
						# Content type of 22 indicates the TLS payload contains a handshake.
						if { $tls_content_type == 22 } {
							# Byte 5 (the first byte of the handshake) indicates the handshake
							# record type, and a value of 1 signifies that the handshake record is
							# a ClientHello.
							binary scan [TCP::payload] @5c tls_handshake_record_type
							if { ! [ expr { [info exists tls_handshake_record_type] && [string is integer -strict $tls_handshake_record_type] } ] }  { reject ; event disable all; return; }
							if { $tls_handshake_record_type == 1 } {
								# Bytes 6-8 are the handshake length (which we ignore).
								# Bytes 9-10 are the TLS version (which we ignore).
								# Bytes 11-42 are random data (which we ignore).
	
								# Byte 43 is the session ID length.  Following this are three
								# variable-length fields which we shall skip over.
								set record_offset 43
	
								# Skip the session ID.
								binary scan [TCP::payload] @${record_offset}c tls_session_id_len
								if { ! [ expr { [info exists tls_session_id_len] && [string is integer -strict $tls_session_id_len] } ] }  { reject ; event disable all; return; }
								incr record_offset [expr {1 + $tls_session_id_len}]
	
								# Skip the cipher_suites field.
								binary scan [TCP::payload] @${record_offset}S tls_cipher_suites_len
								if { ! [ expr { [info exists tls_cipher_suites_len] && [string is integer -strict $tls_cipher_suites_len] } ] }  { reject ; event disable all; return; }
								incr record_offset [expr {2 + $tls_cipher_suites_len}]
	
								# Skip the compression_methods field.
								binary scan [TCP::payload] @${record_offset}c tls_compression_methods_len
								if { ! [ expr { [info exists tls_compression_methods_len] && [string is integer -strict $tls_compression_methods_len] } ] }  { reject ; event disable all; return; }
								incr record_offset [expr {1 + $tls_compression_methods_len}]
	
								# Get the number of extensions, and store the extensions.
								binary scan [TCP::payload] @${record_offset}S tls_extensions_len
								if { ! [ expr { [info exists tls_extensions_len] && [string is integer -strict $tls_extensions_len] } ] }  { reject ; event disable all; return; }
								incr record_offset 2
								binary scan [TCP::payload] @${record_offset}a* tls_extensions
								if { ! [info exists tls_extensions] }  { reject ; event disable all; return; }
								for { set extension_start 0 }
										{ $tls_extensions_len - $extension_start == abs($tls_extensions_len - $extension_start) }
										{ incr extension_start 4 } {
									# Bytes 0-1 of the extension are the extension type.
									# Bytes 2-3 of the extension are the extension length.
									binary scan $tls_extensions @${extension_start}SS extension_type extension_len
									if { ! [ expr { [info exists extension_type] && [string is integer -strict $extension_type] } ] }  { reject ; event disable all; return; }
									if { ! [ expr { [info exists extension_len] && [string is integer -strict $extension_len] } ] }  { reject ; event disable all; return; }
	
									# Extension type 00 is the ServerName extension.
									if { $extension_type == "00" } {
										# Bytes 4-5 of the extension are the SNI length (we ignore this).
	
										# Byte 6 of the extension is the SNI type.
										set sni_type_offset [expr {$extension_start + 6}]
										binary scan $tls_extensions @${sni_type_offset}S sni_type
										if { ! [ expr { [info exists sni_type] && [string is integer -strict $sni_type] } ] }  { reject ; event disable all; return; }
	
										# Type 0 is host_name.
										if { $sni_type == "0" } {
											# Bytes 7-8 of the extension are the SNI data (host_name)
											# length.
											set sni_len_offset [expr {$extension_start + 7}]
											binary scan $tls_extensions @${sni_len_offset}S sni_len
											if { ! [ expr { [info exists sni_len] && [string is integer -strict $sni_len] } ] }  { reject ; event disable all; return; } 
	
											# Bytes 9-$sni_len are the SNI data (host_name).
											set sni_start [expr {$extension_start + 9}]
											binary scan $tls_extensions @${sni_start}A${sni_len} tls_servername
										}
									}
	
									incr extension_start $extension_len
								}
								if { [info exists tls_servername] } {
									set servername_lower [string tolower $tls_servername]
									set domain_length [llength [split $servername_lower "."]]
									set domain_wc [domain $servername_lower [expr {$domain_length - 1}] ]
									# Set wc_host with the wildcard domain
									set wc_host ".$domain_wc"
									set passthru_class "/%[1]s/%[2]s_ssl_passthrough_servername_dg"
									if { [class exists $passthru_class] } {
										# check if the passthrough data group has a record with the servername
										set passthru_dg_key [class match $servername_lower equals $passthru_class]
										set passthru_dg_wc_key [class match $wc_host equals $passthru_class]
										if { $passthru_dg_key != 0 || $passthru_dg_wc_key != 0 } {
											SSL::disable serverside
											set dflt_pool_passthrough ""
		
											# Disable Serverside SSL for Passthrough Class
											set dflt_pool_passthrough [class match -value $servername_lower equals $passthru_class]
											# If no match, try wildcard domain
											if { $dflt_pool_passthrough == "" } {
												if { [class match $wc_host equals $passthru_class] } {
														set dflt_pool_passthrough [class match -value $wc_host equals $passthru_class]
												}
											}
											if { not ($dflt_pool_passthrough equals "") } {
												%[4]s
												HTTP::disable
											}
		
											set ab_class "/%[1]s/%[2]s_ab_deployment_dg"
											if { not [class exists $ab_class] } {
												if { $dflt_pool_passthrough == "" } then {
													log local0.debug "Failed to find pool for $servername_lower $"
												} else {
													pool $dflt_pool_passthrough
												}
											} else {
												set selected_pool [call select_ab_pool $servername_lower $dflt_pool_passthrough ""]
												if { $selected_pool == "" } then {
													log local0.debug "Failed to find pool for $servername_lower"
												} else {
													pool $selected_pool
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			TCP::release
		}

		%[3]s
		
		when SERVER_CONNECTED {
			set reencryptssl_class "/%[1]s/%[2]s_ssl_reencrypt_serverssl_dg"
			set edgessl_class "/%[1]s/%[2]s_ssl_edge_serverssl_dg"
			if { [info exists sslpath] and [class exists $reencryptssl_class] } {
				# Find the nearest child path which matches the reencrypt_class
				for {set i $rc} {$i >= 0} {incr i -1} {
					if { [class exists $reencryptssl_class] } {
						set reen [class match -value $sslpath equals $reencryptssl_class]
                        # check for wildcard domain match
                        if { $reen equals "" } {
						    if { [class match $wc_routepath equals $reencryptssl_class] } {
						        set reen [class match -value $wc_routepath equals $reencryptssl_class]
						    }
                        }
						if { not ($reen equals "") } {
							    set sslprofile $reen
						}
					}
					if { [class exists $edgessl_class] } {
						set edge [class match -value $sslpath equals $edgessl_class]
                        # check for wildcard domain match
                        if { $edge equals "" } {
						    if { [class match $wc_routepath equals $edgessl_class] } {
						        set edge [class match -value $wc_routepath equals $edgessl_class]
						    }
                        }
						if { not ($edge equals "") } {
							    set sslprofile $edge
						}
						
					}
					if { not [info exists sslprofile] } {
						set sslpath [
							string range $sslpath 0 [
								expr {[string last "/" $sslpath]-1}
							]
						]
                        set wc_routepaath [
							string range $wc_routepath 0 [
								expr {[string last "/" $wc_routepath]-1}
							]
						]
					}
					else {
						break
					}
				}
				# Assign respective SSL profile based on ssl_reencrypt_serverssl_dg
				if { not ($sslprofile equals "false") } {
						SSL::profile $reen
				} else {
						SSL::disable serverside
				}
			}
        }
			
		%[5]s`, dgPath, rsVSName, clientSSL, sslDisable, httpRequest)

	iRuleCode := fmt.Sprintf("%s\n\n%s\n\n%s", ctlr.selectClientAcceptediRule(rsVSName, dgPath, allowSourceRange), ctlr.selectPoolIRuleFunc(rsVSName, dgPath, multiPoolPersistence), iRule)

	return iRuleCode
}

func (ctlr *Controller) selectClientAcceptediRule(rsVSName string, dgPath string, allowSourceRange []string) string {

	iRulePrefix := fmt.Sprintf(`when CLIENT_ACCEPTED { TCP::collect }`)
	if len(allowSourceRange) > 0 {
		iRulePrefix = fmt.Sprintf(`when CLIENT_ACCEPTED {if { [class match [IP::client_addr] eq "/%[1]s/%[2]s_allowSourceRange"] } then {TCP::collect} else {reject; event disable all; return;}}`, dgPath, rsVSName)
	}
	return iRulePrefix
}

func (ctlr *Controller) selectPoolIRuleFunc(rsVSName string, dgPath string, multiPoolPersistence MultiPoolPersistence) string {

	iRuleFunc := fmt.Sprintf(`
		proc select_ab_pool {path default_pool domainpath} {
			set last_slash [string length $path]
			set ab_class "/%[1]s/%[2]s_ab_deployment_dg"
			while {$last_slash >= 0} {
				if {[class match $path equals $ab_class]} then {
					break
				}
				set last_slash [string last "/" $path $last_slash]
				incr last_slash -1
				set path [string range $path 0 $last_slash]
			}`, dgPath, rsVSName)

	persistenceType := getPersistenceType(multiPoolPersistence.Method)
	if persistenceType == "" {
		iRuleFunc += fmt.Sprintf(`
			if {$last_slash >= 0} {
				set ab_rule [class match -value $path equals $ab_class]
				if {$ab_rule != ""} then {
					set weight_selection [expr {rand()}]
					set service_rules [split $ab_rule ";"]
                    set active_pool ""
					foreach service_rule $service_rules {
						set fields [split $service_rule ","]
						set pool_name [lindex $fields 0]
                        if { [active_members $pool_name] >= 1 } {
						    set active_pool $pool_name
						}
						set weight [expr {double([lindex $fields 1])}]
						if {$weight_selection <= $weight} then {
                            #check if active pool members are available
						    if { [active_members $pool_name] >= 1 } {
							    return $pool_name
						    } else {
						          # select the any of pool with active members 
						          if {$active_pool!= ""} then {
						              return $active_pool
						          }    
						    }
						}
					}
				}
				# If we had a match, but all weights were 0 then
				# retrun a 503 (Service Unavailable)
				set static::http_status_503 1
			}
			return $default_pool
		}`)
	} else {
		iRuleFunc += fmt.Sprintf(`
			if {$last_slash >= 0} {
				set ab_rule [class match -value $path equals $ab_class]
				if {$ab_rule != ""} then {
					# skip processing of any path based domain 
					# this is to skip creation of persistence entry for any path based domain
					# any path based domain will be processed by default pool
					if {$domainpath ne "" && $domainpath ne "/"}{
							return $default_pool
					}
					set persist_key "[IP::client_addr]:$path"
					set persist_record [linsert [persist lookup %v [list $persist_key any pool] ] 1 member]
					if {$persist_record ne "member"} {
						pool [lindex $persist_record 0] member [lindex $persist_record 2] [lindex $persist_record 3]
						return 
					}
					set weight_selection [expr {rand()}]
					set service_rules [split $ab_rule ";"]
                    set active_pool ""
					foreach service_rule $service_rules {
						set fields [split $service_rule ","]
						set pool_name [lindex $fields 0]
                        if { [active_members $pool_name] >= 1 } {
						    set active_pool $pool_name
						}
						set weight [expr {double([lindex $fields 1])}]
						if {$weight_selection <= $weight} then {
                            #check if active pool members are available
						    if { [active_members $pool_name] >= 1 } {
								persist %v $persist_key %v
							    return $pool_name
						    } else {
						          # select the any of pool with active members 
						          if {$active_pool!= ""} then {
                                      persist %v $persist_key %v
						              return $active_pool
						          }    
						    }
						}
					}
				}
				# If we had a match, but all weights were 0 then
				# retrun a 503 (Service Unavailable)
				set static::http_status_503 1
			}
			return $default_pool
		}`, persistenceType, persistenceType, multiPoolPersistence.TimeOut, persistenceType, multiPoolPersistence.TimeOut)
	}

	return iRuleFunc
}

func updateDataGroupOfDgName(
	intDgMap InternalDataGroupMap,
	poolPathRefs []poolPathRef,
	rsVSName string,
	dgName string,
	namespace string,
	partition string,
	allowSourceRange []string,
	httpPort int32,
) {
	rsDGName := getRSCfgResName(rsVSName, dgName)
	switch dgName {
	case EdgeHostsDgName, ReencryptHostsDgName:
		// Combination of hostName and path are used as key in edge Datagroup.
		// Servername and path from the ssl::payload of clientssl_data Irule event is
		// used as value in edge and reencrypt Datagroup.
		for _, pl := range poolPathRefs {
			for _, hostName := range pl.aliasHostnames {
				routePath := hostName + pl.path
				routePath = strings.TrimSuffix(routePath, "/")
				updateDataGroup(intDgMap, rsDGName,
					partition, namespace, routePath, pl.poolName, DataGroupType)
			}
		}
	case PassthroughHostsDgName:
		// only vsHostname will be used for passthrough routes
		for _, pl := range poolPathRefs {
			for _, hostName := range pl.aliasHostnames {
				updateDataGroup(intDgMap, rsDGName,
					partition, namespace, hostName, pl.poolName, DataGroupType)
			}
		}
	case HttpsRedirectDgName:
		for _, pl := range poolPathRefs {
			path := pl.path
			if path == "" {
				path = "/"
			}
			//for custom http port, host:port match should redirect traffic
			if httpPort != DEFAULT_HTTP_PORT {
				for _, hostName := range pl.aliasHostnames {
					routePath := hostName + ":" + strconv.Itoa(int(httpPort)) + path
					updateDataGroup(intDgMap, rsDGName,
						partition, namespace, routePath, path, DataGroupType)
				}
			} else {
				//for default port 80 either host or host:port match traffic
				//should be redirected
				for _, hostName := range pl.aliasHostnames {
					routePath := hostName + path
					routePathwithPort := hostName + ":" + strconv.Itoa(int(DEFAULT_HTTP_PORT)) + path
					updateDataGroup(intDgMap, rsDGName,
						partition, namespace, routePath, path, DataGroupType)
					updateDataGroup(intDgMap, rsDGName,
						partition, namespace, routePathwithPort, path, DataGroupType)
				}
			}
		}
	case AllowSourceRange:
		for _, sourceNw := range allowSourceRange {
			updateDataGroup(intDgMap, rsDGName,
				partition, namespace, sourceNw, "true", DataGroupAllowSourceRangeType)
		}
	}
}

// Add or update a data group record
func updateDataGroup(
	intDgMap InternalDataGroupMap,
	name string,
	partition string,
	namespace string,
	key string,
	value string,
	dgType string,
) {

	//for wildcard host
	if strings.HasPrefix(key, "*") {
		key = strings.TrimPrefix(key, "*")
	}
	mapKey := NameRef{
		Name:      name,
		Partition: partition,
	}
	nsDg, found := intDgMap[mapKey]
	if !found {
		nsDg = make(DataGroupNamespaceMap)
		intDgMap[mapKey] = nsDg
	}

	dg, found := nsDg[namespace]
	if found {
		dg.AddOrUpdateRecord(key, value)
	} else {
		newDg := InternalDataGroup{
			Name:      name,
			Partition: partition,
			Type:      dgType,
		}
		newDg.AddOrUpdateRecord(key, value)
		nsDg[namespace] = &newDg
	}
}

// updateDataGroupForABRoute updates the data group map based on alternativeBackends of route.
func (ctlr *Controller) updateDataGroupForABRoute(
	route *routeapi.Route,
	dgName string,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
	port intstr.IntOrString,
) {
	if !isRouteABDeployment(route) && ctlr.discoveryMode != Ratio {
		return
	}
	var clusterSvcs []cisapiv1.MultiClusterServiceReference
	if annotation := route.Annotations[resource.MultiClusterServicesAnnotation]; annotation != "" {
		err := json.Unmarshal([]byte(annotation), &clusterSvcs)
		if err != nil {
			log.Warningf("failed to read services from the annotation of route %s: Error: %v", route.Name, err)
		}
	}

	weightTotal := 0.0
	backends := ctlr.GetRouteBackends(route, clusterSvcs)
	for _, svc := range backends {
		weightTotal = weightTotal + svc.Weight
	}

	path := route.Spec.Path
	tls := route.Spec.TLS
	if tls != nil {
		// We don't support path-based A/B for pass-thru
		switch tls.Termination {
		case routeapi.TLSTerminationPassthrough:
			path = ""
		}
	}
	if path == "/" {
		path = ""
	}
	key := route.Spec.Host + path

	if weightTotal == 0 {
		// If all services have 0 weight, openshift requires a 503 to be returned
		// (see https://docs.openshift.com/container-platform/3.6/architecture
		//  /networking/routes.html#alternateBackends)
		updateDataGroup(dgMap, dgName, partition, namespace, key, "", "")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0.0
		for _, be := range backends {
			if be.Weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + be.Weight
			weightedSliceThreshold := runningWeightTotal / weightTotal
			svcNamespace := route.Namespace
			if be.SvcNamespace != "" {
				svcNamespace = be.SvcNamespace
			}
			poolName := ctlr.formatPoolName(
				svcNamespace,
				be.Name,
				port,
				"",
				"",
				be.Cluster,
			)
			entry := fmt.Sprintf("%s,%4.3f", poolName, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, dgName,
			partition, namespace, key, value, "string")
	}
}

func isRouteABDeployment(route *routeapi.Route) bool {
	return route.Spec.AlternateBackends != nil && len(route.Spec.AlternateBackends) > 0
}

func isRoutePathBasedABDeployment(route *routeapi.Route) bool {
	return route.Spec.AlternateBackends != nil && len(route.Spec.AlternateBackends) > 0 && (route.Spec.Path != "" && route.Spec.Path != "/")
}

func isVSABDeployment(pool *cisapiv1.VSPool) bool {
	return pool.AlternateBackends != nil && len(pool.AlternateBackends) > 0
}

func isTSABDeployment(pool *cisapiv1.TSPool) bool {
	return (pool.AlternateBackends != nil && len(pool.AlternateBackends) > 0) || (pool.MultiClusterServices != nil && len(pool.MultiClusterServices) > 0)
}

func isVsPathBasedABDeployment(pool *cisapiv1.VSPool) bool {
	return pool.AlternateBackends != nil && len(pool.AlternateBackends) > 0 && (pool.Path != "" && pool.Path != "/")
}

func isVsPathBasedRatioDeployment(pool *cisapiv1.VSPool, mode discoveryMode) bool {
	return (mode == Ratio || mode == DefaultMode) && (pool.Path != "" && pool.Path != "/")
}

func isRoutePathBasedRatioDeployment(route *routeapi.Route, mode discoveryMode) bool {
	return mode == Ratio && (route.Spec.Path != "" && route.Spec.Path != "/")
}

// GetRouteBackends returns the services associated with a route (names + weight)
func (ctlr *Controller) GetRouteBackends(route *routeapi.Route, clusterSvcs []cisapiv1.MultiClusterServiceReference) []RouteBackendCxt {
	var rbcs []RouteBackendCxt
	if ctlr.discoveryMode != Ratio {
		numOfBackends := 1
		if route.Spec.AlternateBackends != nil {
			numOfBackends += len(route.Spec.AlternateBackends)
		}
		rbcs = make([]RouteBackendCxt, numOfBackends)
		beIdx := 0
		rbcs[beIdx].Name = route.Spec.To.Name
		rbcs[beIdx].Cluster = ctlr.multiClusterHandler.LocalClusterName
		if route.Spec.To.Weight != nil {
			rbcs[beIdx].Weight = float64(*(route.Spec.To.Weight))
		} else {
			// Older versions of openshift do not have a weight field
			// so we will basically ignore it.
			rbcs[beIdx].Weight = 0
		}

		if route.Spec.AlternateBackends != nil {
			for _, svc := range route.Spec.AlternateBackends {
				beIdx = beIdx + 1
				rbcs[beIdx].Name = svc.Name
				rbcs[beIdx].Cluster = ctlr.multiClusterHandler.LocalClusterName
				rbcs[beIdx].Weight = float64(*(svc.Weight))
			}
		}

		return rbcs
	}
	// Prepare backends for Ratio mode
	/*
				Effective weight for a service(S) = Ws/Wt * Rc/Rt
				Ws => Weight specified for the service S
				Wt => Sum of weights of all services (Route service + Alternate backends + External services)
				Rc => Ratio specified for the cluster on which the service is running
				Rt => Sum of all the ratios of the clusters excluding those cluster ratios which don't contribute to this route services

				For example:
					Route(P) (Route in primary cluster)=> Associated services are (Rs(P), ABs1(P), ABs2(P), Svc1 and Svc2)
					Route(S) (Route in secondary cluster)=> Associated services are (Rs(S), ABs1(S), ABs2(S), Svc1 and Svc2)
					* Where (P) and (S) stand for primary and secondary cluster

					If there are 4 clusters CL1, CL2, CL3, CL4 and ratios defined for these clusters along with the services' weights are
					CL1(Primary)   => Ratio: 4 ([Route service Rs(P) => weight 30 ] + Alternate backend services [ ABs1(P) => weight:10, ABs2(P) => weight:20 ])
					CL2(Secondary) => Ratio: 3 ([Route service Rs(S) => weight 30 ] + Alternate backend services [ ABs1(S) => weight:10, ABs2(S) => weight:20 ])
					CL3 		   => Ratio: 2 ([Svc1 => weight 20], [svc2 => weight 10])
					CL4 		   => Ratio: 1 (No services )

					Effective weight calculation considering the service weights as well as the cluster ratio:
					Total Weight(Wt) = 30[Rs(P)] + 30[Rs(S)]  + 10[ABs1(P)] + 10[ABs1(S)] + 20[ABs2(P)] + 20[ABs2(S)] + 20(Svc1) + 10(Svc2) = 150
					Total Ratio(Rt) = 4(CL1) + 3(CL2) + 2(CL3) = 9 [Excluded CL4 ratio as it doesn't contribute to the Route's services]
					-------------------------------------------------------------------------------------------
					Effective weight for service Rs(P)  : 30(Ws)/150(Wt) * 4(Rc)/9(Rt) = 3/15 * 4/9 = 0.088
					Effective weight for service Rs(S)  : 30(Ws)/150(Wt) * 3(Rc)/9(Rt) = 3/15 * 3/9 = 0.066
					Effective weight for service ABs1(P): 10(Ws)/150(Wt) * 4(Rc)/9(Rt) = 1/15 * 4/9 = 0.029
					Effective weight for service ABs1(S): 10(Ws)/150(Wt) * 3(Rc)/9(Rt) = 1/15 * 3/9 = 0.022
					Effective weight for service ABs2(P): 20(Ws)/150(Wt) * 4(Rc)/9(Rt) = 2/15 * 4/9 = 0.059
			 		Effective weight for service ABs2(S): 20(Ws)/150(Wt) * 3(Rc)/9(Rt) = 2/15 * 3/9 = 0.044
					Effective weight for service Svc1   : 20(Ws)/150(Wt) * 2(Rc)/9(Rt) = 2/15 * 2/9 = 0.029
					Effective weight for service Svc2   : 10(Ws)/150(Wt) * 2(Rc)/9(Rt) = 1/15 * 2/9 = 0.014
		            -------------------------------------------------------------------------------------------
	*/

	// First we calculate the total service weights, total ratio and the total number of backends

	// store the localClusterPool state and HA peer cluster pool state in advance for further processing
	localClusterPoolRestricted := ctlr.isAddingPoolRestricted(ctlr.multiClusterHandler.LocalClusterName)
	hAPeerClusterPoolRestricted := true // By default, skip HA cluster service backend
	// If HA peer cluster is present then update the hAPeerClusterPoolRestricted state based on the cluster pool state
	if ctlr.multiClusterHandler.HAPairClusterName != "" {
		hAPeerClusterPoolRestricted = ctlr.isAddingPoolRestricted(ctlr.multiClusterHandler.HAPairClusterName)
	}
	// factor is used to track whether both the primary and secondary cluster needs to be considered or none/one/both of
	// them have to be considered( this is based on multiCluster mode and cluster pool state)
	factor := 0
	if !localClusterPoolRestricted {
		factor++ // it ensures local cluster services associated with the route are considered
	}
	if ctlr.multiClusterHandler.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
		factor++ // it ensures HA peer cluster services associated with the route are considered
	}
	// Default service weight is 100 as per openshift route documentation
	// https://docs.openshift.com/container-platform/4.12/applications/deployments/route-based-deployment-strategies.html
	defaultWeight := 100
	if route.Spec.To.Weight == nil {
		// Older versions of openshift do not have a weight field
		// so we will basically ignore it.
		defaultWeight = 0
	}
	// clusterSvcMap helps in ensuring the cluster ratio is considered only if there is at least one service associated
	// with the route running in that cluster
	clusterSvcMap := make(map[string]struct{})
	clusterSvcMap[""] = struct{}{} // "" is used as key for the local cluster where this CIS is running

	// totalClusterRatio stores the sum total of all the ratio of clusters contributing services to this route
	totalClusterRatio := 0.0
	// totalSvcWeights stores the sum total of all the weights of services associated with this route
	totalSvcWeights := 0.0
	// count of valid external multiCluster services
	validExtSvcCount := 0
	// Include local cluster ratio in the totalClusterRatio calculation
	if !localClusterPoolRestricted {
		totalClusterRatio += float64(*ctlr.clusterRatio[ctlr.multiClusterHandler.LocalClusterName])
	}
	// Include HA partner cluster ratio in the totalClusterRatio calculation
	if ctlr.multiClusterHandler.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
		totalClusterRatio += float64(*ctlr.clusterRatio[ctlr.multiClusterHandler.HAPairClusterName])
	}
	// if adding pool member is restricted for both local or HA partner cluster then skip adding service weights for both the clusters
	if !localClusterPoolRestricted || !hAPeerClusterPoolRestricted {
		totalSvcWeights += float64(*(route.Spec.To.Weight)) * float64(factor)
	}

	// Process multiCluster services
	for i, svc := range clusterSvcs {
		// Skip the service if it's not valid
		// This includes check for cis should be running in multiCluster mode, external server parameters validity and
		// cluster credentials must be specified in the extended configmap
		if ctlr.checkValidMultiClusterService(svc, false) != nil || ctlr.isAddingPoolRestricted(svc.ClusterName) {
			continue
		}
		if _, ok := clusterSvcMap[svc.ClusterName]; !ok {
			if r, ok := ctlr.clusterRatio[svc.ClusterName]; ok {
				clusterSvcMap[svc.ClusterName] = struct{}{}
				totalClusterRatio += float64(*r)
			} else {
				// Service is from unknown cluster. This case should not arise, but if it does then consider weight to
				// be 0 as most probably the cluster config may not have been provided in the extended configmap, in
				// such a case no traffic should be distributed to this cluster
				log.Warningf("%v weight for service %s of cluster %s could not be processed for route %s. Provide the "+
					"cluster config in extendedConfigMap", ctlr.getMultiClusterLog(), svc.SvcName, svc.ClusterName, route.Name)
				zero := 0
				clusterSvcs[i].Weight = &zero
			}
		}
		if svc.Weight == nil {
			clusterSvcs[i].Weight = &defaultWeight
		}
		totalSvcWeights += float64(*clusterSvcs[i].Weight)
		validExtSvcCount++
	}
	numOfBackends := factor + validExtSvcCount
	if route.Spec.AlternateBackends != nil && (!localClusterPoolRestricted || !hAPeerClusterPoolRestricted) {
		numOfBackends += len(route.Spec.AlternateBackends) * factor
		for _, svc := range route.Spec.AlternateBackends {
			totalSvcWeights += float64(*svc.Weight) * float64(factor)
		}
	}

	// Now start creating the list of all the backends

	rbcs = make([]RouteBackendCxt, numOfBackends)
	// Calibrate totalSvcWeights and totalClusterRatio if any of these is 0
	if totalSvcWeights == 0 {
		totalSvcWeights = 1
	}
	if totalClusterRatio == 0 {
		totalClusterRatio = 1
	}
	// Process route spec primary service
	beIdx := -1
	// Route backend service in local cluster
	if !localClusterPoolRestricted {
		beIdx++
		rbcs[beIdx].Name = route.Spec.To.Name
		rbcs[beIdx].Cluster = ctlr.multiClusterHandler.LocalClusterName
		if route.Spec.To.Weight != nil {
			// Route backend service in local cluster
			rbcs[beIdx].Weight = (float64(*(route.Spec.To.Weight)) / totalSvcWeights) *
				(float64(*ctlr.clusterRatio[ctlr.multiClusterHandler.LocalClusterName]) / totalClusterRatio)
		} else {
			// Older versions of openshift do not have a weight field
			// so we will basically ignore it.
			rbcs[beIdx].Weight = 0.0
		}
	}
	// Route backend service in HA partner cluster
	if ctlr.multiClusterHandler.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
		beIdx++
		rbcs[beIdx].Name = route.Spec.To.Name
		if route.Spec.To.Weight != nil {
			rbcs[beIdx].Weight = (float64(*(route.Spec.To.Weight)) / totalSvcWeights) *
				(float64(*ctlr.clusterRatio[ctlr.multiClusterHandler.HAPairClusterName]) / totalClusterRatio)
			rbcs[beIdx].Cluster = ctlr.multiClusterHandler.HAPairClusterName

		} else {
			// Older versions of openshift do not have a weight field
			// so we will basically ignore it.
			rbcs[beIdx].Weight = 0.0
			rbcs[beIdx].Cluster = ctlr.multiClusterHandler.HAPairClusterName
		}
	}

	// Process Alternate backends
	if route.Spec.AlternateBackends != nil && (!localClusterPoolRestricted || !hAPeerClusterPoolRestricted) {
		for _, svc := range route.Spec.AlternateBackends {
			if !localClusterPoolRestricted {
				beIdx = beIdx + 1
				rbcs[beIdx].Name = svc.Name
				rbcs[beIdx].Cluster = ctlr.multiClusterHandler.LocalClusterName
				rbcs[beIdx].Weight = (float64(*(svc.Weight)) / totalSvcWeights) *
					(float64(*ctlr.clusterRatio[ctlr.multiClusterHandler.LocalClusterName]) / totalClusterRatio)
			}
			// HA partner cluster
			if ctlr.multiClusterHandler.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
				beIdx = beIdx + 1
				rbcs[beIdx].Name = svc.Name
				rbcs[beIdx].Weight = (float64(*(svc.Weight)) / totalSvcWeights) *
					(float64(*ctlr.clusterRatio[ctlr.multiClusterHandler.HAPairClusterName]) / totalClusterRatio)
				rbcs[beIdx].Cluster = ctlr.multiClusterHandler.HAPairClusterName
			}
		}
	}
	// External services
	for _, svc := range clusterSvcs {
		// Skip invalid extended service
		if ctlr.checkValidMultiClusterService(svc, false) != nil || ctlr.isAddingPoolRestricted(svc.ClusterName) {
			continue
		}
		beIdx = beIdx + 1
		rbcs[beIdx].Name = svc.SvcName
		if r, ok := ctlr.clusterRatio[svc.ClusterName]; ok {
			rbcs[beIdx].Weight = (float64(*svc.Weight) / totalSvcWeights) *
				(float64(*r) / totalClusterRatio)
		} else {
			// Service is from unknown cluster, so set weight to zero which is already set
			rbcs[beIdx].Weight = 0
		}
		rbcs[beIdx].Cluster = svc.ClusterName
		rbcs[beIdx].SvcNamespace = svc.Namespace
	}
	return rbcs
}

func (ctlr *Controller) updateDataGroupForABTransportServer(
	pool cisapiv1.TSPool,
	dgName string,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
	port intstr.IntOrString,
) {
	if !isTSABDeployment(&pool) && ctlr.discoveryMode != Ratio && ctlr.discoveryMode != DefaultMode {
		/*
				 AB		RATIO      Skip Updating DG
			=========================================
				True  	True    =       False
				True  	False   =       False
				False 	True    =       False
				False  	False   =       True
		*/
		return
	}

	weightTotal := 0.0
	backends := ctlr.GetPoolBackendsForTS(&pool, namespace)
	for _, svc := range backends {
		weightTotal = weightTotal + svc.Weight
	}
	key := "/"
	if weightTotal == 0 {
		// If all services have 0 weight, 503 will be returned
		updateDataGroup(dgMap, dgName, partition, namespace, key, "", "string")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0.0
		for _, be := range backends {
			// fetch target port for backend, if not found use serviceport
			targetPort := ctlr.fetchTargetPort(be.SvcNamespace, be.Name, be.SvcPort, be.Cluster)
			if targetPort != (intstr.IntOrString{}) {
				be.SvcPort = targetPort
			}
			if be.Weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + be.Weight
			weightedSliceThreshold := runningWeightTotal / weightTotal
			svcNamespace := namespace
			if be.SvcNamespace != "" {
				svcNamespace = be.SvcNamespace
			}
			poolName := ctlr.framePoolNameForTS(svcNamespace, pool, be)
			entry := fmt.Sprintf("%s,%4.3f", poolName, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, dgName,
			partition, namespace, key, value, "string")
	}
}

// updateDataGroupForABVirtualServer updates the data group map based on alternativeBackends of route.
func (ctlr *Controller) updateDataGroupForABVirtualServer(
	pool *cisapiv1.VSPool,
	dgName string,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
	port intstr.IntOrString,
	host string,
	hostAliases []string,
	termination string,
) {
	if !isVSABDeployment(pool) && ctlr.discoveryMode != Ratio && ctlr.discoveryMode != DefaultMode {
		/*
				 AB		RATIO      Skip Updating DG
			=========================================
				True  	True    =       False
				True  	False   =       False
				False 	True    =       False
				False  	False   =       True
		*/
		return
	}

	weightTotal := 0.0
	backends := ctlr.GetPoolBackendsForVS(pool, namespace)
	for _, svc := range backends {
		weightTotal = weightTotal + svc.Weight
	}

	path := pool.Path
	// We don't support path-based A/B for pass-thru
	switch termination {
	case TLSPassthrough:
		path = ""
	}
	if path == "/" {
		path = ""
	}
	key := host + path

	if weightTotal == 0 {
		// If all services have 0 weight, 503 will be returned
		updateDataGroup(dgMap, dgName, partition, namespace, key, "", "")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0.0
		for _, be := range backends {
			if be.Weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + be.Weight
			weightedSliceThreshold := runningWeightTotal / weightTotal
			svcNamespace := namespace
			if be.SvcNamespace != "" {
				svcNamespace = be.SvcNamespace
			}
			poolName := ctlr.formatPoolName(
				svcNamespace,
				be.Name,
				port,
				"",
				host,
				be.Cluster,
			)
			entry := fmt.Sprintf("%s,%4.3f", poolName, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, dgName,
			partition, namespace, key, value, "string")
		// Update data group for hostAliases
		for _, host := range hostAliases {
			key := host + path
			updateDataGroup(dgMap, dgName,
				partition, namespace, key, value, "string")
		}
	}
}

func (ctlr *Controller) updateDataGroupForAdvancedSvcTypeLB(
	svc *v1.Service,
	multiClusterServices []cisapiv1.MultiClusterServiceReference,
	dgName string,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
	port v1.ServicePort,
	clusterName string,
) {
	if multiClusterServices == nil {
		return
	}

	weightTotal := 0.0
	backends := ctlr.GetPoolBackendsForSvcTypeLB(svc, port, clusterName, multiClusterServices)
	for _, svc := range backends {
		weightTotal = weightTotal + svc.Weight
	}
	key := "/"
	if weightTotal == 0 {
		// If all services have 0 weight, 503 will be returned
		updateDataGroup(dgMap, dgName, partition, namespace, key, "", "string")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0.0
		for _, be := range backends {
			if be.Weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + be.Weight
			weightedSliceThreshold := runningWeightTotal / weightTotal
			svcNamespace := namespace
			if be.SvcNamespace != "" {
				svcNamespace = be.SvcNamespace
			}
			poolName := ctlr.formatPoolName(
				svcNamespace,
				be.Name,
				be.SvcPort,
				"", "", be.Cluster)
			entry := fmt.Sprintf("%s,%4.3f", poolName, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, dgName,
			partition, namespace, key, value, "string")
	}
}

func (ctlr *Controller) updateDataGroupForIngressLink(
	il *cisapiv1.IngressLink,
	multiClusterServices []cisapiv1.MultiClusterServiceReference,
	dgName string,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
	port v1.ServicePort,
	clusterName string,
) {
	if multiClusterServices == nil {
		return
	}

	weightTotal := 0.0
	backends := ctlr.GetPoolBackendsForIL(&il.Spec, port, clusterName, multiClusterServices)
	for _, svc := range backends {
		weightTotal = weightTotal + svc.Weight
	}
	key := "/"
	if weightTotal == 0 {
		// If all services have 0 weight, 503 will be returned
		updateDataGroup(dgMap, dgName, partition, namespace, key, "", "string")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0.0
		for _, be := range backends {
			if be.Weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + be.Weight
			weightedSliceThreshold := runningWeightTotal / weightTotal
			svcNamespace := namespace
			if be.SvcNamespace != "" {
				svcNamespace = be.SvcNamespace
			}
			poolName := ctlr.formatPoolName(
				svcNamespace,
				be.Name,
				be.SvcPort,
				"", "", be.Cluster)
			entry := fmt.Sprintf("%s,%4.3f", poolName, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, dgName,
			partition, namespace, key, value, "string")
	}
}
