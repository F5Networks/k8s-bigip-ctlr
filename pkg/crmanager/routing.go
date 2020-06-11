/*-
* Copyright (c) 2016-2019, F5 Networks, Inc.
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
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

// processVirtualServerRules process rules for VirtualServer
func processVirtualServerRules(
	vs *cisapiv1.VirtualServer,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)

	for _, pl := range vs.Spec.Pools {
		uri := vs.Spec.Host + pl.Path
		// Service cannot be empty
		if pl.Service == "" {
			continue
		}
		poolName := formatVirtualServerPoolName(
			vs.ObjectMeta.Namespace,
			pl.Service,
		)
		ruleName := formatVirtualServerRuleName(vs.Spec.Host, pl.Path, poolName)
		rl, err := createRule(uri, poolName, ruleName)
		if nil != err {
			log.Warningf("Error configuring rule: %v", err)
			return nil
		}
		if true == strings.HasPrefix(uri, "*.") {
			wildcards[uri] = rl
		} else {
			rlMap[uri] = rl
		}
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

// format the rule name for VirtualServer
func formatVirtualServerRuleName(host, path, pool string) string {
	var rule string
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
func createRule(uri, poolName, ruleName string) (*Rule, error) {
	_u := "scheme://" + uri
	_u = strings.TrimSuffix(_u, "/")
	u, err := url.Parse(_u)
	if nil != err {
		return nil, err
	}

	a := action{
		Forward: true,
		Name:    "0",
		Pool:    poolName,
		Request: true,
	}

	var c []*condition
	if true == strings.HasPrefix(uri, "*.") {
		c = append(c, &condition{
			EndsWith: true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{strings.TrimPrefix(u.Host, "*")},
		})
	} else if u.Host != "" {
		c = append(c, &condition{
			Equals:   true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{u.Host},
		})
	}
	if 0 != len(u.EscapedPath()) {
		c = append(c, createPathSegmentConditions(u)...)
	}

	rl := Rule{
		Name:       ruleName,
		FullURI:    uri,
		Actions:    []*action{&a},
		Conditions: c,
	}

	log.Debugf("Configured rule: %v", rl)
	return &rl, nil
}

func createPathSegmentConditions(u *url.URL) []*condition {
	var c []*condition
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	segments := strings.Split(path, "/")
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
		Controls:  []string{"forwarding"},
		Legacy:    true,
		Name:      policyName,
		Partition: partition,
		Requires:  []string{"http"},
		Rules:     Rules{},
		Strategy:  "/Common/first-match",
	}

	plcy.Rules = rls

	// Check for the existence of the TCP field in the conditions.
	// This would indicate that a whitelist rule is in the policy
	// and that we need to add the "tcp" requirement to the policy.
	requiresTcp := false
	for _, x := range rls {
		for _, c := range x.Conditions {
			if c.Tcp == true {
				requiresTcp = true
			}
		}
	}

	// Add the tcp requirement if needed; indicated by the presence
	// of the TCP field.
	if requiresTcp {
		plcy.Requires = append(plcy.Requires, "tcp")
	}

	log.Debugf("Configured policy: %v", plcy)
	return &plcy
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

	// Strategy 3: "equal" match type takes more priority than others
	// such as "starts-with", "ends-with", "contains"
	// TODO: And "start-with" and "ends-with" takes same priority and take
	// more priority than "contains"
	getConditionCounters := func(rule *Rule) (int, int) {
		var (
			eqCount  int
			endCount int
		)
		for _, cnd := range ruleI.Conditions {
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

	// Strategy 4: Lowest Ordinal
	return ruleI.Ordinal < ruleJ.Ordinal

}

func (rules Rules) Swap(i, j int) {
	rules[i], rules[j] = rules[j], rules[i]
}

func httpRedirectIRule(port int32) string {
	// The key in the data group is the host name or * to match all.
	// The data is a list of paths for the host delimited by '|' or '/' for all.
	iRuleCode := fmt.Sprintf(`
		when HTTP_REQUEST {
			
			# check if there is an entry in data-groups to accept requests from all domains.
			# */ represents [* -> Any host / -> default path]
			set allHosts [class match -value "*/" equals https_redirect_dg]
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
				set paths [class match -value $host equals https_redirect_dg] 
				# Check if host with combination of "/" matches https_redirect_dg
				if {$paths == ""} {
					set hosts ""
					append hosts $host "/"
					set paths [class match -value $hosts equals https_redirect_dg] 
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
					HTTP::redirect https://[getfield [HTTP::host] ":" 1]:%d[HTTP::uri]
				}
			}
		}`, port)

	return iRuleCode
}

func NewServiceFwdRuleMap() ServiceFwdRuleMap {
	return make(ServiceFwdRuleMap)
}

// key is namespace/serviceName, data is map of host to paths.
type ServiceFwdRuleMap map[serviceQueueKey]HostFwdRuleMap

// key is fqdn host name, data is map of paths.
type HostFwdRuleMap map[string]FwdRuleMap

// key is path regex, data unused. Using a map as go doesn't have a set type.
type FwdRuleMap map[string]bool

func (sfrm ServiceFwdRuleMap) AddEntry(ns, svc, host, path string) {
	if path == "" {
		path = "/"
	}
	sKey := serviceQueueKey{Namespace: ns, ServiceName: svc}
	hfrm, found := sfrm[sKey]
	if !found {
		hfrm = make(HostFwdRuleMap)
		sfrm[sKey] = hfrm
	}
	frm, found := hfrm[host]
	if !found {
		frm = make(FwdRuleMap)
		hfrm[host] = frm
	}
	if _, found = frm[path]; !found {
		frm[path] = true
	}
}

func (sfrm ServiceFwdRuleMap) AddToDataGroup(dgMap DataGroupNamespaceMap) {
	// Multiple service keys may reference the same host, so flatten those first
	for skey, hostMap := range sfrm {
		nsGrp, found := dgMap[skey.Namespace]
		if !found {
			nsGrp = &InternalDataGroup{
				Name:      HttpsRedirectDgName,
				Partition: DEFAULT_PARTITION,
			}
			dgMap[skey.Namespace] = nsGrp
		}
		for host, pathMap := range hostMap {
			for path, _ := range pathMap {
				nsGrp.AddOrUpdateRecord(host+path, path)
			}

		}
	}
}

// Update the datagroups cache, indicating if something
// had changed by updating 'stats', which should rewrite the config.
func (crMgr *CRManager) syncDataGroups(
	dgMap InternalDataGroupMap,
	namespace string,
) {
	crMgr.intDgMutex.Lock()
	defer crMgr.intDgMutex.Unlock()

	// Add new or modified data group records
	for mapKey, grp := range dgMap {
		nsDg, found := crMgr.intDgMap[mapKey]
		if found {
			if !reflect.DeepEqual(nsDg[namespace], grp[namespace]) {
				// current namespace records aren't equal
				nsDg[namespace] = grp[namespace]
			}
		} else {
			crMgr.intDgMap[mapKey] = grp
		}
	}

	// Remove non-existent data group records (those that are currently
	// defined, but aren't part of the new set)
	for mapKey, nsDg := range crMgr.intDgMap {
		_, found := dgMap[mapKey]
		if !found {
			_, found := nsDg[namespace]
			if found {
				delete(nsDg, namespace)
				if len(nsDg) == 0 {
					delete(crMgr.intDgMap, mapKey)
				}
			}
		}
	}
}
