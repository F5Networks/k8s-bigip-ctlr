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
	"net"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

// NewResources is Constructor for Resources
func NewResources() *Resources {
	var rs Resources
	rs.Init()
	return &rs
}

// Resources is Map of Resource configs
type Resources struct {
	sync.Mutex
	rm       resourceKeyMap
	rsMap    ResourceConfigMap
	objDeps  ObjectDependencyMap
	oldRsMap ResourceConfigMap
}

// Init is Receiver to initialize the object.
func (rs *Resources) Init() {
	rs.rm = make(resourceKeyMap)
	rs.rsMap = make(ResourceConfigMap)
	rs.objDeps = make(ObjectDependencyMap)
	rs.oldRsMap = make(ResourceConfigMap)
}

type mergedRuleEntry struct {
	RuleName       string
	OtherRuleNames []string
	MergedActions  map[string][]*action
	OriginalRule   *Rule
}

// Key is resource name, value is unused (since go doesn't have set objects).
type resourceList map[string]bool

// Key is namespace/servicename/serviceport, value is map of resources.
type resourceKeyMap map[serviceKey]resourceList

// ResourceConfigMap key is resource name, value is pointer to config. May be shared.
type ResourceConfigMap map[string]*ResourceConfig

// ObjectDependency TODO => dep can be replaced with  internal DS rqkey
// ObjectDependency identifies a K8s Object
type ObjectDependency struct {
	Kind      string
	Namespace string
	Name      string
	Service   string
}

// ObjectDependencyMap key is a VirtualServer and the value is a
// map of other objects it depends on - typically services.
type ObjectDependencyMap map[ObjectDependency]ObjectDependencies

// RuleDep defines the rule for choosing a service from multiple services in VirtualServer, mainly by path.
const RuleDep = "Rule"

// ObjectDependencies contains each dependency and its use count (usually 1)
type ObjectDependencies map[ObjectDependency]int

// NewObjectDependencies parses an object and returns a map of its dependencies
func NewObjectDependencies(
	obj interface{},
) (ObjectDependency, ObjectDependencies) {
	deps := make(ObjectDependencies)
	virtual := obj.(*cisapiv1.VirtualServer)
	// TODO => dep can be replaced with  internal DS rqkey
	key := ObjectDependency{
		Kind:      VirtualServer,
		Name:      virtual.ObjectMeta.Name,
		Namespace: virtual.ObjectMeta.Namespace,
	}

	deps[key] = 1
	for _, pool := range virtual.Spec.Pools {
		dep := ObjectDependency{
			Kind:      RuleDep,
			Namespace: virtual.ObjectMeta.Namespace,
			Name:      virtual.Spec.Host + pool.Path,
			Service:   pool.Service,
		}
		deps[dep]++
	}
	return key, deps
}

type portStruct struct {
	protocol string
	port     int32
}

// Return the required ports for VS (depending on sslRedirect/allowHttp vals)
func (crMgr *CRManager) virtualPorts(vs *cisapiv1.VirtualServer) []portStruct {

	// TODO ==> This will change as we will support custom ports.
	const DEFAULT_HTTP_PORT int32 = 80
	//const DEFAULT_HTTPS_PORT int32 = 443
	var httpPort int32
	// var httpsPort int32
	httpPort = DEFAULT_HTTP_PORT
	// httpsPort = DEFAULT_HTTPS_PORT

	http := portStruct{
		protocol: "http",
		port:     httpPort,
	}
	// Support TLS Type, Create both HTTP and HTTPS
	/**
	https := portStruct{
		protocol: "https",
		port:     httpsPort,
	}**/
	var ports []portStruct

	// Support TLS Type, Create both HTTP and HTTPS
	/**
	if len(vs.Spec.TLS) > 0 {
		// 2 virtual servers needed, both HTTP and HTTPS
		ports = append(ports, http)
		ports = append(ports, https)
	} else {
		// HTTP only
		ports = append(ports, http)
	}**/

	ports = append(ports, http)

	return ports
}

// format the virtual server name for an VirtualServer
func formatVirtualServerName(ip string, port int32) string {
	// Strip any bracket characters; replace special characters ". : /"
	// with "-" and "%" with ".", for naming purposes
	ip = strings.Trim(ip, "[]")
	ip = AS3NameFormatter(ip)
	return fmt.Sprintf("f5_crd_virtualserver_%s_%d", ip, port)
}

// format the pool name for an VirtualServer
func formatVirtualServerPoolName(namespace, svc string) string {
	poolName := fmt.Sprintf("%s_%s", namespace, svc)
	return AS3NameFormatter(poolName)
}

// Creates resource config based on VirtualServer resource config
func (crMgr *CRManager) createRSConfigFromVirtualServer(
	vs *cisapiv1.VirtualServer,
	pStruct portStruct,
) *ResourceConfig {

	var cfg ResourceConfig
	var bindAddr string
	var pools Pools
	var rules *Rules
	var plcy *Policy

	cfg.Virtual.Partition = crMgr.Partition

	if vs.Spec.VirtualServerAddress == "" {
		// Virtual Server IP is not given, exit with error log.
		log.Error("VirtualServer IP Address is not provided.  " +
			"Create VirtualServer with 'virtual.spec.VirtualServerAddress'.")
	} else {
		bindAddr = vs.Spec.VirtualServerAddress
	}
	// Create VirtualServer in resource config.
	cfg.Virtual.Name = formatVirtualServerName(bindAddr, pStruct.port)

	for _, pl := range vs.Spec.Pools {
		pool := Pool{
			Name: formatVirtualServerPoolName(
				vs.ObjectMeta.Namespace,
				pl.Service,
			),
			Partition:   cfg.Virtual.Partition,
			ServiceName: pl.Service,
			ServicePort: pl.ServicePort,
		}
		pools = append(pools, pool)
	}

	rules = processVirtualServerRules(vs)

	policyName := cfg.Virtual.Name + "_policy"

	plcy = createPolicy(*rules, policyName, vs.ObjectMeta.Namespace)

	cfg.MetaData.rscName = vs.ObjectMeta.Name

	// Check to see if we already have any VirtualServer for this IP:Port
	if oldCfg, exists := crMgr.resources.GetByName(cfg.Virtual.Name); exists {
		// If we do, use an existing config
		cfg.copyConfig(oldCfg)

		// If any of the new pools don't already exist, add them
		for _, newPool := range pools {
			found := false
			for _, pl := range cfg.Pools {
				if pl.Name == newPool.Name {
					found = true
					break
				}
			}
			if !found {
				cfg.Pools = append(cfg.Pools, newPool)
			}
		}

		// If any of the new rules already exist, update them; else add them
		if len(cfg.Policies) > 0 && rules != nil {
			policy := cfg.Policies[0]
			for _, newRule := range *rules {
				found := false
				for i, rl := range policy.Rules {
					if rl.Name == newRule.Name && rl.FullURI == newRule.FullURI {
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
	} else { // This is a new VS for an VirtualServer
		cfg.MetaData.ResourceType = "virtualServer"
		cfg.Virtual.Enabled = true
		cfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		cfg.Pools = append(cfg.Pools, pools...)
		if plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	}

	crMgr.resources.rsMap[cfg.Virtual.Name] = &cfg
	return &cfg
}

// SetVirtualAddress sets a VirtualAddress
func (v *Virtual) SetVirtualAddress(bindAddr string, port int32) {
	v.Destination = ""
	if bindAddr == "" && port == 0 {
		v.VirtualAddress = nil
	} else {
		v.VirtualAddress = &virtualAddress{
			BindAddr: bindAddr,
			Port:     port,
		}
		// Validate the IP address, and create the destination
		ip, rd := split_ip_with_route_domain(bindAddr)
		if len(rd) > 0 {
			rd = "%" + rd
		}
		addr := net.ParseIP(ip)
		if nil != addr {
			var format string
			if nil != addr.To4() {
				format = "/%s/%s%s:%d"
			} else {
				format = "/%s/%s%s.%d"
			}
			v.Destination = fmt.Sprintf(format, v.Partition, ip, rd, port)
		}
	}
}

// AddRuleToPolicy adds a new rule to existing policy
func (rc *ResourceConfig) AddRuleToPolicy(
	policyName string,
	rule *Rule,
) {
	// We currently have at most 1 policy, 'forwarding'
	policy := rc.FindPolicy("forwarding")
	if nil != policy {
		foundMatch := false
		for i, r := range policy.Rules {
			if r.Name == rule.Name && r.FullURI == rule.FullURI {
				// Replace old rule with new rule, but make sure Ordinal is correct.
				foundMatch = true
				rule.Ordinal = r.Ordinal
				policy.Rules[i] = rule
				break
			}
		}
		if !foundMatch {
			// Rule not found, add.
			policy.Rules = append(policy.Rules, rule)
		}
	} else {
		policy = createPolicy(Rules{rule}, policyName, rc.Virtual.Partition)
	}
	rc.SetPolicy(*policy)
}

// SetPolicy sets a policy
func (rc *ResourceConfig) SetPolicy(policy Policy) {
	toFind := nameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	found := false
	for _, polName := range rc.Virtual.Policies {
		if reflect.DeepEqual(toFind, polName) {
			found = true
			break
		}
	}
	if !found {
		rc.Virtual.Policies = append(rc.Virtual.Policies, toFind)
	}
	for i, pol := range rc.Policies {
		if pol.Name == policy.Name && pol.Partition == policy.Partition {
			rc.Policies[i] = policy
			return
		}
	}
	rc.Policies = append(rc.Policies, policy)
}

// FindPolicy gets the information of a policy
func (rc *ResourceConfig) FindPolicy(controlType string) *Policy {
	for _, pol := range rc.Policies {
		for _, cType := range pol.Controls {
			if cType == controlType {
				return &pol
			}
		}
	}
	return nil
}

// GetByName gets a specific Resource cfg
func (rs *Resources) GetByName(name string) (*ResourceConfig, bool) {
	resource, ok := rs.rsMap[name]
	return resource, ok
}

// GetAllResources is list of all resource configs
func (rs *Resources) GetAllResources() ResourceConfigs {
	var cfgs ResourceConfigs
	for _, cfg := range rs.rsMap {
		cfgs = append(cfgs, cfg)
	}
	return cfgs
}

// Copies from an existing config into our new config
func (rc *ResourceConfig) copyConfig(cfg *ResourceConfig) {
	// MetaData
	rc.MetaData = cfg.MetaData
	// Virtual
	rc.Virtual = cfg.Virtual
	// Policies ref
	rc.Virtual.Policies = make([]nameRef, len(cfg.Virtual.Policies))
	copy(rc.Virtual.Policies, cfg.Virtual.Policies)
	// Pools
	rc.Pools = make(Pools, len(cfg.Pools))
	copy(rc.Pools, cfg.Pools)
	// Pool Members and Monitor Names
	for i := range rc.Pools {
		rc.Pools[i].Members = make([]Member, len(cfg.Pools[i].Members))
		copy(rc.Pools[i].Members, cfg.Pools[i].Members)
	}
	// Policies
	rc.Policies = make([]Policy, len(cfg.Policies))
	copy(rc.Policies, cfg.Policies)

	for i := range rc.Policies {
		rc.Policies[i].Controls = make([]string, len(cfg.Policies[i].Controls))
		copy(rc.Policies[i].Controls, cfg.Policies[i].Controls)
		rc.Policies[i].Requires = make([]string, len(cfg.Policies[i].Requires))
		copy(rc.Policies[i].Requires, cfg.Policies[i].Requires)

		// Rules
		rc.Policies[i].Rules = make([]*Rule, len(cfg.Policies[i].Rules))
		// Actions and Conditions
		for j := range rc.Policies[i].Rules {
			rc.Policies[i].Rules[j] = &Rule{}
			rc.Policies[i].Rules[j].Actions = make([]*action, len(cfg.Policies[i].Rules[j].Actions))
			rc.Policies[i].Rules[j].Conditions = make([]*condition, len(cfg.Policies[i].Rules[j].Conditions))
			for k := range rc.Policies[i].Rules[j].Conditions {
				rc.Policies[i].Rules[j].Conditions[k] = &condition{}
				rc.Policies[i].Rules[j].Conditions[k].Values =
					make([]string, len(cfg.Policies[i].Rules[j].Conditions[k].Values))
			}
		}
		copy(rc.Policies[i].Rules, cfg.Policies[i].Rules)
		for j := range rc.Policies[i].Rules {
			copy(rc.Policies[i].Rules[j].Actions, cfg.Policies[i].Rules[j].Actions)
			copy(rc.Policies[i].Rules[j].Conditions, cfg.Policies[i].Rules[j].Conditions)
			for k := range rc.Policies[i].Rules[j].Conditions {
				copy(rc.Policies[i].Rules[j].Conditions[k].Values, cfg.Policies[i].Rules[j].Conditions[k].Values)
			}
		}
	}
}

// split_ip_with_route_domain splits ip into ip and route domain
func split_ip_with_route_domain(address string) (ip string, rd string) {
	// Split the address into the ip and routeDomain (optional) parts
	//     address is of the form: <ipv4_or_ipv6>[%<routeDomainID>]
	idRdRegex := regexp.MustCompile(`^([^%]*)%(\d+)$`)

	match := idRdRegex.FindStringSubmatch(address)
	if match != nil {
		ip = match[1]
		rd = match[2]
	} else {
		ip = address
		rd = ""
	}
	return
}

// UpdateDependencies will keep the rs.objDeps map updated, and return two
// arrays identifying what has changed - added for dependencies that were
// added, and removed for dependencies that were removed.
func (rs *Resources) UpdateDependencies(
	newKey ObjectDependency,
	newDeps ObjectDependencies,
	lookupFunc func(key ObjectDependency) bool,
) ([]ObjectDependency, []ObjectDependency) {

	// Update dependencies for newKey
	var added, removed []ObjectDependency
	oldDeps, found := rs.objDeps[newKey]
	if found {
		// build list of removed deps
		for oldDep := range oldDeps {
			if _, found = newDeps[oldDep]; !found {
				// If Rule, put at front of list to ensure we unmerge before trying
				// to process any removed annotation rules
				if oldDep.Kind == RuleDep {
					removed = append([]ObjectDependency{oldDep}, removed...)
				} else {
					removed = append(removed, oldDep)
				}
			}
		}
		// build list of added deps
		for newDep := range newDeps {
			if _, found = oldDeps[newDep]; !found {
				added = append(added, newDep)
			}
		}
	} else {
		// all newDeps are adds
		for newDep := range newDeps {
			added = append(added, newDep)
		}
	}
	rs.objDeps[newKey] = newDeps

	return added, removed
}

func (rc *ResourceConfig) DeleteRuleFromPolicy(
	policyName string,
	rule *Rule,
	mergedRulesMap map[string]map[string]mergedRuleEntry,
) {
	var policy *Policy
	for _, pol := range rc.Policies {
		if pol.Name == policyName {
			policy = &pol
			break
		}
	}
	if nil != policy {
		for i, r := range policy.Rules {
			if r.Name == rule.Name && r.FullURI == rule.FullURI {
				// Remove old rule
				unmerged := rc.UnmergeRule(rule.Name, mergedRulesMap)
				if len(policy.Rules) == 1 && !unmerged {
					rc.RemovePolicy(*policy)
				} else if !unmerged {
					ruleOffsets := []int{i}
					policy.RemoveRules(ruleOffsets)
					rc.SetPolicy(*policy)
				}
				break
			}
		}
	}
}

//TODO ==> To be implemented Post Alpha.
//Delete unused pool from resource config
// Updating or removing the service from virtual may required delete unused pool from rscfg.
// func (rc *ResourceConfig) DeleteUnusedPool(){
// }

func (rc *ResourceConfig) RemovePolicy(policy Policy) {
	toFind := nameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	for i, polName := range rc.Virtual.Policies {
		if reflect.DeepEqual(toFind, polName) {
			// Remove from array
			copy(rc.Virtual.Policies[i:], rc.Virtual.Policies[i+1:])
			rc.Virtual.Policies[len(rc.Virtual.Policies)-1] = nameRef{}
			rc.Virtual.Policies = rc.Virtual.Policies[:len(rc.Virtual.Policies)-1]
			break
		}
	}
	for i, pol := range rc.Policies {
		if pol.Name == toFind.Name && pol.Partition == toFind.Partition {
			if len(rc.Policies) == 1 {
				// No policies left
				rc.Policies = nil
			} else {
				// Remove from array
				copy(rc.Policies[i:], rc.Policies[i+1:])
				rc.Policies[len(rc.Policies)-1] = Policy{}
				rc.Policies = rc.Policies[:len(rc.Policies)-1]
			}
			return
		}
	}
}

func (pol *Policy) RemoveRules(ruleOffsets []int) bool {
	polChanged := false
	if len(ruleOffsets) > 0 {
		polChanged = true
		for i := len(ruleOffsets) - 1; i >= 0; i-- {
			pol.RemoveRuleAt(ruleOffsets[i])
		}
		// Must fix the ordinals on the remaining rules
		for i, rule := range pol.Rules {
			rule.Ordinal = i
		}
	}
	return polChanged
}

func (pol *Policy) RemoveRuleAt(offset int) bool {
	if offset >= len(pol.Rules) {
		return false
	}
	copy(pol.Rules[offset:], pol.Rules[offset+1:])
	pol.Rules[len(pol.Rules)-1] = &Rule{}
	pol.Rules = pol.Rules[:len(pol.Rules)-1]
	return true
}

func (rc *ResourceConfig) UnmergeRule(ruleName string, mergedRulesMap map[string]map[string]mergedRuleEntry) bool {
	rsName := rc.GetName()
	if _, ok := mergedRulesMap[rsName]; !ok {
		return false
	}
	if _, ok := mergedRulesMap[rsName][ruleName]; !ok {
		return false
	}
	entry := mergedRulesMap[rsName][ruleName]

	// This rule had other rules merged into it
	if entry.MergedActions != nil {
		// Find the policy and rule for this entry and delete it
		policy := rc.FindPolicy("forwarding")
		for i := range policy.Rules {
			if policy.Rules[i].Name == entry.RuleName {
				policy.Rules = append(policy.Rules[:i], policy.Rules[i+1:]...)
				break
			}
		}

		// Unmerge the rules that were merged with this rule
		for _, mergeeRuleName := range entry.OtherRuleNames {
			mergeeRuleEntry := mergedRulesMap[rsName][mergeeRuleName]
			mergeeRule := mergeeRuleEntry.OriginalRule

			// Add unmerged rule back to policy delete its mergedRulesMap entry
			policy.Rules = append(policy.Rules, mergeeRule)
			delete(mergedRulesMap[rsName], mergeeRuleName)
		}

		// Reset the policy and delete this mergedRulesMap entry and then merge the rules of the reset policy
		rc.SetPolicy(*policy)
		delete(mergedRulesMap[rsName], ruleName)
		rc.MergeRules(mergedRulesMap)
		// This rule was merged into anther rule
	} else {
		mergerRuleName := entry.OtherRuleNames[0]
		mergerRuleEntry := mergedRulesMap[rsName][mergerRuleName]

		// Remove ruleName from merged rule entry
		for i := range mergerRuleEntry.OtherRuleNames {
			if mergerRuleEntry.OtherRuleNames[i] == ruleName {
				mergerRuleEntry.OtherRuleNames = append(mergerRuleEntry.OtherRuleNames[:i], mergerRuleEntry.OtherRuleNames[i+1:]...)
				break
			}
		}

		// Get the merged actions and delete them from the merger entry and delete mergedRulesMap entries
		mergedActions := mergerRuleEntry.MergedActions[ruleName]
		delete(mergerRuleEntry.MergedActions, ruleName)
		if len(mergerRuleEntry.MergedActions) == 0 {
			delete(mergedRulesMap[rsName], mergerRuleName)
		}
		delete(mergedRulesMap[rsName], ruleName)

		// Find the merger rule and delete the merged actions from it
		policy := rc.FindPolicy("forwarding")
		for i := range policy.Rules {
			if policy.Rules[i].Name == mergerRuleName {
				var deletedActionIndices []int

				// Find and these merged actions indices
				for j := range mergedActions {
					for k := range policy.Rules[i].Actions {
						if mergedActions[j] == policy.Rules[i].Actions[k] {
							deletedActionIndices = append(deletedActionIndices, k)
						}
					}
				}

				// Delete these merged actions
				for _, index := range deletedActionIndices {
					policy.Rules[i].Actions = append(policy.Rules[i].Actions[:index], policy.Rules[i].Actions[index+1:]...)
					for j := range deletedActionIndices {
						deletedActionIndices[j]--
					}
				}

				// Delete the merged rule if everything has been unmerged
				if len(policy.Rules[i].Actions) == 0 {
					policy.Rules = append(policy.Rules[:i], policy.Rules[i+1:]...)
				}
				break
			}
		}

		// Delete the policy if its rules are empty
		if len(policy.Rules) == 0 {
			rc.RemovePolicy(*policy)
		} else {
			rc.SetPolicy(*policy)
		}
	}

	// Delete entry from the mergedRulesMap if it is empty for this config
	if len(mergedRulesMap[rsName]) == 0 {
		delete(mergedRulesMap, rsName)
	}
	return true
}

func (cfg *ResourceConfig) GetName() string {
	return cfg.Virtual.Name
}

func (rc *ResourceConfig) MergeRules(mergedRulesMap map[string]map[string]mergedRuleEntry) {
	policy := rc.FindPolicy("forwarding")
	if policy == nil {
		return
	}

	rules := policy.Rules

	var iDeletedRuleIndices []int
	var jDeletedRuleIndices []int

	// Iterate through the rules and compare them to each other
	for i, rl := range rules {
		if strings.HasSuffix(rl.Name, "-reset") {
			continue
		}
		// Do not merge the same rule to itself or to rules that have already been merged
		for j := i + 1; j < len(rules); j++ {
			if strings.HasSuffix(rules[j].Name, "-reset") {
				continue
			}
			numMatches := 0
			numIConditions := len(rules[i].Conditions)
			numJConditions := len(rules[j].Conditions)
			if numIConditions == numJConditions {
				for k := range rules[i].Conditions {
					for l := range rules[j].Conditions {
						kConditionName := rules[i].Conditions[k].Name
						lConditionName := rules[j].Conditions[l].Name
						rules[i].Conditions[k].Name = ""
						rules[j].Conditions[l].Name = ""
						if reflect.DeepEqual(rules[i].Conditions[k], rules[j].Conditions[l]) {
							numMatches++
						}
						rules[i].Conditions[k].Name = kConditionName
						rules[j].Conditions[l].Name = lConditionName
					}
				}

				// Only merge if both sets of conditions match
				if numMatches == numIConditions {
					var mergerEntry mergedRuleEntry
					var mergeeEntry mergedRuleEntry

					iName := rules[i].Name
					jName := rules[j].Name
					// Merge rule[i] into rule[j]
					if ((strings.Contains(iName, "app-root") || strings.Contains(iName, "url-rewrite")) && !(strings.Contains(jName, "app-root") || strings.Contains(jName, "url-rewrite"))) ||
						((strings.Contains(iName, "app-root") || strings.Contains(iName, "url-rewrite")) && (strings.Contains(jName, "app-root") || strings.Contains(jName, "url-rewrite"))) {
						iDeletedRuleIndices = append(iDeletedRuleIndices, i)
						mergerEntry.RuleName = jName
						mergeeEntry.RuleName = iName
						mergerEntry.OtherRuleNames = []string{iName}
						mergeeEntry.OtherRuleNames = []string{jName}
						mergerEntry.OriginalRule = rules[j]
						mergeeEntry.OriginalRule = rules[i]

						// Merge only unique actions
						for k := range rules[i].Actions {
							found := false
							for l := range rules[j].Actions {
								mergeeName := rules[i].Actions[k].Name
								mergerName := rules[j].Actions[l].Name
								rules[i].Actions[k].Name = ""
								rules[j].Actions[l].Name = ""
								if reflect.DeepEqual(rules[i].Actions[k], rules[j].Actions[l]) {
									found = true
								}
								rules[i].Actions[k].Name = mergeeName
								rules[j].Actions[l].Name = mergerName
							}
							if !found {
								rules[j].Actions = append(rules[j].Actions, rules[i].Actions[k])
								mergerEntry.MergedActions = make(map[string][]*action)
								mergerEntry.MergedActions[iName] = append(mergerEntry.MergedActions[iName], rules[i].Actions[k])
							}
						}
						// Merge rule[j] into rule[i]
					} else if !(strings.Contains(iName, "app-root") || strings.Contains(iName, "url-rewrite")) && (strings.Contains(jName, "app-root") || strings.Contains(jName, "url-rewrite")) {
						jDeletedRuleIndices = append(jDeletedRuleIndices, j)
						mergerEntry.RuleName = iName
						mergeeEntry.RuleName = jName
						mergerEntry.OtherRuleNames = []string{jName}
						mergeeEntry.OtherRuleNames = []string{iName}
						mergerEntry.OriginalRule = rules[i]
						mergeeEntry.OriginalRule = rules[j]

						// Merge only unique actions
						for k := range rules[j].Actions {
							found := false
							for l := range rules[i].Actions {
								mergeeName := rules[j].Actions[k].Name
								mergerName := rules[i].Actions[l].Name
								rules[j].Actions[k].Name = ""
								rules[i].Actions[l].Name = ""
								if reflect.DeepEqual(rules[j].Actions[k], rules[i].Actions[l]) {
									found = true
								}
								rules[j].Actions[k].Name = mergeeName
								rules[i].Actions[l].Name = mergerName
							}
							if !found {
								rules[i].Actions = append(rules[i].Actions, rules[j].Actions[k])
								mergerEntry.MergedActions = make(map[string][]*action)
								mergerEntry.MergedActions[jName] = append(mergerEntry.MergedActions[jName], rules[j].Actions[k])
							}
						}
					}

					contains := func(slice []string, s string) bool {
						for _, v := range slice {
							if v == s {
								return true
							}
						}
						return false
					}

					// Process entries to the mergedRulesMap
					key := rc.GetName()
					if len(mergerEntry.MergedActions) != 0 {
						// Check if there is are entries for this resource config
						if _, ok := mergedRulesMap[key]; ok {
							// See if there is an entry for the merger
							if entry, ok := mergedRulesMap[key][mergerEntry.RuleName]; ok {
								if !contains(entry.OtherRuleNames, mergerEntry.OtherRuleNames[0]) {
									mergerEntry.OtherRuleNames = append(mergerEntry.OtherRuleNames, entry.OtherRuleNames...)
								}
								mergerEntry.OriginalRule = entry.OriginalRule

								if len(entry.MergedActions) != 0 {
									for k, v := range entry.MergedActions {
										mergerEntry.MergedActions[k] = v
									}
								}
							}
							// See if there is an entry for the mergee
							if entry, ok := mergedRulesMap[key][mergeeEntry.RuleName]; ok {
								mergeeEntry.OriginalRule = entry.OriginalRule
							}
						} else {
							mergedRulesMap[key] = make(map[string]mergedRuleEntry)
						}

						mergedRulesMap[key][mergerEntry.RuleName] = mergerEntry
						mergedRulesMap[key][mergeeEntry.RuleName] = mergeeEntry
					}
				}
			}
		}
	}

	// Process deleted rule indices and remove duplicates
	deletedRuleIndices := append(iDeletedRuleIndices, jDeletedRuleIndices...)
	sort.Ints(deletedRuleIndices)
	var uniqueDeletedRuleIndices []int
	for i := range deletedRuleIndices {
		if i == 0 {
			uniqueDeletedRuleIndices = append(uniqueDeletedRuleIndices, deletedRuleIndices[i])
		} else {
			found := false
			for j := range uniqueDeletedRuleIndices {
				if uniqueDeletedRuleIndices[j] == deletedRuleIndices[i] {
					found = true
				}
			}
			if !found {
				uniqueDeletedRuleIndices = append(uniqueDeletedRuleIndices, deletedRuleIndices[i])
			}
		}
	}

	// Remove rules that were merged with others
	for _, index := range uniqueDeletedRuleIndices {
		rules = append(rules[:index], rules[index+1:]...)
		for i := range uniqueDeletedRuleIndices {
			uniqueDeletedRuleIndices[i]--
		}
	}

	// Sort the rules
	//sort.Sort(sort.Reverse(&rules))

	policy.Rules = rules
	rc.SetPolicy(*policy)
}

func (rcs ResourceConfigs) GetAllPoolMembers() []Member {
	// Get all pool members and write them to VxlanMgr to configure ARP entries
	var allPoolMembers []Member

	for _, cfg := range rcs {
		// Filter the configs to only those that have active services
		if cfg.MetaData.Active {
			for _, pool := range cfg.Pools {
				allPoolMembers = append(allPoolMembers, pool.Members...)
			}
		}
	}
	return allPoolMembers
}

func (rs *Resources) updateOldConfig() {
	rs.oldRsMap = make(ResourceConfigMap)
	for k, v := range rs.rsMap {
		rs.oldRsMap[k] = &ResourceConfig{}
		rs.oldRsMap[k].copyConfig(v)
	}
}

// Deletes respective VirtualServer resource configuration from
// resource configs.
func (rs *Resources) deleteVirtualServer(rsName string) {
	delete(rs.rsMap, rsName)
}

// AS3NameFormatter formarts resources names according to AS3 convention
// TODO: Should we use this? Or this will be done in agent?
func AS3NameFormatter(name string) string {
	replacer := strings.NewReplacer(".", "_", ":", "_", "/", "_", "%", ".", "-", "_")
	name = replacer.Replace(name)
	return name
}
