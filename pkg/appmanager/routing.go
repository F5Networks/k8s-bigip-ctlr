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
 * WITHOUT WARRANTIES OR conditionS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"bytes"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

const httpRedirectIRuleName = "http_redirect_irule"
const abDeploymentPathIRuleName = "ab_deployment_path_irule"
const sslPassthroughIRuleName = "openshift_passthrough_irule"

// Internal data group for passthrough routes to map server names to pools.
const passthroughHostsDgName = "ssl_passthrough_servername_dg"

// Internal data group for reencrypt routes.
const reencryptHostsDgName = "ssl_reencrypt_servername_dg"

// Internal data group for reencrypt routes that maps the host name to the
// server ssl profile.
const reencryptServerSslDgName = "ssl_reencrypt_serverssl_dg"

// Internal data group for https redirect
const httpsRedirectDgName = "https_redirect_dg"

// Internal data group for ab deployment routes.
const abDeploymentDgName = "ab_deployment_dg"

// DataGroup flattening.
type FlattenConflictFunc func(key, oldVal, newVal string) string

var groupFlattenFuncMap = map[string]FlattenConflictFunc{
	passthroughHostsDgName:   flattenConflictWarn,
	reencryptHostsDgName:     flattenConflictWarn,
	reencryptServerSslDgName: flattenConflictWarn,
	httpsRedirectDgName:      flattenConflictConcat,
	abDeploymentDgName:       flattenConflictConcat,
}

func (r Rules) Len() int { return len(r) }
func (r Rules) Less(i, j int) bool {
	iApprootRedirect := strings.Contains(r[i].Name, "app-root-redirect-rule")
	iApprootForward := strings.Contains(r[i].Name, "app-root-forward-rule")
	iUrlrewrite := strings.Contains(r[i].Name, "url-rewrite-rule")

	jApprootRedirect := strings.Contains(r[j].Name, "app-root-redirect-rule")
	jApprootForward := strings.Contains(r[j].Name, "app-root-forward-rule")
	jUrlrewrite := strings.Contains(r[j].Name, "url-rewrite-rule")

	if iApprootRedirect && !jApprootRedirect {
		return false
	}
	if !iApprootRedirect && jApprootRedirect {
		return true
	}
	if iApprootForward && !jApprootForward {
		return false
	}
	if !iApprootForward && jApprootForward {
		return true
	}
	if iUrlrewrite && !jUrlrewrite {
		return false
	}
	if !iUrlrewrite && jUrlrewrite {
		return true
	}

	if r[i].FullURI == r[j].FullURI {
		if len(r[j].Actions) > 0 && r[j].Actions[0].Reset {
			return false
		}
		return true
	}

	return r[i].FullURI < r[j].FullURI
}
func (r Rules) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
	r[i].Ordinal = i
	r[j].Ordinal = j
}

type Routes []*routeapi.Route

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

func createRule(uri, poolName, partition, ruleName string) (*Rule, error) {
	_u := "scheme://" + uri
	_u = strings.TrimSuffix(_u, "/")
	u, err := url.Parse(_u)
	if nil != err {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteRune('/')
	b.WriteString(partition)
	b.WriteRune('/')
	b.WriteString(poolName)

	a := action{
		Forward: true,
		Name:    "0",
		Pool:    b.String(),
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

func processIngressRules(
	ing *v1beta1.IngressSpec,
	urlRewriteMap map[string]string,
	whitelistSourceRanges []string,
	appRootMap map[string]string,
	pools []Pool,
	partition string,
) (*Rules, map[string]string, map[string][]string) {
	var err error
	var uri, poolName string
	var rl *Rule
	var urlRewriteRules []*Rule
	var appRootRules []*Rule

	rlMap := make(ruleMap)
	wildcards := make(ruleMap)
	urlRewriteRefs := make(map[string]string)
	appRootRefs := make(map[string][]string)

	for _, rule := range ing.Rules {
		if nil != rule.IngressRuleValue.HTTP {
			for _, path := range rule.IngressRuleValue.HTTP.Paths {
				uri = rule.Host + path.Path
				for _, pool := range pools {
					if path.Backend.ServiceName == pool.ServiceName {
						poolName = pool.Name
					}
				}
				if poolName == "" {
					continue
				}
				ruleName := formatIngressRuleName(rule.Host, path.Path, poolName)
				// This blank name gets overridden by an ordinal later on
				rl, err = createRule(uri, poolName, partition, ruleName)
				if nil != err {
					log.Warningf("Error configuring rule: %v", err)
					return nil, nil, nil
				}
				if true == strings.HasPrefix(uri, "*.") {
					wildcards[uri] = rl
				} else {
					rlMap[uri] = rl
				}

				// Process url-rewrite annotation
				if urlRewriteTargetedVal, ok := urlRewriteMap[uri]; ok == true {
					urlRewriteRule := processURLRewrite(uri, urlRewriteTargetedVal, multiServiceIngressType)
					urlRewriteRules = append(urlRewriteRules, urlRewriteRule)
					urlRewriteRefs[poolName] = urlRewriteRule.Name
				}

				// Process app-root annotation
				if appRootTargetedVal, ok := appRootMap[rule.Host]; ok == true {
					appRootRulePair := processAppRoot(uri, appRootTargetedVal, fmt.Sprintf("/%s/%s", partition, poolName), multiServiceIngressType)
					appRootRules = append(appRootRules, appRootRulePair...)
					if len(appRootRulePair) == 2 {
						appRootRefs[poolName] = append(appRootRefs[poolName], appRootRulePair[0].Name)
						appRootRefs[poolName] = append(appRootRefs[poolName], appRootRulePair[1].Name)
					}
				}
				poolName = ""
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	sortrules := func(r ruleMap, rls *Rules, ordinal int) {
		for _, v := range r {
			*rls = append(*rls, v)
		}
		sort.Sort(sort.Reverse(*rls))
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

	if len(appRootRules) != 0 {
		rls = append(rls, appRootRules...)
	}
	if len(urlRewriteRules) != 0 {
		rls = append(rls, urlRewriteRules...)
	}

	if len(whitelistSourceRanges) != 0 {
		// Add whitelist entries to each rule.
		//
		// Whitelist rules are added as other conditions on the rule so that
		// the whitelist is actually enforced. The whitelist entries cannot
		// be separate rules because of the matching strategy that is used.
		//
		// The matching strategy used is first-match. Therefore, if the
		// whitelist were a separate rule, and they did not match, then
		// further rules will be processed and this is not what the function
		// of a whitelist should be.
		//
		// Whitelists should be used to *prevent* access. So they need to be
		// a separate condition of *each* rule.
		for _, x := range rls {
			cond := condition{
				Tcp:     true,
				Address: true,
				Matches: true,
				Name:    "0",
				Values:  whitelistSourceRanges,
			}
			x.Conditions = append(x.Conditions, &cond)
		}
	}

	return &rls, urlRewriteRefs, appRootRefs
}

func httpRedirectIRule(port int32) string {
	// The key in the data group is the host name or * to match all.
	// The data is a list of paths for the host delimited by '|' or '/' for all.
	iRuleCode := fmt.Sprintf(`
		when HTTP_REQUEST {
			# Look for exact match for host name
			set paths [class match -value [HTTP::host] equals https_redirect_dg]
			if {$paths == ""} {
				# See if there's an entry that matches all hosts
				set paths [class match -value "*" equals https_redirect_dg]
			}
			if {$paths != ""} {
				set redir 0
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

func selectPoolIRuleFunc() string {
	iRuleFunc := fmt.Sprintf(`
		proc select_ab_pool {path default_pool } {
			set last_slash [string length $path]
			set ab_class "/%s/ab_deployment_dg"
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
					foreach service_rule $service_rules {
						set fields [split $service_rule ","]
						set pool_name [lindex $fields 0]
						set weight [expr {double([lindex $fields 1])}]
						if {$weight_selection <= $weight} then {
							return $pool_name
						}
					}
				}
				# If we had a match, but all weights were 0 then
				# retrun a 503 (Service Unavailable)
				HTTP::respond 503
			}
			return $default_pool
		}`, DEFAULT_PARTITION)

	return iRuleFunc
}

func abDeploymentPathIRule() string {
	// For all A/B deployments that include a path.
	// The key in the data group is the specific route (host/path) to examine.
	// The data is a list of pool/weight pairs delimited by ';'. The pair values
	// are delineated by ','. Finally, the weight value is normalized between
	// 0.0 and 1.0 and the pairs should be listed in ascending order or weight
	// values.
	iRuleCode := fmt.Sprintf("%s\n\n%s", selectPoolIRuleFunc(), `
		when HTTP_REQUEST priority 200 {
			set path [string tolower [HTTP::host]][HTTP::path]
			set selected_pool [call select_ab_pool $path ""]
			if {$selected_pool != ""} then {
				pool $selected_pool
				event disable
			}
		}`)

	return iRuleCode
}

func sslPassthroughIRule() string {
	iRule := fmt.Sprintf(`
		when CLIENT_ACCEPTED {
			TCP::collect
		}

		when CLIENT_DATA {
			# Byte 0 is the content type.
			# Bytes 1-2 are the TLS version.
			# Bytes 3-4 are the TLS payload length.
			# Bytes 5-$tls_payload_len are the TLS payload.
			binary scan [TCP::payload] cSS tls_content_type tls_version tls_payload_len

			switch $tls_version {
				"769" -
				"770" -
				"771" {
					# Content type of 22 indicates the TLS payload contains a handshake.
					if { $tls_content_type == 22 } {
						# Byte 5 (the first byte of the handshake) indicates the handshake
						# record type, and a value of 1 signifies that the handshake record is
						# a ClientHello.
						binary scan [TCP::payload] @5c tls_handshake_record_type
						if { $tls_handshake_record_type == 1 } {
							# Bytes 6-8 are the handshake length (which we ignore).
							# Bytes 9-10 are the TLS version (which we ignore).
							# Bytes 11-42 are random data (which we ignore).

							# Byte 43 is the session ID length.  Following this are three
							# variable-length fields which we shall skip over.
							set record_offset 43

							# Skip the session ID.
							binary scan [TCP::payload] @${record_offset}c tls_session_id_len
							incr record_offset [expr {1 + $tls_session_id_len}]

							# Skip the cipher_suites field.
							binary scan [TCP::payload] @${record_offset}S tls_cipher_suites_len
							incr record_offset [expr {2 + $tls_cipher_suites_len}]

							# Skip the compression_methods field.
							binary scan [TCP::payload] @${record_offset}c tls_compression_methods_len
							incr record_offset [expr {1 + $tls_compression_methods_len}]

							# Get the number of extensions, and store the extensions.
							binary scan [TCP::payload] @${record_offset}S tls_extensions_len
							incr record_offset 2
							binary scan [TCP::payload] @${record_offset}a* tls_extensions

							for { set extension_start 0 }
									{ $tls_extensions_len - $extension_start == abs($tls_extensions_len - $extension_start) }
									{ incr extension_start 4 } {
								# Bytes 0-1 of the extension are the extension type.
								# Bytes 2-3 of the extension are the extension length.
								binary scan $tls_extensions @${extension_start}SS extension_type extension_len

								# Extension type 00 is the ServerName extension.
								if { $extension_type == "00" } {
									# Bytes 4-5 of the extension are the SNI length (we ignore this).

									# Byte 6 of the extension is the SNI type.
									set sni_type_offset [expr {$extension_start + 6}]
									binary scan $tls_extensions @${sni_type_offset}S sni_type

									# Type 0 is host_name.
									if { $sni_type == "0" } {
										# Bytes 7-8 of the extension are the SNI data (host_name)
										# length.
										set sni_len_offset [expr {$extension_start + 7}]
										binary scan $tls_extensions @${sni_len_offset}S sni_len

										# Bytes 9-$sni_len are the SNI data (host_name).
										set sni_start [expr {$extension_start + 9}]
										binary scan $tls_extensions @${sni_start}A${sni_len} tls_servername
									}
								}

								incr extension_start $extension_len
							}

							if { [info exists tls_servername] } {
								set servername_lower [string tolower $tls_servername]
								SSL::disable serverside
								set dflt_pool ""
								set passthru_class "/%[1]s/ssl_passthrough_servername_dg"
								set reencrypt_class "/%[1]s/ssl_reencrypt_servername_dg"
								if { [class exists $passthru_class] } {
									set dflt_pool [class match -value $servername_lower equals $passthru_class]
									if { not ($dflt_pool equals "") } {
										SSL::disable
										HTTP::disable
									}
								}
								elseif { [class exists $reencrypt_class] } {
									set dflt_pool [class match -value $servername_lower equals $reencrypt_class]
									if { not ($dflt_pool equals "") } {
										SSL::enable serverside
									}
								}
								set ab_class "/%[1]s/ab_deployment_dg"
								if { not [class exists $ab_class] } {
									if { $dflt_pool == "" } then {
										log local0.debug "Failed to find pool for $servername_lower"
									} else {
										pool $dflt_pool
									}
								} else {
									set selected_pool [call select_ab_pool $servername_lower $dflt_pool]
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

			TCP::release
		}

		when SERVER_CONNECTED {
			set svrssl_class "/%[1]s/ssl_reencrypt_serverssl_dg"
			if { [info exists servername_lower] and [class exists $svrssl_class] } {
				set profile [class match -value $servername_lower equals $svrssl_class]
				if { not ($profile equals "") } {
					SSL::profile $profile
				}
			}
		}`, DEFAULT_PARTITION)

	iRuleCode := fmt.Sprintf("%s\n\n%s", selectPoolIRuleFunc(), iRule)

	return iRuleCode
}

// Update a specific datagroup for passthrough routes, indicating if
// something had changed.
func (appMgr *Manager) updatePassthroughRouteDataGroups(
	partition string,
	namespace string,
	poolName string,
	hostName string,
) (bool, error) {

	changed := false
	key := nameRef{
		Name:      passthroughHostsDgName,
		Partition: partition,
	}

	appMgr.intDgMutex.Lock()
	defer appMgr.intDgMutex.Unlock()
	nsHostDg, found := appMgr.intDgMap[key]
	if false == found {
		return false, fmt.Errorf("Internal Data-group /%s/%s does not exist.",
			partition, passthroughHostsDgName)
	}

	hostDg, found := nsHostDg[namespace]
	if !found {
		hostDg = &InternalDataGroup{}
		nsHostDg[namespace] = hostDg
	}
	if hostDg.AddOrUpdateRecord(hostName, poolName) {
		changed = true
	}

	return changed, nil
}

// Update a data group map based on a passthrough route object.
func updateDataGroupForPassthroughRoute(
	route *routeapi.Route,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
) {
	hostName := route.Spec.Host
	svcName := getRouteCanonicalServiceName(route)
	poolName := formatRoutePoolName(route.ObjectMeta.Namespace, svcName)
	updateDataGroup(dgMap, passthroughHostsDgName,
		partition, namespace, hostName, poolName)
}

// Update a data group map based on a reencrypt route object.
func updateDataGroupForReencryptRoute(
	route *routeapi.Route,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
) {
	hostName := route.Spec.Host
	svcName := getRouteCanonicalServiceName(route)
	poolName := formatRoutePoolName(route.ObjectMeta.Namespace, svcName)
	updateDataGroup(dgMap, reencryptHostsDgName,
		partition, namespace, hostName, poolName)
}

// Update a data group map based on a alternativeBackends route object.
// (ignore an service with a 0 weight value)
func updateDataGroupForABRoute(
	route *routeapi.Route,
	svcName string,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
) {
	if !isRouteABDeployment(route) {
		return
	}

	weightTotal := 0
	svcs := getRouteServices(route)
	for _, svc := range svcs {
		weightTotal = weightTotal + svc.weight
	}

	path := route.Spec.Path
	tls := route.Spec.TLS
	if tls != nil {
		// We don't support path-based A/B for pass-thru and re-encrypt
		switch tls.Termination {
		case routeapi.TLSTerminationPassthrough:
			path = ""
		case routeapi.TLSTerminationReencrypt:
			path = ""
		}
	}
	key := route.Spec.Host + path

	if weightTotal == 0 {
		// If all services have 0 weight, openshift requires a 503 to be returned
		// (see https://docs.openshift.com/container-platform/3.6/architecture
		//  /networking/routes.html#alternateBackends)
		updateDataGroup(dgMap, abDeploymentDgName, partition, namespace, key, "")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0
		for _, svc := range svcs {
			if svc.weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + svc.weight
			weightedSliceThreshold := float64(runningWeightTotal) / float64(weightTotal)
			pool := formatRoutePoolName(route.ObjectMeta.Namespace, svc.name)
			entry := fmt.Sprintf("%s,%4.3f", pool, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, abDeploymentDgName,
			partition, namespace, key, value)
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
) {
	mapKey := nameRef{
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
		}
		newDg.AddOrUpdateRecord(key, value)
		nsDg[namespace] = &newDg
	}
}

// Update the appMgr datagroup cache for routes, indicating if something
// had changed by updating 'stats', which should rewrite the config.
func (appMgr *Manager) syncDataGroups(
	stats *vsSyncStats,
	dgMap InternalDataGroupMap,
	namespace string,
) {
	appMgr.intDgMutex.Lock()
	defer appMgr.intDgMutex.Unlock()

	// Add new or modified data group records
	for mapKey, grp := range dgMap {
		nsDg, found := appMgr.intDgMap[mapKey]
		if found {
			if !reflect.DeepEqual(nsDg[namespace], grp[namespace]) {
				// current namespace records aren't equal
				nsDg[namespace] = grp[namespace]
				stats.dgUpdated += 1
			}
		} else {
			appMgr.intDgMap[mapKey] = grp
		}
	}

	// Remove non-existent data group records (those that are currently
	// defined, but aren't part of the new set)
	for mapKey, nsDg := range appMgr.intDgMap {
		_, found := dgMap[mapKey]
		if !found {
			_, found := nsDg[namespace]
			if found {
				delete(nsDg, namespace)
				if len(nsDg) == 0 {
					delete(appMgr.intDgMap, mapKey)
				}
				stats.dgUpdated += 1
			}
		}
	}
}

// Finds which IRules have no data groups for them
func (appMgr *Manager) syncIRules() {
	// Verify which data groups are still in use
	type iruleRef struct {
		https       bool
		ab          bool
		passthrough bool
		reencrypt   bool
	}
	var iRef iruleRef
	for mapKey, _ := range appMgr.intDgMap {
		switch mapKey.Name {
		case httpsRedirectDgName:
			iRef.https = true
		case abDeploymentDgName:
			iRef.ab = true
		case passthroughHostsDgName:
			iRef.passthrough = true
		case reencryptHostsDgName:
			iRef.reencrypt = true
		case reencryptServerSslDgName:
			iRef.reencrypt = true
		}
	}
	// Delete any IRules for datagroups that are gone
	if !iRef.https {
		// http redirect rule may have a port appended, so find it
		for irule, _ := range appMgr.irulesMap {
			if strings.HasPrefix(irule.Name, httpRedirectIRuleName) {
				appMgr.deleteIRule(irule.Name)
			}
		}
	}
	if !iRef.ab {
		appMgr.deleteIRule(abDeploymentPathIRuleName)
	}
	if !iRef.passthrough && !iRef.reencrypt {
		appMgr.deleteIRule(sslPassthroughIRuleName)
	}
}

// Deletes an IRule from the IRules map, and dereferences it from a Virtual
func (appMgr *Manager) deleteIRule(rule string) {
	ref := nameRef{
		Name:      rule,
		Partition: DEFAULT_PARTITION,
	}
	delete(appMgr.irulesMap, ref)
	fullName := joinBigipPath(DEFAULT_PARTITION, rule)
	for _, cfg := range appMgr.resources.GetAllResources() {
		if cfg.MetaData.ResourceType == "configmap" ||
			cfg.MetaData.ResourceType == "iapp" {
			continue
		}
		cfg.Virtual.RemoveIRule(fullName)
	}
}

func (slice Routes) Len() int {
	return len(slice)
}

func (slice Routes) Less(i, j int) bool {
	return (slice[i].Spec.Host < slice[j].Spec.Host) ||
		(slice[i].Spec.Host == slice[j].Spec.Host &&
			slice[i].Spec.Path < slice[j].Spec.Path)
}

func (slice Routes) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (appInf *appInformer) getOrderedRoutes(namespace string) (Routes, error) {
	routeByIndex, err := appInf.routeInformer.GetIndexer().ByIndex(
		"namespace", namespace)
	var routes Routes
	for _, obj := range routeByIndex {
		route := obj.(*routeapi.Route)
		routes = append(routes, route)
	}
	sort.Sort(routes)
	return routes, err
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
				Name:      httpsRedirectDgName,
				Partition: DEFAULT_PARTITION,
			}
			dgMap[skey.Namespace] = nsGrp
		}
		for host, pathMap := range hostMap {
			paths := []string{}
			for path, _ := range pathMap {
				paths = append(paths, path)
			}
			// Need to sort the paths to have consistent ordering
			sort.Strings(paths)
			var buf bytes.Buffer
			for i, path := range paths {
				if i > 0 {
					buf.WriteString("|")
				}
				buf.WriteString(path)
			}
			nsGrp.AddOrUpdateRecord(host, buf.String())
		}
	}
}

func flattenConflictWarn(key, oldVal, newVal string) string {
	fmt.Printf("Found mismatch for key '%v' old value: '%v' new value: '%v'\n", key, oldVal, newVal)
	return oldVal
}

func flattenConflictConcat(key, oldVal, newVal string) string {
	// Tokenize both values and add to a map to ensure uniqueness
	pathMap := make(map[string]bool)
	for _, token := range strings.Split(oldVal, "|") {
		pathMap[token] = true
	}
	for _, token := range strings.Split(newVal, "|") {
		pathMap[token] = true
	}

	// Convert back to an array
	paths := []string{}
	for path, _ := range pathMap {
		paths = append(paths, path)
	}

	// Sort the paths to have consistent ordering
	sort.Strings(paths)

	// Write back out to a delimited string
	var buf bytes.Buffer
	for i, path := range paths {
		if i > 0 {
			buf.WriteString("|")
		}
		buf.WriteString(path)
	}

	return buf.String()
}

func (dgnm DataGroupNamespaceMap) FlattenNamespaces() *InternalDataGroup {

	// Try to be efficient in these common cases.
	if len(dgnm) == 0 {
		// No namespaces.
		return nil
	} else if len(dgnm) == 1 {
		// Only 1 namespace, just return its dg - no flattening needed.
		for _, dg := range dgnm {
			return dg
		}
	}

	// Use a map to identify duplicates across namespaces
	var partition, name string
	flatMap := make(map[string]string)
	for _, dg := range dgnm {
		if partition == "" {
			partition = dg.Partition
		}
		if name == "" {
			name = dg.Name
		}
		for _, rec := range dg.Records {
			item, found := flatMap[rec.Name]
			if found {
				if item != rec.Data {
					conflictFunc, ok := groupFlattenFuncMap[dg.Name]
					if !ok {
						log.Warningf("No DataGroup conflict handler defined for '%v'",
							dg.Name)
						conflictFunc = flattenConflictWarn
					}
					newVal := conflictFunc(rec.Name, item, rec.Data)
					flatMap[rec.Name] = newVal
				}
			} else {
				flatMap[rec.Name] = rec.Data
			}
		}
	}

	// Create a new datagroup to hold the flattened results
	newDg := InternalDataGroup{
		Partition: partition,
		Name:      name,
	}
	for name, data := range flatMap {
		newDg.AddOrUpdateRecord(name, data)
	}

	return &newDg
}
