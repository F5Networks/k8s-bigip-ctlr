/*-
* Copyright (c) 2016-2020, F5 Networks, Inc.
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

// prepareVirtualServerRules prepares LTM Policy rules for VirtualServer
func (crMgr *CRManager) prepareVirtualServerRules(
	vs *cisapiv1.VirtualServer,
) *Rules {
	rlMap := make(ruleMap)
	wildcards := make(ruleMap)
	var redirects []*Rule

	appRoot := "/"

	if vs.Spec.RewriteAppRoot != "" {
		ruleName := formatVirtualServerRuleName(vs.Spec.Host, "redirectto", vs.Spec.RewriteAppRoot)
		rl, err := createRedirectRule(vs.Spec.Host+appRoot, vs.Spec.RewriteAppRoot, ruleName)
		if nil != err {
			log.Errorf("Error configuring redirect rule: %v", err)
			return nil
		}
		redirects = append(redirects, rl)

	}

	for _, pl := range vs.Spec.Pools {
		// Service cannot be empty
		if pl.Service == "" {
			continue
		}

		uri := vs.Spec.Host + pl.Path

		path := pl.Path
		tls := crMgr.getTLSProfileForVirtualServer(vs, vs.Namespace)

		if tls != nil && tls.Spec.TLS.Termination == TLSPassthrough {
			path = "/"
		}

		if pl.Path == "/" {
			uri = vs.Spec.Host + vs.Spec.RewriteAppRoot
			path = vs.Spec.RewriteAppRoot
		}

		poolName := formatVirtualServerPoolName(
			vs.ObjectMeta.Namespace,
			pl.Service,
			pl.ServicePort,
			pl.NodeMemberLabel,
		)
		ruleName := formatVirtualServerRuleName(vs.Spec.Host, path, poolName)
		var err error
		var event string
		if tls != nil && tls.Spec.TLS.Termination == TLSPassthrough {
			event = TLSClientHello
		} else {
			event = HTTPRequest
		}
		rl, err := createRule(uri, poolName, ruleName, event)
		if nil != err {
			log.Errorf("Error configuring rule: %v", err)
			return nil
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

		if pl.Path == "/" {
			redirects = append(redirects, rl)
		} else if true == strings.HasPrefix(uri, "*.") {
			wildcards[uri] = rl
		} else {
			rlMap[uri] = rl
		}
	}

	if vs.Spec.RewriteAppRoot != "" && len(redirects) != 2 {
		log.Error("AppRoot path not found for rewriting")
		return nil
	}

	if rlMap[vs.Spec.Host] == nil && len(redirects) == 2 {
		rl := &Rule{
			Name:    formatVirtualServerRuleName(vs.Spec.Host, "", redirects[1].Actions[0].Pool),
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
func createRule(uri, poolName, ruleName, event string) (*Rule, error) {
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
	}

	if event == HTTPRequest {
		a.Request = true
	}

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
		switch event {
		case HTTPRequest:
			cond.Request = true
		case TLSClientHello:
			cond.SSLExtensionClient = true
			cond.Equals = true
		}

		conditions = append(conditions, cond)
	}

	if 0 != len(u.EscapedPath()) {
		conditions = append(conditions, createPathSegmentConditions(u)...)
	}

	rl := Rule{
		Name:       ruleName,
		FullURI:    uri,
		Actions:    []*action{&a},
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
				Value:   rwPath,
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

func createRedirectRule(source, target, ruleName string) (*Rule, error) {
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

	// Strategy 4: Lowest Ordinal
	return ruleI.Ordinal < ruleJ.Ordinal

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
func httpRedirectIRule(port int32, rsVSName string) string {
	// The key in the data group is the host name or * to match all.
	// The data is a list of paths for the host delimited by '|' or '/' for all.
	iRuleCode := fmt.Sprintf(`
		when HTTP_REQUEST {
			
			# check if there is an entry in data-groups to accept requests from all domains.
			# */ represents [* -> Any host / -> default path]
			set allHosts [class match -value "*/" equals %[2]s_https_redirect_dg]
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
				set paths [class match -value $host equals %[2]s_https_redirect_dg]
				# Check if host with combination of "/" matches https_redirect_dg
				if {$paths == ""} {
					set hosts ""
					append hosts $host "/"
					set paths [class match -value $hosts equals %[2]s_https_redirect_dg]
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
					HTTP::redirect https://[getfield [HTTP::host] ":" 1]:%[1]d[HTTP::uri]
				}
			}
		}`, port, rsVSName)

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

func (crMgr *CRManager) handleVSDeleteForDataGroups(
	virtual *cisapiv1.VirtualServer,
	rsVSName string,
) {
	if len(virtual.Spec.TLSProfileName) == 0 {
		return
	}
	namespace := virtual.ObjectMeta.Namespace
	tls := crMgr.getTLSProfileForVirtualServer(virtual, namespace)
	if tls == nil {
		return
	}
	var dgNames []string
	switch tls.Spec.TLS.Termination {
	case TLSEdge:
		dgNames = append(dgNames, EdgeServerSslDgName, EdgeHostsDgName)
	case TLSReencrypt:
		dgNames = append(dgNames, ReencryptServerSslDgName, ReencryptHostsDgName)
	}

	if virtual.Spec.HTTPTraffic == TLSRedirectInsecure {
		dgNames = append(dgNames, HttpsRedirectDgName)
	}

	for _, dgName := range dgNames {
		refKey := NameRef{
			Name:      getRSCfgResName(rsVSName, dgName),
			Partition: DEFAULT_PARTITION,
		}

		if nsDg, found := crMgr.intDgMap[refKey]; found {
			if nsGrp, found := nsDg[namespace]; found {
				host := virtual.Spec.Host
				for _, pool := range virtual.Spec.Pools {
					recKey := host
					if dgName != HttpsRedirectDgName {
						path := pool.Path
						if path == "" {
							path = "/"
						}
						recKey = host + path
					}

					nsGrp.RemoveRecord(recKey)
				}
				if len(nsGrp.Records) == 0 {
					delete(nsDg, namespace)
				}
				if len(nsDg) == 0 {
					delete(crMgr.intDgMap, refKey)
				}
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

func (crMgr *CRManager) getTLSIRule(rsVSName string) string {
	dgPath := crMgr.dgPath

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
								set passthru_class "/%[1]s/%[2]s_ssl_passthrough_servername_dg"
								if { [class exists $passthru_class] } {
									set servername_lower [string tolower $tls_servername]
									SSL::disable serverside
									set dflt_pool_passthrough ""

									# Disable Serverside SSL for Passthrough Class
									set dflt_pool_passthrough [class match -value $servername_lower equals $passthru_class]
									if { not ($dflt_pool_passthrough equals "") } {
										SSL::disable
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
										set selected_pool [call select_ab_pool $servername_lower $dflt_pool_passthrough]
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

			TCP::release
		}

		when CLIENTSSL_HANDSHAKE {
 			SSL::collect
		}

         when CLIENTSSL_DATA {
            if { [llength [split [SSL::payload]]] < 1 }{
                reject ; event disable all; return;
                }
            set sslpath [lindex [split [SSL::payload]] 1]
            set routepath ""
            
            if { [info exists tls_servername] } {
				set servername_lower [string tolower $tls_servername]
				# Set routepath as combination of servername and url path
				append routepath $servername_lower $sslpath
				set routepath [string tolower $routepath]
				set sslpath $routepath
				# Find the number of "/" in the routepath
				set rc 0
				foreach x [split $routepath {}] {
				   if {$x eq "/"} {
					   incr rc
				   }
				}
				# Disable serverside ssl and enable only for reencrypt routes													
                SSL::disable serverside
				set reencrypt_class "/%[1]s/%[2]s_ssl_reencrypt_servername_dg"
				set edge_class "/%[1]s/%[2]s_ssl_edge_servername_dg"
                if { [class exists $reencrypt_class] || [class exists $edge_class] } {
					# Compares the routepath with the entries in ssl_reencrypt_servername_dg and
					# ssl_edge_servername_dg.
					for {set i $rc} {$i >= 0} {incr i -1} {
						if { [class exists $reencrypt_class] } {
							set reen_pool [class match -value $routepath equals $reencrypt_class]
							if { not ($reen_pool equals "") } {
								set dflt_pool $reen_pool
								SSL::enable serverside
							}
						}
						if { [class exists $edge_class] } {
							set edge_pool [class match -value $routepath equals $edge_class]
							if { not ($edge_pool equals "") } {
							    set dflt_pool $edge_pool
							}
						}
                        if { not [info exists dflt_pool] } {
                            set routepath [
                                string range $routepath 0 [
                                    expr {[string last "/" $routepath]-1}
                                ]
                            ]
                        }
                        else {
                            break
						}
					}
                }
                set ab_class "/%[1]s/%[2]s_ab_deployment_dg"
                # Handle requests sent to unknown hosts.
                # For valid hosts, Send the request to respective pool.
                if { not [info exists dflt_pool] } then {
                	 # Allowing HTTP2 traffic to be handled by policies and closing the connection for HTTP/1.1 unknown hosts.
                	 if { not ([SSL::payload] starts_with "PRI * HTTP/2.0") } {
                	    reject ; event disable all; return;
                    }
                } else {
                	pool $dflt_pool
                }
                if { [class exists $ab_class] } {
                    set selected_pool [call select_ab_pool $servername_lower $dflt_pool]
                    if { $selected_pool == "" } then {
                        log local0.debug "Unable to find pool for $servername_lower"
                    } else {
                        pool $selected_pool
                    }
                }
            }
            SSL::release
        }

		when SERVER_CONNECTED {
			set reencryptssl_class "/%[1]s/%[2]s_ssl_reencrypt_serverssl_dg"
			set edgessl_class "/%[1]s/%[2]s_ssl_edge_serverssl_dg"
			if { [info exists sslpath] and [class exists $reencryptssl_class] } {
				# Find the nearest child path which matches the reencrypt_class
				for {set i $rc} {$i >= 0} {incr i -1} {
					if { [class exists $reencryptssl_class] } {
						set reen [class match -value $sslpath equals $reencryptssl_class]
						if { not ($reen equals "") } {
							    set sslprofile $reen
						}
					}
					if { [class exists $edgessl_class] } {
						set edge [class match -value $sslpath equals $edgessl_class]
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
					}
					else {
						break
					}
				}
				# Assign respective SSL profile based on ssl_reencrypt_serverssl_dg
				if { not ($sslprofile equals "false") } {
						SSL::profile $reen
				}
			}
        }`, dgPath, rsVSName)

	iRuleCode := fmt.Sprintf("%s\n\n%s", crMgr.selectPoolIRuleFunc(rsVSName), iRule)

	return iRuleCode
}

func (crMgr *CRManager) selectPoolIRuleFunc(rsVSName string) string {
	dgPath := crMgr.dgPath

	iRuleFunc := fmt.Sprintf(`
		proc select_ab_pool {path default_pool } {
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
		}`, dgPath, rsVSName)

	return iRuleFunc
}

func updateDataGroupOfDgName(
	intDgMap InternalDataGroupMap,
	virtual *cisapiv1.VirtualServer,
	rsVSName string,
	dgName string,
) {
	hostName := virtual.Spec.Host
	namespace := virtual.ObjectMeta.Namespace

	rsDGName := getRSCfgResName(rsVSName, dgName)
	switch dgName {
	case EdgeHostsDgName, ReencryptHostsDgName:
		// Combination of hostName and path are used as key in edge Datagroup.
		// Servername and path from the ssl::payload of clientssl_data Irule event is
		// used as value in edge and reencrypt Datagroup.
		for _, pl := range virtual.Spec.Pools {
			path := pl.Path
			routePath := hostName + path
			routePath = strings.TrimSuffix(routePath, "/")
			poolName := formatVirtualServerPoolName(namespace, pl.Service, pl.ServicePort, pl.NodeMemberLabel)
			updateDataGroup(intDgMap, rsDGName,
				DEFAULT_PARTITION, namespace, routePath, poolName)
		}
	case HttpsRedirectDgName:
		for _, pl := range virtual.Spec.Pools {
			path := pl.Path
			if path == "" {
				path = "/"
			}
			routePath := hostName + path
			updateDataGroup(intDgMap, rsDGName,
				DEFAULT_PARTITION, namespace, routePath, path)
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
) {
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
		}
		newDg.AddOrUpdateRecord(key, value)
		nsDg[namespace] = &newDg
	}
}
