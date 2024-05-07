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
	"strconv"

	"sort"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	//"strconv"
	"strings"

	routeapi "github.com/openshift/api/route/v1"
)

type RouteList []*routeapi.Route

func createPathSegmentConditions(u *url.URL) []*Condition {
	var c []*Condition
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	segments := strings.Split(path, "/")
	for i, v := range segments {
		c = append(c, &Condition{
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

	a := Action{
		Forward: true,
		Name:    "0",
		Pool:    b.String(),
		Request: true,
	}

	var c []*Condition
	if true == strings.HasPrefix(uri, "*.") {
		c = append(c, &Condition{
			EndsWith: true,
			Host:     true,
			HTTPHost: true,
			Name:     "0",
			Index:    0,
			Request:  true,
			Values:   []string{strings.TrimPrefix(u.Host, "*")},
		})
	} else if u.Host != "" {
		c = append(c, &Condition{
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
		Actions:    []*Action{&a},
		Conditions: c,
	}

	log.Debugf("[CORE] Configured rule: %v", rl)
	return &rl, nil
}

// format the rule name for an Ingress
func formatIngressRuleName(host, path, pool string) string {
	var rule string
	if path == "" {
		rule = fmt.Sprintf("ingress_%s_%s", host, pool)
	} else {
		// Remove the first slash, then replace any subsequent slashes with '_'
		path = strings.TrimPrefix(path, "/")
		path = strings.Replace(path, "/", "_", -1)
		rule = fmt.Sprintf("ingress_%s_%s_%s", host, path, pool)
	}
	return rule
}

func httpRedirectIRule(port int32, partition string, agent string) string {
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

func (appMgr *Manager) selectPoolIRuleFunc() string {
	dgPath := appMgr.dgPath

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
		}`, dgPath)

	return iRuleFunc
}

func (appMgr *Manager) abDeploymentPathIRule() string {
	// For all A/B deployments that include a path.
	// The key in the data group is the specific route (host/path) to examine.
	// The data is a list of pool/weight pairs delimited by ';'. The pair values
	// are delineated by ','. Finally, the weight value is normalized between
	// 0.0 and 1.0 and the pairs should be listed in ascending order or weight
	// values.
	iRuleCode := fmt.Sprintf("%s\n\n%s", appMgr.selectPoolIRuleFunc(), `
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

func (appMgr *Manager) sslPassthroughIRule() string {
	dgPath := appMgr.dgPath

	iRule := fmt.Sprintf(`
		when CLIENT_ACCEPTED {
			TCP::collect
		}

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
									set passthru_class "/%[1]s/ssl_passthrough_servername_dg"
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
	
										set ab_class "/%[1]s/ab_deployment_dg"
										if { not [class exists $ab_class] } {
											if { $dflt_pool_passthrough == "" } then {
												log local0.debug "Failed to find pool for $servername_lower"
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
				set reencrypt_class "/%[1]s/ssl_reencrypt_servername_dg"
				set edge_class "/%[1]s/ssl_edge_servername_dg"
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
                set ab_class "/%[1]s/ab_deployment_dg"
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
			set reencryptssl_class "/%[1]s/ssl_reencrypt_serverssl_dg"
			set edgessl_class "/%[1]s/ssl_edge_serverssl_dg"
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
        }`, dgPath)

	iRuleCode := fmt.Sprintf("%s\n\n%s", appMgr.selectPoolIRuleFunc(), iRule)

	return iRuleCode
}

// Update a data group map based on a passthrough route object.
func updateDataGroupForPassthroughRoute(
	route *routeapi.Route,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
) {
	hostName := route.Spec.Host
	svcName := GetRouteCanonicalServiceName(route)
	poolName := FormatRoutePoolName(route.ObjectMeta.Namespace, svcName)
	updateDataGroup(dgMap, PassthroughHostsDgName,
		partition, namespace, hostName, poolName)
}

// Update a data group map based on a reencrypt route object.
func updateDataGroupForReencryptRoute(
	route *routeapi.Route,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
) {
	// Combination of hostName and path are used as key in reencrypt Datagroup.
	// Servername and path from the ssl::payload of clientssl_data Irule event is
	// used as value in reencrypt Datagroup.
	hostName := route.Spec.Host
	path := route.Spec.Path
	routePath := hostName + path
	routePath = strings.TrimSuffix(routePath, "/")
	svcName := GetRouteCanonicalServiceName(route)
	poolName := FormatRoutePoolName(route.ObjectMeta.Namespace, svcName)
	updateDataGroup(dgMap, ReencryptHostsDgName,
		partition, namespace, routePath, poolName)
}

// Update a data group map based on a edge route object.
func updateDataGroupForEdgeRoute(
	route *routeapi.Route,
	partition string,
	namespace string,
	dgMap InternalDataGroupMap,
) {
	// Combination of hostName and path are used as key in edge Datagroup.
	// Servername and path from the ssl::payload of clientssl_data Irule event is
	// used as value in edge Datagroup.
	hostName := route.Spec.Host
	path := route.Spec.Path
	routePath := hostName + path
	routePath = strings.TrimSuffix(routePath, "/")
	svcName := GetRouteCanonicalServiceName(route)
	poolName := FormatRoutePoolName(route.ObjectMeta.Namespace, svcName)
	updateDataGroup(dgMap, EdgeHostsDgName,
		partition, namespace, routePath, poolName)
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
	if !IsRouteABDeployment(route) {
		return
	}

	weightTotal := 0
	svcs := GetRouteServices(route)
	for _, svc := range svcs {
		weightTotal = weightTotal + svc.Weight
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
		updateDataGroup(dgMap, AbDeploymentDgName, partition, namespace, key, "")
	} else {
		// Place each service in a segment between 0.0 and 1.0 that corresponds to
		// it's ratio percentage.  The order does not matter in regards to which
		// service is listed first, but the list must be in ascending order.
		var entries []string
		runningWeightTotal := 0
		for _, svc := range svcs {
			if svc.Weight == 0 {
				continue
			}
			runningWeightTotal = runningWeightTotal + svc.Weight
			weightedSliceThreshold := float64(runningWeightTotal) / float64(weightTotal)
			pool := FormatRoutePoolName(route.ObjectMeta.Namespace, svc.Name)
			entry := fmt.Sprintf("%s,%4.3f", pool, weightedSliceThreshold)
			entries = append(entries, entry)
		}
		value := strings.Join(entries, ";")
		updateDataGroup(dgMap, AbDeploymentDgName,
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
		edge        bool
	}
	var iRef iruleRef
	for mapKey, _ := range appMgr.intDgMap {
		switch mapKey.Name {
		case HttpsRedirectDgName:
			iRef.https = true
		case AbDeploymentDgName:
			iRef.ab = true
		case PassthroughHostsDgName:
			iRef.passthrough = true
		case ReencryptHostsDgName:
			iRef.reencrypt = true
		case EdgeHostsDgName:
			iRef.edge = true
		case ReencryptServerSslDgName:
			iRef.reencrypt = true
		case EdgeServerSslDgName:
			iRef.edge = true
		}
	}
	// Delete any IRules for datagroups that are gone
	if !iRef.https {
		// http redirect rule may have a port appended, so find it
		for irule, _ := range appMgr.irulesMap {
			if strings.HasPrefix(irule.Name, HttpRedirectIRuleName) {
				appMgr.deleteIRule(irule.Name)
			}
		}
	}
	if !iRef.ab {
		appMgr.deleteIRule(AbDeploymentPathIRuleName)
	}
	if !iRef.passthrough && !iRef.reencrypt && !iRef.edge {
		appMgr.deleteIRule(SslPassthroughIRuleName)
	}
}

// Deletes an IRule from the IRules map, and dereferences it from a Virtual
func (appMgr *Manager) deleteIRule(rule string) {
	ref := NameRef{
		Name:      rule,
		Partition: DEFAULT_PARTITION,
	}
	delete(appMgr.irulesMap, ref)
	fullName := JoinBigipPath(DEFAULT_PARTITION, rule)
	for _, cfg := range appMgr.resources.RsMap {
		if cfg.MetaData.ResourceType == "configmap" ||
			cfg.MetaData.ResourceType == "iapp" {
			continue
		}
		cfg.Virtual.RemoveIRule(fullName)
	}
}

func (slice RouteList) Len() int {
	return len(slice)
}

func (slice RouteList) Less(i, j int) bool {
	if slice[i].Spec.Host == slice[j].Spec.Host {
		if (len(slice[i].Spec.Path) == 0 || len(slice[j].Spec.Path) == 0) && (slice[i].Spec.Path == "/" || slice[j].Spec.Path == "/") {
			return slice[i].CreationTimestamp.Before(&slice[j].CreationTimestamp)
		}
	}
	return (slice[i].Spec.Host < slice[j].Spec.Host) ||
		(slice[i].Spec.Host == slice[j].Spec.Host &&
			slice[i].Spec.Path == slice[j].Spec.Path &&
			slice[i].CreationTimestamp.Before(&slice[j].CreationTimestamp)) ||
		(slice[i].Spec.Host == slice[j].Spec.Host &&
			slice[i].Spec.Path < slice[j].Spec.Path)
}

func (slice RouteList) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (appInf *appInformer) getOrderedRoutes(namespace string) (RouteList, error) {
	routeByIndex, err := appInf.routeInformer.GetIndexer().ByIndex(
		"namespace", namespace)
	var routes RouteList
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

func (sfrm ServiceFwdRuleMap) AddToDataGroup(dgMap DataGroupNamespaceMap, partition string) {
	// Multiple service keys may reference the same host, so flatten those first
	for skey, hostMap := range sfrm {
		nsGrp, found := dgMap[skey.Namespace]
		if !found {
			nsGrp = &InternalDataGroup{
				Name:      HttpsRedirectDgName,
				Partition: partition,
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
