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
	"context"
	"encoding/json"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"sort"
	"strconv"
	"strings"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

// NewResourceStore is Constructor for ResourceStore
func NewResourceStore() *ResourceStore {
	var rs ResourceStore
	rs.Init()
	return &rs
}

// Init is Receiver to initialize the object.
func (rs *ResourceStore) Init() {
	rs.rsMap = make(ResourceConfigMap)
	rs.oldRsMap = make(ResourceConfigMap)
	rs.dnsConfig = make(DNSConfig)
	rs.oldDNSConfig = make(DNSConfig)
	rs.poolMemCache = make(PoolMemberCache)
	rs.nplStore = make(NPLStore)
}

const (
	DEFAULT_MODE       string = "tcp"
	DEFAULT_BALANCE    string = "round-robin"
	DEFAULT_HTTP_PORT  int32  = 80
	DEFAULT_HTTPS_PORT int32  = 443
	DEFAULT_SNAT       string = "auto"

	urlRewriteRulePrefix      = "url-rewrite-rule-"
	appRootForwardRulePrefix  = "app-root-forward-rule-"
	appRootRedirectRulePrefix = "app-root-redirect-rule-"

	// Indicator to use an F5 schema
	schemaIndicator string = "f5schemadb://"

	// Constants for CustomProfile.Type as defined in CCCL
	CustomProfileAll    string = "all"
	CustomProfileClient string = "clientside"
	CustomProfileServer string = "serverside"

	// Constants for CustomProfile.PeerCertMode
	PeerCertRequired = "require"
	PeerCertIgnored  = "ignore"
	PeerCertDefault  = PeerCertIgnored

	// Constants
	HttpRedirectIRuleName = "http_redirect_irule"
	// Constants
	HttpRedirectNoHostIRuleName = "http_redirect_irule_nohost"
	// Internal data group for https redirect
	HttpsRedirectDgName = "https_redirect_dg"
	TLSIRuleName        = "tls_irule"
)

// constants for TLS references
const (
	// reference for profiles stored in BIG-IP
	BIGIP = "bigip"
	// reference for profiles stores as secrets in k8s cluster
	Secret = "secret"
)

func NewCustomProfile(
	profile ProfileRef,
	cert,
	key,
	serverName string,
	sni bool,
	peerCertMode,
	caFile string,
) CustomProfile {
	cp := CustomProfile{
		Name:         profile.Name,
		Partition:    profile.Partition,
		Context:      profile.Context,
		Cert:         cert,
		Key:          key,
		ServerName:   serverName,
		SNIDefault:   sni,
		PeerCertMode: peerCertMode,
	}
	if peerCertMode == PeerCertRequired {
		cp.CAFile = caFile
	}
	return cp
}

// NewCustomProfiles is a Constructor for CustomProfiles
func NewCustomProfiles() *CustomProfileStore {
	var cps CustomProfileStore
	cps.Profs = make(map[SecretKey]CustomProfile)
	return &cps
}

func NewIRule(name, partition, code string) *IRule {
	return &IRule{
		Name:      name,
		Partition: partition,
		Code:      code,
	}
}

// Creates an IRule if it doesn't already exist
func (rsCfg *ResourceConfig) addIRule(name, partition, rule string) {
	key := NameRef{
		Name:      name,
		Partition: partition,
	}
	if _, found := rsCfg.IRulesMap[key]; !found {
		rsCfg.IRulesMap[key] = NewIRule(name, partition, rule)
	}
}

func (rsCfg *ResourceConfig) removeIRule(name, partition string) {
	key := NameRef{
		Name:      name,
		Partition: partition,
	}
	delete(rsCfg.IRulesMap, key)
}

// Creates an InternalDataGroup if it doesn't already exist
func (rsCfg *ResourceConfig) addInternalDataGroup(name, partition string) DataGroupNamespaceMap {
	key := NameRef{
		Name:      name,
		Partition: partition,
	}
	if _, found := rsCfg.IntDgMap[key]; !found {
		rsCfg.IntDgMap[key] = make(DataGroupNamespaceMap)
	}
	return rsCfg.IntDgMap[key]
}

func JoinBigipPath(partition, objName string) string {
	if objName == "" {
		return ""
	}
	if partition == "" {
		return objName
	}
	return fmt.Sprintf("/%s/%s", partition, objName)
}

// Adds an IRule reference to a Virtual object
func (v *Virtual) AddIRule(ruleName string) bool {
	for _, irule := range v.IRules {
		if irule == ruleName {
			return false
		}
	}
	v.IRules = append(v.IRules, ruleName)
	return true
}

func (slice ProfileRefs) Less(i, j int) bool {
	return ((slice[i].Partition < slice[j].Partition) ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name))
}

func (slice ProfileRefs) Len() int {
	return len(slice)
}

func (slice ProfileRefs) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Return the required ports for VS (depending on sslRedirect/allowHttp vals)
func (ctlr *Controller) virtualPorts(vs *cisapiv1.VirtualServer) []portStruct {

	var httpPort int32
	var httpsPort int32

	if vs.Spec.VirtualServerHTTPPort == 0 {
		httpPort = 80
	} else {
		httpPort = vs.Spec.VirtualServerHTTPPort
	}

	if vs.Spec.VirtualServerHTTPSPort == 0 {
		httpsPort = 443
	} else {
		httpsPort = vs.Spec.VirtualServerHTTPSPort
	}

	http := portStruct{
		protocol: "http",
		port:     httpPort,
	}

	https := portStruct{
		protocol: "https",
		port:     httpsPort,
	}
	var ports []portStruct

	if 0 != len(vs.Spec.TLSProfileName) {
		// 2 virtual servers needed, both HTTP and HTTPS
		ports = append(ports, https)
		ports = append(ports, http)
	} else {
		// HTTP only
		ports = append(ports, http)
	}

	return ports
}

// format the virtual server name for an VirtualServer
func formatVirtualServerName(ip string, port int32) string {
	// Strip any bracket characters; replace special characters ". : /"
	// with "-" and "%" with ".", for naming purposes
	ip = strings.Trim(ip, "[]")
	ip = AS3NameFormatter(ip)
	return fmt.Sprintf("crd_%s_%d", ip, port)
}

// format the virtual server name for an VirtualServer
func formatCustomVirtualServerName(name string, port int32) string {
	// Replace special characters ". : /"
	// with "-" and "%" with ".", for naming purposes
	name = AS3NameFormatter(name)
	return fmt.Sprintf("%s_%d", name, port)
}

// format the pool name for an VirtualServer
func formatVirtualServerPoolName(namespace, svc string, port int32, nodeMemberLabel string) string {
	servicePort := fmt.Sprint(port)
	poolName := fmt.Sprintf("%s_%s_%s", svc, servicePort, namespace)
	if nodeMemberLabel != "" {
		nodeMemberLabel = strings.ReplaceAll(nodeMemberLabel, "=", "_")
		poolName = fmt.Sprintf("%s_%s", poolName, nodeMemberLabel)
	}
	return AS3NameFormatter(poolName)
}

// format the monitor name for an VirtualServer pool
func formatMonitorName(namespace, svc string, monitorType string, port int32) string {
	servicePort := fmt.Sprint(port)
	monitorName := fmt.Sprintf("%s_%s_%s_%s", svc, namespace, monitorType, servicePort)
	return AS3NameFormatter(monitorName)
}

// format the policy name for VirtualServer
func formatPolicyName(hostname, hostGroup, name string) string {
	host := hostname
	if hostGroup != "" {
		host = hostGroup
	}
	if strings.HasPrefix(host, "*") {
		host = strings.Replace(host, "*", "wildcard", 1)
	}
	policyName := fmt.Sprintf("%s_%s_%s", name, host, "policy")
	return AS3NameFormatter(policyName)
}

// Prepares resource config based on VirtualServer resource config
func (ctlr *Controller) prepareRSConfigFromVirtualServer(
	rsCfg *ResourceConfig,
	vs *cisapiv1.VirtualServer,
) error {

	var httpPort int32
	httpPort = DEFAULT_HTTP_PORT
	var snat string
	snat = DEFAULT_SNAT
	var pools Pools
	var rules *Rules
	var plcy *Policy
	var poolExist bool
	var monitors []Monitor
	for _, pl := range vs.Spec.Pools {
		pool := Pool{
			Name: formatVirtualServerPoolName(
				vs.ObjectMeta.Namespace,
				pl.Service,
				pl.ServicePort,
				pl.NodeMemberLabel,
			),
			Partition:       rsCfg.Virtual.Partition,
			ServiceName:     pl.Service,
			ServicePort:     pl.ServicePort,
			NodeMemberLabel: pl.NodeMemberLabel,
		}
		for _, p := range pools {
			if pool.Name == p.Name {
				poolExist = true
				break
			}
		}
		if poolExist {
			poolExist = false
			continue
		}

		if pl.Monitor.Send != "" && pl.Monitor.Type != "" {
			pool.MonitorNames = append(pool.MonitorNames, JoinBigipPath(DEFAULT_PARTITION,
				formatMonitorName(vs.ObjectMeta.Namespace, pl.Service, pl.Monitor.Type, pl.ServicePort)))
			monitor := Monitor{
				Name:      formatMonitorName(vs.ObjectMeta.Namespace, pl.Service, pl.Monitor.Type, pl.ServicePort),
				Partition: rsCfg.Virtual.Partition,
				Type:      pl.Monitor.Type,
				Interval:  pl.Monitor.Interval,
				Send:      pl.Monitor.Send,
				Recv:      pl.Monitor.Recv,
				Timeout:   pl.Monitor.Timeout,
			}
			monitors = append(monitors, monitor)
		}
		pools = append(pools, pool)
	}
	rsCfg.Pools = append(rsCfg.Pools, pools...)
	rsCfg.Monitors = append(rsCfg.Monitors, monitors...)

	// set the SNAT policy to auto  if it's not defined by end user
	if vs.Spec.SNAT == "" {
		if rsCfg.Virtual.SNAT == "" {
			rsCfg.Virtual.SNAT = snat
		}
	} else {
		rsCfg.Virtual.SNAT = vs.Spec.SNAT
	}

	if len(rsCfg.ServiceAddress) == 0 {
		for _, sa := range vs.Spec.ServiceIPAddress {
			rsCfg.ServiceAddress = append(rsCfg.ServiceAddress, ServiceAddress(sa))
		}
	}

	// set the WAF policy
	if vs.Spec.WAF != "" {
		rsCfg.Virtual.WAF = vs.Spec.WAF
	}

	//Attach allowVlans.
	rsCfg.Virtual.AllowVLANs = vs.Spec.AllowVLANs

	if vs.Spec.PersistenceProfile != "" {
		rsCfg.Virtual.PersistenceProfile = vs.Spec.PersistenceProfile
	}
	// Do not Create Virtual Server L7 Forwarding policies if HTTPTraffic is set to None or Redirect
	if len(vs.Spec.TLSProfileName) > 0 &&
		rsCfg.Virtual.VirtualAddress.Port == httpPort &&
		(vs.Spec.HTTPTraffic == TLSNoInsecure || vs.Spec.HTTPTraffic == TLSRedirectInsecure) {
		return nil
	}

	rules = ctlr.prepareVirtualServerRules(vs)
	if rules == nil {
		return fmt.Errorf("failed to create LTM Rules")
	}

	// Update the existing policy with rules
	// Otherwise create new policy and set
	if policy := rsCfg.FindPolicy(PolicyControlForward); policy != nil {
		policy.AddRules(rules)
		rsCfg.SetPolicy(*policy)
		return nil
	}
	policyName := formatPolicyName(vs.Spec.Host, vs.Spec.HostGroup, rsCfg.Virtual.Name)
	plcy = createPolicy(*rules, policyName, vs.ObjectMeta.Namespace)
	if plcy != nil {
		rsCfg.SetPolicy(*plcy)
	}

	// Attach user specified iRules
	if len(vs.Spec.IRules) > 0 {
		rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, vs.Spec.IRules...)
	}
	return nil
}

// handleVirtualServerTLS handles TLS configuration for the Virtual Server resource
// Return value is whether or not a custom profile was updated
func (ctlr *Controller) handleVirtualServerTLS(
	rsCfg *ResourceConfig,
	vs *cisapiv1.VirtualServer,
	tls *cisapiv1.TLSProfile,
	ip string,
) bool {
	if 0 == len(vs.Spec.TLSProfileName) {
		// Probably this is a non-tls Virtual Server, nothing to do w.r.t TLS
		return false
	}

	if tls == nil {
		return false
	}

	var httpsPort int32

	if vs.Spec.VirtualServerHTTPSPort == 0 {
		httpsPort = 443
	} else {
		httpsPort = vs.Spec.VirtualServerHTTPSPort
	}

	// If we are processing the HTTPS server,
	// then we don't need a redirect policy, only profiles
	if rsCfg.Virtual.VirtualAddress.Port == httpsPort {
		// Virtual Server related properties
		// Virtual Server and TLSProfile are assumed to be in same namespace
		vsNamespace := vs.ObjectMeta.Namespace
		vsName := vs.ObjectMeta.Name

		// TLSProfile Object
		tlsName := vs.Spec.TLSProfileName

		if tls.Spec.TLS.Termination == TLSPassthrough {
			rsCfg.Virtual.TLSTermination = TLSPassthrough
			//rsCfg.Virtual.PersistenceProfile = []string{"tls-session-id"}
			return true
		}

		// Process Profile
		switch tls.Spec.TLS.Reference {
		case BIGIP:
			clientSSL := tls.Spec.TLS.ClientSSL
			serverSSL := tls.Spec.TLS.ServerSSL
			// Profile is a BIG-IP default
			log.Debugf("Processing BIGIP referenced profiles for Virtual '%s' using TLSProfile '%s'",
				vsName, tlsName)
			// Process referenced BIG-IP clientSSL
			if clientSSL != "" {
				clientProfRef := ConvertStringToProfileRef(
					clientSSL, CustomProfileClient, vsNamespace)
				rsCfg.Virtual.AddOrUpdateProfile(clientProfRef)
			}
			// Process referenced BIG-IP serverSSL
			if serverSSL != "" {
				serverProfRef := ConvertStringToProfileRef(
					serverSSL, CustomProfileServer, vsNamespace)
				rsCfg.Virtual.AddOrUpdateProfile(serverProfRef)
			}
			log.Debugf("Updated BIGIP referenced profiles for Virtual '%s' using TLSProfile '%s'",
				vsName, tlsName)
		case Secret:
			// Prepare SSL Transient Context
			// Check if TLS Secret already exists
			// Process ClientSSL stored as kubernetes secret
			clientSSL := tls.Spec.TLS.ClientSSL
			if clientSSL != "" {
				if secret, ok := ctlr.SSLContext[clientSSL]; ok {
					log.Debugf("clientSSL secret %s for TLSProfile '%s' is already available with CIS in "+
						"SSLContext as clientSSL", secret.ObjectMeta.Name, tlsName)
					err, _ := ctlr.createSecretClientSSLProfile(rsCfg, secret, CustomProfileClient)
					if err != nil {
						log.Debugf("error %v encountered for '%s' using TLSProfile '%s'",
							err, vsName, tlsName)
						return false
					}
				} else {
					// Check if profile is contained in a Secret
					// Update the SSL Context if secret found, This is used to avoid api calls
					log.Debugf("saving clientSSL secret for TLSProfile '%s' into SSLContext", tlsName)
					secret, err := ctlr.kubeClient.CoreV1().Secrets(vsNamespace).
						Get(context.TODO(), clientSSL, metav1.GetOptions{})
					if err != nil {
						log.Errorf("secret %s not found for Virtual '%s' using TLSProfile '%s'",
							clientSSL, vsName, tlsName)
						return false
					}
					ctlr.SSLContext[clientSSL] = secret
					err, _ = ctlr.createSecretClientSSLProfile(rsCfg, secret, CustomProfileClient)
					if err != nil {
						log.Errorf("error %v encountered for '%s' using TLSProfile '%s'",
							err, vsName, tlsName)
						return false
					}
				}
			}
			// Process ServerSSL stored as kubernetes secret
			serverSSL := tls.Spec.TLS.ServerSSL
			if serverSSL != "" {
				if secret, ok := ctlr.SSLContext[serverSSL]; ok {
					log.Debugf("serverSSL secret %s for TLSProfile '%s' is already available with CIS in"+
						"SSLContext", secret.ObjectMeta.Name, tlsName)
					err, _ := ctlr.createSecretServerSSLProfile(rsCfg, secret, CustomProfileServer)
					if err != nil {
						log.Debugf("error %v encountered for '%s' using TLSProfile '%s'",
							err, vsName, tlsName)
						return false
					}
				} else {
					// Check if profile is contained in a Secret
					// Update the SSL Context if secret found, This is used to avoid api calls
					log.Debugf("saving serverSSL secret for TLSProfile '%s' into SSLContext", tlsName)
					secret, err := ctlr.kubeClient.CoreV1().Secrets(vsNamespace).
						Get(context.TODO(), serverSSL, metav1.GetOptions{})
					if err != nil {
						log.Errorf("secret %s not found for Virtual '%s' using TLSProfile '%s'",
							serverSSL, vsName, tlsName)
						return false
					}
					ctlr.SSLContext[serverSSL] = secret
					err, _ = ctlr.createSecretServerSSLProfile(rsCfg, secret, CustomProfileServer)
					if err != nil {
						log.Errorf("error %v encountered for '%s' using TLSProfile '%s'",
							err, vsName, tlsName)
						return false
					}
				}
			}
		default:
			log.Errorf("referenced profile does not exist for Virtual '%s' using TLSProfile '%s'",
				vsName, tlsName)
			return false
		}
		// TLS Cert/Key
		for _, pl := range vs.Spec.Pools {
			if "" != vs.Spec.TLSProfileName {
				switch tls.Spec.TLS.Termination {
				case TLSEdge:
					serverSsl := "false"
					hostName := vs.Spec.Host
					path := pl.Path
					sslPath := hostName + path
					sslPath = strings.TrimSuffix(sslPath, "/")
					updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, EdgeServerSslDgName),
						DEFAULT_PARTITION, vs.ObjectMeta.Namespace, sslPath, serverSsl)

				case TLSReencrypt:
					hostName := vs.Spec.Host
					path := pl.Path
					sslPath := hostName + path
					sslPath = strings.TrimSuffix(sslPath, "/")
					serverSsl := AS3NameFormatter("crd_" + ip + "_tls_client")
					if "" != tls.Spec.TLS.ServerSSL {
						updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, ReencryptServerSslDgName),
							DEFAULT_PARTITION, vs.ObjectMeta.Namespace, sslPath, serverSsl)
					}
				}
			}
		}
		//Create datagroups
		if "" != vs.Spec.TLSProfileName {
			switch tls.Spec.TLS.Termination {
			case TLSReencrypt:
				if vs.Spec.HTTPTraffic == TLSAllowInsecure {
					log.Errorf("Error in processing Virtual '%s' using TLSProfile '%s' as httpTraffic is configured as ALLOW for reencrypt Termination",
						vsName, tlsName)
					return false
				}
				updateDataGroupOfDgName(
					rsCfg.IntDgMap,
					vs,
					rsCfg.Virtual.Name,
					ReencryptHostsDgName,
				)
			case TLSEdge:
				updateDataGroupOfDgName(
					rsCfg.IntDgMap,
					vs,
					rsCfg.Virtual.Name,
					EdgeHostsDgName,
				)
			}
		}

		ctlr.handleDataGroupIRules(
			rsCfg,
			vs.ObjectMeta.Name,
			vs.Spec.Host,
			tls,
		)

		return true
	}

	// httpTraffic defines the behaviour of http Virtual Server on BIG-IP
	// Possible values are allow, none and redirect
	httpTraffic := vs.Spec.HTTPTraffic
	if httpTraffic != "" {
		// -----------------------------------------------------------------
		// httpTraffic = allow -> Allows HTTP
		// httpTraffic = none  -> Only HTTPS
		// httpTraffic = redirect -> redirects HTTP to HTTPS
		// -----------------------------------------------------------------
		switch httpTraffic {
		case TLSRedirectInsecure:
			// set HTTP redirect iRule
			log.Debugf("Applying HTTP redirect iRule.")
			log.Debugf("Redirect HTTP(insecure) requests for VirtualServer %s", vs.ObjectMeta.Name)
			var ruleName string
			if vs.Spec.Host == "" {
				ruleName = fmt.Sprintf("%s_%d", getRSCfgResName(rsCfg.Virtual.Name, HttpRedirectNoHostIRuleName), httpsPort)
				rsCfg.addIRule(ruleName, DEFAULT_PARTITION, httpRedirectIRuleNoHost(httpsPort))
			} else {
				ruleName = fmt.Sprintf("%s_%d", getRSCfgResName(rsCfg.Virtual.Name, HttpRedirectIRuleName), httpsPort)
				rsCfg.addIRule(ruleName, DEFAULT_PARTITION, httpRedirectIRule(httpsPort, rsCfg.Virtual.Name, DEFAULT_PARTITION))
			}
			ruleName = JoinBigipPath(DEFAULT_PARTITION, ruleName)
			rsCfg.Virtual.AddIRule(ruleName)
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				vs,
				rsCfg.Virtual.Name,
				HttpsRedirectDgName,
			)
		case TLSAllowInsecure:
			// State 3, do not apply any policy
			log.Debugf("Allow HTTP(insecure) requests for VirtualServer %s", vs.ObjectMeta.Name)
		case TLSNoInsecure:
			//if policy := rsCfg.FindPolicy(PolicyControlForward); policy != nil {
			//	rsCfg.RemovePolicy(*policy)
			//}
			log.Debugf("Disable HTTP(insecure) requests for VirtualServer %s", vs.ObjectMeta.Name)
		}
	}

	return true
}

// validate TLSProfile
// validation includes valid parameters for the type of termination(edge, re-encrypt and Pass-through)
func validateTLSProfile(tls *cisapiv1.TLSProfile) bool {
	//validation for re-encrypt termination
	if tls.Spec.TLS.Termination == "reencrypt" {
		// Should contain both client and server SSL profiles
		if (tls.Spec.TLS.ClientSSL == "") || (tls.Spec.TLS.ServerSSL == "") {
			log.Errorf("TLSProfile %s of type re-encrypt termination should contain both "+
				"ClientSSL and ServerSSL", tls.ObjectMeta.Name)
			return false
		}
	} else if tls.Spec.TLS.Termination == "edge" {
		// Should contain only client SSL
		if tls.Spec.TLS.ClientSSL == "" {
			log.Errorf("TLSProfile %s of type edge termination should contain Client SSL",
				tls.ObjectMeta.Name)
			return false
		}
		if tls.Spec.TLS.ServerSSL != "" {
			log.Errorf("TLSProfile %s of type edge termination should NOT contain ServerSSL",
				tls.ObjectMeta.Name)
			return false
		}
	} else {
		// Pass-through
		if (tls.Spec.TLS.ClientSSL != "") || (tls.Spec.TLS.ServerSSL != "") {
			log.Errorf("TLSProfile %s of type Pass-through termination should NOT contain either "+
				"ClientSSL or ServerSSL", tls.ObjectMeta.Name)
			return false
		}
	}
	return true
}

// ConvertStringToProfileRef converts strings to profile references
func ConvertStringToProfileRef(profileName, context, ns string) ProfileRef {
	profName := strings.TrimSpace(strings.TrimPrefix(profileName, "/"))
	parts := strings.Split(profName, "/")
	profRef := ProfileRef{Context: context, Namespace: ns}
	switch len(parts) {
	case 2:
		profRef.Partition = parts[0]
		profRef.Name = parts[1]
	case 1:
		log.Debugf("[RESOURCE] Partition not provided in profile '%s', using default partition '%s'",
			profileName, DEFAULT_PARTITION)
		profRef.Partition = DEFAULT_PARTITION
		profRef.Name = profileName
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("[RESOURCE] Profile name '%v' is formatted incorrectly.", profileName)
	}
	return profRef
}

// AddOrUpdateProfile updates profile to rsCfg
func (v *Virtual) AddOrUpdateProfile(prof ProfileRef) bool {
	// The profiles are maintained as a sorted array.
	// The profiles are maintained as a sorted array.
	keyFunc := func(i int) bool {
		return ((v.Profiles[i].Partition > prof.Partition) ||
			(v.Profiles[i].Partition == prof.Partition &&
				v.Profiles[i].Name >= prof.Name))
	}
	profCt := v.Profiles.Len()
	i := sort.Search(profCt, keyFunc)
	if i < profCt && v.Profiles[i].Partition == prof.Partition &&
		v.Profiles[i].Name == prof.Name {
		// found, look for data changed
		if v.Profiles[i].Context == prof.Context {
			// unchanged
			return false
		}
	} else {
		// Insert into the correct position.
		v.Profiles = append(v.Profiles, ProfileRef{})
		copy(v.Profiles[i+1:], v.Profiles[i:])
	}
	v.Profiles[i] = prof

	return true
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

// SetPolicy sets a policy
func (rc *ResourceConfig) SetPolicy(policy Policy) {
	toFind := nameRef{
		Name:      policy.Name,
		Partition: policy.Partition,
	}
	found := false
	for _, polName := range rc.Virtual.Policies {
		if toFind == polName {
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
func (rs *ResourceStore) GetByName(name string) (*ResourceConfig, bool) {
	resource, ok := rs.rsMap[name]
	return resource, ok
}

// GetAllResources is list of all resource configs
func (rs *ResourceStore) GetAllResources() ResourceConfigs {
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
		rc.Pools[i].Members = make([]PoolMember, len(cfg.Pools[i].Members))
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
	match := strings.Split(address, "%")
	if len(match) == 2 {
		_, err := strconv.Atoi(match[1])
		//Matches only when RD contains number, Not allowing RD has 80f
		if err == nil {
			ip = match[0]
			rd = match[1]
		} else {
			ip = address
		}
	} else {
		ip = match[0]
	}
	return
}

func (pol *Policy) mergeRules(rls *Rules) Rules {
	existingRlMap := make(ruleMap)
	// populate existing rules into a map
	for _, rule := range pol.Rules {
		existingRlMap[rule.Name] = rule
	}
	var newRules Rules
	for _, newRule := range *rls {
		if existingRule, found := existingRlMap[newRule.Name]; found {
			for _, existingCond := range existingRule.Conditions {
				if existingCond.HTTPHost == true {
					for _, newCond := range newRule.Conditions {
						if newCond.HTTPHost == true {
							// Merge host names
							existingCond.Values = append(existingCond.Values, newCond.Values[0])
							break
						}
					}
					break
				}
			}
		} else {
			newRules = append(newRules, newRule)
		}
	}
	return newRules
}

func (pol *Policy) AddRules(rls *Rules) {
	// check for existing policy rule with same name and merge hosts if found
	newRules := pol.mergeRules(rls)
	tcpReqExist := false
	for _, req := range pol.Requires {
		if "tcp" == req {
			tcpReqExist = true
			break
		}
	}
	if !tcpReqExist {
		// Check for the existence of the TCP field in the conditions.
		// This would indicate that a whitelist rule is in the policy
		// and that we need to add the "tcp" requirement to the policy.
		requiresTcp := false
		for _, x := range newRules {
			for _, c := range x.Conditions {
				if c.Tcp == true {
					requiresTcp = true
				}
			}
		}

		// Add the tcp requirement if needed; indicated by the presence
		// of the TCP field.
		if requiresTcp {
			pol.Requires = append(pol.Requires, "tcp")
		}
	}

	pol.Rules = append(pol.Rules, newRules...)
	sort.Sort(pol.Rules)
}

func (cfg *ResourceConfig) GetName() string {
	return cfg.Virtual.Name
}

func (rcs ResourceConfigs) GetAllPoolMembers() []PoolMember {
	// Get all pool members and write them to VxlanMgr to configure ARP entries
	var allPoolMembers []PoolMember

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

func (rs *ResourceStore) updateOldConfig() {
	rs.oldRsMap = make(ResourceConfigMap)
	for k, v := range rs.rsMap {
		rs.oldRsMap[k] = &ResourceConfig{}
		rs.oldRsMap[k].copyConfig(v)
	}
	rs.oldDNSConfig = make(DNSConfig)
	for k, v := range rs.dnsConfig {
		rs.oldDNSConfig[k] = v
	}
}

// Deletes respective VirtualServer resource configuration from
// resource configs.
func (rs *ResourceStore) deleteVirtualServer(rsName string) {
	delete(rs.rsMap, rsName)
}

// Internal data group for reencrypt termination.
const ReencryptHostsDgName = "ssl_reencrypt_servername_dg"

// Internal data group for edge termination.
const EdgeHostsDgName = "ssl_edge_servername_dg"

// Internal data group for reencrypt termination that maps the host name to the
// server ssl profile.
const ReencryptServerSslDgName = "ssl_reencrypt_serverssl_dg"

// Internal data group for edge termination that maps the host name to the
// false. This will help Irule to understand ssl should be disabled
// on serverside.
const EdgeServerSslDgName = "ssl_edge_serverssl_dg"

// Internal data group for ab deployment routes.
const AbDeploymentDgName = "ab_deployment_dg"

func (slice InternalDataGroupRecords) Less(i, j int) bool {
	return slice[i].Name < slice[j].Name
}

func (slice InternalDataGroupRecords) Len() int {
	return len(slice)
}

func (slice InternalDataGroupRecords) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (idg *InternalDataGroup) AddOrUpdateRecord(name, data string) bool {
	// The records are maintained as a sorted array.
	nameKeyFunc := func(i int) bool {
		return idg.Records[i].Name >= name
	}
	i := sort.Search(idg.Records.Len(), nameKeyFunc)
	if i < idg.Records.Len() && idg.Records[i].Name == name {
		if idg.Records[i].Data != data {
			// name found with different data, update
			idg.Records[i].Data = data
			return true
		}
		// name found with same data
		return false
	}

	// Insert into the correct position.
	idg.Records = append(idg.Records, InternalDataGroupRecord{})
	copy(idg.Records[i+1:], idg.Records[i:])
	idg.Records[i] = InternalDataGroupRecord{Name: name, Data: data}

	return true
}

func (idg *InternalDataGroup) RemoveRecord(name string) bool {
	// The records are maintained as a sorted array.
	nameKeyFunc := func(i int) bool {
		return idg.Records[i].Name >= name
	}
	nbrRecs := idg.Records.Len()
	i := sort.Search(nbrRecs, nameKeyFunc)
	if i < nbrRecs && idg.Records[i].Name == name {
		// found, remove it and adjust the array.
		nbrRecs -= 1
		copy(idg.Records[i:], idg.Records[i+1:])
		idg.Records[nbrRecs] = InternalDataGroupRecord{}
		idg.Records = idg.Records[:nbrRecs]
		return true
	}
	return false
}

// AS3NameFormatter formarts resources names according to AS3 convention
// TODO: Should we use this? Or this will be done in agent?
func AS3NameFormatter(name string) string {
	modifySpecialChars := map[string]string{
		".": "_",
		":": "_",
		"/": "_",
		"%": ".",
		"-": "_",
		"=": "_"}
	SpecialChars := [6]string{".", ":", "/", "%", "-", "="}
	for _, key := range SpecialChars {
		name = strings.ReplaceAll(name, key, modifySpecialChars[key])
	}
	return name
}

func (ctlr *Controller) handleDataGroupIRules(
	rsCfg *ResourceConfig,
	virtualName string,
	vsHost string,
	tls *cisapiv1.TLSProfile,
) {
	// For https
	if nil != tls {
		termination := tls.Spec.TLS.Termination
		tlsIRuleName := JoinBigipPath(DEFAULT_PARTITION,
			getRSCfgResName(rsCfg.Virtual.Name, TLSIRuleName))
		switch termination {
		case TLSEdge:
			rsCfg.addIRule(
				getRSCfgResName(rsCfg.Virtual.Name, TLSIRuleName), DEFAULT_PARTITION, ctlr.getTLSIRule(rsCfg.Virtual.Name))
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, EdgeHostsDgName), DEFAULT_PARTITION)
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, EdgeServerSslDgName), DEFAULT_PARTITION)
		case TLSReencrypt:
			rsCfg.addIRule(
				getRSCfgResName(rsCfg.Virtual.Name, TLSIRuleName), DEFAULT_PARTITION, ctlr.getTLSIRule(rsCfg.Virtual.Name))
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, ReencryptHostsDgName), DEFAULT_PARTITION)
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, ReencryptServerSslDgName), DEFAULT_PARTITION)
		}
		if vsHost != "" {
			rsCfg.Virtual.AddIRule(tlsIRuleName)
		}
	}
}

func (ctlr *Controller) deleteVirtualServer(rsName string) {
	ctlr.resources.deleteVirtualServer(rsName)
}

// Prepares resource config based on VirtualServer resource config
func (ctlr *Controller) prepareRSConfigFromTransportServer(
	rsCfg *ResourceConfig,
	vs *cisapiv1.TransportServer,
) error {

	var pools Pools
	var monitors []Monitor
	var snat string
	snat = DEFAULT_SNAT
	pool := Pool{
		Name: formatVirtualServerPoolName(
			vs.ObjectMeta.Namespace,
			vs.Spec.Pool.Service,
			vs.Spec.Pool.ServicePort,
			vs.Spec.Pool.NodeMemberLabel,
		),
		Partition:       rsCfg.Virtual.Partition,
		ServiceName:     vs.Spec.Pool.Service,
		ServicePort:     vs.Spec.Pool.ServicePort,
		NodeMemberLabel: vs.Spec.Pool.NodeMemberLabel,
	}

	if vs.Spec.Pool.Monitor.Type != "" {
		pool.MonitorNames = append(pool.MonitorNames, JoinBigipPath(DEFAULT_PARTITION,
			formatMonitorName(vs.ObjectMeta.Namespace, vs.Spec.Pool.Service, vs.Spec.Pool.Monitor.Type, vs.Spec.Pool.ServicePort)))
		monitor := Monitor{
			Name:      formatMonitorName(vs.ObjectMeta.Namespace, vs.Spec.Pool.Service, vs.Spec.Pool.Monitor.Type, vs.Spec.Pool.ServicePort),
			Partition: rsCfg.Virtual.Partition,
			Type:      vs.Spec.Pool.Monitor.Type,
			Interval:  vs.Spec.Pool.Monitor.Interval,
			Send:      "",
			Recv:      "",
			Timeout:   vs.Spec.Pool.Monitor.Timeout,
		}
		monitors = append(monitors, monitor)
	}
	pools = append(pools, pool)
	rsCfg.Virtual.Mode = vs.Spec.Mode
	rsCfg.Virtual.IpProtocol = vs.Spec.Type
	rsCfg.Virtual.PoolName = pool.Name
	rsCfg.Pools = append(rsCfg.Pools, pools...)
	rsCfg.Monitors = append(rsCfg.Monitors, monitors...)
	// set the SNAT policy to auto is it's not defined by end user
	if vs.Spec.SNAT == "" {
		rsCfg.Virtual.SNAT = snat
	} else {
		rsCfg.Virtual.SNAT = vs.Spec.SNAT
	}

	if len(rsCfg.ServiceAddress) == 0 {
		for _, sa := range vs.Spec.ServiceIPAddress {
			rsCfg.ServiceAddress = append(rsCfg.ServiceAddress, ServiceAddress(sa))
		}
	}

	//set allowed VLAN's per TS config
	rsCfg.Virtual.AllowVLANs = vs.Spec.AllowVLANs

	if vs.Spec.PersistenceProfile != "" {
		rsCfg.Virtual.PersistenceProfile = vs.Spec.PersistenceProfile
	}

	// Attach user specified iRules
	if len(vs.Spec.IRules) > 0 {
		rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, vs.Spec.IRules...)
	}
	return nil
}

// Prepares resource config based on VirtualServer resource config
func (ctlr *Controller) prepareRSConfigFromLBService(
	rsCfg *ResourceConfig,
	svc *v1.Service,
	svcPort v1.ServicePort,
) error {

	poolName := formatVirtualServerPoolName(
		svc.Namespace,
		svc.Name,
		svcPort.TargetPort.IntVal,
		"")
	pool := Pool{
		Name:            poolName,
		Partition:       rsCfg.Virtual.Partition,
		ServiceName:     svc.Name,
		ServicePort:     svcPort.TargetPort.IntVal,
		NodeMemberLabel: "",
	}

	// Health Monitor Annotation
	hmStr, found := svc.Annotations[HealthMonitorAnnotation]
	var monitor Monitor
	if found {
		monitorType := strings.ToLower(string(svcPort.Protocol))
		var mon ServiceTypeLBHealthMonitor
		err := json.Unmarshal([]byte(hmStr), &mon)
		if err != nil {
			msg := fmt.Sprintf(
				"Unable to parse health monitor JSON array '%v': %v", hmStr, err)
			log.Errorf("[CORE] %s", msg)
		}
		pool.MonitorNames = append(pool.MonitorNames, JoinBigipPath(DEFAULT_PARTITION,
			formatMonitorName(svc.Namespace, svc.Name, monitorType, svcPort.TargetPort.IntVal)))
		monitor = Monitor{
			Name:      formatMonitorName(svc.Namespace, svc.Name, monitorType, svcPort.TargetPort.IntVal),
			Partition: rsCfg.Virtual.Partition,
			Type:      monitorType,
			Interval:  mon.Interval,
			Send:      "",
			Recv:      "",
			Timeout:   mon.Timeout,
		}
		rsCfg.Monitors = append(rsCfg.Monitors, monitor)
	}
	rsCfg.Pools = Pools{pool}
	rsCfg.Virtual.PoolName = poolName
	rsCfg.Virtual.SNAT = DEFAULT_SNAT
	rsCfg.Virtual.Mode = "standard"

	return nil
}

// Returns Partition and resourceName
func getPartitionAndName(objectName string) (string, string) {
	allParts := strings.Split(objectName, "/")
	if len(allParts) == 3 {
		return allParts[1], allParts[2]
	}
	return "", objectName
}

func (ctlr *Controller) handleVSResourceConfigForPolicy(
	rsCfg *ResourceConfig,
	plc *cisapiv1.Policy,
) error {
	rsCfg.Virtual.WAF = plc.Spec.L7Policies.WAF
	rsCfg.Virtual.Firewall = plc.Spec.L3Policies.FirewallPolicy
	rsCfg.Virtual.PersistenceProfile = plc.Spec.Profiles.PersistenceProfile

	if len(plc.Spec.Profiles.LogProfiles) > 0 {
		rsCfg.Virtual.LogProfiles = append(rsCfg.Virtual.LogProfiles, plc.Spec.Profiles.LogProfiles...)
	}
	var iRule string
	// Profiles common for both HTTP and HTTPS
	// service_HTTP supports profileTCP and profileHTTP
	// service_HTTPS supports profileTCP, profileHTTP and profileHTTP2
	if len(plc.Spec.Profiles.HTTP) > 0 {
		rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
			Name:    plc.Spec.Profiles.HTTP,
			Context: "http",
		})
	}
	if len(plc.Spec.Profiles.TCP) > 0 {
		rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
			Name:    plc.Spec.Profiles.TCP,
			Context: "tcp",
		})
	}

	switch rsCfg.MetaData.Protocol {
	case "https":
		iRule = plc.Spec.IRules.Secure
		if len(plc.Spec.Profiles.HTTP2) > 0 {
			rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
				Name:    plc.Spec.Profiles.HTTP2,
				Context: "http2",
			})
		}
	case "http":
		iRule = plc.Spec.IRules.InSecure
	}
	if len(iRule) > 0 {
		switch plc.Spec.IRules.Priority {
		case "override":
			rsCfg.Virtual.IRules = []string{iRule}
		case "high":
			rsCfg.Virtual.IRules = append([]string{iRule}, rsCfg.Virtual.IRules...)
		default:
			rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, iRule)
		}
	}
	return nil
}

func (ctlr *Controller) handleTSResourceConfigForPolicy(
	rsCfg *ResourceConfig,
	plc *cisapiv1.Policy,
) error {
	rsCfg.Virtual.WAF = plc.Spec.L7Policies.WAF
	rsCfg.Virtual.Firewall = plc.Spec.L3Policies.FirewallPolicy
	rsCfg.Virtual.PersistenceProfile = plc.Spec.Profiles.PersistenceProfile

	if len(plc.Spec.Profiles.LogProfiles) > 0 {
		rsCfg.Virtual.LogProfiles = append(rsCfg.Virtual.LogProfiles, plc.Spec.Profiles.LogProfiles...)
	}
	if len(plc.Spec.Profiles.UDP) > 0 {
		rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
			Name:    plc.Spec.Profiles.UDP,
			Context: "udp",
		})
	}
	if len(plc.Spec.Profiles.TCP) > 0 {
		rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
			Name:    plc.Spec.Profiles.TCP,
			Context: "tcp",
		})
	}
	var iRule string
	iRule = plc.Spec.IRules.InSecure
	if len(iRule) > 0 {
		switch plc.Spec.IRules.Priority {
		case "override":
			rsCfg.Virtual.IRules = []string{iRule}
		case "high":
			rsCfg.Virtual.IRules = append([]string{iRule}, rsCfg.Virtual.IRules...)
		default:
			rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, iRule)
		}
	}
	return nil
}

func getRSCfgResName(rsVSName, resName string) string {
	return fmt.Sprintf("%s_%s", rsVSName, resName)
}
