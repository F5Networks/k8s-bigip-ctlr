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
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	routeapi "github.com/openshift/api/route/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	rs.ltmConfig = make(LTMConfig)
	rs.ltmConfigCache = make(LTMConfig)
	rs.gtmConfig = make(GTMConfig)
	rs.gtmConfigCache = make(GTMConfig)
	rs.poolMemCache = make(PoolMemberCache)
	rs.nplStore = make(NPLStore)
	rs.extdSpecMap = make(extendedSpecMap)
	rs.invertedNamespaceLabelMap = make(map[string]string)
	rs.svcResourceCache = make(map[string]map[string]struct{})
	rs.ipamContext = make(map[string]ficV1.IPSpec)
	rs.processedNativeResources = make(map[resourceRef]struct{})
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
	// reference for routes
	Certificate = "certificate"
)

func NewCustomProfile(
	profile ProfileRef,
	cert,
	key,
	serverName string,
	sni bool,
	peerCertMode,
	caFile string,
	chainCA string,
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
		ChainCA:      chainCA,
	}
	if peerCertMode == PeerCertRequired {
		cp.CAFile = caFile
	}
	return cp
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
func (ctlr *Controller) virtualPorts(input interface{}) []portStruct {

	http := portStruct{
		protocol: "http",
		port:     DEFAULT_HTTP_PORT,
	}

	https := portStruct{
		protocol: "https",
		port:     DEFAULT_HTTPS_PORT,
	}

	var ports []portStruct

	switch input.(type) {
	case *cisapiv1.VirtualServer:
		vs := input.(*cisapiv1.VirtualServer)
		if vs.Spec.VirtualServerHTTPPort != 0 {
			http.port = vs.Spec.VirtualServerHTTPPort
		}

		if vs.Spec.VirtualServerHTTPSPort != 0 {
			https.port = vs.Spec.VirtualServerHTTPSPort
		}

		ports = append(ports, http)

		if len(vs.Spec.TLSProfileName) != 0 {
			ports = append(ports, https)
		}
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

func framePoolName(ns string, pool cisapiv1.Pool, port intstr.IntOrString, host string) string {
	poolName := pool.Name
	if poolName == "" {
		poolName = formatPoolName(ns, pool.Service, port, pool.NodeMemberLabel, host)
	}

	return poolName
}

// format the pool name for an VirtualServer
func formatPoolName(namespace, svc string, port intstr.IntOrString, nodeMemberLabel string, host string) string {
	servicePort := fetchPortString(port)
	poolName := fmt.Sprintf("%s_%s_%s", svc, servicePort, namespace)
	if len(host) > 0 {
		poolName = fmt.Sprintf("%s_%s", poolName, host)
	}
	if nodeMemberLabel != "" {
		nodeMemberLabel = strings.ReplaceAll(nodeMemberLabel, "=", "_")
		poolName = fmt.Sprintf("%s_%s", poolName, nodeMemberLabel)
	}
	return AS3NameFormatter(poolName)
}

// format the monitor name for an VirtualServer pool
func formatMonitorName(namespace, svc string, monitorType string, port int32, sendString string) string {
	monitorName := fmt.Sprintf("%s_%s", svc, namespace)

	if monitorType != "" && port != 0 {
		servicePort := fmt.Sprint(port)
		monitorName = monitorName + fmt.Sprintf("_%s_%s", monitorType, servicePort)
	}
	if len(sendString) > 0 && sendString != "/" {
		if strings.Contains(sendString, "/") {
			monitorName = monitorName + fmt.Sprintf("%s", sendString)
		} else {
			monitorName = monitorName + fmt.Sprintf("_%s", sendString)
		}
	}
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

func (ctlr *Controller) getSvcDepResources(svcDepRscKey string) map[string]struct{} {
	return ctlr.resources.svcResourceCache[svcDepRscKey]
}

func (ctlr *Controller) updateSvcDepResources(rsName string, rsCfg *ResourceConfig) {
	for _, pool := range rsCfg.Pools {
		svcDepRscKey := rsCfg.MetaData.namespace + "_" + pool.ServiceName
		if resources, found := ctlr.resources.svcResourceCache[svcDepRscKey]; found {
			if _, found := resources[rsName]; !found {
				ctlr.resources.svcResourceCache[svcDepRscKey][rsName] = struct{}{}
			}
		} else {
			ctlr.resources.svcResourceCache[svcDepRscKey] = make(map[string]struct{})
			ctlr.resources.svcResourceCache[svcDepRscKey][rsName] = struct{}{}
		}
	}
}

func (ctlr *Controller) deleteSvcDepResource(rsName string, rsCfg *ResourceConfig) {

	if rsCfg == nil {
		return
	}

	for _, pool := range rsCfg.Pools {
		svcDepRscKey := rsCfg.MetaData.namespace + "_" + pool.ServiceName
		if resources, found := ctlr.resources.svcResourceCache[svcDepRscKey]; found {
			if _, found := resources[rsName]; found {
				delete(ctlr.resources.svcResourceCache[svcDepRscKey], rsName)
			}
		}
	}
}

// fetch target port from service
func (ctlr *Controller) fetchTargetPort(namespace, svcName string, servicePort int32) intstr.IntOrString {
	var targetPort intstr.IntOrString
	var svcIndexer cache.Indexer
	svcKey := namespace + "/" + svcName
	if ctlr.watchingAllNamespaces() {
		svcIndexer = ctlr.crInformers[""].svcInformer.GetIndexer()
	} else {
		if informer, ok := ctlr.crInformers[namespace]; ok {
			svcIndexer = informer.svcInformer.GetIndexer()
		} else {
			return targetPort
		}
	}
	item, found, _ := svcIndexer.GetByKey(svcKey)
	if !found {
		log.Debugf("service '%v' not found", svcKey)
		return targetPort
	}
	svc := item.(*v1.Service)
	for _, port := range svc.Spec.Ports {
		if port.Port == servicePort {
			return port.TargetPort
		}
	}
	return targetPort
}

// Prepares resource config based on VirtualServer resource config
func (ctlr *Controller) prepareRSConfigFromVirtualServer(
	rsCfg *ResourceConfig,
	vs *cisapiv1.VirtualServer,
	passthroughVS bool,
) error {

	var httpPort int32
	httpPort = DEFAULT_HTTP_PORT
	var snat string
	snat = DEFAULT_SNAT
	var pools Pools
	var rules *Rules
	var monitors []Monitor

	framedPools := make(map[string]struct{})
	for _, pl := range vs.Spec.Pools {
		targetPort := ctlr.fetchTargetPort(vs.Namespace, pl.Service, pl.ServicePort)
		if (intstr.IntOrString{}) == targetPort {
			targetPort = intstr.IntOrString{IntVal: pl.ServicePort}
		}
		poolName := framePoolName(vs.ObjectMeta.Namespace, pl, targetPort, vs.Spec.Host)
		monitorName := pl.Name + "-monitor"

		if _, ok := framedPools[poolName]; ok {
			// Pool with same name framed earlier, so skipping this pool
			log.Debugf("Duplicate pool name: %v in Virtual Server: %v/%v", poolName, vs.Namespace, vs.Name)
			continue
		}
		framedPools[poolName] = struct{}{}

		pool := Pool{
			Name:             poolName,
			Partition:        rsCfg.Virtual.Partition,
			ServiceName:      pl.Service,
			ServiceNamespace: vs.ObjectMeta.Namespace,
			ServicePort:      targetPort,
			NodeMemberLabel:  pl.NodeMemberLabel,
			Balance:          pl.Balance,
		}

		if pl.Monitor.Send != "" && pl.Monitor.Type != "" {
			if pl.Name == "" {
				monitorName = formatMonitorName(vs.ObjectMeta.Namespace, pl.Service, pl.Monitor.Type, pl.ServicePort, pl.Monitor.Send)
			}
			pool.MonitorNames = append(pool.MonitorNames, JoinBigipPath(rsCfg.Virtual.Partition, monitorName))
			monitor := Monitor{
				Name:       monitorName,
				Partition:  rsCfg.Virtual.Partition,
				Type:       pl.Monitor.Type,
				Interval:   pl.Monitor.Interval,
				Send:       pl.Monitor.Send,
				Recv:       pl.Monitor.Recv,
				Timeout:    pl.Monitor.Timeout,
				TargetPort: pl.Monitor.TargetPort,
			}
			monitors = append(monitors, monitor)
		}
		pools = append(pools, pool)
	}
	rsCfg.Pools = append(rsCfg.Pools, pools...)
	rsCfg.Monitors = append(rsCfg.Monitors, monitors...)

	// set the SNAT policy to auto if it's not defined by end user
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

	if len(vs.Spec.Profiles.TCP.Client) > 0 || len(vs.Spec.Profiles.TCP.Server) > 0 {
		rsCfg.Virtual.TCP.Client = vs.Spec.Profiles.TCP.Client
		rsCfg.Virtual.TCP.Server = vs.Spec.Profiles.TCP.Server
	}

	if vs.Spec.DOS != "" {
		rsCfg.Virtual.ProfileDOS = vs.Spec.DOS
	}

	if len(vs.Spec.AllowSourceRange) > 0 {
		rsCfg.Virtual.AllowSourceRange = vs.Spec.AllowSourceRange
	}

	if vs.Spec.BotDefense != "" {
		rsCfg.Virtual.ProfileBotDefense = vs.Spec.BotDefense
	}

	if vs.Spec.ProfileMultiplex != "" {
		rsCfg.Virtual.ProfileMultiplex = vs.Spec.ProfileMultiplex
	}

	// Do not Create Virtual Server L7 Forwarding policies if HTTPTraffic is set to None or Redirect
	if len(vs.Spec.TLSProfileName) > 0 &&
		rsCfg.Virtual.VirtualAddress.Port == httpPort &&
		(vs.Spec.HTTPTraffic == TLSNoInsecure || vs.Spec.HTTPTraffic == TLSRedirectInsecure) {
		return nil
	}

	// skip the policy creation for passthrough termination
	if !passthroughVS {
		rules = ctlr.prepareVirtualServerRules(vs, rsCfg)
		if rules == nil {
			return fmt.Errorf("failed to create LTM Rules")
		}

		policyName := formatPolicyName(vs.Spec.Host, vs.Spec.HostGroup, rsCfg.Virtual.Name)

		rsCfg.AddRuleToPolicy(policyName, vs.Namespace, rules)
	}

	// Attach user specified iRules
	if len(vs.Spec.IRules) > 0 {
		rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, vs.Spec.IRules...)
	}
	return nil
}

func (rsCfg *ResourceConfig) AddRuleToPolicy(policyName, partition string, rules *Rules) {
	// Update the existing policy with rules
	// Otherwise create new policy and set
	if policy := rsCfg.FindPolicy(PolicyControlForward); policy != nil {
		policy.AddRules(rules)
		rsCfg.SetPolicy(*policy)
		return
	}
	plcy := createPolicy(*rules, policyName, partition)
	if plcy != nil {
		rsCfg.SetPolicy(*plcy)
	}
}

// function updates the rscfg as per the passed parameter for routes as well as for virtual server
func (ctlr *Controller) handleTLS(
	rsCfg *ResourceConfig,
	tlsContext TLSContext,
) bool {

	if rsCfg.Virtual.VirtualAddress.Port == tlsContext.httpsPort {
		if tlsContext.termination != TLSPassthrough {
			clientSSL := tlsContext.bigIPSSLProfiles.clientSSL
			serverSSL := tlsContext.bigIPSSLProfiles.serverSSL
			// Process Profile
			switch tlsContext.referenceType {
			case BIGIP:
				log.Debugf("Processing  BIGIP referenced profiles for '%s' '%s'/'%s'",
					tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
				// Process referenced BIG-IP clientSSL
				if clientSSL != "" {
					clientProfRef := ConvertStringToProfileRef(
						clientSSL, CustomProfileClient, tlsContext.namespace)
					rsCfg.Virtual.AddOrUpdateProfile(clientProfRef)
				}
				// Process referenced BIG-IP serverSSL
				if serverSSL != "" {
					serverProfRef := ConvertStringToProfileRef(
						serverSSL, CustomProfileServer, tlsContext.namespace)
					rsCfg.Virtual.AddOrUpdateProfile(serverProfRef)
				}
				log.Debugf("Updated BIGIP referenced profiles for '%s' '%s'/'%s'",
					tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
			case Secret:
				// Prepare SSL Transient Context
				// Check if TLS Secret already exists
				// Process ClientSSL stored as kubernetes secret
				if clientSSL != "" {
					if secret, ok := ctlr.SSLContext[clientSSL]; ok {
						log.Debugf("clientSSL secret %s for '%s'/'%s' is already available with CIS in "+
							"SSLContext as clientSSL", secret.ObjectMeta.Name, tlsContext.namespace, tlsContext.name)
						err, _ := ctlr.createSecretClientSSLProfile(rsCfg, secret, CustomProfileClient)
						if err != nil {
							log.Debugf("error %v encountered while creating clientssl profile  for '%s' '%s'/'%s' using secret '%s'",
								err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name, secret.ObjectMeta.Name)
							return false
						}
					} else {
						// Check if profile is contained in a Secret
						// Update the SSL Context if secret found, This is used to avoid api calls
						log.Debugf("saving clientSSL secret for '%s' '%s'/'%s' into SSLContext", tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
						secret, err := ctlr.kubeClient.CoreV1().Secrets(tlsContext.namespace).
							Get(context.TODO(), clientSSL, metav1.GetOptions{})
						if err != nil {
							log.Errorf("secret %s not found for '%s' '%s'/'%s'",
								clientSSL, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
						ctlr.SSLContext[clientSSL] = secret
						err, _ = ctlr.createSecretClientSSLProfile(rsCfg, secret, CustomProfileClient)
						if err != nil {
							log.Errorf("error %v encountered while creating clientssl profile for '%s' '%s'/'%s'",
								err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
					}
				}
				// Process ServerSSL stored as kubernetes secret
				if serverSSL != "" {
					if secret, ok := ctlr.SSLContext[serverSSL]; ok {
						log.Debugf("serverSSL secret %s for '%s'/'%s' is already available with CIS in "+
							"SSLContext as serverSSL", secret.ObjectMeta.Name, tlsContext.namespace, tlsContext.name)
						err, _ := ctlr.createSecretServerSSLProfile(rsCfg, secret, CustomProfileServer)
						if err != nil {
							log.Debugf("error %v encountered while creating serverssl profile for '%s' '%s'/'%s' using secret '%s'",
								err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name, secret.ObjectMeta.Name)
							return false
						}
					} else {
						// Check if profile is contained in a Secret
						// Update the SSL Context if secret found, This is used to avoid api calls
						log.Debugf("saving serverSSL secret for '%s' '%s'/'%s' into SSLContext", tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
						secret, err := ctlr.kubeClient.CoreV1().Secrets(tlsContext.namespace).
							Get(context.TODO(), serverSSL, metav1.GetOptions{})
						if err != nil {
							log.Errorf("secret %s not found for '%s' '%s'/'%s'",
								serverSSL, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
						ctlr.SSLContext[serverSSL] = secret
						err, _ = ctlr.createSecretServerSSLProfile(rsCfg, secret, CustomProfileServer)
						if err != nil {
							log.Errorf("error %v encountered while creating serverssl profile for '%s' '%s'/'%s'",
								err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
					}
				}

			case Certificate:
				// Prepare SSL Transient Context
				if tlsContext.bigIPSSLProfiles.key != "" && tlsContext.bigIPSSLProfiles.certificate != "" {
					err, _ := ctlr.createClientSSLProfile(rsCfg, tlsContext.bigIPSSLProfiles.key, tlsContext.bigIPSSLProfiles.certificate, fmt.Sprintf("%s-clientssl", tlsContext.name), tlsContext.namespace, CustomProfileClient)
					if err != nil {
						log.Debugf("error %v encountered while creating clientssl profile  for '%s' '%s'/'%s'",
							err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
						return false
					}
				}
				// Create Server SSL profile for bigip
				if tlsContext.bigIPSSLProfiles.destinationCACertificate != "" {
					var err error
					if tlsContext.bigIPSSLProfiles.caCertificate != "" {
						err, _ = ctlr.createServerSSLProfile(rsCfg, tlsContext.bigIPSSLProfiles.destinationCACertificate, tlsContext.bigIPSSLProfiles.caCertificate, tlsContext.name, tlsContext.namespace, CustomProfileServer)
					} else {
						err, _ = ctlr.createServerSSLProfile(rsCfg, tlsContext.bigIPSSLProfiles.destinationCACertificate, "", fmt.Sprintf("%s-serverssl", tlsContext.name), tlsContext.namespace, CustomProfileServer)
					}
					if err != nil {
						log.Debugf("error %v encountered while creating serverssl profile  for '%s' '%s'/'%s'",
							err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
						return false
					}
				}
			default:
				log.Errorf("Invalid reference type provided for  '%s' '%s'/'%s'",
					tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
				return false
			}
			// TLS Cert/Key
			for _, poolPathRef := range tlsContext.poolPathRefs {
				switch tlsContext.termination {
				case TLSEdge:
					serverSsl := "false"
					sslPath := tlsContext.hostname + poolPathRef.path
					sslPath = strings.TrimSuffix(sslPath, "/")
					updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, EdgeServerSslDgName),
						rsCfg.Virtual.Partition, tlsContext.namespace, sslPath, serverSsl)

				case TLSReencrypt:
					sslPath := tlsContext.hostname + poolPathRef.path
					sslPath = strings.TrimSuffix(sslPath, "/")
					serverSsl := AS3NameFormatter("crd_" + tlsContext.ipAddress + "_tls_client")
					if "" != serverSSL {
						updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, ReencryptServerSslDgName),
							rsCfg.Virtual.Partition, tlsContext.namespace, sslPath, serverSsl)
					}
				}
			}
		}

		//Create datagroups
		switch tlsContext.termination {
		case TLSReencrypt:
			if tlsContext.httpTraffic == TLSAllowInsecure {
				log.Errorf("Error in processing '%s' '%s/%s' as httpTraffic is configured as ALLOW for reencrypt Termination",
					tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
				return false
			}
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				ReencryptHostsDgName,
				tlsContext.hostname,
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
			)
		case TLSEdge:
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				EdgeHostsDgName,
				tlsContext.hostname,
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
			)
		case TLSPassthrough:
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				PassthroughHostsDgName,
				tlsContext.hostname,
				tlsContext.namespace,
				rsCfg.Virtual.Partition)
		}
		ctlr.handleDataGroupIRules(
			rsCfg,
			tlsContext.hostname,
			tlsContext.termination,
		)
		return true
	}
	// httpTraffic defines the behaviour of http Virtual Server on BIG-IP
	// Possible values are allow, none and redirect
	if tlsContext.httpTraffic != "" {
		// -----------------------------------------------------------------
		// httpTraffic = allow -> Allows HTTP
		// httpTraffic = none  -> Only HTTPS
		// httpTraffic = redirect -> redirects HTTP to HTTPS
		// -----------------------------------------------------------------
		switch tlsContext.httpTraffic {
		case TLSRedirectInsecure:
			// set HTTP redirect iRule
			log.Debugf("Applying HTTP redirect iRule.")
			log.Debugf("Redirect HTTP(insecure) requests for VirtualServer %s", tlsContext.name)
			var ruleName string
			if tlsContext.hostname == "" {
				ruleName = fmt.Sprintf("%s_%d", getRSCfgResName(rsCfg.Virtual.Name, HttpRedirectNoHostIRuleName), tlsContext.httpsPort)
				rsCfg.addIRule(ruleName, rsCfg.Virtual.Partition, httpRedirectIRuleNoHost(tlsContext.httpsPort))
			} else {
				ruleName = fmt.Sprintf("%s_%d", getRSCfgResName(rsCfg.Virtual.Name, HttpRedirectIRuleName), tlsContext.httpsPort)
				rsCfg.addIRule(ruleName, rsCfg.Virtual.Partition, httpRedirectIRule(tlsContext.httpsPort, rsCfg.Virtual.Name, rsCfg.Virtual.Partition))
			}
			ruleName = JoinBigipPath(rsCfg.Virtual.Partition, ruleName)
			rsCfg.Virtual.AddIRule(ruleName)
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				HttpsRedirectDgName,
				tlsContext.hostname,
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
			)
		case TLSAllowInsecure:
			// State 3, do not apply any policy
			log.Debugf("Allow HTTP(insecure) requests for '%s' '%s/%s'", tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
		case TLSNoInsecure:
			//if policy := rsCfg.FindPolicy(PolicyControlForward); policy != nil {
			//	rsCfg.RemovePolicy(*policy)
			//}
			log.Debugf("Disable HTTP(insecure) requests for '%s' '%s/%s'", tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
		}
	}
	return true
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
		httpsPort = DEFAULT_HTTPS_PORT
	} else {
		httpsPort = vs.Spec.VirtualServerHTTPSPort
	}
	bigIPSSLProfiles := BigIPSSLProfiles{}
	if tls.Spec.TLS.ClientSSL != "" {
		bigIPSSLProfiles.clientSSL = tls.Spec.TLS.ClientSSL
	}
	if tls.Spec.TLS.ServerSSL != "" {
		bigIPSSLProfiles.serverSSL = tls.Spec.TLS.ServerSSL
	}
	var poolPathRefs []poolPathRef
	for _, pl := range vs.Spec.Pools {

		poolName := framePoolName(
			vs.ObjectMeta.Namespace,
			pl,
			intstr.IntOrString{IntVal: pl.ServicePort},
			vs.Spec.Host,
		)

		poolPathRefs = append(poolPathRefs, poolPathRef{pl.Path, poolName})
	}
	return ctlr.handleTLS(rsCfg, TLSContext{vs.ObjectMeta.Name,
		vs.ObjectMeta.Namespace,
		VirtualServer,
		tls.Spec.TLS.Reference,
		vs.Spec.Host,
		httpsPort,
		ip,
		tls.Spec.TLS.Termination,
		vs.Spec.HTTPTraffic,
		poolPathRefs,
		bigIPSSLProfiles,
	})
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
	profRef := ProfileRef{Context: context, Namespace: ns, BigIPProfile: true}
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

func (rs *ResourceStore) getPartitionResourceMap(partition string) ResourceMap {
	_, ok := rs.ltmConfig[partition]
	if !ok {
		rs.ltmConfig[partition] = make(ResourceMap)
	}

	return rs.ltmConfig[partition]
}

// getResourceConfig gets a specific Resource cfg
func (rs *ResourceStore) getResourceConfig(partition, name string) (*ResourceConfig, error) {

	rsMap, ok := rs.ltmConfig[partition]
	if !ok {
		return nil, fmt.Errorf("partition not available")
	}
	if res, ok := rsMap[name]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("resource not available")
}

func (rs *ResourceStore) setResourceConfig(partition, name string, rsCfg *ResourceConfig) error {
	rsMap, ok := rs.ltmConfig[partition]
	if !ok {
		return fmt.Errorf("partition not available")
	}
	rsMap[name] = rsCfg
	return nil
}

// getLTMConfigCopy is a Resource reference copy of LTMConfig
func (rs *ResourceStore) getLTMConfigCopy() LTMConfig {
	ltmConfig := make(LTMConfig)
	for prtn, rsMap := range rs.ltmConfig {
		ltmConfig[prtn] = make(ResourceMap)
		for rsName, res := range rsMap {
			ltmConfig[prtn][rsName] = res
		}
	}
	return ltmConfig
}

// getLTMConfigDeepCopy is a Resource reference copy of LTMConfig
func (rs *ResourceStore) getLTMConfigDeepCopy() LTMConfig {
	ltmConfig := make(LTMConfig)
	for prtn, rsMap := range rs.ltmConfig {
		ltmConfig[prtn] = make(ResourceMap)
		for rsName, res := range rsMap {
			copyRes := &ResourceConfig{}
			copyRes.copyConfig(res)
			ltmConfig[prtn][rsName] = copyRes
		}
	}
	return ltmConfig
}

// getGTMConfigCopy is a WideIP reference copy of GTMConfig
func (rs *ResourceStore) getGTMConfigCopy() GTMConfig {
	gtmConfig := make(GTMConfig)
	for dominName, wip := range rs.gtmConfig {
		// Everytime new wip object gets created from the scratch
		// so no need to deep copy wip
		gtmConfig[dominName] = wip
		rs.gtmConfigCache[dominName] = wip
	}
	return gtmConfig
}

func (rs *ResourceStore) updateCaches() {
	// No need to deep copy as each RsCfg will be framed in a fresh memory block while creating live ltmConfig
	rs.ltmConfigCache = rs.getLTMConfigCopy()
	rs.gtmConfigCache = rs.getGTMConfigCopy()
}

func (rs *ResourceStore) isConfigUpdated() bool {
	return !reflect.DeepEqual(rs.ltmConfig, rs.ltmConfigCache) ||
		!reflect.DeepEqual(rs.gtmConfig, rs.gtmConfigCache)
}

// Deletes respective VirtualServer resource configuration from  ResourceStore
func (rs *ResourceStore) deleteVirtualServer(partition, rsName string) {
	delete(rs.getPartitionResourceMap(partition), rsName)
}

func (lc LTMConfig) GetAllPoolMembers() []PoolMember {
	// Get all pool members and write them to VxlanMgr to configure ARP entries
	var allPoolMembers []PoolMember

	for _, rsMap := range lc {
		for _, cfg := range rsMap {
			// Filter the configs to only those that have active services
			if cfg.MetaData.Active {
				for _, pool := range cfg.Pools {
					allPoolMembers = append(allPoolMembers, pool.Members...)
				}
			}
		}
	}

	return allPoolMembers
}

// Copies from an existing config into our new config
func (rc *ResourceConfig) copyConfig(cfg *ResourceConfig) {
	// MetaData
	rc.MetaData = cfg.MetaData
	rc.MetaData.baseResources = make(map[string]string)
	for k, v := range cfg.MetaData.baseResources {
		rc.MetaData.baseResources[k] = v
	}
	copy(rc.MetaData.hosts, rc.MetaData.hosts)

	// Virtual
	rc.Virtual = cfg.Virtual
	// Policies ref
	rc.Virtual.Policies = make([]nameRef, len(cfg.Virtual.Policies))
	copy(rc.Virtual.Policies, cfg.Virtual.Policies)
	//IRules
	rc.Virtual.IRules = make([]string, len(cfg.Virtual.IRules))
	copy(rc.Virtual.IRules, cfg.Virtual.IRules)
	//LogProfiles
	rc.Virtual.LogProfiles = make([]string, len(cfg.Virtual.LogProfiles))
	copy(rc.Virtual.LogProfiles, cfg.Virtual.LogProfiles)
	//AllowVLANS
	rc.Virtual.AllowVLANs = make([]string, len(cfg.Virtual.AllowVLANs))
	copy(rc.Virtual.AllowVLANs, cfg.Virtual.AllowVLANs)

	// Pools
	rc.Pools = make(Pools, len(cfg.Pools))
	copy(rc.Pools, cfg.Pools)
	// Pool Members and Monitor Names
	for i := range rc.Pools {
		rc.Pools[i].Members = make([]PoolMember, len(cfg.Pools[i].Members))
		copy(rc.Pools[i].Members, cfg.Pools[i].Members)
		rc.Pools[i].MonitorNames = make([]string, len(cfg.Pools[i].MonitorNames))
		copy(rc.Pools[i].MonitorNames, cfg.Pools[i].MonitorNames)
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

	// Monitors
	rc.Monitors = make([]Monitor, len(cfg.Monitors))
	copy(rc.Monitors, cfg.Monitors)

	// ServiceAddress
	rc.ServiceAddress = make([]ServiceAddress, len(cfg.ServiceAddress))
	copy(rc.ServiceAddress, cfg.ServiceAddress)

	//IRulesMap
	rc.IRulesMap = make(IRulesMap, len(cfg.IRulesMap))
	for ref, irl := range cfg.IRulesMap {
		rc.IRulesMap[ref] = &IRule{
			Name:      irl.Name,
			Partition: irl.Partition,
			Code:      irl.Code,
		}
	}

	//IntDgMap
	rc.IntDgMap = make(InternalDataGroupMap, len(cfg.IntDgMap))
	for nameRef, dgnm := range cfg.IntDgMap {
		rc.IntDgMap[nameRef] = make(DataGroupNamespaceMap, len(dgnm))
		for ns, idg := range dgnm {
			rc.IntDgMap[nameRef][ns] = &InternalDataGroup{
				Name:      idg.Name,
				Partition: idg.Partition,
				Records:   make(InternalDataGroupRecords, len(idg.Records)),
			}
			copy(rc.IntDgMap[nameRef][ns].Records, idg.Records)
		}
	}

	// customProfiles
	rc.customProfiles = make(map[SecretKey]CustomProfile, len(cfg.customProfiles))
	for secKey, cusProf := range cfg.customProfiles {
		rc.customProfiles[secKey] = cusProf
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

// Internal data group for reencrypt termination.
const ReencryptHostsDgName = "ssl_reencrypt_servername_dg"

// Internal data group for edge termination.
const EdgeHostsDgName = "ssl_edge_servername_dg"

// Internal data group for passthrough termination.
const PassthroughHostsDgName = "ssl_passthrough_servername_dg"

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
		".":  "_",
		":":  "_",
		"/":  "_",
		"%":  ".",
		"-":  "_",
		"[":  "",
		"]":  "",
		"=":  "_",
		"*_": ""}
	SpecialChars := [9]string{".", ":", "/", "%", "-", "[", "]", "=", "*_"}
	for _, key := range SpecialChars {
		name = strings.ReplaceAll(name, key, modifySpecialChars[key])
	}
	return name
}

func (ctlr *Controller) handleDataGroupIRules(
	rsCfg *ResourceConfig,
	vsHost string,
	tlsTerminationType string,
) {
	// For https
	if "" != tlsTerminationType {
		tlsIRuleName := JoinBigipPath(rsCfg.Virtual.Partition,
			getRSCfgResName(rsCfg.Virtual.Name, TLSIRuleName))
		rsCfg.addIRule(
			getRSCfgResName(rsCfg.Virtual.Name, TLSIRuleName), rsCfg.Virtual.Partition, ctlr.getTLSIRule(rsCfg.Virtual.Name, rsCfg.Virtual.Partition))
		switch tlsTerminationType {
		case TLSEdge:
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, EdgeHostsDgName), rsCfg.Virtual.Partition)
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, EdgeServerSslDgName), rsCfg.Virtual.Partition)
		case TLSPassthrough:
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, PassthroughHostsDgName), rsCfg.Virtual.Partition)
		case TLSReencrypt:
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, ReencryptHostsDgName), rsCfg.Virtual.Partition)
			rsCfg.addInternalDataGroup(getRSCfgResName(rsCfg.Virtual.Name, ReencryptServerSslDgName), rsCfg.Virtual.Partition)
		}
		if vsHost != "" {
			rsCfg.Virtual.AddIRule(tlsIRuleName)
		}
	}
}

func (ctlr *Controller) deleteVirtualServer(partition, rsName string) {
	ctlr.resources.deleteVirtualServer(partition, rsName)
}

func (ctlr *Controller) getVirtualServer(partition, rsName string) *ResourceConfig {
	res, _ := ctlr.resources.getResourceConfig(partition, rsName)
	return res
}

// Prepares resource config based on VirtualServer resource config
func (ctlr *Controller) prepareRSConfigFromTransportServer(
	rsCfg *ResourceConfig,
	vs *cisapiv1.TransportServer,
) error {
	targetPort := ctlr.fetchTargetPort(vs.Namespace, vs.Spec.Pool.Service, vs.Spec.Pool.ServicePort)
	if (intstr.IntOrString{}) == targetPort {
		targetPort = intstr.IntOrString{IntVal: vs.Spec.Pool.ServicePort}
	}
	poolName := framePoolName(
		vs.ObjectMeta.Namespace,
		vs.Spec.Pool,
		targetPort,
		"",
	)
	monitorName := poolName + "-monitor"

	pool := Pool{
		Name:             poolName,
		Partition:        rsCfg.Virtual.Partition,
		ServiceName:      vs.Spec.Pool.Service,
		ServiceNamespace: vs.ObjectMeta.Namespace,
		ServicePort:      targetPort,
		NodeMemberLabel:  vs.Spec.Pool.NodeMemberLabel,
		Balance:          vs.Spec.Pool.Balance,
	}

	if vs.Spec.Pool.Monitor.Type != "" {
		if vs.Spec.Pool.Name == "" {
			monitorName = formatMonitorName(vs.ObjectMeta.Namespace, vs.Spec.Pool.Service, vs.Spec.Pool.Monitor.Type, vs.Spec.Pool.ServicePort, "")
		}
		pool.MonitorNames = append(pool.MonitorNames, JoinBigipPath(rsCfg.Virtual.Partition, monitorName))

		monitor := Monitor{
			Name:       monitorName,
			Partition:  rsCfg.Virtual.Partition,
			Type:       vs.Spec.Pool.Monitor.Type,
			Interval:   vs.Spec.Pool.Monitor.Interval,
			Send:       "",
			Recv:       "",
			Timeout:    vs.Spec.Pool.Monitor.Timeout,
			TargetPort: vs.Spec.Pool.Monitor.TargetPort,
		}
		rsCfg.Monitors = append(rsCfg.Monitors, monitor)
	}

	rsCfg.Virtual.Mode = vs.Spec.Mode
	rsCfg.Virtual.IpProtocol = vs.Spec.Type
	rsCfg.Virtual.PoolName = pool.Name
	rsCfg.Pools = append(rsCfg.Pools, pool)

	if vs.Spec.ProfileL4 != "" {
		rsCfg.Virtual.ProfileL4 = vs.Spec.ProfileL4
	}
	// Replace SNAT set from policy CR to the one defined by user in the TS spec
	if vs.Spec.SNAT == "" {
		if rsCfg.Virtual.SNAT == "" {
			rsCfg.Virtual.SNAT = DEFAULT_SNAT
		}
	} else {
		rsCfg.Virtual.SNAT = vs.Spec.SNAT
	}

	if vs.Spec.DOS != "" {
		rsCfg.Virtual.ProfileDOS = vs.Spec.DOS
	}

	if vs.Spec.BotDefense != "" {
		rsCfg.Virtual.ProfileBotDefense = vs.Spec.BotDefense
	}

	if len(vs.Spec.Profiles.TCP.Client) > 0 || len(vs.Spec.Profiles.TCP.Server) > 0 {
		rsCfg.Virtual.TCP.Client = vs.Spec.Profiles.TCP.Client
		rsCfg.Virtual.TCP.Server = vs.Spec.Profiles.TCP.Server
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
	poolName := formatPoolName(
		svc.Namespace,
		svc.Name,
		svcPort.TargetPort,
		"", "")
	pool := Pool{
		Name:             poolName,
		Partition:        rsCfg.Virtual.Partition,
		ServiceName:      svc.Name,
		ServiceNamespace: svc.Namespace,
		ServicePort:      svcPort.TargetPort,
		NodeMemberLabel:  "",
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
		pool.MonitorNames = append(pool.MonitorNames, JoinBigipPath(rsCfg.Virtual.Partition,
			formatMonitorName(svc.Namespace, svc.Name, monitorType, svcPort.TargetPort.IntVal, "")))
		monitor = Monitor{
			Name:      formatMonitorName(svc.Namespace, svc.Name, monitorType, svcPort.TargetPort.IntVal, ""),
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
	rsCfg.Virtual.Mode = "standard"
	// Use default SNAT if not provided by user
	if rsCfg.Virtual.SNAT == "" {
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
	}

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
	rsCfg.Virtual.ProfileMultiplex = plc.Spec.Profiles.ProfileMultiplex
	rsCfg.Virtual.ProfileDOS = plc.Spec.L3Policies.DOS
	rsCfg.Virtual.ProfileBotDefense = plc.Spec.L3Policies.BotDefense
	rsCfg.Virtual.TCP.Client = plc.Spec.Profiles.TCP.Client
	rsCfg.Virtual.TCP.Server = plc.Spec.Profiles.TCP.Server
	rsCfg.Virtual.AllowSourceRange = plc.Spec.L3Policies.AllowSourceRange

	if len(plc.Spec.Profiles.LogProfiles) > 0 {
		rsCfg.Virtual.LogProfiles = append(rsCfg.Virtual.LogProfiles, plc.Spec.Profiles.LogProfiles...)
	}
	var iRule string
	// Profiles common for both HTTP and HTTPS
	// service_HTTP supports profileTCP and profileHTTP
	// service_HTTPS supports profileTCP, profileHTTP and profileHTTP2
	if len(plc.Spec.Profiles.HTTP) > 0 {
		rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
			Name:         plc.Spec.Profiles.HTTP,
			Context:      "http",
			BigIPProfile: true,
		})
	}

	switch rsCfg.MetaData.Protocol {
	case "https":
		iRule = plc.Spec.IRules.Secure
		if len(plc.Spec.Profiles.HTTP2) > 0 {
			rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
				Name:         plc.Spec.Profiles.HTTP2,
				Context:      "http2",
				BigIPProfile: true,
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
	// set snat as specified by user in the policy
	snat := plc.Spec.SNAT
	if snat != "" {
		rsCfg.Virtual.SNAT = snat
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
	rsCfg.Virtual.ProfileL4 = plc.Spec.Profiles.ProfileL4
	rsCfg.Virtual.ProfileDOS = plc.Spec.L3Policies.DOS
	rsCfg.Virtual.ProfileBotDefense = plc.Spec.L3Policies.BotDefense
	rsCfg.Virtual.TCP.Client = plc.Spec.Profiles.TCP.Client
	rsCfg.Virtual.TCP.Server = plc.Spec.Profiles.TCP.Server

	if len(plc.Spec.Profiles.LogProfiles) > 0 {
		rsCfg.Virtual.LogProfiles = append(rsCfg.Virtual.LogProfiles, plc.Spec.Profiles.LogProfiles...)
	}
	if len(plc.Spec.Profiles.UDP) > 0 {
		rsCfg.Virtual.Profiles = append(rsCfg.Virtual.Profiles, ProfileRef{
			Name:         plc.Spec.Profiles.UDP,
			Context:      "udp",
			BigIPProfile: true,
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
	// set snat as specified by user or else use auto as default
	snat := plc.Spec.SNAT
	if snat != "" {
		rsCfg.Virtual.SNAT = snat
	} else {
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
	}
	return nil
}

func getRSCfgResName(rsVSName, resName string) string {
	return fmt.Sprintf("%s_%s", rsVSName, resName)
}

func (rs *ResourceStore) getExtendedRouteSpec(routeGroup string) (*ExtendedRouteGroupSpec, string) {
	extdSpec, ok := rs.extdSpecMap[routeGroup]

	if !ok {
		return nil, ""
	}

	if extdSpec.override && extdSpec.local != nil {
		ergc := &ExtendedRouteGroupSpec{
			VServerName:   extdSpec.global.VServerName,
			VServerAddr:   extdSpec.global.VServerAddr,
			AllowOverride: extdSpec.global.AllowOverride,
			SNAT:          extdSpec.global.SNAT,
			WAF:           extdSpec.global.WAF,
		}

		if extdSpec.local.VServerName != "" {
			ergc.VServerName = extdSpec.local.VServerName
		}
		if extdSpec.local.VServerAddr != "" {
			ergc.VServerAddr = extdSpec.local.VServerAddr
		}
		if extdSpec.local.SNAT != "" {
			ergc.SNAT = extdSpec.local.SNAT
		}
		if extdSpec.local.WAF != "" {
			ergc.WAF = extdSpec.local.WAF
		}

		if extdSpec.local.IRules != nil {
			ergc.IRules = make([]string, len(extdSpec.local.IRules))
			copy(ergc.IRules, extdSpec.local.IRules)
		} else if extdSpec.global.IRules != nil {
			ergc.IRules = make([]string, len(extdSpec.global.IRules))
			copy(ergc.IRules, extdSpec.global.IRules)
		}

		if extdSpec.local.HealthMonitors != nil {
			ergc.HealthMonitors = make(Monitors, len(extdSpec.local.HealthMonitors))
			copy(ergc.HealthMonitors, extdSpec.local.HealthMonitors)
		} else if extdSpec.global.HealthMonitors != nil {
			ergc.HealthMonitors = make(Monitors, len(extdSpec.global.HealthMonitors))
			copy(ergc.HealthMonitors, extdSpec.global.HealthMonitors)
		}
		return ergc, extdSpec.partition
	}

	return extdSpec.global, extdSpec.partition
}

// handleRouteTLS handles TLS configuration for the Route resource
// Return value is whether or not a custom profile was updated
func (ctlr *Controller) handleRouteTLS(
	rsCfg *ResourceConfig,
	route *routeapi.Route,
	vServerAddr string,
	servicePort intstr.IntOrString) bool {

	if route.Spec.TLS == nil {
		// Probably this is a non-tls route, nothing to do w.r.t TLS
		return false
	}

	bigIPSSLProfiles := BigIPSSLProfiles{}

	if route.Spec.TLS.Key != "" {
		bigIPSSLProfiles.key = route.Spec.TLS.Key
	}
	if route.Spec.TLS.Certificate != "" {
		bigIPSSLProfiles.certificate = route.Spec.TLS.Certificate
	}
	if route.Spec.TLS.CACertificate != "" {
		bigIPSSLProfiles.caCertificate = route.Spec.TLS.CACertificate
	}
	if route.Spec.TLS.DestinationCACertificate != "" {
		bigIPSSLProfiles.destinationCACertificate = route.Spec.TLS.DestinationCACertificate
	}
	var poolPathRefs []poolPathRef

	for _, pl := range rsCfg.Pools {
		if pl.Name == formatPoolName(
			route.Namespace,
			route.Spec.To.Name,
			servicePort,
			"",
			"",
		) {
			poolPathRefs = append(
				poolPathRefs,
				poolPathRef{
					route.Spec.Path,
					formatPoolName(
						route.ObjectMeta.Namespace,
						route.Spec.To.Name,
						pl.ServicePort,
						"",
						""),
				})
		}
	}

	return ctlr.handleTLS(rsCfg, TLSContext{route.ObjectMeta.Name,
		route.ObjectMeta.Namespace,
		Route,
		Certificate,
		route.Spec.Host,
		DEFAULT_HTTPS_PORT,
		vServerAddr,
		string(route.Spec.TLS.Termination),
		strings.ToLower(string(route.Spec.TLS.InsecureEdgeTerminationPolicy)),
		poolPathRefs,
		bigIPSSLProfiles,
	})
}
