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
	"encoding/json"
	"fmt"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"

	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	routeapi "github.com/openshift/api/route/v1"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

// NewResourceStore is Constructor for ResourceStore
func NewResourceStore() *ResourceStore {
	var rs ResourceStore
	rs.Init()
	return &rs
}

func newMultiClusterResourceStore() *MultiClusterResourceStore {
	var rs MultiClusterResourceStore
	rs.rscSvcMap = make(map[resourceRef]map[MultiClusterServiceKey]MultiClusterServiceConfig)
	rs.clusterSvcMap = make(map[string]map[MultiClusterServiceKey]map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})
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
	rs.ipamContext = make(map[string]ficV1.IPSpec)
	rs.processedNativeResources = make(map[resourceRef]struct{})
	rs.externalClustersConfig = make(map[string]ExternalClusterConfig)
}

const (
	DEFAULT_MODE              string = "tcp"
	DEFAULT_BALANCE           string = "round-robin"
	DEFAULT_HTTP_PORT         int32  = 80
	DEFAULT_HTTPS_PORT        int32  = 443
	DEFAULT_SNAT              string = "auto"
	urlRewriteRulePrefix             = "url-rewrite-rule-"
	appRootForwardRulePrefix         = "app-root-forward-rule-"
	appRootRedirectRulePrefix        = "app-root-redirect-rule-"

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
	ABPathIRuleName     = "ab_deployment_path_irule"
)

// constants for TLS references
const (
	// reference for profiles stored in BIG-IP
	BIGIP = "bigip"
	// reference for profiles stores as secrets in k8s cluster
	Secret = "secret"
	// refrence for profiles stored a mix of secret and bigip
	Hybrid = "hybrid"
	// reference for routes
	Certificate = "certificate"
	// reference for service“
	ServiceRef = "service"
)

// constants for SSL options
const (
	PolicySSLOption           = "policySSL"
	AnnotationSSLOption       = "annotation"
	RouteCertificateSSLOption = "routeCertificate"
	DefaultSSLOption          = "defaultSSL"
	InvalidSSLOption          = "invalid"
)

func NewCustomProfile(
	profile ProfileRef,
	certificates []certificate,
	serverName string,
	sni bool,
	peerCertMode,
	caFile string,
	chainCA string,
	tlsCipher TLSCipher,
	renegotiation *bool,
) CustomProfile {
	cp := CustomProfile{
		Name:         profile.Name,
		Partition:    profile.Partition,
		Context:      profile.Context,
		Certificates: certificates,
		ServerName:   serverName,
		SNIDefault:   sni,
		PeerCertMode: peerCertMode,
		ChainCA:      chainCA,
	}
	if renegotiation != nil {
		cp.RenegotiationEnabled = renegotiation
	}
	if peerCertMode == PeerCertRequired {
		cp.CAFile = caFile
	}

	if tlsCipher.TLSVersion == string(TLSVerion1_3) {
		cp.CipherGroup = tlsCipher.CipherGroup
	} else {
		cp.Ciphers = tlsCipher.Ciphers
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
		// Skip adding iRule for "none" value
		if irule == ruleName || irule == "none" {
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

func (ctlr *Controller) framePoolNameForTS(ns string, pool cisapiv1.TSPool, host string) string {
	poolName := pool.Name
	if poolName == "" {
		targetPort := pool.ServicePort

		if (intstr.IntOrString{}) == targetPort {
			svcNamespace := ns
			if pool.ServiceNamespace != "" {
				svcNamespace = pool.ServiceNamespace
			}
			targetPort = ctlr.fetchTargetPort(svcNamespace, pool.Service, pool.ServicePort, "")
		}
		poolName = ctlr.formatPoolName(ns, pool.Service, targetPort, pool.NodeMemberLabel, host, "")
	}
	return poolName
}

func (ctlr *Controller) framePoolNameForDefaultPool(ns string, pool cisapiv1.DefaultPool, host string) string {
	poolName := pool.Name
	if poolName == "" {
		targetPort := pool.ServicePort
		if (intstr.IntOrString{}) == targetPort {
			svcNamespace := ns
			if pool.ServiceNamespace != "" {
				svcNamespace = pool.ServiceNamespace
			}
			targetPort = ctlr.fetchTargetPort(svcNamespace, pool.Service, pool.ServicePort, "")
		}
		poolName = ctlr.formatPoolName(ns, pool.Service, targetPort, pool.NodeMemberLabel, host, "")
	}
	return poolName
}

func (ctlr *Controller) framePoolNameForVS(ns string, pool cisapiv1.VSPool, host string, cxt SvcBackendCxt) string {
	poolName := pool.Name
	if poolName == "" || pool.AlternateBackends != nil {
		targetPort := pool.ServicePort
		svcNamespace := ns
		if cxt.SvcNamespace != "" {
			svcNamespace = cxt.SvcNamespace
		}
		if (intstr.IntOrString{}) == targetPort {
			targetPort = ctlr.fetchTargetPort(svcNamespace, cxt.Name, pool.ServicePort, cxt.Cluster)
		}
		poolName = ctlr.formatPoolName(svcNamespace, cxt.Name, targetPort, pool.NodeMemberLabel, host, cxt.Cluster)
	}
	return poolName
}

// format the pool name for an VirtualServer
func (ctlr *Controller) formatPoolName(namespace, svc string, port intstr.IntOrString, nodeMemberLabel string, host, cluster string) string {
	servicePort := fetchPortString(port)
	poolName := fmt.Sprintf("%s_%s_%s", svc, servicePort, namespace)
	if len(host) > 0 {
		poolName = fmt.Sprintf("%s_%s", poolName, host)

	}
	if nodeMemberLabel != "" {
		nodeMemberLabel = strings.ReplaceAll(nodeMemberLabel, "=", "_")
		poolName = fmt.Sprintf("%s_%s", poolName, nodeMemberLabel)
	}

	// Attach cluster name to pool name only in case of multi-cluster ratio mode
	if ctlr.multiClusterMode != "" && ctlr.haModeType == Ratio {
		if cluster == "" {
			cluster = ctlr.multiClusterConfigs.LocalClusterName
		}
		if cluster != "" {
			poolName = fmt.Sprintf("%s_%s", poolName, cluster)
		}
	}

	return AS3NameFormatter(poolName)
}

// format the monitor name for an VirtualServer pool
func formatMonitorName(namespace, svc string, monitorType string, port intstr.IntOrString, hostName string, path string) string {
	monitorName := fmt.Sprintf("%s_%s", svc, namespace)

	if len(hostName) > 0 {
		monitorName = monitorName + fmt.Sprintf("_%s", hostName)
	}
	if len(path) > 0 && path != "/" {
		if path[0] == '/' {
			monitorName = monitorName + fmt.Sprintf("%s", path)
		} else {
			monitorName = monitorName + fmt.Sprintf("_%s", path)
		}
	}

	if monitorType != "" && (port.IntVal != 0 || port.StrVal != "") {
		servicePort := fetchPortString(port)
		monitorName = monitorName + fmt.Sprintf("_%s_%s", monitorType, servicePort)
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

// fetch target port from service
func (ctlr *Controller) fetchTargetPort(namespace, svcName string, servicePort intstr.IntOrString, cluster string) intstr.IntOrString {
	var targetPort intstr.IntOrString
	var svcIndexer cache.Indexer
	var svc *v1.Service
	svcKey := namespace + "/" + svcName
	if cluster == "" {
		if ctlr.watchingAllNamespaces() {
			svcIndexer = ctlr.comInformers[""].svcInformer.GetIndexer()
		} else {
			if informer, ok := ctlr.comInformers[namespace]; ok {
				svcIndexer = informer.svcInformer.GetIndexer()
			} else {
				return targetPort
			}
		}
		item, found, _ := svcIndexer.GetByKey(svcKey)
		if !found {
			log.Debugf("service '%v' not found", svcKey)

			var err error
			item, found, err = ctlr.getSvcFromHACluster(namespace, svcName)
			if !found {
				if err != nil {
					log.Debugf("[MultiCluster] could not fetch service %v ", err)
				}
				return targetPort
			}
		}
		svc = item.(*v1.Service)
	} else {
		if _, ok := ctlr.multiClusterPoolInformers[cluster]; ok {
			var poolInf *MultiClusterPoolInformer
			var found bool
			if poolInf, found = ctlr.multiClusterPoolInformers[cluster][""]; !found {
				poolInf, found = ctlr.multiClusterPoolInformers[cluster][namespace]
			}
			if !found {
				// If informers not found for the namespace, return empty targetPort
				log.Warningf("[MultiCluster] Informer not found for namespace: %v in cluster: %s", namespace, cluster)
				return targetPort
			}

			if poolInf.svcInformer != nil {
				item, mFound, _ := poolInf.svcInformer.GetIndexer().GetByKey(svcKey)
				if !mFound {
					log.Warningf("[MultiCluster] service '%v' %s not found", svcKey, getClusterLog(cluster))
					return targetPort
				}
				svc = item.(*v1.Service)
			} else {
				// If service informer not found return empty targetPort
				return targetPort
			}
		} else {
			// If informers not found for the cluster, return empty targetPort
			return targetPort
		}
	}
	for _, port := range svc.Spec.Ports {
		if servicePort.StrVal == "" {
			if port.Port == servicePort.IntVal {
				// In case of named targetPort, send service port name to match endpoint name as targetPort
				if port.TargetPort.StrVal != "" {
					// port name is required when using the named targetPort
					if port.Name != "" {
						return intstr.IntOrString{StrVal: port.Name}
					} else {
						log.Errorf("port name should be defined with the named targetPort for service %v", svcKey)
						return targetPort
					}
				}
				return port.TargetPort
			}
		} else {
			if port.Name == servicePort.StrVal {
				// In case of named targetPort, send service port name to match endpoint name as targetPort
				if port.TargetPort.StrVal != "" {
					// port name is required when using the named targetPort
					return intstr.IntOrString{StrVal: port.Name}
				}
				return port.TargetPort
			}
		}
	}
	return targetPort
}

// Prepares resource config based on VirtualServer resource config
func (ctlr *Controller) prepareRSConfigFromVirtualServer(
	rsCfg *ResourceConfig,
	vs *cisapiv1.VirtualServer,
	passthroughVS bool,
	tlsTermination string,
) error {

	var httpsPort int32
	var httpPort int32
	if vs.Spec.VirtualServerHTTPSPort == 0 {
		httpsPort = DEFAULT_HTTPS_PORT
	} else {
		httpsPort = vs.Spec.VirtualServerHTTPSPort
	}
	if vs.Spec.VirtualServerHTTPPort == 0 {
		httpPort = DEFAULT_HTTP_PORT
	} else {
		httpPort = vs.Spec.VirtualServerHTTPPort
	}
	var snat string
	snat = DEFAULT_SNAT
	var pools Pools
	var rules *Rules

	rsRef := resourceRef{
		name:      vs.Name,
		namespace: vs.Namespace,
		kind:      VirtualServer,
	}
	framedPools := make(map[string]struct{})
	for _, pl := range vs.Spec.Pools {
		//Fetch service backends with weights for pool
		backendSvcs := ctlr.GetPoolBackends(&pl)
		for _, SvcBackend := range backendSvcs {
			poolName := ctlr.framePoolNameForVS(vs.Namespace, pl, vs.Spec.Host, SvcBackend)
			if _, ok := framedPools[poolName]; ok {
				// Pool with same name framed earlier, so skipping this pool
				log.Debugf("Duplicate pool name: %v in Virtual Server: %v/%v", poolName, vs.Namespace, vs.Name)
				continue
			}
			framedPools[poolName] = struct{}{}
			svcNamespace := vs.Namespace
			if SvcBackend.SvcNamespace != "" {
				svcNamespace = SvcBackend.SvcNamespace
			}
			targetPort := ctlr.fetchTargetPort(svcNamespace, SvcBackend.Name, pl.ServicePort, SvcBackend.Cluster)
			if (intstr.IntOrString{}) == targetPort {
				targetPort = pl.ServicePort
			}
			pool := Pool{
				Name:              poolName,
				Partition:         rsCfg.Virtual.Partition,
				ServiceName:       SvcBackend.Name,
				ServiceNamespace:  svcNamespace,
				ServicePort:       targetPort,
				NodeMemberLabel:   pl.NodeMemberLabel,
				Balance:           pl.Balance,
				MinimumMonitors:   pl.MinimumMonitors,
				ReselectTries:     pl.ReselectTries,
				ServiceDownAction: pl.ServiceDownAction,
				Cluster:           SvcBackend.Cluster, // In all modes other than ratio, the cluster is ""
			}

			if ctlr.multiClusterMode != "" {
				//check for external service reference
				if len(pl.MultiClusterServices) > 0 {
					if _, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; !ok {
						// only process if vs key is not present. else skip the processing
						// on vs update we are clearing the resource service
						// if event comes from vs then we will read and populate data, else we will skip processing
						ctlr.processResourceExternalClusterServices(rsRef, pl.MultiClusterServices)
					} else {
						// prepare one of extended services key from pool
						// to check if pool is processed before and svckey exists in rscSvcMap
						// If not external cluster services for this pool will be added to rscSvcMap
						externalSvcKey := MultiClusterServiceKey{
							clusterName: pl.MultiClusterServices[0].ClusterName,
							serviceName: pl.MultiClusterServices[0].SvcName,
							namespace:   pl.MultiClusterServices[0].Namespace,
						}
						// for multiple pools scenario vs resource reference exists after first pool is processed
						// we still need to process if svckey doesnt exist in multicluster cluster rsMap
						if _, ok := ctlr.multiClusterResources.rscSvcMap[rsRef][externalSvcKey]; !ok {
							ctlr.processResourceExternalClusterServices(rsRef, pl.MultiClusterServices)
						}
					}
				}
				if ctlr.haModeType != Ratio {
					if svcs, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; ok {
						for svc, config := range svcs {
							// update the clusterSvcMap
							ctlr.updatePoolIdentifierForService(svc, rsRef, config.svcPort, pool.Name, pool.Partition, rsCfg.Virtual.Name, pl.Path)
						}
					}
					pool.MultiClusterServices = pl.MultiClusterServices
					// update the multicluster resource serviceMap with local cluster services
					ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, pl.Service, pl.Path, pool, pl.ServicePort, "")
					// update the multicluster resource serviceMap with HA pair cluster services
					if ctlr.haModeType == Active && ctlr.multiClusterConfigs.HAPairClusterName != "" {
						ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, pl.Service, pl.Path, pool, pl.ServicePort,
							ctlr.multiClusterConfigs.HAPairClusterName)
					}
				} else {
					// Update the multiCluster resource service map for each pool which constitutes a service in case of ratio mode
					ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, SvcBackend.Name, pl.Path, pool, pl.ServicePort, SvcBackend.Cluster)
				}
			} else {
				ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, pl.Service, pl.Path, pool, pl.ServicePort, "")
			}
			// Update the pool Members
			ctlr.updatePoolMembersForResources(&pool)
			if len(pool.Members) > 0 {
				rsCfg.MetaData.Active = true
			}

			if !reflect.DeepEqual(pl.Monitor, cisapiv1.Monitor{}) {
				ctlr.createVirtualServerMonitor(pl.Monitor, &pool, rsCfg, pl.ServicePort, vs.Spec.Host, pl.Path,
					vs.ObjectMeta.Namespace+"/"+vs.ObjectMeta.Name, SvcBackend.Cluster)
			} else if pl.Monitors != nil {
				var formatPort intstr.IntOrString
				for _, monitor := range pl.Monitors {
					if monitor.TargetPort != 0 {
						formatPort = intstr.IntOrString{IntVal: monitor.TargetPort}
					} else {
						formatPort = pl.ServicePort
					}
					ctlr.createVirtualServerMonitor(monitor, &pool, rsCfg, formatPort, vs.Spec.Host, pl.Path,
						vs.ObjectMeta.Namespace+"/"+vs.ObjectMeta.Name, SvcBackend.Cluster)
				}
			}
			pools = append(pools, pool)
			if tlsTermination != "" {
				//Handle AB datagroup for secure virtualserver
				if rsCfg.Virtual.VirtualAddress.Port == httpsPort || (rsCfg.Virtual.VirtualAddress.Port == httpPort && strings.ToLower(vs.Spec.HTTPTraffic) == TLSAllowInsecure) {
					ctlr.updateDataGroupForABVirtualServer(&pl,
						getRSCfgResName(rsCfg.Virtual.Name, AbDeploymentDgName),
						rsCfg.Virtual.Partition,
						vs.Namespace,
						rsCfg.IntDgMap,
						pl.ServicePort,
						vs.Spec.Host,
						vs.Spec.HostAliases,
						tlsTermination,
					)
					//path based AB deployment/Cluster ratio not supported for passthrough
					if (isVsPathBasedABDeployment(&pl) || isVsPathBasedRatioDeployment(&pl, ctlr.haModeType)) &&
						(tlsTermination == TLSEdge ||
							(tlsTermination == TLSReencrypt && strings.ToLower(vs.Spec.HTTPTraffic) != TLSAllowInsecure)) {
						ctlr.HandlePathBasedABIRule(rsCfg, vs.Spec.Host, tlsTermination)
					}
					// handle AB traffic for edge termination with allow
					if (isVSABDeployment(&pl) || ctlr.haModeType == Ratio) && rsCfg.Virtual.VirtualAddress.Port == httpPort && strings.ToLower(vs.Spec.HTTPTraffic) == TLSAllowInsecure {
						ctlr.HandlePathBasedABIRule(rsCfg, vs.Spec.Host, tlsTermination)
					}
				}
			} else {
				if isVSABDeployment(&pl) || ctlr.haModeType == Ratio {
					// Handle AB datagroup for insecure virtualserver
					ctlr.updateDataGroupForABVirtualServer(&pl,
						getRSCfgResName(rsCfg.Virtual.Name, AbDeploymentDgName),
						rsCfg.Virtual.Partition,
						vs.Namespace,
						rsCfg.IntDgMap,
						pl.ServicePort,
						vs.Spec.Host,
						vs.Spec.HostAliases,
						tlsTermination,
					)
					// Handle AB path based IRules for insecure virtualserver
					ctlr.HandlePathBasedABIRule(rsCfg, vs.Spec.Host, tlsTermination)
				}
			}
		}
	}

	rsCfg.Pools = append(rsCfg.Pools, pools...)

	// handle the default pool for virtual
	ctlr.handleDefaultPool(rsCfg, vs, rsRef)

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

	// set the ConnectionMirroring
	if vs.Spec.ConnectionMirroring != "" {
		rsCfg.Virtual.ConnectionMirroring = vs.Spec.ConnectionMirroring
	}
	//Attach allowVlans.
	if len(vs.Spec.AllowVLANs) > 0 {
		rsCfg.Virtual.AllowVLANs = vs.Spec.AllowVLANs
	}
	if vs.Spec.PersistenceProfile != "" {
		rsCfg.Virtual.PersistenceProfile = vs.Spec.PersistenceProfile
	}

	if vs.Spec.HTMLProfile != "" {
		rsCfg.Virtual.HTMLProfile = vs.Spec.HTMLProfile
	}

	if len(vs.Spec.Profiles.TCP.Client) > 0 || len(vs.Spec.Profiles.TCP.Server) > 0 {
		rsCfg.Virtual.TCP.Client = vs.Spec.Profiles.TCP.Client
		rsCfg.Virtual.TCP.Server = vs.Spec.Profiles.TCP.Server
	}

	if len(vs.Spec.Profiles.HTTP2.Client) > 0 || len(vs.Spec.Profiles.HTTP2.Server) > 0 {
		rsCfg.Virtual.HTTP2.Client = vs.Spec.Profiles.HTTP2.Client
		rsCfg.Virtual.HTTP2.Server = vs.Spec.Profiles.HTTP2.Server
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
	// check if custom http port set on virtual
	if vs.Spec.VirtualServerHTTPPort != 0 {
		httpPort = vs.Spec.VirtualServerHTTPPort
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
		if *rules != nil || len(*rules) != 0 {
			policyName := formatPolicyName(vs.Spec.Host, vs.Spec.HostGroup, rsCfg.Virtual.Name)

			rsCfg.AddRuleToPolicy(policyName, vs.Namespace, rules)
		}
	}

	// Attach user specified iRules
	if len(vs.Spec.IRules) > 0 {
		rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, vs.Spec.IRules...)
	}

	// Append all the hosts from a host group/ single host
	hosts := getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)
	if vs.Spec.Host != "" {
		rsCfg.MetaData.hosts = append(rsCfg.MetaData.hosts, hosts...)
	}
	return nil
}

func (ctlr *Controller) createVirtualServerMonitor(monitor cisapiv1.Monitor, pool *Pool, rsCfg *ResourceConfig,
	formatPort intstr.IntOrString, host, path, vsName string, cluster string) {
	if !reflect.DeepEqual(monitor, Monitor{}) {
		if monitor.Reference == BIGIP {
			if monitor.Name != "" {
				pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitor.Name, Reference: monitor.Reference})
			} else {
				log.Errorf("missing monitor name with bigip reference in virtual server: %v", vsName)
				return
			}
		} else {
			if (monitor.Type == HTTPS || monitor.Type == HTTP) && monitor.Send == "" {
				log.Errorf("missing send string for monitor. skipping monitor for virtual server: %v", vsName)
				return
			}

			monitorName := monitor.Name
			if monitorName == "" {
				monitorName = formatMonitorName(pool.ServiceNamespace, pool.ServiceName, monitor.Type, formatPort, host,
					path)
			}

			// Format the monitor name in case of multi cluster ratio mode
			monitorName = ctlr.formatMonitorNameForMultiCluster(monitorName, cluster)

			pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: JoinBigipPath(rsCfg.Virtual.Partition, monitorName)})
			monitor := Monitor{
				Name:       monitorName,
				Partition:  rsCfg.Virtual.Partition,
				Type:       monitor.Type,
				Interval:   monitor.Interval,
				Send:       monitor.Send,
				Recv:       monitor.Recv,
				Timeout:    monitor.Timeout,
				TargetPort: monitor.TargetPort,
				SSLProfile: monitor.SSLProfile,
			}
			rsCfg.Monitors = append(rsCfg.Monitors, monitor)
		}
	}
}

func (ctlr *Controller) createTransportServerMonitor(monitor cisapiv1.Monitor, pool *Pool, rsCfg *ResourceConfig,
	formatPort intstr.IntOrString, vsNamespace, vsName string) {
	if !reflect.DeepEqual(monitor, Monitor{}) {
		if monitor.Reference == BIGIP {
			if monitor.Name != "" {
				pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: monitor.Name, Reference: monitor.Reference})
			} else {
				log.Errorf("missing monitor name with bigip reference in transport server: %v", vsNamespace+"/"+vsName)
				return
			}
		} else {
			monitorName := monitor.Name
			if monitorName == "" {
				monitorName = formatMonitorName(vsNamespace, pool.ServiceName, monitor.Type, formatPort, "", "")
			}

			pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: JoinBigipPath(rsCfg.Virtual.Partition, monitorName)})
			monitor := Monitor{
				Name:       monitorName,
				Partition:  rsCfg.Virtual.Partition,
				Type:       monitor.Type,
				Interval:   monitor.Interval,
				Send:       monitor.Send,
				Recv:       monitor.Recv,
				Timeout:    monitor.Timeout,
				TargetPort: monitor.TargetPort,
			}
			rsCfg.Monitors = append(rsCfg.Monitors, monitor)
		}
	}
}

// Handle the default pool for virtual server
func (ctlr *Controller) handleDefaultPool(
	rsCfg *ResourceConfig,
	vs *cisapiv1.VirtualServer,
	rsRef resourceRef,
) {
	// if it's an insecure virtual server and vs traffic is redirect or none, we should not add the default pool
	if rsCfg.MetaData.Protocol == HTTP && len(vs.Spec.TLSProfileName) > 0 && (vs.Spec.HTTPTraffic == TLSRedirectInsecure || vs.Spec.HTTPTraffic == TLSNoInsecure) {
		return
	}
	if !reflect.DeepEqual(vs.Spec.DefaultPool, cisapiv1.DefaultPool{}) {
		if vs.Spec.DefaultPool.Reference == BIGIP && vs.Spec.DefaultPool.Name != "" {
			rsCfg.Virtual.PoolName = vs.Spec.DefaultPool.Name
			rsCfg.MetaData.defaultPoolType = BIGIP
		} else if vs.Spec.DefaultPool.Reference == ServiceRef {
			rsCfg.Virtual.PoolName = ctlr.framePoolNameForDefaultPool(vs.Namespace, vs.Spec.DefaultPool, vs.Spec.Host)
			svcNamespace := vs.Namespace
			if vs.Spec.DefaultPool.ServiceNamespace != "" {
				svcNamespace = vs.Spec.DefaultPool.ServiceNamespace
			}
			targetPort := ctlr.fetchTargetPort(svcNamespace, vs.Spec.DefaultPool.Service, vs.Spec.DefaultPool.ServicePort, "")
			if (intstr.IntOrString{}) == targetPort {
				targetPort = vs.Spec.DefaultPool.ServicePort
			}
			pool := Pool{
				Name:              rsCfg.Virtual.PoolName,
				Partition:         rsCfg.Virtual.Partition,
				ServiceName:       vs.Spec.DefaultPool.Service,
				ServiceNamespace:  svcNamespace,
				ServicePort:       targetPort,
				NodeMemberLabel:   vs.Spec.DefaultPool.NodeMemberLabel,
				Balance:           vs.Spec.DefaultPool.Balance,
				ReselectTries:     vs.Spec.DefaultPool.ReselectTries,
				ServiceDownAction: vs.Spec.DefaultPool.ServiceDownAction,
			}
			if vs.Spec.DefaultPool.Monitors != nil {
				for _, mtr := range vs.Spec.DefaultPool.Monitors {
					var monitorName string
					if mtr.Name != "" && mtr.Reference == BIGIP {
						pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: mtr.Name, Reference: mtr.Reference})
					} else {
						var formatPort intstr.IntOrString
						if mtr.TargetPort != 0 {
							formatPort = intstr.IntOrString{IntVal: mtr.TargetPort}
						} else {
							formatPort = vs.Spec.DefaultPool.ServicePort
						}
						if mtr.Name == "" {
							monitorName = formatMonitorName(svcNamespace, rsCfg.Virtual.PoolName, mtr.Type, formatPort, vs.Spec.Host, "")
						}
						pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: JoinBigipPath(rsCfg.Virtual.Partition, monitorName)})
						mntr := Monitor{
							Name:       monitorName,
							Partition:  rsCfg.Virtual.Partition,
							Type:       mtr.Type,
							Interval:   mtr.Interval,
							Send:       mtr.Send,
							Recv:       mtr.Recv,
							Timeout:    mtr.Timeout,
							TargetPort: mtr.TargetPort,
						}
						rsCfg.Monitors = append(rsCfg.Monitors, mntr)
					}
				}
			}
			ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, vs.Spec.DefaultPool.Service, "", pool, vs.Spec.DefaultPool.ServicePort, "")
			// Update the pool Members
			ctlr.updatePoolMembersForResources(&pool)
			rsCfg.Pools = append(rsCfg.Pools, pool)
		}
	}
}

// Handle the default pool for virtual server
func (ctlr *Controller) handleDefaultPoolForPolicy(
	rsCfg *ResourceConfig,
	plc *cisapiv1.Policy,
	rsRef resourceRef,
	host string,
	httpTraffic string,
	isTLS bool,
) {
	// if it's an insecure virtual server and vs traffic is redirect or none, we should not add the default pool
	if rsCfg.MetaData.Protocol == HTTP && isTLS && (httpTraffic == TLSRedirectInsecure || httpTraffic == TLSNoInsecure) {
		return
	}
	if !reflect.DeepEqual(plc.Spec.DefaultPool, cisapiv1.DefaultPool{}) {
		if plc.Spec.DefaultPool.Reference == BIGIP && plc.Spec.DefaultPool.Name != "" {
			rsCfg.Virtual.PoolName = plc.Spec.DefaultPool.Name
			rsCfg.MetaData.defaultPoolType = BIGIP
		} else if plc.Spec.DefaultPool.Reference == ServiceRef {
			rsCfg.Virtual.PoolName = ctlr.framePoolNameForDefaultPool(rsRef.namespace, plc.Spec.DefaultPool, host)
			svcNamespace := rsRef.namespace
			if plc.Spec.DefaultPool.ServiceNamespace != "" {
				svcNamespace = plc.Spec.DefaultPool.ServiceNamespace
			}
			targetPort := ctlr.fetchTargetPort(svcNamespace, plc.Spec.DefaultPool.Service, plc.Spec.DefaultPool.ServicePort, "")
			if (intstr.IntOrString{}) == targetPort {
				targetPort = plc.Spec.DefaultPool.ServicePort
			}
			pool := Pool{
				Name:              rsCfg.Virtual.PoolName,
				Partition:         rsCfg.Virtual.Partition,
				ServiceName:       plc.Spec.DefaultPool.Service,
				ServiceNamespace:  svcNamespace,
				ServicePort:       targetPort,
				NodeMemberLabel:   plc.Spec.DefaultPool.NodeMemberLabel,
				Balance:           plc.Spec.DefaultPool.Balance,
				ReselectTries:     plc.Spec.DefaultPool.ReselectTries,
				ServiceDownAction: plc.Spec.DefaultPool.ServiceDownAction,
			}
			if plc.Spec.DefaultPool.Monitors != nil {
				for _, mtr := range plc.Spec.DefaultPool.Monitors {
					var monitorName string
					if mtr.Name != "" && mtr.Reference == BIGIP {
						pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: mtr.Name, Reference: mtr.Reference})
					} else {
						var formatPort intstr.IntOrString
						if mtr.TargetPort != 0 {
							formatPort = intstr.IntOrString{IntVal: mtr.TargetPort}
						} else {
							formatPort = plc.Spec.DefaultPool.ServicePort
						}
						if mtr.Name == "" {
							monitorName = formatMonitorName(svcNamespace, rsCfg.Virtual.PoolName, mtr.Type, formatPort, host, "")
						}
						pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: JoinBigipPath(rsCfg.Virtual.Partition, monitorName)})
						mntr := Monitor{
							Name:       monitorName,
							Partition:  rsCfg.Virtual.Partition,
							Type:       mtr.Type,
							Interval:   mtr.Interval,
							Send:       mtr.Send,
							Recv:       mtr.Recv,
							Timeout:    mtr.Timeout,
							TargetPort: mtr.TargetPort,
						}
						rsCfg.Monitors = append(rsCfg.Monitors, mntr)
					}
				}
			}
			ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, plc.Spec.DefaultPool.Service, "", pool, plc.Spec.DefaultPool.ServicePort, "")
			// Update the pool Members
			ctlr.updatePoolMembersForResources(&pool)
			rsCfg.Pools = append(rsCfg.Pools, pool)
		}
	}
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
			clientSSL := tlsContext.bigIPSSLProfiles.clientSSLs
			serverSSL := tlsContext.bigIPSSLProfiles.serverSSLs
			// Process Profile
			switch tlsContext.referenceType {
			case BIGIP:
				log.Debugf("Processing  BIGIP referenced profiles for '%s' '%s'/'%s'",
					tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
				// Process referenced BIG-IP clientSSL
				if len(clientSSL) > 0 {
					for _, profile := range clientSSL {
						clientProfRef := ConvertStringToProfileRef(
							profile, CustomProfileClient, tlsContext.namespace)
						rsCfg.Virtual.AddOrUpdateProfile(clientProfRef)
					}
				}
				// Process referenced BIG-IP serverSSL
				if len(serverSSL) > 0 {
					for _, profile := range serverSSL {
						serverProfRef := ConvertStringToProfileRef(
							profile, CustomProfileServer, tlsContext.namespace)
						rsCfg.Virtual.AddOrUpdateProfile(serverProfRef)
					}
				}
				log.Debugf("Updated BIGIP referenced profiles for '%s' '%s'/'%s'",
					tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
			case Secret:
				// Process ClientSSL stored as kubernetes secret
				var namespace string
				if ctlr.watchingAllNamespaces() {
					namespace = ""
				} else {
					namespace = tlsContext.namespace
				}
				if len(clientSSL) > 0 {
					var secrets []*v1.Secret
					for _, secretName := range clientSSL {
						secretKey := tlsContext.namespace + "/" + secretName
						if _, ok := ctlr.comInformers[namespace]; !ok {
							return false
						}
						obj, found, err := ctlr.comInformers[namespace].secretsInformer.GetIndexer().GetByKey(secretKey)
						if err != nil || !found {
							log.Errorf("secret %s not found for '%s' '%s'/'%s'",
								clientSSL, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
						secrets = append(secrets, obj.(*v1.Secret))
					}
					err, _ := ctlr.createSecretClientSSLProfile(rsCfg, secrets, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileClient, tlsContext.bigIPSSLProfiles.clientSSlParams.RenegotiationEnabled)
					if err != nil {
						log.Errorf("error %v encountered while creating clientssl profile for '%s' '%s'/'%s'",
							err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
						return false
					}
				}
				// Process ServerSSL stored as kubernetes secret
				if len(serverSSL) > 0 {
					var secrets []*v1.Secret
					for _, secret := range serverSSL {
						secretKey := tlsContext.namespace + "/" + secret
						if _, ok := ctlr.comInformers[namespace]; !ok {
							return false
						}
						obj, found, err := ctlr.comInformers[namespace].secretsInformer.GetIndexer().GetByKey(secretKey)
						if err != nil || !found {
							log.Errorf("secret %s not found for '%s' '%s'/'%s'",
								serverSSL, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
						secrets = append(secrets, obj.(*v1.Secret))
						err, _ = ctlr.createSecretServerSSLProfile(rsCfg, secrets, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileServer, tlsContext.bigIPSSLProfiles.serverSSlParams.RenegotiationEnabled)
						if err != nil {
							log.Errorf("error %v encountered while creating serverssl profile for '%s' '%s'/'%s'",
								err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
							return false
						}
					}
				}
			case Hybrid:
				// Process sslProfiles stored as either secret or bigip refrence
				var namespace string
				if ctlr.watchingAllNamespaces() {
					namespace = ""
				} else {
					namespace = tlsContext.namespace
				}
				if len(clientSSL) > 0 {
					if tlsContext.bigIPSSLProfiles.clientSSlParams.ProfileReference != "" {
						switch tlsContext.bigIPSSLProfiles.clientSSlParams.ProfileReference {
						case BIGIP:
							// Process referenced BIG-IP clientSSL
							for _, profile := range clientSSL {
								clientProfRef := ConvertStringToProfileRef(
									profile, CustomProfileClient, tlsContext.namespace)
								rsCfg.Virtual.AddOrUpdateProfile(clientProfRef)
							}
						case Secret:
							// Process ClientSSL stored as kubernetes secret
							var secrets []*v1.Secret
							for _, secretName := range clientSSL {
								secretKey := tlsContext.namespace + "/" + secretName
								if _, ok := ctlr.comInformers[namespace]; !ok {
									return false
								}
								obj, found, err := ctlr.comInformers[namespace].secretsInformer.GetIndexer().GetByKey(secretKey)
								if err != nil || !found {
									log.Errorf("secret %s not found for '%s' '%s'/'%s'",
										clientSSL, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
									return false
								}
								secrets = append(secrets, obj.(*v1.Secret))
							}
							err, _ := ctlr.createSecretClientSSLProfile(rsCfg, secrets, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileClient, tlsContext.bigIPSSLProfiles.clientSSlParams.RenegotiationEnabled)
							if err != nil {
								log.Errorf("error %v encountered while creating clientssl profile for '%s' '%s'/'%s'",
									err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
								return false
							}
						}

					} else {
						log.Errorf("profileRefrence in clientSSLParams is mandatory for hybrid mode '%s' '%s'/'%s'", tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
					}
				}
				if len(serverSSL) > 0 {
					if tlsContext.bigIPSSLProfiles.serverSSlParams.ProfileReference != "" {
						switch tlsContext.bigIPSSLProfiles.serverSSlParams.ProfileReference {
						case BIGIP:
							// Process referenced BIG-IP serverSSL
							for _, profile := range serverSSL {
								serverProfRef := ConvertStringToProfileRef(
									profile, CustomProfileServer, tlsContext.namespace)
								rsCfg.Virtual.AddOrUpdateProfile(serverProfRef)
							}
						case Secret:
							// Process ServerSSL stored as kubernetes secret
							var secrets []*v1.Secret
							for _, secret := range serverSSL {
								secretKey := tlsContext.namespace + "/" + secret
								if _, ok := ctlr.comInformers[namespace]; !ok {
									return false
								}
								obj, found, err := ctlr.comInformers[namespace].secretsInformer.GetIndexer().GetByKey(secretKey)
								if err != nil || !found {
									log.Errorf("secret %s not found for '%s' '%s'/'%s'",
										serverSSL, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
									return false
								}
								secrets = append(secrets, obj.(*v1.Secret))
								err, _ = ctlr.createSecretServerSSLProfile(rsCfg, secrets, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileServer, tlsContext.bigIPSSLProfiles.serverSSlParams.RenegotiationEnabled)
								if err != nil {
									log.Errorf("error %v encountered while creating serverssl profile for '%s' '%s'/'%s'",
										err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
									return false
								}
							}
						}

					} else {
						log.Errorf("profileRefrence in clientSSLParams is mandatory for hybrid mode '%s' '%s'/'%s'", tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
					}
				}
			case Certificate:
				// Prepare SSL Transient Context
				if tlsContext.bigIPSSLProfiles.key != "" && tlsContext.bigIPSSLProfiles.certificate != "" {
					cert := certificate{Cert: tlsContext.bigIPSSLProfiles.certificate, Key: tlsContext.bigIPSSLProfiles.key}
					err, _ := ctlr.createClientSSLProfile(rsCfg, []certificate{cert},
						fmt.Sprintf("%s-clientssl", tlsContext.name), tlsContext.namespace, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileClient, tlsContext.bigIPSSLProfiles.clientSSlParams.RenegotiationEnabled)
					if err != nil {
						log.Debugf("error %v encountered while creating clientssl profile  for '%s' '%s'/'%s'",
							err, tlsContext.resourceType, tlsContext.namespace, tlsContext.name)
						return false
					}
				}
				// Create Server SSL profile for bigip
				if tlsContext.bigIPSSLProfiles.destinationCACertificate != "" {
					var err error
					cert := certificate{Cert: tlsContext.bigIPSSLProfiles.destinationCACertificate}
					if tlsContext.bigIPSSLProfiles.caCertificate != "" {
						err, _ = ctlr.createServerSSLProfile(rsCfg, []certificate{cert},
							tlsContext.bigIPSSLProfiles.caCertificate, tlsContext.name, tlsContext.namespace, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileServer, tlsContext.bigIPSSLProfiles.serverSSlParams.RenegotiationEnabled)
					} else {
						err, _ = ctlr.createServerSSLProfile(rsCfg, []certificate{cert},
							"", fmt.Sprintf("%s-serverssl", tlsContext.name), tlsContext.namespace, ctlr.resources.baseRouteConfig.TLSCipher, CustomProfileServer, tlsContext.bigIPSSLProfiles.serverSSlParams.RenegotiationEnabled)
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
					for _, hostname := range poolPathRef.aliasHostnames {
						sslPath := hostname + poolPathRef.path
						sslPath = strings.TrimSuffix(sslPath, "/")
						updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, EdgeServerSslDgName),
							rsCfg.Virtual.Partition, tlsContext.namespace, sslPath, serverSsl, DataGroupType)
					}

				case TLSReencrypt:
					for _, hostname := range poolPathRef.aliasHostnames {
						sslPath := hostname + poolPathRef.path
						sslPath = strings.TrimSuffix(sslPath, "/")
						if len(serverSSL) > 0 {
							if tlsContext.referenceType == BIGIP || (tlsContext.referenceType == Hybrid && tlsContext.bigIPSSLProfiles.serverSSlParams.ProfileReference == BIGIP) {
								// for bigip referenced profiles we need to add entries for all profiles
								for _, profileName := range serverSSL {
									updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, ReencryptServerSslDgName),
										rsCfg.Virtual.Partition, tlsContext.namespace, sslPath, profileName, DataGroupType)
								}

							} else {
								// for secrets all the ca certificates will be bundle within a single profile
								profileName := AS3NameFormatter(rsCfg.Virtual.Name + "_tls_client")
								updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, ReencryptServerSslDgName),
									rsCfg.Virtual.Partition, tlsContext.namespace, sslPath, profileName, DataGroupType)
							}

						}
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
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
				[]string{},
				tlsContext.httpPort,
			)
		case TLSEdge:
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				EdgeHostsDgName,
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
				[]string{},
				tlsContext.httpPort,
			)
		case TLSPassthrough:
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				PassthroughHostsDgName,
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
				[]string{},
				tlsContext.httpPort)
		}
		if len(rsCfg.Virtual.AllowSourceRange) > 0 {
			updateDataGroupOfDgName(
				rsCfg.IntDgMap,
				tlsContext.poolPathRefs,
				rsCfg.Virtual.Name,
				AllowSourceRangeDgName,
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
				rsCfg.Virtual.AllowSourceRange,
				tlsContext.httpPort)
		}
		// create data group for default pool
		if len(rsCfg.Virtual.PoolName) > 0 {
			updateDataGroup(rsCfg.IntDgMap, getRSCfgResName(rsCfg.Virtual.Name, DefaultPoolsDgName),
				rsCfg.Virtual.Partition, tlsContext.namespace, DefaultPool, rsCfg.Virtual.PoolName, DataGroupType)
		}
		ctlr.handleDataGroupIRules(
			rsCfg,
			tlsContext.vsHostname,
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
			if tlsContext.vsHostname == "" {
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
				tlsContext.namespace,
				rsCfg.Virtual.Partition,
				[]string{},
				tlsContext.httpPort,
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
	var httpPort int32
	if vs.Spec.VirtualServerHTTPSPort == 0 {
		httpsPort = DEFAULT_HTTPS_PORT
	} else {
		httpsPort = vs.Spec.VirtualServerHTTPSPort
	}
	if vs.Spec.VirtualServerHTTPPort == 0 {
		httpPort = DEFAULT_HTTP_PORT
	} else {
		httpPort = vs.Spec.VirtualServerHTTPPort
	}
	bigIPSSLProfiles := BigIPSSLProfiles{}
	// Giving priority to ClientSSLs over ClientSSL
	if len(tls.Spec.TLS.ClientSSLs) > 0 {
		bigIPSSLProfiles.clientSSLs = tls.Spec.TLS.ClientSSLs
	} else if tls.Spec.TLS.ClientSSL != "" {
		bigIPSSLProfiles.clientSSLs = append(bigIPSSLProfiles.clientSSLs, tls.Spec.TLS.ClientSSL)
	}
	bigIPSSLProfiles.clientSSlParams = tls.Spec.TLS.ClientSSLParams
	// Giving priority to ServerSSLs over ServerSSL
	if len(tls.Spec.TLS.ServerSSLs) > 0 {
		bigIPSSLProfiles.serverSSLs = tls.Spec.TLS.ServerSSLs
	} else if tls.Spec.TLS.ServerSSL != "" {
		bigIPSSLProfiles.serverSSLs = append(bigIPSSLProfiles.serverSSLs, tls.Spec.TLS.ServerSSL)
	}
	bigIPSSLProfiles.serverSSlParams = tls.Spec.TLS.ServerSSLParams
	var poolPathRefs []poolPathRef
	for _, pl := range vs.Spec.Pools {
		poolBackends := ctlr.GetPoolBackends(&pl)
		for _, backend := range poolBackends {
			poolName := ctlr.framePoolNameForVS(
				vs.ObjectMeta.Namespace,
				pl,
				vs.Spec.Host,
				backend,
			)
			if len(tls.Spec.Hosts) > 1 && !hasWildcardHost(tls.Spec.Hosts) {
				//For wildcard certificates, multiple hosts may be mapped to different subdomains
				//of the same domain. In this case, we need to create a poolPathRef for vs host matched.
				poolPathRefs = append(poolPathRefs, poolPathRef{pl.Path, poolName, tls.Spec.Hosts})
			} else {
				hosts := getUniqueHosts(vs.Spec.Host, vs.Spec.HostAliases)
				poolPathRefs = append(poolPathRefs, poolPathRef{pl.Path, poolName, hosts})
			}
		}
	}
	return ctlr.handleTLS(rsCfg, TLSContext{name: vs.ObjectMeta.Name,
		namespace:        vs.ObjectMeta.Namespace,
		resourceType:     VirtualServer,
		referenceType:    tls.Spec.TLS.Reference,
		vsHostname:       vs.Spec.Host,
		httpsPort:        httpsPort,
		httpPort:         httpPort,
		ipAddress:        ip,
		termination:      tls.Spec.TLS.Termination,
		httpTraffic:      vs.Spec.HTTPTraffic,
		poolPathRefs:     poolPathRefs,
		bigIPSSLProfiles: bigIPSSLProfiles,
	})
}

// validate TLSProfile
// validation includes valid parameters for the type of termination(edge, re-encrypt and Pass-through)
func validateTLSProfile(tls *cisapiv1.TLSProfile) bool {
	//validation for re-encrypt termination
	if tls.Spec.TLS.Termination == "reencrypt" {
		// Should contain both client and server SSL profiles
		if (tls.Spec.TLS.ClientSSL == "" || tls.Spec.TLS.ServerSSL == "") && (len(tls.Spec.TLS.ClientSSLs) == 0 || len(tls.Spec.TLS.ServerSSLs) == 0) {
			log.Errorf("TLSProfile %s of type re-encrypt termination should contain both "+
				"ClientSSLs and ServerSSLs", tls.ObjectMeta.Name)
			return false
		}
	} else if tls.Spec.TLS.Termination == "edge" {
		// Should contain only client SSL
		if tls.Spec.TLS.ClientSSL == "" && len(tls.Spec.TLS.ClientSSLs) == 0 {
			log.Errorf("TLSProfile %s of type edge termination should contain ClientSSLs",
				tls.ObjectMeta.Name)
			return false
		}
		if tls.Spec.TLS.ServerSSL != "" || len(tls.Spec.TLS.ServerSSLs) != 0 {
			log.Errorf("TLSProfile %s of type edge termination should NOT contain ServerSSLs",
				tls.ObjectMeta.Name)
			return false
		}
	} else {
		// Pass-through
		if (tls.Spec.TLS.ClientSSL != "") || (tls.Spec.TLS.ServerSSL != "") || len(tls.Spec.TLS.ClientSSLs) != 0 || len(tls.Spec.TLS.ServerSSLs) != 0 {
			log.Errorf("TLSProfile %s of type Pass-through termination should NOT contain either "+
				"ClientSSLs or ServerSSLs", tls.ObjectMeta.Name)
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
	case 3:
		// refernce to existing profile created using AS3 in Common(non-cis-managed) partition
		if parts[1] == "Shared" {
			profRef.Partition = parts[0] + "/" + parts[1]
			profRef.Name = parts[2]
		}

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
		zero := 0
		rs.ltmConfig[partition] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: &zero}
	}

	return rs.ltmConfig[partition].ResourceMap
}

func (rs *ResourceStore) getLTMPartitions() []string {
	var partitions []string

	for partition, _ := range rs.ltmConfig {
		partitions = append(partitions, partition)
	}
	return partitions
}

// getResourceConfig gets a specific Resource cfg
func (rs *ResourceStore) getResourceConfig(partition, name string) (*ResourceConfig, error) {

	rsMap, ok := rs.ltmConfig[partition]
	if !ok {
		return nil, fmt.Errorf("partition not available")
	}
	if res, ok := rsMap.ResourceMap[name]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("resource not available")
}

func (rs *ResourceStore) setResourceConfig(partition, name string, rsCfg *ResourceConfig) error {
	partitionConfig, ok := rs.ltmConfig[partition]
	if !ok {
		return fmt.Errorf("partition not available")
	}
	partitionConfig.ResourceMap[name] = rsCfg
	return nil
}

// getSanitizedLTMConfigCopy is a Resource reference copy of LTMConfig
func (rs *ResourceStore) getSanitizedLTMConfigCopy() LTMConfig {
	ltmConfig := make(LTMConfig)
	var deletePartitions []string
	for prtn, partitionConfig := range rs.ltmConfig {
		// copy only those partitions where virtual server exists otherwise remove from ltmConfig
		if len(partitionConfig.ResourceMap) > 0 {
			ltmConfig[prtn] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: partitionConfig.Priority}
			for rsName, res := range partitionConfig.ResourceMap {
				ltmConfig[prtn].ResourceMap[rsName] = res
			}
		} else {
			// Delete partition from ltmConfig only if the priority is 0 else don't delete it
			partitionConfig.PriorityMutex.RLock()
			if *(partitionConfig.Priority) == 0 {
				deletePartitions = append(deletePartitions, prtn)
			}
			partitionConfig.PriorityMutex.RUnlock()
		}
	}
	// delete the partitions if there are no virtuals in that partition
	for _, prtn := range deletePartitions {
		delete(rs.ltmConfig, prtn)
	}
	return ltmConfig
}

// getLTMConfigDeepCopy is a Resource reference copy of LTMConfig
func (rs *ResourceStore) getLTMConfigDeepCopy() LTMConfig {
	ltmConfig := make(LTMConfig)
	for prtn, partitionConfig := range rs.ltmConfig {
		partitionConfig.PriorityMutex.RLock()
		ltmConfig[prtn] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: partitionConfig.Priority}
		partitionConfig.PriorityMutex.RUnlock()
		for rsName, res := range partitionConfig.ResourceMap {
			copyRes := &ResourceConfig{}
			copyRes.copyConfig(res)
			ltmConfig[prtn].ResourceMap[rsName] = copyRes
		}
	}
	return ltmConfig
}

// getGTMConfigCopy is a WideIP reference copy of GTMConfig
func (rs *ResourceStore) getGTMConfigCopy() GTMConfig {
	gtmConfig := make(GTMConfig)
	for partition, gtmPartitionConfig := range rs.gtmConfig {
		gtmConfig[partition] = GTMPartitionConfig{
			WideIPs: make(map[string]WideIP),
		}
		for domainName, wip := range gtmPartitionConfig.WideIPs {
			copyRes := copyGTMConfig(wip)
			gtmConfig[partition].WideIPs[domainName] = copyRes
		}
	}
	return gtmConfig
}

func (rs *ResourceStore) updateCaches() {
	// No need to deep copy as each RsCfg will be framed in a fresh memory block while creating live ltmConfig
	rs.ltmConfigCache = rs.getSanitizedLTMConfigCopy()
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

// Update the tenant priority in ltmConfigCache
func (rs *ResourceStore) updatePartitionPriority(partition string, priority int) {
	if _, ok := rs.ltmConfig[partition]; ok {
		rs.ltmConfig[partition].PriorityMutex.Lock()
		*rs.ltmConfig[partition].Priority = priority
		rs.ltmConfig[partition].PriorityMutex.Unlock()
	}
}

func (lc LTMConfig) GetAllPoolMembers() []PoolMember {
	// Get all pool members and write them to VxlanMgr to configure ARP entries
	var allPoolMembers []PoolMember

	for _, partitionConfig := range lc {
		for _, cfg := range partitionConfig.ResourceMap {
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
func copyGTMConfig(cfg WideIP) (rc WideIP) {
	// MetaData
	rc.DomainName = cfg.DomainName
	rc.UID = cfg.UID
	rc.LBMethod = cfg.LBMethod
	rc.TTLPersistence = cfg.TTLPersistence
	rc.PersistCidrIPv4 = cfg.PersistCidrIPv4
	rc.PersistCidrIPv6 = cfg.PersistCidrIPv6
	rc.PersistenceEnabled = cfg.PersistenceEnabled
	if cfg.ClientSubnetPreferred != nil {
		rc.ClientSubnetPreferred = cfg.ClientSubnetPreferred
	}
	rc.RecordType = cfg.RecordType
	// Pools
	rc.Pools = make([]GSLBPool, len(cfg.Pools))
	copy(rc.Pools, cfg.Pools)
	// Pool Members and Monitor Names
	for i := range rc.Pools {
		rc.Pools[i].Members = make([]string, len(cfg.Pools[i].Members))
		copy(rc.Pools[i].Members, cfg.Pools[i].Members)
		rc.Pools[i].Monitors = make([]Monitor, len(cfg.Pools[i].Monitors))
		copy(rc.Pools[i].Monitors, cfg.Pools[i].Monitors)
	}
	return rc
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
		rc.Pools[i].MonitorNames = make([]MonitorName, len(cfg.Pools[i].MonitorNames))
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
				Type:      idg.Type,
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

// Internal data group for default pool of a virtual server.
const DefaultPoolsDgName = "default_pool_servername_dg"

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

// Internal DataGroup Default Type
const DataGroupType = "string"

// Allow Source Range
const DataGroupAllowSourceRangeType = "ip"
const AllowSourceRangeDgName = "allowSourceRange"

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
			getRSCfgResName(rsCfg.Virtual.Name, TLSIRuleName), rsCfg.Virtual.Partition, ctlr.getTLSIRule(rsCfg.Virtual.Name, rsCfg.Virtual.Partition, rsCfg.Virtual.AllowSourceRange, rsCfg.Virtual.MultiPoolPersistence))
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

func (ctlr *Controller) HandlePathBasedABIRule(
	rsCfg *ResourceConfig,
	vsHost string,
	tlsTerminationType string,
) {
	// For passthrough, don't add the iRule
	if tlsTerminationType != TLSPassthrough {
		rsCfg.addIRule(
			getRSCfgResName(rsCfg.Virtual.Name, ABPathIRuleName), rsCfg.Virtual.Partition,
			ctlr.getPathBasedABDeployIRule(rsCfg.Virtual.Name, rsCfg.Virtual.Partition, rsCfg.Virtual.MultiPoolPersistence))
		if vsHost != "" {
			abPathIRule := JoinBigipPath(rsCfg.Virtual.Partition,
				getRSCfgResName(rsCfg.Virtual.Name, ABPathIRuleName))
			rsCfg.Virtual.AddIRule(abPathIRule)
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

	poolName := ctlr.framePoolNameForTS(
		vs.ObjectMeta.Namespace,
		vs.Spec.Pool,
		"",
	)
	svcNamespace := vs.Namespace
	if vs.Spec.Pool.ServiceNamespace != "" {
		svcNamespace = vs.Spec.Pool.ServiceNamespace
	}
	targetPort := ctlr.fetchTargetPort(svcNamespace, vs.Spec.Pool.Service, vs.Spec.Pool.ServicePort, "")
	if (intstr.IntOrString{}) == targetPort {
		targetPort = vs.Spec.Pool.ServicePort
	}
	pool := Pool{
		Name:              poolName,
		Partition:         rsCfg.Virtual.Partition,
		ServiceName:       vs.Spec.Pool.Service,
		ServiceNamespace:  svcNamespace,
		ServicePort:       targetPort,
		NodeMemberLabel:   vs.Spec.Pool.NodeMemberLabel,
		Balance:           vs.Spec.Pool.Balance,
		ReselectTries:     vs.Spec.Pool.ReselectTries,
		ServiceDownAction: vs.Spec.Pool.ServiceDownAction,
	}
	svcKey := MultiClusterServiceKey{
		serviceName: vs.Spec.Pool.Service,
		clusterName: "",
		namespace:   vs.Namespace,
	}
	rsRef := resourceRef{
		name:      vs.Name,
		namespace: vs.Namespace,
		kind:      TransportServer,
	}
	// update the pool identifier for service
	ctlr.updatePoolIdentifierForService(svcKey, rsRef, vs.Spec.Pool.ServicePort, pool.Name, pool.Partition, rsCfg.Virtual.Name, "")

	if ctlr.multiClusterMode != "" {
		//check for external service reference
		if len(vs.Spec.Pool.MultiClusterServices) > 0 {
			if _, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; !ok {
				// only process if ts key is not present. else skip the processing
				// on ts update we are clearing the resource service
				// if event comes from ts then we will read and populate data, else we will skip processing
				ctlr.processResourceExternalClusterServices(rsRef, vs.Spec.Pool.MultiClusterServices)
			}
		}
		var multiClusterServices []cisapiv1.MultiClusterServiceReference
		if svcs, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; ok {
			for svc, config := range svcs {
				multiClusterServices = append(multiClusterServices, cisapiv1.MultiClusterServiceReference{
					ClusterName: svc.clusterName,
					SvcName:     svc.serviceName,
					Namespace:   svc.namespace,
					ServicePort: config.svcPort,
				})
				// update the clusterSvcMap
				ctlr.updatePoolIdentifierForService(svc, rsRef, config.svcPort, pool.Name, pool.Partition, rsCfg.Virtual.Name, "")
			}
			pool.MultiClusterServices = multiClusterServices
		}
		// update the multicluster resource serviceMap with local cluster services
		ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, vs.Spec.Pool.Service, vs.Spec.Pool.Path, pool, vs.Spec.Pool.ServicePort, "")
		// update the multicluster resource serviceMap with HA pair cluster services
		if ctlr.haModeType == Active && ctlr.multiClusterConfigs.HAPairClusterName != "" {
			ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, vs.Spec.Pool.Service, "", pool, vs.Spec.Pool.ServicePort,
				ctlr.multiClusterConfigs.HAPairClusterName)
		}
	} else {
		ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, vs.Spec.Pool.Service, vs.Spec.Pool.Path, pool, vs.Spec.Pool.ServicePort, "")
	}
	// Update the pool Members
	ctlr.updatePoolMembersForResources(&pool)
	if len(pool.Members) > 0 {
		rsCfg.MetaData.Active = true
	}

	if !reflect.DeepEqual(vs.Spec.Pool.Monitor, cisapiv1.Monitor{}) {
		ctlr.createTransportServerMonitor(vs.Spec.Pool.Monitor, &pool, rsCfg, vs.Spec.Pool.ServicePort,
			vs.ObjectMeta.Namespace, vs.ObjectMeta.Name)
	} else if vs.Spec.Pool.Monitors != nil {
		var formatPort intstr.IntOrString
		for _, monitor := range vs.Spec.Pool.Monitors {
			if monitor.TargetPort != 0 {
				formatPort = intstr.IntOrString{IntVal: monitor.TargetPort}
			} else {
				formatPort = vs.Spec.Pool.ServicePort
			}
			ctlr.createTransportServerMonitor(monitor, &pool, rsCfg, formatPort,
				vs.ObjectMeta.Namespace, vs.ObjectMeta.Name)
		}
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
	// Set Connection Mirroring
	if vs.Spec.ConnectionMirroring != "" {
		rsCfg.Virtual.ConnectionMirroring = vs.Spec.ConnectionMirroring
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
	if len(vs.Spec.AllowVLANs) > 0 {
		rsCfg.Virtual.AllowVLANs = vs.Spec.AllowVLANs
	}
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
	poolName := ctlr.formatPoolName(
		svc.Namespace,
		svc.Name,
		svcPort.TargetPort,
		"", "", "")
	pool := Pool{
		Name:             poolName,
		Partition:        rsCfg.Virtual.Partition,
		ServiceName:      svc.Name,
		ServiceNamespace: svc.Namespace,
		ServicePort:      svcPort.TargetPort,
		NodeMemberLabel:  "",
	}
	svcKey := MultiClusterServiceKey{
		serviceName: svc.Name,
		clusterName: "",
		namespace:   svc.Namespace,
	}
	rsRef := resourceRef{
		name:      svc.Name,
		namespace: svc.Namespace,
		kind:      Service,
	}
	// update the pool identifier for service
	ctlr.updatePoolIdentifierForService(svcKey, rsRef, pool.ServicePort, pool.Name, pool.Partition, rsCfg.Virtual.Name, "")
	// Update the pool Members
	ctlr.updatePoolMembersForResources(&pool)
	if len(pool.Members) > 0 {
		rsCfg.MetaData.Active = true
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
		pool.MonitorNames = append(pool.MonitorNames, MonitorName{Name: JoinBigipPath(rsCfg.Virtual.Partition,
			formatMonitorName(svc.Namespace, svc.Name, monitorType, svcPort.TargetPort, "", ""))})
		monitor = Monitor{
			Name:      formatMonitorName(svc.Namespace, svc.Name, monitorType, svcPort.TargetPort, "", ""),
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
	// update the multicluster resource serviceMap with local cluster services
	ctlr.updateMultiClusterResourceServiceMap(rsCfg, rsRef, svc.Name, "", pool, pool.ServicePort, "")

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
	rsCfg.Virtual.HTMLProfile = plc.Spec.Profiles.HTMLProfile
	if ctlr.PoolMemberType == Cluster {
		rsCfg.Virtual.MultiPoolPersistence.Method = plc.Spec.PoolSettings.MultiPoolPersistence.Method
		rsCfg.Virtual.MultiPoolPersistence.TimeOut = plc.Spec.PoolSettings.MultiPoolPersistence.TimeOut
	}
	rsCfg.Virtual.ProfileMultiplex = plc.Spec.Profiles.ProfileMultiplex
	rsCfg.Virtual.ProfileDOS = plc.Spec.L3Policies.DOS
	rsCfg.Virtual.ProfileBotDefense = plc.Spec.L3Policies.BotDefense
	rsCfg.Virtual.TCP.Client = plc.Spec.Profiles.TCP.Client
	rsCfg.Virtual.TCP.Server = plc.Spec.Profiles.TCP.Server
	rsCfg.Virtual.HTTP2.Client = plc.Spec.Profiles.HTTP2.Client
	rsCfg.Virtual.HTTP2.Server = plc.Spec.Profiles.HTTP2.Server
	rsCfg.Virtual.AllowSourceRange = plc.Spec.L3Policies.AllowSourceRange
	rsCfg.Virtual.AllowVLANs = plc.Spec.L3Policies.AllowVlans
	rsCfg.Virtual.IpIntelligencePolicy = plc.Spec.L3Policies.IpIntelligencePolicy
	rsCfg.Virtual.AutoLastHop = plc.Spec.AutoLastHop
	if rsCfg.Virtual.HttpMrfRoutingEnabled == nil && plc.Spec.Profiles.HttpMrfRoutingEnabled != nil {
		rsCfg.Virtual.HttpMrfRoutingEnabled = plc.Spec.Profiles.HttpMrfRoutingEnabled
	}
	if plc.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile != "" &&
		(rsCfg.MetaData.Protocol == HTTP || rsCfg.MetaData.Protocol == HTTPS) {
		rsCfg.Virtual.AnalyticsProfiles.HTTPAnalyticsProfile = plc.Spec.Profiles.AnalyticsProfiles.HTTPAnalyticsProfile
	}

	//profileWebSocket is supported for service_HTTP and service_HTTPS
	if plc.Spec.Profiles.ProfileWebSocket != "" &&
		(rsCfg.MetaData.Protocol == HTTP || rsCfg.MetaData.Protocol == HTTPS) {
		rsCfg.Virtual.ProfileWebSocket = plc.Spec.Profiles.ProfileWebSocket
	}
	if len(plc.Spec.Profiles.LogProfiles) > 0 {
		rsCfg.Virtual.LogProfiles = append(rsCfg.Virtual.LogProfiles, plc.Spec.Profiles.LogProfiles...)
	}
	var iRule []string
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
		if len(plc.Spec.IRuleList) > 0 {
			iRule = plc.Spec.IRuleList
		} else if plc.Spec.IRules.Secure != "" {
			iRule = append(iRule, plc.Spec.IRules.Secure)
		}
	case "http":
		if len(plc.Spec.IRuleList) > 0 {
			iRule = plc.Spec.IRuleList
		} else if plc.Spec.IRules.InSecure != "" {
			iRule = append(iRule, plc.Spec.IRules.InSecure)
		}
	}
	if len(iRule) > 0 {
		switch plc.Spec.IRules.Priority {
		case "override":
			rsCfg.Virtual.IRules = iRule
		case "high":
			rsCfg.Virtual.IRules = append(iRule, rsCfg.Virtual.IRules...)
		default:
			rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, iRule...)
		}
	}
	// set snat as specified by user in the policy
	if plc.Spec.SNAT != "" {
		rsCfg.Virtual.SNAT = plc.Spec.SNAT
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
	rsCfg.Virtual.AllowVLANs = plc.Spec.L3Policies.AllowVlans
	rsCfg.Virtual.IpIntelligencePolicy = plc.Spec.L3Policies.IpIntelligencePolicy

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

	var iRule []string
	if len(plc.Spec.IRuleList) > 0 {
		iRule = plc.Spec.IRuleList
	} else if plc.Spec.IRules.InSecure != "" {
		iRule = append(iRule, plc.Spec.IRules.InSecure)
	}
	if len(iRule) > 0 {
		switch plc.Spec.IRules.Priority {
		case "override":
			rsCfg.Virtual.IRules = iRule
		case "high":
			rsCfg.Virtual.IRules = append(iRule, rsCfg.Virtual.IRules...)
		default:
			rsCfg.Virtual.IRules = append(rsCfg.Virtual.IRules, iRule...)
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

func (ctlr *Controller) handlePoolResourceConfigForPolicy(
	rsCfg *ResourceConfig,
	plc *cisapiv1.Policy,
) error {
	for i, pl := range rsCfg.Pools {
		if pl.ReselectTries == 0 && plc.Spec.PoolSettings.ReselectTries != 0 {
			pl.ReselectTries = plc.Spec.PoolSettings.ReselectTries
		}
		if pl.ServiceDownAction == "" && plc.Spec.PoolSettings.ServiceDownAction != "" {
			pl.ServiceDownAction = plc.Spec.PoolSettings.ServiceDownAction
		}
		if plc.Spec.PoolSettings.SlowRampTime != 0 {
			pl.SlowRampTime = plc.Spec.PoolSettings.SlowRampTime
		}
		//update pool
		rsCfg.Pools[i] = pl
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

	// check if defaultRouteGroup is used
	if extdSpec.defaultrg != nil {
		return extdSpec.defaultrg, extdSpec.partition
	}

	if extdSpec.override && extdSpec.local != nil {
		ergc := &ExtendedRouteGroupSpec{
			VServerName:   extdSpec.global.VServerName,
			VServerAddr:   extdSpec.global.VServerAddr,
			AllowOverride: extdSpec.global.AllowOverride,
		}

		if extdSpec.local.VServerName != "" {
			ergc.VServerName = extdSpec.local.VServerName
		}
		if extdSpec.local.VServerAddr != "" {
			ergc.VServerAddr = extdSpec.local.VServerAddr
		}
		if extdSpec.local.Policy != "" {
			ergc.Policy = extdSpec.local.Policy
		}
		if extdSpec.local.HTTPServerPolicyCR != "" {
			ergc.Policy = extdSpec.local.HTTPServerPolicyCR
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
	servicePort intstr.IntOrString,
	policySSLProfiles rgPlcSSLProfiles) bool {

	if route.Spec.TLS == nil {
		// Probably this is a non-tls route, nothing to do w.r.t TLS
		return false
	}
	var tlsReferenceType string
	bigIPSSLProfiles := BigIPSSLProfiles{}
	sslProfileOption := ctlr.getSSLProfileOption(route, policySSLProfiles)
	switch sslProfileOption {
	case "":
		log.Infof("Either TLS spec is not provided for route %v/%v or it's passthrough termination", route.Namespace, route.Name)
		break
	case PolicySSLOption:
		tlsReferenceType = BIGIP

		bigIPSSLProfiles.clientSSLs = policySSLProfiles.clientSSLs

		if route.Spec.TLS.Termination == TLSReencrypt {
			if len(policySSLProfiles.serverSSLs) == 0 {
				return false
			}
			bigIPSSLProfiles.serverSSLs = policySSLProfiles.serverSSLs
		}
		log.Infof("Policy SSL profiles are given highest priority, using %v with route %v/%v", sslProfileOption, route.Namespace, route.Name)
	case AnnotationSSLOption:
		if clientSSL, ok := route.ObjectMeta.Annotations[resource.F5ClientSslProfileAnnotation]; ok {
			if len(strings.Split(clientSSL, "/")) > 1 {
				tlsReferenceType = BIGIP
			} else {
				tlsReferenceType = Secret
			}
			bigIPSSLProfiles.clientSSLs = append(bigIPSSLProfiles.clientSSLs, clientSSL)
			serverSSL, ok := route.ObjectMeta.Annotations[resource.F5ServerSslProfileAnnotation]
			if route.Spec.TLS.Termination == routeapi.TLSTerminationReencrypt {
				if !ok {
					return false
				}
				bigIPSSLProfiles.serverSSLs = append(bigIPSSLProfiles.serverSSLs, serverSSL)
			}
			log.Infof("Route annotation are given second priority, using %v with route %v/%v", sslProfileOption, route.Namespace, route.Name)
		}
	case RouteCertificateSSLOption:
		tlsReferenceType = Certificate
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
		log.Infof("Route spec certs are given third priority, using %v with route %v/%v", sslProfileOption, route.Namespace, route.Name)
		// Set DependsOnTLS to true in case of route certificate and defaultSSLProfile
		if ctlr.resources.baseRouteConfig != (BaseRouteConfig{}) {
			//set for default routegroup
			if ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig != (DefaultRouteGroupConfig{}) {
				//Flag to track the route groups which are using TLS profiles.
				if ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].defaultrg != nil {
					ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].defaultrg.Meta = Meta{
						DependsOnTLS: true,
					}
				}
			} else {
				ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].global.Meta = Meta{
					DependsOnTLS: true,
				}
			}
		}
	case DefaultSSLOption:
		// Check for default tls in baseRouteSpec
		tlsReferenceType = BIGIP

		if ctlr.resources.baseRouteConfig.DefaultTLS.ClientSSL == "" {
			return false
		}
		bigIPSSLProfiles.clientSSLs = append(bigIPSSLProfiles.clientSSLs, ctlr.resources.baseRouteConfig.DefaultTLS.ClientSSL)

		if route.Spec.TLS.Termination == TLSReencrypt {
			if ctlr.resources.baseRouteConfig.DefaultTLS.ServerSSL == "" {
				return false
			}
			bigIPSSLProfiles.serverSSLs = append(bigIPSSLProfiles.serverSSLs, ctlr.resources.baseRouteConfig.DefaultTLS.ServerSSL)
		}
		log.Infof("Default SSL defined in extended configMap are given least priority, using %v with route %v/%v", sslProfileOption, route.Namespace, route.Name)
		// Set DependsOnTLS to true in case of route certificate and defaultSSLProfile
		if ctlr.resources.baseRouteConfig != (BaseRouteConfig{}) {
			//Flag to track the route groups which are using TLS Ciphers
			if ctlr.resources.baseRouteConfig.DefaultRouteGroupConfig != (DefaultRouteGroupConfig{}) {
				if ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].defaultrg != nil {
					ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].defaultrg.Meta = Meta{
						DependsOnTLS: true,
					}
				}
			} else {
				if ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].global != nil {
					ctlr.resources.extdSpecMap[ctlr.resources.supplementContextCache.invertedNamespaceLabelMap[route.Namespace]].global.Meta = Meta{
						DependsOnTLS: true,
					}
				}
			}
		}
	default:
		log.Errorf("Missing certificate/key/SSL profile annotation/defaultSSL for route: %v", route.ObjectMeta.Name)
		return false
	}

	var poolPathRefs []poolPathRef

	for _, pl := range rsCfg.Pools {
		if pl.Name == ctlr.formatPoolName(
			route.Namespace,
			route.Spec.To.Name,
			servicePort,
			"",
			"",
			pl.Cluster,
		) {
			poolPathRefs = append(
				poolPathRefs,
				poolPathRef{
					route.Spec.Path,
					ctlr.formatPoolName(
						route.ObjectMeta.Namespace,
						route.Spec.To.Name,
						pl.ServicePort,
						"",
						"",
						pl.Cluster),
					[]string{route.Spec.Host},
				})
		}
	}

	if rsCfg.Virtual.VirtualAddress.Port == DEFAULT_HTTPS_PORT {
		ctlr.updateDataGroupForABRoute(route,
			getRSCfgResName(rsCfg.Virtual.Name, AbDeploymentDgName),
			rsCfg.Virtual.Partition,
			route.Namespace,
			rsCfg.IntDgMap,
			servicePort,
		)
		if (isRoutePathBasedABDeployment(route) || isRoutePathBasedRatioDeployment(route, ctlr.haModeType)) &&
			(route.Spec.TLS.Termination == TLSEdge ||
				(route.Spec.TLS.Termination == TLSReencrypt && strings.ToLower(string(route.Spec.TLS.InsecureEdgeTerminationPolicy)) != TLSAllowInsecure)) {
			ctlr.HandlePathBasedABIRule(rsCfg, route.Spec.Host, string(route.Spec.TLS.Termination))
		}
	}

	return ctlr.handleTLS(rsCfg, TLSContext{route.ObjectMeta.Name,
		route.ObjectMeta.Namespace,
		Route,
		tlsReferenceType,
		route.Spec.Host,
		DEFAULT_HTTPS_PORT,
		DEFAULT_HTTP_PORT,
		vServerAddr,
		string(route.Spec.TLS.Termination),
		strings.ToLower(string(route.Spec.TLS.InsecureEdgeTerminationPolicy)),
		poolPathRefs,
		bigIPSSLProfiles,
	})
}

/*
getSSLProfileOption returns which ssl profile option to be used for the route
Examples: annotation, routeCertificate, defaultSSL, invalid
*/
func (ctlr *Controller) getSSLProfileOption(route *routeapi.Route, plcSSLProfiles rgPlcSSLProfiles) string {
	sslProfileOption := ""
	if route == nil || route.Spec.TLS == nil || route.Spec.TLS.Termination == routeapi.TLSTerminationPassthrough {
		return sslProfileOption
	}
	if len(plcSSLProfiles.clientSSLs) > 0 {
		sslProfileOption = PolicySSLOption
	} else if _, ok := route.ObjectMeta.Annotations[resource.F5ClientSslProfileAnnotation]; ok {
		sslProfileOption = AnnotationSSLOption
	} else if route.Spec.TLS != nil && route.Spec.TLS.Key != "" && route.Spec.TLS.Certificate != "" {
		sslProfileOption = RouteCertificateSSLOption
	} else if ctlr.resources != nil && ctlr.resources.baseRouteConfig != (BaseRouteConfig{}) &&
		ctlr.resources.baseRouteConfig.DefaultTLS != (DefaultSSLProfile{}) &&
		ctlr.resources.baseRouteConfig.DefaultTLS.Reference == BIGIP {
		sslProfileOption = DefaultSSLOption
	} else {
		sslProfileOption = InvalidSSLOption
	}
	return sslProfileOption
}

// return the services associated with a virtualserver pool (svc names + weight)
func (ctlr *Controller) GetPoolBackends(pool *cisapiv1.VSPool) []SvcBackendCxt {
	var sbcs []SvcBackendCxt
	defaultWeight := 100
	if ctlr.haModeType != Ratio {
		numOfBackends := 1
		if pool.AlternateBackends != nil {
			numOfBackends += len(pool.AlternateBackends)
		}
		sbcs = make([]SvcBackendCxt, numOfBackends)

		beIdx := 0
		sbcs[beIdx].Name = pool.Service

		if pool.Weight != nil {
			sbcs[beIdx].Weight = float64(*pool.Weight)
		} else {
			sbcs[beIdx].Weight = float64(defaultWeight)
		}
		if pool.ServiceNamespace != "" {
			sbcs[beIdx].SvcNamespace = pool.ServiceNamespace
		}
		if pool.AlternateBackends != nil {
			for _, svc := range pool.AlternateBackends {
				beIdx = beIdx + 1
				sbcs[beIdx].Name = svc.Service
				if svc.Weight != nil {
					sbcs[beIdx].Weight = float64(*svc.Weight)
				} else {
					sbcs[beIdx].Weight = float64(defaultWeight)
				}
				sbcs[beIdx].SvcNamespace = svc.ServiceNamespace
			}
		}
		return sbcs
	}
	// Prepare backends for Ratio mode
	/*
				Effective weight for a service(S) = Ws/Wt * Rc/Rt
				Ws => Weight specified for the service S
				Wt => Sum of weights of all services (VS service + Alternate backends + External services)
				Rc => Ratio specified for the cluster on which the service is running
				Rt => Sum of all the ratios of the clusters excluding those cluster ratios which don't contribute to this VS services

				For example:
					Route(P) (Route in primary cluster)=> Associated services are (Rs(P), ABs1(P), ABs2(P), Svc1 and Svc2)
					Route(S) (Route in secondary cluster)=> Associated services are (Rs(S), ABs1(S), ABs2(S), Svc1 and Svc2)
					* Where (P) and (S) stand for primary and secondary cluster

					If there are 4 clusters CL1, CL2, CL3, CL4 and ratios defined for these clusters along with the services' weights are
					CL1(Primary)   => Ratio: 4 ([VS service Rs(P) => weight 30 ] + Alternate backend services [ ABs1(P) => weight:10, ABs2(P) => weight:20 ])
					CL2(Secondary) => Ratio: 3 ([VS service Rs(S) => weight 30 ] + Alternate backend services [ ABs1(S) => weight:10, ABs2(S) => weight:20 ])
					CL3 		   => Ratio: 2 ([Svc1 => weight 20], [svc2 => weight 10])
					CL4 		   => Ratio: 1 (No services )

					Effective weight calculation considering the service weights as well as the cluster ratio:
					Total Weight(Wt) = 30[Rs(P)] + 30[Rs(S)]  + 10[ABs1(P)] + 10[ABs1(S)] + 20[ABs2(P)] + 20[ABs2(S)] + 20(Svc1) + 10(Svc2) = 150
					Total Ratio(Rt) = 4(CL1) + 3(CL2) + 2(CL3) = 9 [Excluded CL4 ratio as it doesn't contribute to the VS's services]
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
	localClusterPoolRestricted := ctlr.isAddingPoolRestricted(ctlr.multiClusterConfigs.LocalClusterName)
	hAPeerClusterPoolRestricted := true // By default, skip HA cluster service backend
	// If HA peer cluster is present then update the hAPeerClusterPoolRestricted state based on the cluster pool state
	if ctlr.multiClusterConfigs.HAPairClusterName != "" {
		hAPeerClusterPoolRestricted = ctlr.isAddingPoolRestricted(ctlr.multiClusterConfigs.HAPairClusterName)
	}
	// factor is used to track whether both the primary and secondary cluster needs to be considered or none/one/both of
	// them have to be considered( this is based on multiCluster mode and cluster pool state)
	factor := 0
	if !localClusterPoolRestricted {
		factor++ // it ensures local cluster services associated with the VS are considered
	}
	if ctlr.multiClusterConfigs.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
		factor++ // it ensures HA peer cluster services associated with the VS are considered
	}
	// clusterSvcMap helps in ensuring the cluster ratio is considered only if there is at least one service associated
	// with the VS running in that cluster
	clusterSvcMap := make(map[string]struct{})
	clusterSvcMap[""] = struct{}{} // "" is used as key for the local cluster where this CIS is running
	// totalClusterRatio stores the sum total of all the ratio of clusters contributing services to this VS
	totalClusterRatio := 0.0
	// totalSvcWeights stores the sum total of all the weights of services associated with this VS
	totalSvcWeights := 0.0
	// Include local cluster ratio in the totalClusterRatio calculation
	if !localClusterPoolRestricted {
		totalClusterRatio += float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.LocalClusterName])
	}
	// Include HA partner cluster ratio in the totalClusterRatio calculation
	if ctlr.multiClusterConfigs.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
		totalClusterRatio += float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.HAPairClusterName])
	}
	// if adding pool member is restricted for both local or HA partner cluster then skip adding service weights for both the clusters
	if !localClusterPoolRestricted || !hAPeerClusterPoolRestricted {
		if pool.Weight != nil {
			totalSvcWeights += float64(*pool.Weight) * float64(factor)
		} else {
			totalSvcWeights += float64(defaultWeight) * float64(factor)
		}
	}
	// count of valid external multiCluster services
	validExtSvcCount := 0
	// Process multiCluster services
	for i, svc := range pool.MultiClusterServices {
		// Skip the service if it's not valid
		// This includes check for cis should be running in multiCluster mode, external server parameters validity and
		// cluster credentials must be specified in the extended configmap
		if ctlr.checkValidExtendedService(svc) != nil || ctlr.isAddingPoolRestricted(svc.ClusterName) {
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
				zero := 0
				pool.MultiClusterServices[i].Weight = &zero
			}
		}
		// If weight is nil then update the weight to defualt value 100 so that further processing won't require this check
		if svc.Weight == nil {
			pool.MultiClusterServices[i].Weight = &defaultWeight
		}
		totalSvcWeights += float64(*pool.MultiClusterServices[i].Weight)
		validExtSvcCount++
	}
	numOfBackends := factor + validExtSvcCount
	if pool.AlternateBackends != nil && (!localClusterPoolRestricted || !hAPeerClusterPoolRestricted) {
		numOfBackends += len(pool.AlternateBackends) * factor
		for _, svc := range pool.AlternateBackends {
			if svc.Weight != nil {
				totalSvcWeights += float64(*svc.Weight) * float64(factor)
			} else {
				totalSvcWeights += float64(defaultWeight) * float64(factor)
			}
		}
	}

	// Now start creating the list of all the backends

	sbcs = make([]SvcBackendCxt, numOfBackends)

	// Calibrate totalSvcWeights and totalClusterRatio if any of these is 0 to avoid division by zero
	if totalSvcWeights == 0 {
		totalSvcWeights = 1
	}
	if totalClusterRatio == 0 {
		totalClusterRatio = 1
	}
	// Process VS spec primary service
	beIdx := -1
	// VS backend service in local cluster
	if !localClusterPoolRestricted {
		beIdx++
		sbcs[beIdx].Name = pool.Service
		if pool.ServiceNamespace != "" {
			sbcs[beIdx].SvcNamespace = pool.ServiceNamespace
		}
		if pool.Weight != nil {
			sbcs[beIdx].Weight = (float64(*pool.Weight) / totalSvcWeights) *
				(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.LocalClusterName]) / totalClusterRatio)
		} else {
			sbcs[beIdx].Weight = (float64(defaultWeight) / totalSvcWeights) *
				(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.LocalClusterName]) / totalClusterRatio)
		}
	}
	// VS backend service in HA partner cluster
	if ctlr.multiClusterConfigs.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
		beIdx++
		sbcs[beIdx].Name = pool.Service
		sbcs[beIdx].SvcNamespace = pool.ServiceNamespace
		if pool.Weight != nil {
			sbcs[beIdx].Weight = (float64(*pool.Weight) / totalSvcWeights) *
				(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.HAPairClusterName]) / totalClusterRatio)
		} else {
			sbcs[beIdx].Weight = (float64(defaultWeight) / totalSvcWeights) *
				(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.HAPairClusterName]) / totalClusterRatio)
		}
		sbcs[beIdx].Cluster = ctlr.multiClusterConfigs.HAPairClusterName
	}
	// Process Alternate backends
	if pool.AlternateBackends != nil && (!localClusterPoolRestricted || !hAPeerClusterPoolRestricted) {
		for _, svc := range pool.AlternateBackends {
			if !localClusterPoolRestricted {
				beIdx = beIdx + 1
				sbcs[beIdx].Name = svc.Service
				sbcs[beIdx].SvcNamespace = svc.ServiceNamespace
				if svc.Weight != nil {
					sbcs[beIdx].Weight = (float64(*svc.Weight) / totalSvcWeights) *
						(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.LocalClusterName]) / totalClusterRatio)
				} else {
					sbcs[beIdx].Weight = (float64(defaultWeight) / totalSvcWeights) *
						(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.LocalClusterName]) / totalClusterRatio)
				}
			}
			// HA partner cluster
			if ctlr.multiClusterConfigs.HAPairClusterName != "" && !hAPeerClusterPoolRestricted {
				beIdx = beIdx + 1
				sbcs[beIdx].Name = svc.Service
				sbcs[beIdx].SvcNamespace = svc.ServiceNamespace
				if svc.Weight != nil {
					sbcs[beIdx].Weight = (float64(*svc.Weight) / totalSvcWeights) *
						(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.HAPairClusterName]) / totalClusterRatio)
				} else {
					sbcs[beIdx].Weight = (float64(defaultWeight) / totalSvcWeights) *
						(float64(*ctlr.clusterRatio[ctlr.multiClusterConfigs.HAPairClusterName]) / totalClusterRatio)
				}
				sbcs[beIdx].Cluster = ctlr.multiClusterConfigs.HAPairClusterName
			}
		}
	}
	// External services
	for _, svc := range pool.MultiClusterServices {
		// Skip invalid extended service
		if ctlr.checkValidExtendedService(svc) != nil || ctlr.isAddingPoolRestricted(svc.ClusterName) {
			continue
		}
		beIdx = beIdx + 1
		sbcs[beIdx].Name = svc.SvcName
		if r, ok := ctlr.clusterRatio[svc.ClusterName]; ok {
			// Here we don't need to check if Weight is nil or not as we have already assigned the default value in case of nil
			sbcs[beIdx].Weight = (float64(*svc.Weight) / totalSvcWeights) *
				(float64(*r) / totalClusterRatio)
		} else {
			// Service is from unknown cluster, so set weight to zero which is already set
			sbcs[beIdx].Weight = 0
		}
		sbcs[beIdx].Cluster = svc.ClusterName
		sbcs[beIdx].SvcNamespace = svc.Namespace
	}
	return sbcs
}

// updatePoolMembersConfig updates the common config related to pool members
func (ctlr *Controller) updatePoolMembersConfig(poolMembers *[]PoolMember, clusterName string, podConnections int32) {
	for i := 0; i < len(*poolMembers); i++ {
		// updates the admin state of pool members based on the cluster admin state
		if adminState, ok := ctlr.clusterAdminState[clusterName]; ok && adminState != "" {
			(*poolMembers)[i].AdminState = string(adminState)
		}
		// updates the connection limit of pool members based on the pod connections allowed
		if podConnections != 0 {
			(*poolMembers)[i].ConnectionLimit = podConnections
		}
	}
}

// formatMonitorNameForMultiCluster formats the monitor name based on the cluster name
func (ctlr *Controller) formatMonitorNameForMultiCluster(monitorName string, cluster string) string {
	// Update monitor name only in case of multiCluster ratio mode as in this mode only CIS creates distinct pools for
	// services in different clusters,thus we need to update the monitor name to make them distinguishable
	if ctlr.multiClusterMode == "" || len(ctlr.clusterRatio) == 0 {
		return monitorName
	}
	if cluster != "" {
		// If cluster is specified then append the cluster name to the monitor name
		monitorName += "_" + cluster
	} else {
		// If cluster is not specified then it means that  the monitor is for a pool belonging to the local cluster,
		// where CIS is running. In this scenario append the local cluster name to the monitor name.
		// For standalone mode as local cluster name is not specified, append "_local_cluster" to the monitor name.
		// For all other modes the local cluster name is provided in the extended configmap as Primary/Secondary cluster
		// details, which is stored in LocalClusterName based on whether the CIS is running in primary or secondary mode.
		if ctlr.multiClusterMode != StandAloneCIS {
			monitorName += "_" + ctlr.multiClusterConfigs.LocalClusterName
		} else {
			monitorName += "_local_cluster"
		}
	}
	return monitorName
}

func hasWildcardHost(hosts []string) bool {
	for _, host := range hosts {
		if strings.HasPrefix(host, "*") {
			return true
		}
	}
	return false
}

// getUniqueHosts returns unique hosts from host and hostAliases
func getUniqueHosts(host string, hostAliases []string) []string {
	uniqueHostsMap := make(map[string]struct{})
	uniqueHostsMap[host] = struct{}{}
	var uniqueHosts []string
	uniqueHosts = append(uniqueHosts, host)
	for _, host := range hostAliases {
		if _, ok := uniqueHostsMap[host]; !ok {
			uniqueHostsMap[host] = struct{}{}
			uniqueHosts = append(uniqueHosts, host)
		}
	}
	return uniqueHosts
}
