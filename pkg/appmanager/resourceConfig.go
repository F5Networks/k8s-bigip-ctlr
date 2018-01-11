/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"github.com/xeipuuv/gojsonschema"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
)

// Definition of a Big-IP Virtual Server config
// Most of this comes directly from a ConfigMap, with the exception
// of NodePort and Nodes, which are dynamic
// For more information regarding this structure and data model:
//  f5/schemas/bigip-virtual-server_[version].json

const DEFAULT_MODE string = "tcp"
const DEFAULT_BALANCE string = "round-robin"
const DEFAULT_HTTP_PORT int32 = 80
const DEFAULT_HTTPS_PORT int32 = 443

// FIXME: remove this global variable.
var DEFAULT_PARTITION string

// Indicator to use an F5 schema
const schemaIndicator string = "f5schemadb://"

// Where the schemas reside locally
const schemaLocal string = "file:///app/vendor/src/f5/schemas/"

// Constants for CustomProfile.Type as defined in CCCL
const customProfileAll string = "all"
const customProfileClient string = "clientside"
const customProfileServer string = "serverside"

// Constants for CustomProfile.PeerCertMode
const peerCertRequired = "require"
const peerCertIgnored = "ignore"
const peerCertDefault = peerCertIgnored

func (v *Virtual) GetProfileCountByContext(context string) int {
	// Valid values of context are 'clientside', serverside', and 'all'.
	// 'all' does not mean all profiles, but profiles that can be used in
	// multiple contexts.

	profCt := 0

	for _, prof := range v.Profiles {
		if prof.Context == context {
			profCt++
		}
	}

	return profCt
}

func (v *Virtual) ReferencesProfile(profile CustomProfile) bool {
	for _, prof := range v.Profiles {
		if prof.Name == profile.Name &&
			prof.Partition == profile.Partition &&
			prof.Context == profile.Context {
			return true
		}
	}
	return false
}

func (v *Virtual) AddIRule(ruleName string) bool {
	for _, irule := range v.IRules {
		if irule == ruleName {
			return false
		}
	}
	v.IRules = append(v.IRules, ruleName)
	return true
}

func (v *Virtual) ToString() string {
	output, err := json.Marshal(v)
	if nil != err {
		log.Errorf("Unable to convert virtual {%+v} to string: %v", v, err)
		return ""
	}
	return string(output)
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

func (v *Virtual) AddOrUpdateProfile(prof ProfileRef) bool {
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
		if v.Profiles[i] == prof {
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

func (v *Virtual) RemoveProfile(prof ProfileRef) bool {
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
		// found, remove it and adjust the array.
		profCt -= 1
		copy(v.Profiles[i:], v.Profiles[i+1:])
		v.Profiles[profCt] = ProfileRef{}
		v.Profiles = v.Profiles[:profCt]
		return true
	}
	return false
}

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

// format the virtual server name for a ConfigMap
func formatConfigMapVSName(cm *v1.ConfigMap) string {
	return fmt.Sprintf("%s_%s", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
}

// format the pool name for a ConfigMap
func formatConfigMapPoolName(namespace, cmName, svc string) string {
	return fmt.Sprintf("cfgmap_%s_%s_%s", namespace, cmName, svc)
}

// format the virtual server name for an Ingress
func formatIngressVSName(ip string, port int32) string {
	// Strip any bracket characters; replace special characters ". : /"
	// with "-" and "%" with ".", for naming purposes
	ip = strings.Trim(ip, "[]")
	var replacer = strings.NewReplacer(".", "-", ":", "-", "/", "-", "%", ".")
	ip = replacer.Replace(ip)
	return fmt.Sprintf("ingress_%s_%d", ip, port)
}

// format the pool name for an Ingress
func formatIngressPoolName(namespace, svc string) string {
	return fmt.Sprintf("ingress_%s_%s", namespace, svc)
}

// format the rule name for an Ingress
func formatIngressRuleName(host, path, pool string) string {
	var rule string
	if path == "" {
		rule = fmt.Sprintf("ingress_%s_%s", host, pool)
	} else {
		path = strings.TrimPrefix(path, "/")
		rule = fmt.Sprintf("ingress_%s_%s_%s", host, path, pool)
	}
	return rule
}

func getRouteCanonicalService(route *routeapi.Route) string {
	return route.Spec.To.Name
}

// return the services associated with a route
func getRouteServiceNames(route *routeapi.Route) []string {
	numOfSvcs := 1
	if route.Spec.AlternateBackends != nil {
		numOfSvcs += len(route.Spec.AlternateBackends)
	}
	svcs := make([]string, numOfSvcs)

	svcIndex := 0
	if route.Spec.AlternateBackends != nil {
		for _, svc := range route.Spec.AlternateBackends {
			svcs[svcIndex], svcIndex = svc.Name, svcIndex+1
		}
	}
	svcs[svcIndex] = getRouteCanonicalService(route)

	return svcs
}

// Verify if the service is associated with the route
func existsRouteServiceName(route *routeapi.Route, expSvcName string) bool {
	// We don't expect an extensive list, so we're not using a map
	svcNames := getRouteServiceNames(route)
	for _, svcName := range svcNames {
		if expSvcName == svcName {
			return true
		}
	}
	return false
}

// format the pool name for a Route
func formatRoutePoolName(route *routeapi.Route, svcName string) string {
	return fmt.Sprintf("openshift_%s_%s",
		route.ObjectMeta.Namespace, svcName)
}

// format the Rule name for a Route
func formatRouteRuleName(route *routeapi.Route) string {
	return fmt.Sprintf("openshift_route_%s_%s", route.ObjectMeta.Namespace,
		route.ObjectMeta.Name)
}

// format the client ssl profile name for a Route
func makeRouteClientSSLProfileRef(partition, namespace, name string) ProfileRef {
	return ProfileRef{
		Partition: partition,
		Name:      fmt.Sprintf("openshift_route_%s_%s-client-ssl", namespace, name),
		Context:   customProfileClient,
	}
}

// format the server ssl profile name for a Route
func makeRouteServerSSLProfileRef(partition, namespace, name string) ProfileRef {
	return ProfileRef{
		Partition: partition,
		Name:      fmt.Sprintf("openshift_route_%s_%s-server-ssl", namespace, name),
		Context:   customProfileServer,
	}
}

func makeCertificateFileName(name string) string {
	// All certificates are currently in the Common partition
	return joinBigipPath("Common", name) + ".crt"
}

func extractCertificateName(fn string) string {
	// performs the reverse of makeCertificateFileName
	_, name := splitBigipPath(fn, false)
	if strings.HasSuffix(name, ".crt") {
		name = name[:len(name)-4]
	}
	return name
}

func formatIngressSslProfileName(secret string) string {
	profName := strings.TrimSpace(strings.TrimPrefix(secret, "/"))
	parts := strings.Split(profName, "/")
	switch len(parts) {
	case 2:
		profName = fmt.Sprintf("%v/%v", parts[0], parts[1])
	case 1:
		// This is technically supported on the Big-IP, but will fail in the
		// python driver. Issue a warning here for better context.
		log.Warningf("TLS secret '%v' does not contain a full path.", secret)
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("TLS secret '%v' is formatted incorrectly.", secret)
	}
	return profName
}

func convertStringToProfileRef(profileName, context string) ProfileRef {
	profName := strings.TrimSpace(strings.TrimPrefix(profileName, "/"))
	parts := strings.Split(profName, "/")
	profRef := ProfileRef{Context: context}
	switch len(parts) {
	case 2:
		profRef.Partition = parts[0]
		profRef.Name = parts[1]
	case 1:
		// This is technically supported on the Big-IP, but will fail in the
		// python driver. Issue a warning here for better context.
		log.Warningf("Profile name '%v' does not contain a full path.", profileName)
		profRef.Name = profileName
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("Profile name '%v' is formatted incorrectly.", profileName)
	}
	return profRef
}

// Store of CustomProfiles
type CustomProfileStore struct {
	sync.Mutex
	profs map[secretKey]CustomProfile
}

// Contructor for CustomProfiles
func NewCustomProfiles() CustomProfileStore {
	var cps CustomProfileStore
	cps.profs = make(map[secretKey]CustomProfile)
	return cps
}

// Key is resource name, value is unused (since go doesn't have set objects).
type resourceList map[string]bool

// Key is namespace/servicename/serviceport, value is map of resources.
type resourceKeyMap map[serviceKey]resourceList

// Key is resource name, value is pointer to config. May be shared.
type ResourceConfigMap map[string]*ResourceConfig

// Map of Resource configs
type Resources struct {
	sync.Mutex
	rm    resourceKeyMap
	rsMap ResourceConfigMap
}

type ResourceInterface interface {
	Init()
	Assign(key serviceKey, name string, cfg *ResourceConfig)
	Count() int
	CountOf(key serviceKey) int
	Get(key serviceKey, name string) (*ResourceConfig, bool)
	GetAll(key serviceKey) ResourceConfigs
	GetAllWithName(name string) (ResourceConfigs, []serviceKey)
	GetAllResources() ResourceConfigs
	Delete(key serviceKey, name string) bool
	ForEach(f ResourceEnumFunc)
}

// Constructor for Resources
func NewResources() *Resources {
	var rs Resources
	rs.Init()
	return &rs
}

// Receiver to initialize the object.
func (rs *Resources) Init() {
	rs.rm = make(resourceKeyMap)
	rs.rsMap = make(ResourceConfigMap)
}

// callback type for ForEach()
type ResourceEnumFunc func(key serviceKey, cfg *ResourceConfig)

// Add or update a Resource config, identified by key.
func (rs *Resources) Assign(svcKey serviceKey, name string, cfg *ResourceConfig) {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		rsList = make(resourceList)
		rs.rm[svcKey] = rsList
	}
	rsList[name] = true
	rs.rsMap[name] = cfg
}

func (cfg *ResourceConfig) GetName() string {
	if cfg.MetaData.ResourceType == "iapp" {
		return cfg.IApp.Name
	}
	return cfg.Virtual.Name
}

func (cfg *ResourceConfig) GetPartition() string {
	if cfg.MetaData.ResourceType == "iapp" {
		return cfg.IApp.Partition
	}
	return cfg.Virtual.Partition
}

// Count of all pools (svcKeys) currently stored.
func (rs *Resources) PoolCount() int {
	var ct int = 0
	for _, rsList := range rs.rm {
		ct += len(rsList)
	}
	return ct
}

// Count of all virtuals currently stored.
func (rs *Resources) VirtualCount() int {
	return len(rs.rsMap)
}

// Count of all configurations for a specific backend.
func (rs *Resources) CountOf(svcKey serviceKey) int {
	if rsList, ok := rs.rm[svcKey]; ok {
		return len(rsList)
	}
	return 0
}

func (rs *Resources) deleteImpl(
	rsList resourceList,
	rsName string,
	svcKey serviceKey,
) {
	// Remove mapping for a backend -> virtual/iapp
	delete(rsList, rsName)
	if len(rsList) == 0 {
		// Remove backend since no virtuals/iapps remain
		delete(rs.rm, svcKey)
	}

	// Look at all service keys to see if another references rsName
	useCt := 0
	for _, otherList := range rs.rm {
		for otherName, _ := range otherList {
			if otherName == rsName {
				// Found one, can't delete this resource yet.
				useCt += 1
				break
			}
		}
	}
	if useCt == 0 {
		delete(rs.rsMap, rsName)
	}
}

// Remove a specific resource configuration.
func (rs *Resources) Delete(svcKey serviceKey, name string) bool {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		// svcKey not found
		return false
	}
	if name == "" {
		// Delete all resources for svcKey
		for rsName, _ := range rsList {
			rs.deleteImpl(rsList, rsName, svcKey)
		}
		return true
	}
	if _, ok = rsList[name]; ok {
		// Delete specific named resource for svcKey
		rs.deleteImpl(rsList, name, svcKey)
		return true
	}
	return false
}

// Remove a svcKey's reference to a config (pool was removed)
func (rs *Resources) DeleteKeyRef(sKey serviceKey, name string) bool {
	rsList, ok := rs.rm[sKey]
	if !ok {
		// sKey not found
		return false
	}
	if _, ok = rsList[name]; ok {
		delete(rsList, name)
		return true
	}
	return false
}

// Iterate over all configurations, calling the supplied callback with each.
func (rs *Resources) ForEach(f ResourceEnumFunc) {
	for svcKey, rsList := range rs.rm {
		for rsName, _ := range rsList {
			cfg, _ := rs.rsMap[rsName]
			f(svcKey, cfg)
		}
	}
}

// Get a specific Resource cfg
func (rs *Resources) Get(svcKey serviceKey, name string) (*ResourceConfig, bool) {
	rsList, ok := rs.rm[svcKey]
	if !ok {
		return nil, ok
	}
	_, ok = rsList[name]
	if !ok {
		return nil, ok
	}
	resource, ok := rs.rsMap[name]
	return resource, ok
}

// Get a specific Resource cfg
func (rs *Resources) GetByName(name string) (*ResourceConfig, bool) {
	resource, ok := rs.rsMap[name]
	return resource, ok
}

// Get all configurations for a specific backend
func (rs *Resources) GetAll(svcKey serviceKey) ResourceConfigs {
	var cfgs ResourceConfigs
	rsList, ok := rs.rm[svcKey]
	if ok {
		for rsKey, _ := range rsList {
			cfgs = append(cfgs, rs.rsMap[rsKey])
		}
	}
	return cfgs
}

// Get all configurations with a specific name, spanning multiple backends
// This is for multi-service ingress
func (rs *Resources) GetAllWithName(name string) (ResourceConfigs, []serviceKey) {
	var cfgs ResourceConfigs
	var keys []serviceKey
	rs.ForEach(func(key serviceKey, cfg *ResourceConfig) {
		if name == cfg.Virtual.Name {
			cfgs = append(cfgs, cfg)
			keys = append(keys, key)
		}
	})
	return cfgs, keys
}

func (rs *Resources) GetAllResources() ResourceConfigs {
	var cfgs ResourceConfigs
	for _, cfg := range rs.rsMap {
		cfgs = append(cfgs, cfg)
	}
	return cfgs
}

func setProfilesForMode(mode string, cfg *ResourceConfig) {
	tcpProf := ProfileRef{
		Partition: "Common",
		Name:      "tcp",
		Context:   customProfileAll,
	}
	switch mode {
	case "http":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "http",
				Context:   customProfileAll,
			})
		cfg.Virtual.AddOrUpdateProfile(tcpProf)
	case "tcp":
		cfg.Virtual.IpProtocol = "tcp"
		cfg.Virtual.AddOrUpdateProfile(tcpProf)
	case "udp":
		cfg.Virtual.IpProtocol = "udp"
		cfg.Virtual.AddOrUpdateProfile(
			ProfileRef{
				Partition: "Common",
				Name:      "udp",
				Context:   customProfileAll,
			})
	}
}

// Unmarshal an expected ConfigMap object
func parseConfigMap(cm *v1.ConfigMap) (*ResourceConfig, error) {
	var cfg ResourceConfig
	var cfgMap ConfigMap

	if data, ok := cm.Data["data"]; ok {
		err := json.Unmarshal([]byte(data), &cfgMap)
		if nil != err {
			return nil, err
		}
		if schemaName, ok := cm.Data["schema"]; ok {
			// FIXME For now, "f5schemadb" means the schema is local
			// Trim whitespace and embedded quotes
			schemaName = strings.TrimSpace(schemaName)
			schemaName = strings.Trim(schemaName, "\"")
			if strings.HasPrefix(schemaName, schemaIndicator) {
				schemaName = strings.Replace(
					schemaName, schemaIndicator, schemaLocal, 1)
			}
			// Load the schema
			schemaLoader := gojsonschema.NewReferenceLoader(schemaName)
			schema, err := gojsonschema.NewSchema(schemaLoader)
			if err != nil {
				return &cfg, err
			}
			// Load the ConfigMap data and validate
			dataLoader := gojsonschema.NewStringLoader(data)
			result, err := schema.Validate(dataLoader)
			if err != nil {
				return &cfg, err
			}

			//Check if we care about the partition specified in the configmap
			if cfgMap.VirtualServer.Frontend.Partition != DEFAULT_PARTITION {
				var errStr string = fmt.Sprintf("The partition '%s' in the ConfigMap does not match '%s' that the controller watches for", cfgMap.VirtualServer.Frontend.Partition, DEFAULT_PARTITION)
				return &cfg, errors.New(errStr)
			}
			if result.Valid() {
				ns := cm.ObjectMeta.Namespace
				copyConfigMap(formatConfigMapVSName(cm), ns, &cfg, &cfgMap)

				// Checking for annotation in VS, not iApp
				if cfg.MetaData.ResourceType != "iapp" && cfg.Virtual.VirtualAddress != nil {
					// Precedence to configmap bindAddr if annotation is also set
					if cfg.Virtual.VirtualAddress.BindAddr != "" &&
						cm.ObjectMeta.Annotations[f5VsBindAddrAnnotation] != "" {
						log.Warningf(
							"Both configmap bindAddr and %s annotation are set. "+
								"Choosing configmap's bindAddr...", f5VsBindAddrAnnotation)
					} else if cfg.Virtual.VirtualAddress.BindAddr == "" {
						// Check for IP annotation provided by IPAM system
						if addr, ok := cm.ObjectMeta.Annotations[f5VsBindAddrAnnotation]; ok == true {
							cfg.Virtual.SetVirtualAddress(addr, 0)
						} else {
							log.Infof("No virtual IP was specified for the virtual server %s creating pool only.", cm.ObjectMeta.Name)
						}
					}
				}
			} else {
				var errors []string
				for _, desc := range result.Errors() {
					errors = append(errors, desc.String())
				}
				return &cfg, fmt.Errorf("configMap is not valid, errors: %q", errors)
			}
		} else {
			return &cfg, fmt.Errorf("configmap %s does not contain schema key",
				cm.ObjectMeta.Name)
		}
	} else {
		return nil, fmt.Errorf("configmap %s does not contain data key",
			cm.ObjectMeta.Name)
	}

	return &cfg, nil
}

func copyConfigMap(virtualName, ns string, cfg *ResourceConfig, cfgMap *ConfigMap) {
	cmName := strings.Split(virtualName, "_")[1]
	poolName := formatConfigMapPoolName(ns, cmName, cfgMap.VirtualServer.Backend.ServiceName)
	if cfgMap.VirtualServer.Frontend.IApp == "" {
		// Handle virtual server specific config.
		cfg.MetaData.ResourceType = "configmap"
		cfg.Virtual.Name = virtualName
		cfg.Virtual.Partition = cfgMap.VirtualServer.Frontend.Partition
		cfg.Virtual.Enabled = true
		cfg.Virtual.SourceAddrTranslation.Type = "automap"
		cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, poolName)

		// If mode not set, use default
		mode := DEFAULT_MODE
		if cfgMap.VirtualServer.Frontend.Mode != "" {
			mode = strings.ToLower(cfgMap.VirtualServer.Frontend.Mode)
		}
		setProfilesForMode(mode, cfg)

		if nil != cfgMap.VirtualServer.Frontend.VirtualAddress {
			cfg.Virtual.SetVirtualAddress(
				cfgMap.VirtualServer.Frontend.VirtualAddress.BindAddr,
				cfgMap.VirtualServer.Frontend.VirtualAddress.Port)
		} else {
			// Pool-only
			cfg.Virtual.SetVirtualAddress("", 0)
		}
		if nil != cfgMap.VirtualServer.Frontend.SslProfile {
			if len(cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileName) > 0 {
				profRef := convertStringToProfileRef(
					cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileName,
					customProfileClient)
				cfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				for _, profName := range cfgMap.VirtualServer.Frontend.SslProfile.F5ProfileNames {
					profRef := convertStringToProfileRef(profName, customProfileClient)
					cfg.Virtual.AddOrUpdateProfile(profRef)
				}
			}
		}
	} else {
		// Handle IApp specific config.
		cfg.MetaData.ResourceType = "iapp"
		cfg.IApp.Name = virtualName
		cfg.IApp.Partition = cfgMap.VirtualServer.Frontend.Partition
		cfg.IApp.IApp = cfgMap.VirtualServer.Frontend.IApp
		cfg.IApp.IAppPoolMemberTable = cfgMap.VirtualServer.Frontend.IAppPoolMemberTable
		cfg.IApp.IAppOptions = cfgMap.VirtualServer.Frontend.IAppOptions
		cfg.IApp.IAppTables = cfgMap.VirtualServer.Frontend.IAppTables
		cfg.IApp.IAppVariables = cfgMap.VirtualServer.Frontend.IAppVariables
		poolName = virtualName
	}

	// If balance not set, use default
	var balance string
	if cfgMap.VirtualServer.Frontend.Balance == "" {
		balance = DEFAULT_BALANCE
	} else {
		balance = cfgMap.VirtualServer.Frontend.Balance
	}
	var monitorNames []string
	for index, mon := range cfgMap.VirtualServer.Backend.HealthMonitors {
		monitor := Monitor{
			// Append the protocol to the monitor names to differentiate them.
			// Also add a monitor index to the name to be consistent with the
			// marathon-bigip-ctlr. Since the monitor names are already unique here,
			// appending a '0' is sufficient.
			Name:      fmt.Sprintf("%s_%d_%s", poolName, index, mon.Protocol),
			Partition: cfgMap.VirtualServer.Frontend.Partition,
			Interval:  mon.Interval,
			Type:      mon.Protocol,
			Send:      mon.Send,
			Recv:      mon.Recv,
			Timeout:   mon.Timeout,
		}
		cfg.Monitors = append(cfg.Monitors, monitor)
		fullName := fmt.Sprintf("/%s/%s",
			cfgMap.VirtualServer.Frontend.Partition, monitor.Name)
		monitorNames = append(monitorNames, fullName)
	}
	pool := Pool{
		Name:         poolName,
		Partition:    cfgMap.VirtualServer.Frontend.Partition,
		Balance:      balance,
		ServiceName:  cfgMap.VirtualServer.Backend.ServiceName,
		ServicePort:  cfgMap.VirtualServer.Backend.ServicePort,
		Members:      nil,
		MonitorNames: monitorNames,
	}
	cfg.Pools = append(cfg.Pools, pool)
}

// Create a ResourceConfig based on an Ingress resource config
func createRSConfigFromIngress(
	ing *v1beta1.Ingress,
	resources *Resources,
	ns string,
	svcIndexer cache.Indexer,
	pStruct portStruct,
	defaultIP string,
) *ResourceConfig {
	if class, ok := ing.ObjectMeta.Annotations[k8sIngressClass]; ok == true {
		if class != "f5" {
			return nil
		}
	}

	var cfg ResourceConfig
	var balance string
	if bal, ok := ing.ObjectMeta.Annotations[f5VsBalanceAnnotation]; ok == true {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	if partition, ok := ing.ObjectMeta.Annotations[f5VsPartitionAnnotation]; ok == true {
		cfg.Virtual.Partition = partition
	} else {
		cfg.Virtual.Partition = DEFAULT_PARTITION
	}

	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[f5VsBindAddrAnnotation]; ok == true {
		if addr == "controller-default" {
			bindAddr = defaultIP
		} else {
			bindAddr = addr
		}
	} else {
		log.Infof("No virtual IP was specified for the virtual server %s, creating pool only.",
			ing.ObjectMeta.Name)
	}
	cfg.Virtual.Name = formatIngressVSName(bindAddr, pStruct.port)

	// Create our pools and policy/rules based on the Ingress
	var pools Pools
	var plcy *Policy
	var rules *Rules
	if nil != ing.Spec.Rules { //multi-service
		for _, rule := range ing.Spec.Rules {
			if nil != rule.IngressRuleValue.HTTP {
				for _, path := range rule.IngressRuleValue.HTTP.Paths {
					exists := false
					for _, pl := range pools {
						if pl.ServiceName == path.Backend.ServiceName &&
							pl.ServicePort == path.Backend.ServicePort.IntVal {
							exists = true
						}
					}
					if exists {
						continue
					}
					// If service doesn't exist, don't create a pool for it
					sKey := ns + "/" + path.Backend.ServiceName
					_, svcFound, _ := svcIndexer.GetByKey(sKey)
					if !svcFound {
						continue
					}
					pool := Pool{
						Name: formatIngressPoolName(
							ing.ObjectMeta.Namespace,
							path.Backend.ServiceName,
						),
						Partition:   cfg.Virtual.Partition,
						Balance:     balance,
						ServiceName: path.Backend.ServiceName,
						ServicePort: path.Backend.ServicePort.IntVal,
					}
					pools = append(pools, pool)
				}
			}
		}
		rules = processIngressRules(&ing.Spec, pools, cfg.Virtual.Partition)
		plcy = createPolicy(*rules, cfg.Virtual.Name, cfg.Virtual.Partition)
	} else { // single-service
		pool := Pool{
			Name: formatIngressPoolName(
				ing.ObjectMeta.Namespace,
				ing.Spec.Backend.ServiceName,
			),
			Partition:   cfg.Virtual.Partition,
			Balance:     balance,
			ServiceName: ing.Spec.Backend.ServiceName,
			ServicePort: ing.Spec.Backend.ServicePort.IntVal,
		}
		pools = append(pools, pool)
		cfg.Virtual.PoolName = joinBigipPath(cfg.Virtual.Partition, pool.Name)
	}

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we already have any Ingresses for this IP:Port
	if oldCfg, exists := resources.GetByName(cfg.Virtual.Name); exists {
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
		if len(cfg.Pools) > 1 {
			cfg.Virtual.PoolName = ""
		}
		// If any of the new rules already exist, update them; else add them
		if len(cfg.Policies) > 0 && rules != nil {
			policy := cfg.Policies[0]
			for _, newRule := range *rules {
				found := false
				for i, rl := range policy.Rules {
					if rl.Name == newRule.Name || rl.FullURI == newRule.FullURI {
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
	} else { // This is a new VS for an Ingress
		cfg.MetaData.ResourceType = "ingress"
		cfg.Virtual.Enabled = true
		setProfilesForMode("http", &cfg)
		cfg.Virtual.SourceAddrTranslation.Type = "automap"
		cfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		cfg.Pools = append(cfg.Pools, pools...)
		if plcy != nil {
			cfg.SetPolicy(*plcy)
		}
	}

	return &cfg
}

func createRSConfigFromRoute(
	route *routeapi.Route,
	svcName string,
	resources Resources,
	routeConfig RouteConfig,
	pStruct portStruct,
	svcIndexer cache.Indexer,
	svcFwdRulesMap ServiceFwdRuleMap,
) (ResourceConfig, error, Pool) {
	var rsCfg ResourceConfig
	rsCfg.MetaData.RouteProfs = make(map[routeKey]string)
	var policyName, rsName string

	if pStruct.protocol == "http" {
		policyName = "openshift_insecure_routes"
		rsName = routeConfig.HttpVs
	} else {
		policyName = "openshift_secure_routes"
		rsName = routeConfig.HttpsVs
	}

	var backendPort int32
	var err error
	if route.Spec.Port != nil {
		strVal := route.Spec.Port.TargetPort.StrVal
		if strVal == "" {
			backendPort = route.Spec.Port.TargetPort.IntVal
		} else {
			backendPort, err = getServicePort(route, svcName, svcIndexer, strVal)
			if nil != err {
				log.Warningf("%v", err)
			}
		}
	} else {
		backendPort, err = getServicePort(route, svcName, svcIndexer, "")
		if nil != err {
			log.Warningf("%v", err)
		}
	}
	var balance string
	if bal, ok := route.ObjectMeta.Annotations[f5VsBalanceAnnotation]; ok {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}

	// Create the pool
	pool := Pool{
		Name:        formatRoutePoolName(route, svcName),
		Partition:   DEFAULT_PARTITION,
		Balance:     balance,
		ServiceName: svcName,
		ServicePort: backendPort,
	}
	// Create the rule
	uri := route.Spec.Host + route.Spec.Path
	rule, err := createRule(uri, pool.Name, pool.Partition, formatRouteRuleName(route))
	if nil != err {
		err = fmt.Errorf("Error configuring rule for Route %s: %v", route.ObjectMeta.Name, err)
		return rsCfg, err, Pool{}
	}

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we have any Routes already saved for this VS type
	if oldCfg, exists := resources.GetByName(rsName); exists {
		// If we do, use an existing config
		rsCfg.copyConfig(oldCfg)

		// If this pool doesn't already exist, add it
		var found bool
		for i, pl := range rsCfg.Pools {
			if pl.Name == pool.Name {
				// If port has changed, update it
				if pl.ServicePort != pool.ServicePort {
					rsCfg.Pools[i].ServicePort = pool.ServicePort
				}
				found = true
			}
		}
		if !found {
			rsCfg.Pools = append(rsCfg.Pools, pool)
		}
		// If rule already exists, update it; else add it
		found = false
		if len(rsCfg.Policies) > 0 {
			for i, rl := range rsCfg.Policies[0].Rules {
				if rl.Name == rule.Name || rl.FullURI == rule.FullURI {
					found = true
					rsCfg.Policies[0].Rules[i] = rule
				}
			}
		}
	} else { // This is a new VS for a Route
		rsCfg.MetaData.ResourceType = "route"
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.Enabled = true
		setProfilesForMode("http", &rsCfg)
		rsCfg.Virtual.SourceAddrTranslation.Type = "automap"
		rsCfg.Virtual.Partition = DEFAULT_PARTITION
		bindAddr := ""
		if routeConfig.RouteVSAddr != "" {
			bindAddr = routeConfig.RouteVSAddr
		}
		rsCfg.Virtual.SetVirtualAddress(bindAddr, pStruct.port)
		rsCfg.Pools = append(rsCfg.Pools, pool)
	}

	rsCfg.HandleRouteTls(route, pStruct.protocol, policyName, rule,
		svcFwdRulesMap)

	return rsCfg, nil, pool
}

// Copies from an existing config into our new config
func (rc *ResourceConfig) copyConfig(cfg *ResourceConfig) {
	rc.MetaData = cfg.MetaData
	rc.Virtual = cfg.Virtual
	rc.Virtual.Profiles = make([]ProfileRef, len(cfg.Virtual.Profiles))
	copy(rc.Virtual.Profiles, cfg.Virtual.Profiles)
	rc.Pools = make(Pools, len(cfg.Pools))
	copy(rc.Pools, cfg.Pools)
	rc.Monitors = make(Monitors, len(cfg.Monitors))
	copy(rc.Monitors, cfg.Monitors)
	rc.Policies = make([]Policy, len(cfg.Policies))
	copy(rc.Policies, cfg.Policies)
}

func (rc *ResourceConfig) HandleRouteTls(
	route *routeapi.Route,
	protocol string,
	policyName string,
	rule *Rule,
	svcFwdRulesMap ServiceFwdRuleMap,
) {
	tls := route.Spec.TLS
	if protocol == "http" {
		if nil == tls || len(tls.Termination) == 0 {
			rc.AddRuleToPolicy(policyName, rule)
		} else {
			// Handle redirect policy for edge. Reencrypt and passthrough do not
			// support redirect policies, despite what the OpenShift docs say.
			if tls.Termination == routeapi.TLSTerminationEdge {
				// edge supports 'allow' and 'redirect'
				switch tls.InsecureEdgeTerminationPolicy {
				case routeapi.InsecureEdgeTerminationPolicyAllow:
					rc.AddRuleToPolicy(policyName, rule)
				case routeapi.InsecureEdgeTerminationPolicyRedirect:
					redirectIRuleName := fmt.Sprintf("/%s/%s",
						DEFAULT_PARTITION, httpRedirectIRuleName)
					rc.Virtual.AddIRule(redirectIRuleName)
					// TLS config indicates to forward http to https.
					path := "/"
					if route.Spec.Path != "" {
						path = route.Spec.Path
					}
					svcFwdRulesMap.AddEntry(route.ObjectMeta.Namespace, route.Spec.To.Name,
						route.Spec.Host, path)
				}
			}
		}
	} else {
		// https
		if nil != tls {
			passThroughRuleName := fmt.Sprintf("/%s/%s",
				DEFAULT_PARTITION, sslPassthroughIRuleName)
			switch tls.Termination {
			case routeapi.TLSTerminationEdge:
				rc.AddRuleToPolicy(policyName, rule)
			case routeapi.TLSTerminationPassthrough:
				rc.Virtual.AddIRule(passThroughRuleName)
			case routeapi.TLSTerminationReencrypt:
				rc.Virtual.AddIRule(passThroughRuleName)
				rc.AddRuleToPolicy(policyName, rule)
			}
		}
	}
}

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

func (rc *ResourceConfig) RemovePolicy(toFind nameRef) {
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

func (rc *ResourceConfig) SetMonitor(pool *Pool, monitor Monitor) bool {
	var updated, found bool
	toFind := fmt.Sprintf("/%s/%s", monitor.Partition, monitor.Name)
	for _, name := range pool.MonitorNames {
		if name == toFind {
			found = true
			break
		}
	}

	if !found {
		pool.MonitorNames = append(pool.MonitorNames, toFind)
		updated = true
	}
	for i, mon := range rc.Monitors {
		if mon.Name == monitor.Name && mon.Partition == monitor.Partition {
			if !reflect.DeepEqual(rc.Monitors[i], monitor) {
				rc.Monitors[i] = monitor
				updated = true
			}
			return updated
		}
	}
	rc.Monitors = append(rc.Monitors, monitor)
	return updated
}

func (rc *ResourceConfig) RemoveMonitor(pool, monitor string) bool {
	var removed bool
	for i, pl := range rc.Pools {
		if pl.Name == pool {
			for j, mon := range pl.MonitorNames {
				if mon == monitor {
					if j >= len(pl.MonitorNames)-1 {
						pl.MonitorNames = pl.MonitorNames[:len(pl.MonitorNames)-1]
					} else {
						copy(pl.MonitorNames[j:], pl.MonitorNames[j+1:])
						pl.MonitorNames[len(pl.MonitorNames)-1] = ""
						pl.MonitorNames = pl.MonitorNames[:len(pl.MonitorNames)-1]
					}
					rc.Pools[i].MonitorNames = pl.MonitorNames
					removed = true
					break
				}
			}
		}
	}
	for i, mon := range rc.Monitors {
		name := strings.Split(monitor, "/")[2]
		if mon.Name == name {
			if i >= len(rc.Monitors)-1 {
				rc.Monitors = rc.Monitors[:len(rc.Monitors)-1]
			} else {
				copy(rc.Monitors[i:], rc.Monitors[i+1:])
				rc.Monitors[len(rc.Monitors)-1] = Monitor{}
				rc.Monitors = rc.Monitors[:len(rc.Monitors)-1]
			}
			removed = true
			break
		}
	}
	return removed
}

func (rc *ResourceConfig) RemovePoolAt(offset int) bool {
	if offset >= len(rc.Pools) {
		return false
	}
	copy(rc.Pools[offset:], rc.Pools[offset+1:])
	rc.Pools[len(rc.Pools)-1] = Pool{}
	rc.Pools = rc.Pools[:len(rc.Pools)-1]
	return true
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

// Sorting methods for unit testing
func (slice Virtuals) Len() int {
	return len(slice)
}

func (slice Virtuals) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name)
}

func (slice Virtuals) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortVirtuals() {
	sort.Sort(cfg.Virtuals)
	for _, vs := range cfg.Virtuals {
		sort.Sort(vs.Profiles)
	}
}

func (slice Pools) Len() int {
	return len(slice)
}

func (slice Pools) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name)
}

func (slice Pools) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortPools() {
	sort.Sort(cfg.Pools)
}

func (slice Monitors) Len() int {
	return len(slice)
}

func (slice Monitors) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].Name < slice[j].Name)
}

func (slice Monitors) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortMonitors() {
	sort.Sort(cfg.Monitors)
}

func (rc *ResourceConfig) SortMonitors() {
	sort.Sort(rc.Monitors)
}

func splitBigipPath(path string, keepSlash bool) (partition, objName string) {
	cleanPath := strings.TrimLeft(path, "/")
	slashPos := strings.Index(cleanPath, "/")
	if slashPos == -1 {
		// No partition
		objName = cleanPath
	} else {
		// Partition and name
		partition = cleanPath[:slashPos]
		if keepSlash {
			objName = cleanPath[slashPos:]
		} else {
			objName = cleanPath[slashPos+1:]
		}
	}
	return
}

func joinBigipPath(partition, objName string) string {
	if objName == "" {
		return ""
	}
	if partition == "" {
		return objName
	}
	return fmt.Sprintf("/%s/%s", partition, objName)
}

func NewIRule(name, partition, code string) *IRule {
	return &IRule{
		Name:      name,
		Partition: partition,
		Code:      code,
	}
}

func NewInternalDataGroup(name, partition string) *InternalDataGroup {
	// Need to explicitly initialize Records to an empty array so it isn't nil.
	return &InternalDataGroup{
		Name:      name,
		Partition: partition,
		Records:   []InternalDataGroupRecord{},
	}
}

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
	if peerCertMode == peerCertRequired {
		cp.CAFile = caFile
	}
	return cp
}

// If name is provided, return port number for that port name,
// else return the first port found from a Route's service.
func getServicePort(
	route *routeapi.Route,
	svcName string,
	svcIndexer cache.Indexer,
	name string,
) (int32, error) {
	ns := route.ObjectMeta.Namespace
	key := ns + "/" + svcName

	obj, found, err := svcIndexer.GetByKey(key)
	if nil != err {
		return 0, fmt.Errorf("Error looking for service '%s': %v", key, err)
	}
	if found {
		svc := obj.(*v1.Service)
		if name != "" {
			for _, port := range svc.Spec.Ports {
				if port.Name == name {
					return port.Port, nil
				}
			}
			return 0,
				fmt.Errorf("Could not find service port '%s' on service '%s'", name, key)
		} else {
			return svc.Spec.Ports[0].Port, nil
		}
	}
	return 0, fmt.Errorf("Could not find service ports for service '%s'", key)
}
