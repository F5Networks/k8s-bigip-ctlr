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

// Wrappers around the ssl profile name to simplify its use due to the
// pointer and nested depth.
func (v *Virtual) AddFrontendSslProfileName(name string) {
	if 0 == len(name) {
		return
	}
	if nil == v.SslProfile {
		// the pointer is nil, need to create the nested object
		v.SslProfile = &sslProfile{}
	}
	// Use a variable with a shorter name to make this code more readable.
	sslProf := v.SslProfile
	nbrProfs := len(sslProf.F5ProfileNames)
	if nbrProfs == 0 {
		if sslProf.F5ProfileName == name {
			// Adding same profile is a no-op.
			return
		}
		if sslProf.F5ProfileName == "" {
			// We only have one profile currently.
			sslProf.F5ProfileName = name
			return
		}
		// # profiles will be > 1, switch to array.
		insertProfileName(sslProf, sslProf.F5ProfileName, 0)
		sslProf.F5ProfileName = ""
	}

	// The ssl profile names are maintained as a sorted array.
	i := sort.SearchStrings(sslProf.F5ProfileNames, name)
	if i < len(sslProf.F5ProfileNames) && sslProf.F5ProfileNames[i] == name {
		// found, don't add a duplicate.
	} else {
		// Insert into the correct position.
		insertProfileName(sslProf, name, i)
	}
}

func insertProfileName(sslProf *sslProfile, name string, i int) {
	sslProf.F5ProfileNames = append(sslProf.F5ProfileNames, "")
	copy(sslProf.F5ProfileNames[i+1:], sslProf.F5ProfileNames[i:])
	sslProf.F5ProfileNames[i] = name
}

func (v *Virtual) RemoveFrontendSslProfileName(name string) bool {
	if 0 == len(name) || nil == v.SslProfile {
		return false
	}
	// Use a variable with a shorter name to make this code more readable.
	sslProf := v.SslProfile
	nbrProfs := len(sslProf.F5ProfileNames)
	if nbrProfs == 0 {
		if sslProf.F5ProfileName == name {
			v.SslProfile = nil
			return true
		}
		return false
	}
	// The ssl profile names are maintained as a sorted array.
	i := sort.SearchStrings(sslProf.F5ProfileNames, name)
	if i < nbrProfs && sslProf.F5ProfileNames[i] == name {
		// found, remove it and adjust the array.
		nbrProfs -= 1
		copy(sslProf.F5ProfileNames[i:], sslProf.F5ProfileNames[i+1:])
		sslProf.F5ProfileNames[nbrProfs] = ""
		sslProf.F5ProfileNames = sslProf.F5ProfileNames[:nbrProfs]
		if nbrProfs == 1 {
			// Stop using array.
			sslProf.F5ProfileName = sslProf.F5ProfileNames[0]
			sslProf.F5ProfileNames = []string{}
		}
		return true
	}
	return false
}

func (v *Virtual) GetFrontendSslProfileNames() []string {
	if nil == v.SslProfile {
		return []string{}
	}
	if "" != v.SslProfile.F5ProfileName {
		return []string{v.SslProfile.F5ProfileName}
	}
	return v.SslProfile.F5ProfileNames
}

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

	if context == customProfileClient {
		// Until client SSL profiles are stored exclusively within v.Profiles we
		// need to to count the ones in the frontend struct as well.
		profCt += len(v.GetFrontendSslProfileNames())
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
	if profile.Context == customProfileClient {
		// Until client SSL profiles are stored exclusively within v.Profiles we
		// need to look in frontend as well.
		nameToFind := fmt.Sprintf("%s/%s", profile.Partition, profile.Name)
		for _, profName := range v.GetFrontendSslProfileNames() {
			if profName == nameToFind {
				return true
			}
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

// format the namespace and name for use in the frontend definition
func formatConfigMapVSName(cm *v1.ConfigMap) string {
	return fmt.Sprintf("%v_%v", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
}

// format the namespace and name for use in the frontend definition
func formatIngressVSName(ing *v1beta1.Ingress, protocol string) string {
	return fmt.Sprintf("%v_%v-ingress_%s",
		ing.ObjectMeta.Namespace, ing.ObjectMeta.Name, protocol)
}

// format the namespace and name for use in the backend definition
func formatRoutePoolName(route *routeapi.Route) string {
	return fmt.Sprintf("openshift_%s_%s",
		route.ObjectMeta.Namespace, route.Spec.To.Name)
}

// format the Rule name for a Route
func formatRouteRuleName(route *routeapi.Route) string {
	return fmt.Sprintf("openshift_route_%s_%s", route.ObjectMeta.Namespace,
		route.ObjectMeta.Name)
}

// format the client ssl profile name for a Route
func formatRouteClientSSLName(partition, namespace, name string) string {
	if partition == "" {
		return fmt.Sprintf("openshift_route_%s_%s-client-ssl",
			namespace, name)
	}
	return fmt.Sprintf("%s/openshift_route_%s_%s-client-ssl",
		partition, namespace, name)
}

// format the server ssl profile name for a Route
func formatRouteServerSSLName(namespace, name string) string {
	return fmt.Sprintf("openshift_route_%s_%s-server-ssl", namespace, name)
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

type ResourceConfigMap map[string]*ResourceConfig

// Map of Resource configs
type Resources struct {
	sync.Mutex
	rm map[serviceKey]ResourceConfigMap
}

type ResourceInterface interface {
	Init()
	Assign(key serviceKey, name string, cfg *ResourceConfig)
	Count() int
	CountOf(key serviceKey) int
	Get(key serviceKey, name string) (*ResourceConfig, bool)
	GetAll(key serviceKey) (ResourceConfigMap, bool)
	GetAllWithName(name string) (ResourceConfigs, []serviceKey)
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
	rs.rm = make(map[serviceKey]ResourceConfigMap)
}

// callback type for ForEach()
type ResourceEnumFunc func(key serviceKey, cfg *ResourceConfig)

// Add or update a Resource config, identified by key.
func (rs *Resources) Assign(key serviceKey, name string, cfg *ResourceConfig) {
	rsMap, ok := rs.rm[key]
	if !ok {
		rsMap = make(map[string]*ResourceConfig)
		rs.rm[key] = rsMap
	}
	rsMap[name] = cfg
}

// Count of all configurations currently stored.
func (rs *Resources) Count() int {
	var ct int = 0
	for _, cfgs := range rs.rm {
		ct += len(cfgs)
	}
	return ct
}

// Count of all configurations for a specific backend.
func (rs *Resources) CountOf(key serviceKey) int {
	if rsMap, ok := rs.rm[key]; ok {
		return len(rsMap)
	}
	return 0
}

// Remove a specific resource configuration.
func (rs *Resources) Delete(key serviceKey, name string) bool {
	rsMap, ok := rs.rm[key]
	if !ok {
		return false
	}
	if name == "" {
		delete(rs.rm, key)
		return true
	}
	if _, ok := rsMap[name]; ok {
		delete(rsMap, name)
		if len(rsMap) == 0 {
			delete(rs.rm, key)
		}
		return true
	}
	return false
}

// Iterate over all configurations, calling the supplied callback with each.
func (rs *Resources) ForEach(f ResourceEnumFunc) {
	for key, cfgs := range rs.rm {
		for _, cfg := range cfgs {
			f(key, cfg)
		}
	}
}

// Get a specific Resource cfg
func (rs *Resources) Get(key serviceKey, name string) (*ResourceConfig, bool) {
	rsMap, ok := rs.rm[key]
	if !ok {
		return nil, ok
	}
	resource, ok := rsMap[name]
	return resource, ok
}

// Get all configurations for a specific backend
func (rs *Resources) GetAll(key serviceKey) (ResourceConfigMap, bool) {
	rsMap, ok := rs.rm[key]
	return rsMap, ok
}

// Get all configurations with a specific name, spanning multiple backends
// This is for multi-service ingress
func (rs *Resources) GetAllWithName(name string) (ResourceConfigs, []serviceKey) {
	var cfgs ResourceConfigs
	var keys []serviceKey
	rs.ForEach(func(key serviceKey, cfg *ResourceConfig) {
		if name == cfg.Virtual.VirtualServerName {
			cfgs = append(cfgs, cfg)
			keys = append(keys, key)
		}
	})
	return cfgs, keys
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
				cfg.Virtual.VirtualServerName = formatConfigMapVSName(cm)
				copyConfigMap(&cfg, &cfgMap)

				// Checking for annotation in VS, not iApp
				if cfg.Virtual.IApp == "" && cfg.Virtual.VirtualAddress != nil {
					// Precedence to configmap bindAddr if annotation is also set
					if cfg.Virtual.VirtualAddress.BindAddr != "" &&
						cm.ObjectMeta.Annotations["virtual-server.f5.com/ip"] != "" {
						log.Warning(
							"Both configmap bindAddr and virtual-server.f5.com/ip annotation are set. " +
								"Choosing configmap's bindAddr...")
					} else if cfg.Virtual.VirtualAddress.BindAddr == "" {
						// Check for IP annotation provided by IPAM system
						if addr, ok := cm.ObjectMeta.Annotations["virtual-server.f5.com/ip"]; ok == true {
							cfg.Virtual.VirtualAddress.BindAddr = addr
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

func copyConfigMap(cfg *ResourceConfig, cfgMap *ConfigMap) {
	// If mode not set, use default
	if cfgMap.VirtualServer.Frontend.Mode == "" {
		cfg.Virtual.Mode = DEFAULT_MODE
	} else {
		cfg.Virtual.Mode = cfgMap.VirtualServer.Frontend.Mode
	}
	// If balance not set, use default
	var balance string
	if cfgMap.VirtualServer.Frontend.Balance == "" {
		balance = DEFAULT_BALANCE
	} else {
		balance = cfgMap.VirtualServer.Frontend.Balance
	}

	cfg.Virtual.Partition = cfgMap.VirtualServer.Frontend.Partition
	cfg.Virtual.VirtualAddress = cfgMap.VirtualServer.Frontend.VirtualAddress
	cfg.Virtual.SslProfile = cfgMap.VirtualServer.Frontend.SslProfile
	cfg.Virtual.IApp = cfgMap.VirtualServer.Frontend.IApp
	cfg.Virtual.IAppPoolMemberTable = cfgMap.VirtualServer.Frontend.IAppPoolMemberTable
	cfg.Virtual.IAppOptions = cfgMap.VirtualServer.Frontend.IAppOptions
	cfg.Virtual.IAppTables = cfgMap.VirtualServer.Frontend.IAppTables
	cfg.Virtual.IAppVariables = cfgMap.VirtualServer.Frontend.IAppVariables

	var monitorNames []string
	var name string
	for index, mon := range cfgMap.VirtualServer.Backend.HealthMonitors {
		name = fmt.Sprintf("%s_%d_%s", cfg.Virtual.VirtualServerName, index, mon.Protocol)
		monitor := Monitor{
			// Append the protocol to the monitor names to differentiate them.
			// Also add a monitor index to the name to be consistent with the
			// marathon-bigip-ctlr. Since the monitor names are already unique here,
			// appending a '0' is sufficient.
			Name:      name,
			Partition: cfg.Virtual.Partition,
			Interval:  mon.Interval,
			Protocol:  mon.Protocol,
			Send:      mon.Send,
			Timeout:   mon.Timeout,
		}
		cfg.Monitors = append(cfg.Monitors, monitor)
		fullName := fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, monitor.Name)
		monitorNames = append(monitorNames, fullName)
	}
	pool := Pool{
		Name:         cfg.Virtual.VirtualServerName,
		Partition:    cfg.Virtual.Partition,
		Balance:      balance,
		ServiceName:  cfgMap.VirtualServer.Backend.ServiceName,
		ServicePort:  cfgMap.VirtualServer.Backend.ServicePort,
		Members:      nil,
		MonitorNames: monitorNames,
	}
	cfg.Pools = append(cfg.Pools, pool)
	cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, pool.Name)
}

// Create a ResourceConfig based on an Ingress resource config
func createRSConfigFromIngress(ing *v1beta1.Ingress,
	ns string,
	svcIndexer cache.Indexer,
	pStruct portStruct,
) *ResourceConfig {
	var cfg ResourceConfig

	if class, ok := ing.ObjectMeta.Annotations["kubernetes.io/ingress.class"]; ok == true {
		if class != "f5" {
			return nil
		}
	}
	cfg.Virtual.VirtualServerName = formatIngressVSName(ing, pStruct.protocol)
	cfg.Virtual.Mode = "http"
	var balance string
	if bal, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/balance"]; ok == true {
		balance = bal
	} else {
		balance = DEFAULT_BALANCE
	}
	cfg.Virtual.VirtualAddress = &virtualAddress{}
	cfg.Virtual.VirtualAddress.Port = pStruct.port

	if partition, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/partition"]; ok == true {
		cfg.Virtual.Partition = partition
	} else {
		cfg.Virtual.Partition = DEFAULT_PARTITION
	}

	if addr, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/ip"]; ok == true {
		cfg.Virtual.VirtualAddress.BindAddr = addr
	} else {
		log.Infof("No virtual IP was specified for the virtual server %s, creating pool only.",
			ing.ObjectMeta.Name)
	}

	if nil != ing.Spec.Rules { //multi-service
		index := 0
		poolName := cfg.Virtual.VirtualServerName
		for _, rule := range ing.Spec.Rules {
			if nil != rule.IngressRuleValue.HTTP {
				for _, path := range rule.IngressRuleValue.HTTP.Paths {
					exists := false
					for _, pl := range cfg.Pools {
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
						index++
						continue
					}
					if index > 0 {
						poolName = fmt.Sprintf("%s_%d", cfg.Virtual.VirtualServerName, index)
					}
					pool := Pool{
						Name:        poolName,
						Partition:   cfg.Virtual.Partition,
						Balance:     balance,
						ServiceName: path.Backend.ServiceName,
						ServicePort: path.Backend.ServicePort.IntVal,
					}
					cfg.Pools = append(cfg.Pools, pool)
					index++
				}
			}
		}
		rules := processIngressRules(&ing.Spec, cfg.Pools, cfg.Virtual.Partition)
		plcy := createPolicy(*rules, cfg.Virtual.VirtualServerName, cfg.Virtual.Partition)
		cfg.SetPolicy(*plcy)
	} else { // single-service
		pool := Pool{
			Name:        cfg.Virtual.VirtualServerName,
			Partition:   cfg.Virtual.Partition,
			Balance:     balance,
			ServiceName: ing.Spec.Backend.ServiceName,
			ServicePort: ing.Spec.Backend.ServicePort.IntVal,
		}
		cfg.Pools = append(cfg.Pools, pool)
		cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, pool.Name)
	}

	return &cfg
}

func createRSConfigFromRoute(
	route *routeapi.Route,
	resources Resources,
	routeConfig RouteConfig,
	pStruct portStruct,
) (ResourceConfig, error) {
	var rsCfg ResourceConfig
	var policyName, rsName string

	if pStruct.protocol == "http" {
		policyName = "openshift_insecure_routes"
		rsName = routeConfig.HttpVs
	} else {
		policyName = "openshift_secure_routes"
		rsName = routeConfig.HttpsVs
	}
	tls := route.Spec.TLS

	var backendPort int32
	if route.Spec.Port != nil {
		backendPort = route.Spec.Port.TargetPort.IntVal
	} else if tls != nil && len(tls.Termination) != 0 {
		if tls.Termination == routeapi.TLSTerminationPassthrough ||
			tls.Termination == routeapi.TLSTerminationReencrypt {
			backendPort = 443
		} else {
			backendPort = 80
		}
	} else {
		backendPort = 80
	}

	// Create the pool
	pool := Pool{
		Name:        formatRoutePoolName(route),
		Partition:   DEFAULT_PARTITION,
		Balance:     DEFAULT_BALANCE,
		ServiceName: route.Spec.To.Name,
		ServicePort: backendPort,
	}
	// Create the rule
	uri := route.Spec.Host + route.Spec.Path
	rule, err := createRule(uri, pool.Name, pool.Partition, formatRouteRuleName(route))
	if nil != err {
		err = fmt.Errorf("Error configuring rule for Route %s: %v", route.ObjectMeta.Name, err)
		return rsCfg, err
	}

	resources.Lock()
	defer resources.Unlock()
	// Check to see if we have any Routes already saved for this VS type
	cfgs, _ := resources.GetAllWithName(rsName)
	if len(cfgs) > 0 {
		// If we do, use an existing config
		rsCfg = *cfgs[0]
		// If this pool doesn't already exist, add it
		var found bool
		for _, pl := range rsCfg.Pools {
			if pl.Name == pool.Name {
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
				if rl.Name == rule.Name {
					found = true
					rsCfg.Policies[0].Rules[i] = rule
				}
			}
		}
		if !found {
			rsCfg.HandleRouteTls(tls, pStruct.protocol, policyName, rule)
		}
	} else { // This is a new VS for a Route
		rsCfg.MetaData.ResourceType = "route"
		rsCfg.Virtual.VirtualServerName = rsName
		rsCfg.Virtual.Mode = "http"
		rsCfg.Virtual.Partition = DEFAULT_PARTITION
		rsCfg.Virtual.VirtualAddress = &virtualAddress{}
		rsCfg.Virtual.VirtualAddress.Port = pStruct.port
		if routeConfig.RouteVSAddr != "" {
			rsCfg.Virtual.VirtualAddress.BindAddr = routeConfig.RouteVSAddr
		}
		rsCfg.Pools = append(rsCfg.Pools, pool)

		rsCfg.HandleRouteTls(tls, pStruct.protocol, policyName, rule)
	}

	return rsCfg, nil
}

func (rc *ResourceConfig) HandleRouteTls(
	tls *routeapi.TLSConfig,
	protocol string,
	policyName string,
	rule *Rule,
) {
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
		policy.Rules = append(policy.Rules, rule)
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

func (rc *ResourceConfig) SetMonitor(pool *Pool, monitor Monitor) {
	found := false
	toFind := fmt.Sprintf("/%s/%s", monitor.Partition, monitor.Name)
	for _, name := range pool.MonitorNames {
		if name == toFind {
			found = true
			break
		}
	}

	if !found {
		pool.MonitorNames = append(pool.MonitorNames, toFind)
	}
	for i, mon := range rc.Monitors {
		if mon.Name == monitor.Name && mon.Partition == monitor.Partition {
			rc.Monitors[i] = monitor
			return
		}
	}
	rc.Monitors = append(rc.Monitors, monitor)
}

// Sorting methods for unit testing
func (slice Virtuals) Len() int {
	return len(slice)
}

func (slice Virtuals) Less(i, j int) bool {
	return slice[i].Partition < slice[j].Partition ||
		(slice[i].Partition == slice[j].Partition &&
			slice[i].VirtualServerName < slice[j].VirtualServerName)
}

func (slice Virtuals) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (cfg *BigIPConfig) SortVirtuals() {
	sort.Sort(cfg.Virtuals)
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
	cProfiles CustomProfileStore,
) CustomProfile {
	return CustomProfile{
		Name:       profile.Name,
		Partition:  profile.Partition,
		Context:    profile.Context,
		Cert:       cert,
		Key:        key,
		ServerName: serverName,
		SNIDefault: sni,
	}
}
