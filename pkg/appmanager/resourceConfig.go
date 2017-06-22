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
	"strconv"
	"strings"
	"sync"

	log "f5/vlogger"

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

var DEFAULT_MODE string = "tcp"
var DEFAULT_BALANCE string = "round-robin"
var DEFAULT_HTTP_PORT int32 = 80
var DEFAULT_PARTITION string

type BigIPConfig struct {
	Virtuals []Virtual `json:"virtualServers,omitempty"`
	Pools    []Pool    `json:"pools,omitempty"`
	Monitors []Monitor `json:"monitors,omitempty"`
	Policies []Policy  `json:"l7Policies,omitempty"`
}

type metaData struct {
	Active   bool
	NodePort int32
}

type ResourceConfig struct {
	MetaData metaData  `json:"-"`
	Virtual  Virtual   `json:"virtual,omitempty"`
	Pools    []Pool    `json:"pools,omitempty"`
	Monitors []Monitor `json:"monitors,omitempty"`
	Policies []Policy  `json:"policies,omitempty"`
}

// virtual server frontend
type Virtual struct {
	VirtualServerName string `json:"name"`
	PoolName          string `json:"pool"`
	// Mutual parameter, partition
	Partition string `json:"partition"`

	// VirtualServer parameters
	Balance        string          `json:"balance,omitempty"`
	Mode           string          `json:"mode,omitempty"`
	VirtualAddress *virtualAddress `json:"virtualAddress,omitempty"`
	SslProfile     *sslProfile     `json:"sslProfile,omitempty"`
	Policies       []nameRef       `json:"policies,omitempty"`

	// iApp parameters
	IApp                string                    `json:"iapp,omitempty"`
	IAppPoolMemberTable iappPoolMemberTable       `json:"iappPoolMemberTable,omitempty"`
	IAppOptions         map[string]string         `json:"iappOptions,omitempty"`
	IAppTables          map[string]iappTableEntry `json:"iappTables,omitempty"`
	IAppVariables       map[string]string         `json:"iappVariables,omitempty"`
}

// Pool backend
type Pool struct {
	Name            string   `json:"name"`
	Partition       string   `json:"partition"`
	ServiceName     string   `json:"serviceName"`
	ServicePort     int32    `json:"servicePort"`
	PoolMemberAddrs []string `json:"poolMemberAddrs"`
	MonitorNames    []string `json:"monitor"`
}

// backend health monitor
type Monitor struct {
	Name      string `json:"name"`
	Partition string `json:"partition"`
	Interval  int    `json:"interval,omitempty"`
	Protocol  string `json:"protocol"`
	Send      string `json:"send,omitempty"`
	Timeout   int    `json:"timeout,omitempty"`
}

// virtual policy
type Policy struct {
	Name        string   `json:"name"`
	Partition   string   `json:"partition"`
	SubPath     string   `json:"subPath,omitempty"`
	Controls    []string `json:"controls,omitempty"`
	Description string   `json:"description,omitempty"`
	Legacy      bool     `json:"legacy,omitempty"`
	Requires    []string `json:"requires,omitempty"`
	Rules       []*Rule  `json:"rules,omitempty"`
	Strategy    string   `json:"strategy,omitempty"`
}

type Rule struct {
	Name       string       `json:"name"`
	FullURI    string       `json:"-"`
	Ordinal    int          `json:"ordinal,omitempty"`
	Actions    []*action    `json:"actions,omitempty"`
	Conditions []*condition `json:"conditions,omitempty"`
}

type action struct {
	Name      string `json:"name"`
	Pool      string `json:"pool",omitempty"`
	HttpReply bool   `json:"httpReply,omitempty"`
	Forward   bool   `json:"forward,omitempty"`
	Location  string `json:"location,omitempty"`
	Redirect  bool   `json:"redirect,omitempty"`
	Request   bool   `json:"request,omitempty"`
	Reset     bool   `json:"reset,omitempty"`
}

type condition struct {
	Name            string   `json:"name"`
	CaseInsensitive bool     `json:"caseInsensitive,omitempty"`
	Equals          bool     `json:"equals,omitempty"`
	EndsWith        bool     `json:"endsWith,omitempty"`
	External        bool     `json:"external,omitempty"`
	HTTPHost        bool     `json:"httpHost,omitempty"`
	Host            bool     `json:"host,omitempty"`
	HTTPURI         bool     `json:"httpUri,omitempty"`
	Index           int      `json:"index,omitempty"`
	PathSegment     bool     `json:"pathSegment,omitempty"`
	Present         bool     `json:"present,omitempty"`
	Remote          bool     `json:"remote,omitempty"`
	Request         bool     `json:"request,omitempty"`
	Scheme          bool     `json:"scheme,omitempty"`
	Values          []string `json:"values"`
}

type Rules []*Rule
type ruleMap map[string]*Rule

// virtual server policy/profile reference
type nameRef struct {
	Name      string `json:"name"`
	Partition string `json:"partition"`
}

// frontend bindaddr and port
type virtualAddress struct {
	BindAddr string `json:"bindAddr,omitempty"`
	Port     int32  `json:"port,omitempty"`
}

// frontend ssl profile
type sslProfile struct {
	F5ProfileName  string   `json:"f5ProfileName,omitempty"`
	F5ProfileNames []string `json:"f5ProfileNames,omitempty"`
}

// frontend pool member column definition
type iappPoolMemberColumn struct {
	Name  string `json:"name"`
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value,omitempty"`
}

// frontend pool member table
type iappPoolMemberTable struct {
	Name    string                 `json:"name"`
	Columns []iappPoolMemberColumn `json:"columns"`
}

// frontend iapp table entry
type iappTableEntry struct {
	Columns []string   `json:"columns,omitempty"`
	Rows    [][]string `json:"rows,omitempty"`
}

// Used to unmarshal ConfigMap data
type ConfigMap struct {
	VirtualServer struct {
		Backend  configMapBackend `json:"backend"`
		Frontend Virtual          `json:"frontend"`
	} `json:"virtualServer"`
}

type configMapBackend struct {
	ServiceName     string    `json:"serviceName"`
	ServicePort     int32     `json:"servicePort"`
	PoolMemberAddrs []string  `json:"poolMemberAddrs"`
	HealthMonitors  []Monitor `json:"healthMonitors,omitempty"`
}

// This is the format for each item in the health monitor annotation used
// in the Ingress object.
type IngressHealthMonitor struct {
	Path     string `json:"path"`
	Interval int    `json:"interval"`
	Send     string `json:"send"`
	Timeout  int    `json:"timeout"`
}
type IngressHealthMonitors []IngressHealthMonitor

type ingressRuleData struct {
	svcName   string
	svcPort   int32
	healthMon IngressHealthMonitor
	assigned  bool
}
type ingressPathToRuleMap map[string]*ingressRuleData
type ingressHostToPathMap map[string]ingressPathToRuleMap

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

func (v *Virtual) ToString() string {
	output, err := json.Marshal(v)
	if nil != err {
		log.Errorf("Unable to convert virtual {%+v} to string: %v", v, err)
		return ""
	}
	return string(output)
}

type ResourceConfigs []*ResourceConfig

func (slice ResourceConfigs) Len() int {
	return len(slice)
}

func (slice ResourceConfigs) Less(i, j int) bool {
	return slice[i].Pools[0].ServiceName <
		slice[j].Pools[0].ServiceName ||
		(slice[i].Pools[0].ServiceName ==
			slice[j].Pools[0].ServiceName &&
			slice[i].Pools[0].ServicePort <
				slice[j].Pools[0].ServicePort)
}

func (slice ResourceConfigs) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Indicator to use an F5 schema
var schemaIndicator string = "f5schemadb://"

// Where the schemas reside locally
var schemaLocal string = "file:///app/vendor/src/f5/schemas/"

// Virtual Server Key - unique server is Name + Port
type serviceKey struct {
	ServiceName string
	ServicePort int32
	Namespace   string
}

// format the namespace and name for use in the frontend definition
func formatConfigMapVSName(cm *v1.ConfigMap) string {
	return fmt.Sprintf("%v_%v", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
}

// format the namespace and name for use in the frontend definition
func formatIngressVSName(ing *v1beta1.Ingress) string {
	return fmt.Sprintf("%v_%v-ingress", ing.ObjectMeta.Namespace, ing.ObjectMeta.Name)
}

// format the namespace and name for use in the frontend definition
func formatIngressSslProfileName(secret string) string {
	profName := strings.TrimSpace(strings.TrimPrefix(secret, "/"))
	parts := strings.Split(profName, "/")
	switch len(parts) {
	case 2:
		profName = fmt.Sprintf("%v/%v", parts[0], parts[1])
	case 1:
		// This is technically supported on the Big-IP, but will fail in the
		// python driver. Issue a warning here for better context.
		log.Warningf("WARNING: TLS secret '%v' does not contain a full path.",
			secret)
	default:
		// This is almost certainly an error, but again issue a warning for
		// improved context here and pass it through to be handled elsewhere.
		log.Warningf("WARNING: TLS secret '%v' is formatted incorrectly.",
			secret)
	}
	return profName
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
	if cfgMap.VirtualServer.Frontend.Balance == "" {
		cfg.Virtual.Balance = DEFAULT_BALANCE
	} else {
		cfg.Virtual.Balance = cfgMap.VirtualServer.Frontend.Balance
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
		if index > 0 {
			name = fmt.Sprintf("%s_%d", cfg.Virtual.VirtualServerName, index)
		} else {
			name = fmt.Sprintf("%s", cfg.Virtual.VirtualServerName)
		}
		monitor := Monitor{
			Name:      name,
			Partition: cfg.Virtual.Partition,
			Interval:  mon.Interval,
			Protocol:  mon.Protocol,
			Send:      mon.Send,
			Timeout:   mon.Timeout,
		}
		cfg.Monitors = append(cfg.Monitors, monitor)
		fullName := fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, name)
		monitorNames = append(monitorNames, fullName)
	}
	pool := Pool{
		Name:            cfg.Virtual.VirtualServerName,
		Partition:       cfg.Virtual.Partition,
		ServiceName:     cfgMap.VirtualServer.Backend.ServiceName,
		ServicePort:     cfgMap.VirtualServer.Backend.ServicePort,
		PoolMemberAddrs: cfgMap.VirtualServer.Backend.PoolMemberAddrs,
		MonitorNames:    monitorNames,
	}
	cfg.Pools = append(cfg.Pools, pool)
	cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, pool.Name)
}

// Create a ResourceConfig based on an Ingress resource config
func createRSConfigFromIngress(ing *v1beta1.Ingress,
	ns string,
	svcIndexer cache.Indexer,
) *ResourceConfig {
	var cfg ResourceConfig

	if class, ok := ing.ObjectMeta.Annotations["kubernetes.io/ingress.class"]; ok == true {
		if class != "f5" {
			return nil
		}
	}
	cfg.Virtual.VirtualServerName = formatIngressVSName(ing)
	cfg.Virtual.Mode = "http"
	if balance, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/balance"]; ok == true {
		cfg.Virtual.Balance = balance
	} else {
		cfg.Virtual.Balance = DEFAULT_BALANCE
	}
	cfg.Virtual.VirtualAddress = &virtualAddress{}

	if partition, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/partition"]; ok == true {
		cfg.Virtual.Partition = partition
	} else {
		cfg.Virtual.Partition = DEFAULT_PARTITION
	}

	if httpPort, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/http-port"]; ok == true {
		port, _ := strconv.ParseInt(httpPort, 10, 32)
		cfg.Virtual.VirtualAddress.Port = int32(port)
	} else {
		cfg.Virtual.VirtualAddress.Port = DEFAULT_HTTP_PORT
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
		if nil != cfg.Pools {
			cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, cfg.Pools[0].Name)
		}
	} else { // single-service
		pool := Pool{
			Name:        cfg.Virtual.VirtualServerName,
			Partition:   cfg.Virtual.Partition,
			ServiceName: ing.Spec.Backend.ServiceName,
			ServicePort: ing.Spec.Backend.ServicePort.IntVal,
		}
		cfg.Pools = append(cfg.Pools, pool)
		cfg.Virtual.PoolName = fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, pool.Name)
	}

	return &cfg
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
