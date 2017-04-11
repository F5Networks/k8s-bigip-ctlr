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

package virtualServer

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	log "f5/vlogger"
	"github.com/xeipuuv/gojsonschema"
	"k8s.io/client-go/pkg/api/v1"
)

// Definition of a Big-IP Virtual Server config
// Most of this comes directly from a ConfigMap, with the exception
// of NodePort and Nodes, which are dynamic
// For more information regarding this structure and data model:
//  f5/schemas/bigip-virtual-server_[version].json

var DEFAULT_MODE string = "tcp"
var DEFAULT_BALANCE string = "round-robin"

// frontend bindaddr and port
type virtualAddress struct {
	BindAddr string `json:"bindAddr,omitempty"`
	Port     int32  `json:"port,omitempty"`
}

// backend health monitor
type healthMonitor struct {
	Interval int    `json:"interval,omitempty"`
	Protocol string `json:"protocol"`
	Send     string `json:"send,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

// virtual server backend backend
type virtualServerBackend struct {
	ServiceName     string          `json:"serviceName"`
	ServicePort     int32           `json:"servicePort"`
	PoolMemberAddrs []string        `json:"poolMemberAddrs"`
	HealthMonitors  []healthMonitor `json:"healthMonitors,omitempty"`
}

// frontend ssl profile
type sslProfile struct {
	F5ProfileName string `json:"f5ProfileName,omitempty"`
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

// virtual server frontend
type virtualServerFrontend struct {
	VirtualServerName string `json:"virtualServerName"`
	// Mutual parameter, partition
	Partition string `json:"partition"`

	// VirtualServer parameters
	Balance        string          `json:"balance,omitempty"`
	Mode           string          `json:"mode,omitempty"`
	VirtualAddress *virtualAddress `json:"virtualAddress,omitempty"`
	SslProfile     *sslProfile     `json:"sslProfile,omitempty"`

	// iApp parameters
	IApp                string                    `json:"iapp,omitempty"`
	IAppPoolMemberTable iappPoolMemberTable       `json:"iappPoolMemberTable,omitempty"`
	IAppOptions         map[string]string         `json:"iappOptions,omitempty"`
	IAppTables          map[string]iappTableEntry `json:"iappTables,omitempty"`
	IAppVariables       map[string]string         `json:"iappVariables,omitempty"`
}

type metaData struct {
	Active   bool
	NodePort int32
}

// main virtual server configuration
type VirtualServerConfig struct {
	MetaData      metaData `json:"-"`
	VirtualServer struct {
		Backend  virtualServerBackend  `json:"backend"`
		Frontend virtualServerFrontend `json:"frontend"`
	} `json:"virtualServer"`
}

type VirtualServerConfigs []*VirtualServerConfig

func (slice VirtualServerConfigs) Len() int {
	return len(slice)
}

func (slice VirtualServerConfigs) Less(i, j int) bool {
	return slice[i].VirtualServer.Backend.ServiceName <
		slice[j].VirtualServer.Backend.ServiceName ||
		(slice[i].VirtualServer.Backend.ServiceName ==
			slice[j].VirtualServer.Backend.ServiceName &&
			slice[i].VirtualServer.Backend.ServicePort <
				slice[j].VirtualServer.Backend.ServicePort)
}

func (slice VirtualServerConfigs) Swap(i, j int) {
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
func formatVirtualServerName(cm *v1.ConfigMap) string {
	return fmt.Sprintf("%v_%v", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
}

type VirtualServerConfigMap map[string]*VirtualServerConfig

// Map of Virtual Server configs
type VirtualServers struct {
	sync.Mutex
	m map[serviceKey]VirtualServerConfigMap
}

// callback type for ForEach()
type VirtualServerEnumFunc func(key serviceKey, cfg *VirtualServerConfig)

type VirtualServerInterface interface {
	Init()
	Assign(key serviceKey, name string, cfg *VirtualServerConfig)
	Count() int
	CountOf(key serviceKey) int
	Get(key serviceKey, frontEndName string) (*VirtualServerConfig, bool)
	GetAll(key serviceKey) (VirtualServerConfigMap, bool)
	Delete(key serviceKey, frontEndName string) bool
	ForEach(f VirtualServerEnumFunc)
}

// Constructor for VirtualServers.
func NewVirtualServers() *VirtualServers {
	var vss VirtualServers
	vss.Init()
	return &vss
}

// Receiver to initialize the object.
func (vss *VirtualServers) Init() {
	vss.m = make(map[serviceKey]VirtualServerConfigMap)
}

// Add or update cfg in VirtualServers, identified by key.
func (vss *VirtualServers) Assign(
	key serviceKey,
	name string,
	cfg *VirtualServerConfig,
) {
	vsMap, ok := vss.m[key]
	if !ok {
		vsMap = make(map[string]*VirtualServerConfig)
		vss.m[key] = vsMap
	}
	vsMap[name] = cfg
}

// Count of all confiugrations currently stored.
func (vss *VirtualServers) Count() int {
	var ct int = 0
	for _, cfgs := range vss.m {
		ct += len(cfgs)
	}
	return ct
}

// Count of all configurations for a specific backend.
func (vss *VirtualServers) CountOf(key serviceKey) int {
	if vsMap, ok := vss.m[key]; ok {
		return len(vsMap)
	}
	return 0
}

// Remove a specific configuration.
func (vss *VirtualServers) Delete(key serviceKey, frontEndName string) bool {
	vsMap, ok := vss.m[key]
	if !ok {
		return false
	}
	if _, ok := vsMap[frontEndName]; ok {
		delete(vsMap, frontEndName)
		if len(vsMap) == 0 {
			delete(vss.m, key)
		}
		return true
	}
	return false
}

// Iterate over all configurations, calling the supplied callback with each.
func (vss *VirtualServers) ForEach(f VirtualServerEnumFunc) {
	for key, cfgs := range vss.m {
		for _, cfg := range cfgs {
			f(key, cfg)
		}
	}
}

// Get a specific configuration.
func (vss *VirtualServers) Get(
	key serviceKey,
	frontEndName string,
) (*VirtualServerConfig, bool) {
	vsMap, ok := vss.m[key]
	if !ok {
		return nil, ok
	}
	vs, ok := vsMap[frontEndName]
	return vs, ok
}

// Get all configurations for a specific backend
func (vss *VirtualServers) GetAll(
	key serviceKey) (VirtualServerConfigMap, bool) {
	vsMap, ok := vss.m[key]
	return vsMap, ok
}

// Unmarshal an expected VirtualServerConfig object
func parseVirtualServerConfig(cm *v1.ConfigMap) (*VirtualServerConfig, error) {
	var cfg VirtualServerConfig

	if data, ok := cm.Data["data"]; ok {
		err := json.Unmarshal([]byte(data), &cfg)
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

			if result.Valid() {
				// If mode not set, use default
				if cfg.VirtualServer.Frontend.Mode == "" {
					cfg.VirtualServer.Frontend.Mode = DEFAULT_MODE
				}
				// If balance not set, use default
				if cfg.VirtualServer.Frontend.Balance == "" {
					cfg.VirtualServer.Frontend.Balance = DEFAULT_BALANCE
				}
				// Checking for annotation in VS, not iApp
				if cfg.VirtualServer.Frontend.IApp == "" {
					// Precedence to configmap bindAddr if annotation is also set
					if cfg.VirtualServer.Frontend.VirtualAddress.BindAddr != "" &&
						cm.ObjectMeta.Annotations["virtual-server.f5.com/ip"] != "" {
						log.Warning(
							"Both configmap bindAddr and virtual-server.f5.com/ip annotation are set. " +
								"Choosing configmap's bindAddr...")
					} else if cfg.VirtualServer.Frontend.VirtualAddress.BindAddr == "" {
						// Check for IP annotation provided by IPAM system
						if addr, ok := cm.ObjectMeta.Annotations["virtual-server.f5.com/ip"]; ok == true {
							cfg.VirtualServer.Frontend.VirtualAddress.BindAddr = addr
						} else {
							return &cfg, fmt.Errorf(
								"No virtual IP was specified for the virtual server %s", cm.ObjectMeta.Name)
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
