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

type (
	// Configs for each BIG-IP partition
	PartitionMap map[string]*BigIPConfig

	// Config of all resources to configure on the BIG-IP
	BigIPConfig struct {
		Virtuals           Virtuals            `json:"virtualServers,omitempty"`
		Pools              Pools               `json:"pools,omitempty"`
		Monitors           Monitors            `json:"monitors,omitempty"`
		Policies           []Policy            `json:"l7Policies,omitempty"`
		CustomProfiles     []CustomProfile     `json:"customProfiles,omitempty"`
		IRules             []IRule             `json:"iRules,omitempty"`
		InternalDataGroups []InternalDataGroup `json:"internalDataGroups,omitempty"`
		IApps              []IApp              `json:"iapps,omitempty"`
	}

	// Config for a single resource (ConfigMap, Ingress, or Route)
	ResourceConfig struct {
		MetaData metaData `json:"-"`
		Virtual  Virtual  `json:"virtual,omitempty"`
		Pools    []Pool   `json:"pools,omitempty"`
		Monitors Monitors `json:"monitors,omitempty"`
		Policies []Policy `json:"policies,omitempty"`
	}
	ResourceConfigs []*ResourceConfig

	metaData struct {
		Active       bool
		NodePort     int32
		ResourceType string
		// Only used for Routes (for keeping track of annotated profiles)
		RouteProfs map[routeKey]string
	}

	// Key used to store annotated profiles for a route
	routeKey struct {
		Name      string
		Namespace string
		Context   string
	}

	// Reference to pre-existing profiles
	ProfileRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
		Context   string `json:"context"` // 'clientside', 'serverside', or 'all'
	}
	ProfileRefs []ProfileRef

	// Virtual server config
	Virtual struct {
		VirtualServerName string `json:"name"`
		PoolName          string `json:"pool,omitempty"`
		// Mutual parameter, partition
		Partition string `json:"partition,omitempty"`

		// VirtualServer parameters
		Balance               string                `json:"balance,omitempty"`
		Mode                  string                `json:"mode,omitempty"`
		VirtualAddress        *virtualAddress       `json:"virtualAddress,omitempty"`
		Destination           string                `json:"destination,omitempty"`
		Enabled               bool                  `json:"enabled,omitempty"`
		IpProtocol            string                `json:"ipProtocol,omitempty"`
		SourceAddrTranslation sourceAddrTranslation `json:"sourceAddressTranslation,omitempty"`
		SslProfile            *sslProfile           `json:"sslProfile,omitempty"`
		Policies              []nameRef             `json:"policies,omitempty"`
		IRules                []string              `json:"rules,omitempty"`
		// FIXME: All profiles should reside in Profiles, just server ssl ones now.
		Profiles ProfileRefs `json:"profiles,omitempty"`

		// iApp parameters
		IApp                string                    `json:"iapp,omitempty"`
		IAppPoolMemberTable *iappPoolMemberTable      `json:"iappPoolMemberTable,omitempty"`
		IAppOptions         map[string]string         `json:"iappOptions,omitempty"`
		IAppTables          map[string]iappTableEntry `json:"iappTables,omitempty"`
		IAppVariables       map[string]string         `json:"iappVariables,omitempty"`
	}
	Virtuals []Virtual

	// IApp
	IApp struct {
		Name                string                    `json:"name"`
		Partition           string                    `json:"partition,omitempty"`
		IApp                string                    `json:"template"`
		IAppPoolMemberTable *iappPoolMemberTable      `json:"poolMemberTable,omitempty"`
		IAppOptions         map[string]string         `json:"options,omitempty"`
		IAppTables          map[string]iappTableEntry `json:"tables,omitempty"`
		IAppVariables       map[string]string         `json:"variables,omitempty"`
	}

	// Pool Member
	Member struct {
		Address string `json:"address"`
		Port    int32  `json:"port"`
		Session string `json:"session,omitempty"`
	}

	// Pool config
	Pool struct {
		Name         string   `json:"name"`
		Partition    string   `json:"partition,omitempty"`
		Balance      string   `json:"loadBalancingMode"`
		ServiceName  string   `json:"serviceName,omitempty"`
		ServicePort  int32    `json:"servicePort,omitempty"`
		Members      []Member `json:"members"`
		MonitorNames []string `json:"monitors,omitempty"`
	}
	Pools []Pool

	// Pool health monitor
	Monitor struct {
		Name      string `json:"name"`
		Partition string `json:"partition,omitempty"`
		Interval  int    `json:"interval,omitempty"`
		Protocol  string `json:"protocol,omitempty"`
		Type      string `json:"type,omitempty"`
		Send      string `json:"send,omitempty"`
		Timeout   int    `json:"timeout,omitempty"`
	}
	Monitors []Monitor

	// Virtual Server Source Address Translation
	sourceAddrTranslation struct {
		Type string `json:"type"`
	}

	// Virtual policy
	Policy struct {
		Name        string   `json:"name"`
		Partition   string   `json:"partition,omitempty"`
		SubPath     string   `json:"subPath,omitempty"`
		Controls    []string `json:"controls,omitempty"`
		Description string   `json:"description,omitempty"`
		Legacy      bool     `json:"legacy,omitempty"`
		Requires    []string `json:"requires,omitempty"`
		Rules       []*Rule  `json:"rules,omitempty"`
		Strategy    string   `json:"strategy,omitempty"`
	}

	// Rule config for a Policy
	Rule struct {
		Name       string       `json:"name"`
		FullURI    string       `json:"-"`
		Ordinal    int          `json:"ordinal,omitempty"`
		Actions    []*action    `json:"actions,omitempty"`
		Conditions []*condition `json:"conditions,omitempty"`
	}

	// action config for a Rule
	action struct {
		Name      string `json:"name"`
		Pool      string `json:"pool",omitempty"`
		HttpReply bool   `json:"httpReply,omitempty"`
		Forward   bool   `json:"forward,omitempty"`
		Location  string `json:"location,omitempty"`
		Redirect  bool   `json:"redirect,omitempty"`
		Request   bool   `json:"request,omitempty"`
		Reset     bool   `json:"reset,omitempty"`
	}

	// condition config for a Rule
	condition struct {
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

	Rules   []*Rule
	ruleMap map[string]*Rule

	// virtual server policy/profile reference
	nameRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
	}

	// frontend bindaddr and port
	virtualAddress struct {
		BindAddr string `json:"bindAddr,omitempty"`
		Port     int32  `json:"port,omitempty"`
	}

	// frontend ssl profile
	sslProfile struct {
		F5ProfileName  string   `json:"f5ProfileName,omitempty"`
		F5ProfileNames []string `json:"f5ProfileNames,omitempty"`
	}

	// frontend pool member column definition
	iappPoolMemberColumn struct {
		Name  string `json:"name"`
		Kind  string `json:"kind,omitempty"`
		Value string `json:"value,omitempty"`
	}

	// frontend pool member table
	iappPoolMemberTable struct {
		Name    string                 `json:"name"`
		Columns []iappPoolMemberColumn `json:"columns"`
		Members []Member               `json:"members,omitempty"`
	}

	// frontend iapp table entry
	iappTableEntry struct {
		Columns []string   `json:"columns,omitempty"`
		Rows    [][]string `json:"rows,omitempty"`
	}

	// SSL Profile loaded from Secret or Route object
	CustomProfile struct {
		Name       string `json:"name"`
		Partition  string `json:"partition,omitempty"`
		Context    string `json:"context"` // 'clientside', 'serverside', or 'all'
		Cert       string `json:"cert"`
		Key        string `json:"key"`
		ServerName string `json:"serverName,omitempty"`
		SNIDefault bool   `json:"sniDefault,omitempty"`
	}

	// Used to unmarshal ConfigMap data
	ConfigMap struct {
		VirtualServer struct {
			Backend  configMapBackend `json:"backend"`
			Frontend Virtual          `json:"frontend"`
		} `json:"virtualServer"`
	}

	configMapBackend struct {
		ServiceName     string    `json:"serviceName"`
		ServicePort     int32     `json:"servicePort"`
		PoolMemberAddrs []string  `json:"poolMemberAddrs"`
		HealthMonitors  []Monitor `json:"healthMonitors,omitempty"`
	}

	// This is the format for each item in the health monitor annotation used
	// in the Ingress and Route objects.
	AnnotationHealthMonitor struct {
		Path     string `json:"path"`
		Interval int    `json:"interval"`
		Send     string `json:"send"`
		Timeout  int    `json:"timeout"`
	}
	AnnotationHealthMonitors []AnnotationHealthMonitor

	ruleData struct {
		svcName   string
		svcPort   int32
		healthMon AnnotationHealthMonitor
		assigned  bool
	}
	pathToRuleMap map[string]*ruleData
	hostToPathMap map[string]pathToRuleMap

	// Virtual Server Key - unique server is Name + Port
	serviceKey struct {
		ServiceName string
		ServicePort int32
		Namespace   string
	}

	// iRules
	IRule struct {
		Name      string `json:"name"`
		Partition string `json:"partition,omitempty"`
		Code      string `json:"apiAnonymous"`
	}

	IRulesMap map[nameRef]*IRule

	InternalDataGroup struct {
		Name      string                   `json:"name"`
		Partition string                   `json:"partition,omitempty"`
		Records   InternalDataGroupRecords `json:"records"`
	}

	InternalDataGroupRecord struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	InternalDataGroupRecords []InternalDataGroupRecord

	InternalDataGroupMap map[nameRef]*InternalDataGroup
)
