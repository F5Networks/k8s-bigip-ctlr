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
	// Config of all resources to configure on the BIG-IP
	BigIPConfig struct {
		Virtuals       []Virtual       `json:"virtualServers,omitempty"`
		Pools          []Pool          `json:"pools,omitempty"`
		Monitors       []Monitor       `json:"monitors,omitempty"`
		Policies       []Policy        `json:"l7Policies,omitempty"`
		CustomProfiles []CustomProfile `json:"customProfiles,omitempty"`
	}

	// Config for a single resource (ConfigMap or Ingress)
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
	}

	// Virtual server config
	Virtual struct {
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

	// Pool config
	Pool struct {
		Name            string   `json:"name"`
		Partition       string   `json:"partition"`
		Balance         string   `json:"loadBalancingMode"`
		ServiceName     string   `json:"serviceName"`
		ServicePort     int32    `json:"servicePort"`
		PoolMemberAddrs []string `json:"poolMemberAddrs"`
		MonitorNames    []string `json:"monitor"`
	}

	// Pool health monitor
	Monitor struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
		Interval  int    `json:"interval,omitempty"`
		Protocol  string `json:"protocol"`
		Send      string `json:"send,omitempty"`
		Timeout   int    `json:"timeout,omitempty"`
	}
	Monitors []Monitor

	// Virtual policy
	Policy struct {
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
	}

	// frontend iapp table entry
	iappTableEntry struct {
		Columns []string   `json:"columns,omitempty"`
		Rows    [][]string `json:"rows,omitempty"`
	}

	// Client SSL Profile loaded from Secret
	CustomProfile struct {
		Name       string `json:"name"`
		Partition  string `json:"partition"`
		Cert       string `json:"cert"`
		Key        string `json:"key"`
		ServerName string `json:"serverName,omitempty"`
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
	// in the Ingress object.
	IngressHealthMonitor struct {
		Path     string `json:"path"`
		Interval int    `json:"interval"`
		Send     string `json:"send"`
		Timeout  int    `json:"timeout"`
	}
	IngressHealthMonitors []IngressHealthMonitor

	ingressRuleData struct {
		svcName   string
		svcPort   int32
		healthMon IngressHealthMonitor
		assigned  bool
	}
	ingressPathToRuleMap map[string]*ingressRuleData
	ingressHostToPathMap map[string]ingressPathToRuleMap

	// Virtual Server Key - unique server is Name + Port
	serviceKey struct {
		ServiceName string
		ServicePort int32
		Namespace   string
	}
)
