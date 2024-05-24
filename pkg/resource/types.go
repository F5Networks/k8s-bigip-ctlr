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

package resource

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
		ServiceIPAddress   []ServiceAddress    `json:"serviceAddress,omitempty"`
	}

	// Config for a single resource (ConfigMap, Ingress, or Route)
	ResourceConfig struct {
		MetaData       MetaData         `json:"-"`
		Virtual        Virtual          `json:"virtual,omitempty"`
		IApp           IApp             `json:"iapp,omitempty"`
		Pools          Pools            `json:"pools,omitempty"`
		Monitors       Monitors         `json:"monitors,omitempty"`
		Policies       Policies         `json:"policies,omitempty"`
		ServiceAddress []ServiceAddress `json:"serviceAddress,omitempty"`
	}
	ResourceConfigs []*ResourceConfig

	ServiceAddress struct {
		ArpEnabled         bool   `json:"arpEnabled,omitempty"`
		ICMPEcho           string `json:"icmpEcho,omitempty"`
		RouteAdvertisement string `json:"routeAdvertisement,omitempty"`
		TrafficGroup       string `json:"trafficGroup,omitempty"`
		SpanningEnabled    bool   `json:"spanningEnabled,omitempty"`
	}

	MetaData struct {
		Active       bool
		ResourceType string
		// Only used for Routes (for keeping track of annotated profiles)
		RouteProfs map[RouteKey]string
		// Name of the Ingress that created this config
		// Used to prevent single-service Ingresses from sharing virtuals
		DefaultIngressName string
	}

	// Key used to store annotated profiles for a route
	RouteKey struct {
		Name      string
		Namespace string
		Context   string
	}

	// Reference to pre-existing profiles
	ProfileRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
		Context   string `json:"context"` // 'clientside', 'serverside', or 'all'
		// Used as reference to which Namespace/Ingress this profile came from
		// (for deletion purposes)
		Namespace string `json:"-"`
	}
	ProfileRefs []ProfileRef

	// Virtual server config
	Virtual struct {
		Name                   string                `json:"name"`
		PoolName               string                `json:"pool,omitempty"`
		Partition              string                `json:"-"`
		Destination            string                `json:"destination"`
		Enabled                bool                  `json:"enabled"`
		IpProtocol             string                `json:"ipProtocol,omitempty"`
		SourceAddrTranslation  SourceAddrTranslation `json:"sourceAddressTranslation,omitempty"`
		Policies               []NameRef             `json:"policies,omitempty"`
		IRules                 []string              `json:"rules,omitempty"`
		Profiles               ProfileRefs           `json:"profiles,omitempty"`
		Description            string                `json:"description,omitempty"`
		VirtualAddress         *VirtualAddress       `json:"-"`
		Mask                   string                `json:"mask,omitempty"`
		TranslateServerAddress string                `json:"translateAddress,omitempty"`
	}
	Virtuals []Virtual

	// IApp
	IApp struct {
		Name                string                    `json:"name"`
		Partition           string                    `json:"-"`
		IApp                string                    `json:"template"`
		IAppPoolMemberTable *IappPoolMemberTable      `json:"poolMemberTable,omitempty"`
		IAppOptions         map[string]string         `json:"options,omitempty"`
		IAppTables          map[string]iappTableEntry `json:"tables,omitempty"`
		IAppVariables       map[string]string         `json:"variables,omitempty"`
	}

	// Pool Member
	Member struct {
		Address         string `json:"address"`
		Port            int32  `json:"port"`
		MemberType      string `json:"memberType"`
		SvcPort         int32  `json:"svcPort"`
		Session         string `json:"session,omitempty"`
		AdminState      string `json:"adminState,omitempty"`
		ConnectionLimit int32  `json:"connectionLimit,omitempty"`
	}

	// Pool config
	Pool struct {
		Name         string   `json:"name"`
		Partition    string   `json:"-"`
		ServiceName  string   `json:"-"`
		ServicePort  int32    `json:"-"`
		Balance      string   `json:"loadBalancingMode"`
		Members      []Member `json:"members"`
		MonitorNames []string `json:"monitors,omitempty"`
	}
	Pools []Pool

	// Pool health monitor
	Monitor struct {
		Name       string `json:"name"`
		Partition  string `json:"-"`
		Interval   int    `json:"interval,omitempty"`
		Type       string `json:"type,omitempty"`
		Send       string `json:"send,omitempty"`
		Recv       string `json:"recv,omitempty"`
		Timeout    int    `json:"timeout,omitempty"`
		SslProfile string `json:"sslProfile,omitempty"`
	}
	Monitors []Monitor

	// Virtual Server Source Address Translation
	SourceAddrTranslation struct {
		Type string `json:"type"`
		Pool string `json:"pool,omitempty"`
	}

	// Virtual policy
	Policy struct {
		Name        string   `json:"name"`
		Partition   string   `json:"-"`
		SubPath     string   `json:"subPath,omitempty"`
		Controls    []string `json:"controls,omitempty"`
		Description string   `json:"description,omitempty"`
		Legacy      bool     `json:"legacy,omitempty"`
		Requires    []string `json:"requires,omitempty"`
		Rules       Rules    `json:"rules,omitempty"`
		Strategy    string   `json:"strategy,omitempty"`
	}
	Policies []Policy

	// Rule config for a Policy
	Rule struct {
		Name       string       `json:"name"`
		FullURI    string       `json:"-"`
		Ordinal    int          `json:"ordinal,omitempty"`
		Actions    []*Action    `json:"actions,omitempty"`
		Conditions []*Condition `json:"conditions,omitempty"`
	}

	// Action config for a Rule
	Action struct {
		Name      string `json:"name"`
		Pool      string `json:"pool,omitempty"`
		HTTPHost  bool   `json:"httpHost,omitempty"`
		HttpReply bool   `json:"httpReply,omitempty"`
		HTTPURI   bool   `json:"httpUri,omitempty"`
		Forward   bool   `json:"forward,omitempty"`
		Location  string `json:"location,omitempty"`
		Path      string `json:"path,omitempty"`
		Redirect  bool   `json:"redirect,omitempty"`
		Replace   bool   `json:"replace,omitempty"`
		Request   bool   `json:"request,omitempty"`
		Reset     bool   `json:"reset,omitempty"`
		Select    bool   `json:"select,omitempty"`
		Value     string `json:"value,omitempty"`
	}

	// Condition config for a Rule
	Condition struct {
		Name            string   `json:"name"`
		Address         bool     `json:"address,omitempty"`
		CaseInsensitive bool     `json:"caseInsensitive,omitempty"`
		Equals          bool     `json:"equals,omitempty"`
		EndsWith        bool     `json:"endsWith,omitempty"`
		External        bool     `json:"external,omitempty"`
		HTTPHost        bool     `json:"httpHost,omitempty"`
		Host            bool     `json:"host,omitempty"`
		HTTPURI         bool     `json:"httpUri,omitempty"`
		Index           int      `json:"index,omitempty"`
		Matches         bool     `json:"matches,omitempty"`
		Path            bool     `json:"path,omitempty"`
		PathSegment     bool     `json:"pathSegment,omitempty"`
		Present         bool     `json:"present,omitempty"`
		Remote          bool     `json:"remote,omitempty"`
		Request         bool     `json:"request,omitempty"`
		Scheme          bool     `json:"scheme,omitempty"`
		Tcp             bool     `json:"tcp,omitempty"`
		Values          []string `json:"values"`
	}

	Rules   []*Rule
	RuleMap map[string]*Rule

	// virtual server policy/profile reference
	NameRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
	}

	// frontend bindaddr and port
	VirtualAddress struct {
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
	IappPoolMemberTable struct {
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
		Name         string `json:"name"`
		Partition    string `json:"-"`
		Context      string `json:"context"` // 'clientside', 'serverside', or 'all'
		Cert         string `json:"cert"`
		Key          string `json:"key"`
		ServerName   string `json:"serverName,omitempty"`
		SNIDefault   bool   `json:"sniDefault,omitempty"`
		PeerCertMode string `json:"peerCertMode,omitempty"`
		CAFile       string `json:"caFile,omitempty"`
		ChainCA      string `json:"chainCA,onitempty"`
	}

	// Used to unmarshal ConfigMap data
	ConfigMap struct {
		VirtualServer struct {
			Backend  configMapBackend  `json:"backend"`
			Frontend configMapFrontend `json:"frontend"`
		} `json:"virtualServer"`
	}

	ConfigMapMonitor struct {
		Name      string `json:"name"`
		Partition string `json:"partition,omitempty"`
		Interval  int    `json:"interval,omitempty"`
		Protocol  string `json:"protocol,omitempty"`
		Send      string `json:"send,omitempty"`
		Recv      string `json:"recv,omitempty"`
		Timeout   int    `json:"timeout,omitempty"`
	}

	configMapBackend struct {
		ServiceName     string             `json:"serviceName"`
		ServicePort     int32              `json:"servicePort"`
		PoolMemberAddrs []string           `json:"poolMemberAddrs"`
		HealthMonitors  []ConfigMapMonitor `json:"healthMonitors,omitempty"`
	}

	configMapFrontend struct {
		Name     string `json:"name"`
		PoolName string `json:"pool,omitempty"`
		// Mutual parameter, partition
		Partition string `json:"partition,omitempty"`

		// VirtualServer parameters
		Balance               string                `json:"balance,omitempty"`
		Mode                  string                `json:"mode,omitempty"`
		VirtualAddress        *VirtualAddress       `json:"virtualAddress,omitempty"`
		Destination           string                `json:"destination,omitempty"`
		Enabled               bool                  `json:"enabled,omitempty"`
		IpProtocol            string                `json:"ipProtocol,omitempty"`
		SourceAddrTranslation SourceAddrTranslation `json:"sourceAddressTranslation,omitempty"`
		SslProfile            *sslProfile           `json:"sslProfile,omitempty"`
		Policies              []NameRef             `json:"policies,omitempty"`
		IRules                []string              `json:"rules,omitempty"`
		Profiles              ProfileRefs           `json:"profiles,omitempty"`

		// iApp parameters
		IApp                string                    `json:"iapp,omitempty"`
		IAppPoolMemberTable *IappPoolMemberTable      `json:"iappPoolMemberTable,omitempty"`
		IAppOptions         map[string]string         `json:"iappOptions,omitempty"`
		IAppTables          map[string]iappTableEntry `json:"iappTables,omitempty"`
		IAppVariables       map[string]string         `json:"iappVariables,omitempty"`
	}

	// This is the format for each item in the health monitor annotation used
	// in the Ingress and Route objects.
	AnnotationHealthMonitor struct {
		Path       string `json:"path"`
		Interval   int    `json:"interval"`
		Send       string `json:"send"`
		Recv       string `json:"recv"`
		Timeout    int    `json:"timeout"`
		Type       string `json:"type"`
		SslProfile string `json:"sslProfile"`
	}
	AnnotationHealthMonitors []AnnotationHealthMonitor

	// This is the format for each item in the clientssl annotation used
	// in the Ingress objects.
	AnnotationProfile struct {
		Hosts        []string `json:"hosts,omitempty"`
		Bigipprofile string   `json:"bigIpProfile"`
	}
	AnnotationProfiles []AnnotationProfile

	RuleData struct {
		SvcName   string
		SvcPort   int32
		HealthMon AnnotationHealthMonitor
		Assigned  bool
	}
	PathToRuleMap map[string]*RuleData
	HostToPathMap map[string]PathToRuleMap

	// Virtual Server Key - unique server is Name + Port
	ServiceKey struct {
		ServiceName string
		ServicePort int32
		Namespace   string
	}

	// iRules
	IRule struct {
		Name      string `json:"name"`
		Partition string `json:"-"`
		Code      string `json:"apiAnonymous"`
	}

	IRulesMap map[NameRef]*IRule

	InternalDataGroup struct {
		Name      string                   `json:"name"`
		Partition string                   `json:"-"`
		Records   InternalDataGroupRecords `json:"records"`
	}

	InternalDataGroupRecord struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	InternalDataGroupRecords []InternalDataGroupRecord

	DataGroupNamespaceMap map[string]*InternalDataGroup
	InternalDataGroupMap  map[NameRef]DataGroupNamespaceMap

	// AS3 Backend supported features
	ConstVirtuals int

	// Routes annotation features that are possible by an AS3 declaration can be added here. Initially enabling a WAF
	// policy is added as an AS3 feature.
	// | Host + Path | Virtual Server to Apply | WAF Policy Name |
	// |-------------|-------------------------|-----------------|
	// Host + Path is a unique record. The columns can be extended to add future features.
	// InternalF5ResourcesGroup takes OpenShift/Kubernetes namespace as key
	InternalF5ResourcesGroup map[string]InternalF5Resources
	InternalF5Resources      map[Record]F5Resources

	Record struct {
		Host string
		Path string
	}

	F5Resources struct {
		Virtual   ConstVirtuals // 0 - HTTP, 1 - HTTPS, 2 - HTTP/S
		WAFPolicy string
	}

	SecretKey struct {
		Name         string
		ResourceName string
	}

	AgentCfgMap struct {
		Operation    string
		GetEndpoints func(string, string) ([]Member, error)
		Data         string
		Name         string
		Namespace    string
		Label        map[string]string
	}

	AgentResources struct {
		RsMap      ResourceConfigMap
		Partitions map[string]struct{}
	}

	ResourceRequest struct {
		AgentCfgSvcCache map[string][]Member
		Resources        *AgentResources
		Profs            map[SecretKey]CustomProfile
		IrulesMap        IRulesMap
		IntDgMap         InternalDataGroupMap
		IntF5Res         InternalF5ResourcesGroup
		AgentCfgmaps     []*AgentCfgMap
	}

	ResourceResponse struct {
		IsResponseSuccessful bool
	}

	MessageRequest struct {
		ReqID   uint
		MsgType string
		ResourceRequest
	}

	MessageResponse struct {
		ReqID uint
		ResourceResponse
	}
)

// Determines which virtual server needs a specific feature applied.
const (
	HTTP ConstVirtuals = iota
	HTTPS
	HTTPANDS
)

var DEFAULT_PARTITION string = "k8s"

const (
	DEFAULT_MODE       string = "tcp"
	DEFAULT_BALANCE    string = "round-robin"
	DEFAULT_HTTP_PORT  int32  = 80
	DEFAULT_HTTPS_PORT int32  = 443

	InsecurePolicyName = "openshift_insecure_routes"
	SecurePolicyName   = "openshift_secure_routes"

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

	// Constants for Resource Types
	ResourceTypeIngress          string = "ingress"
	ResourceTypeRoute            string = "route"
	ResourceTypeCfgMap           string = "cfgMap"
	DefaultSourceAddrTranslation        = "automap"
	SnatSourceAddrTranslation           = "snat"
)

const HttpRedirectIRuleName = "http_redirect_irule"
const AbDeploymentPathIRuleName = "ab_deployment_path_irule"
const SslPassthroughIRuleName = "openshift_passthrough_irule"

const DefaultConfigMapLabel = "f5type in (virtual-server)"
const VsStatusBindAddrAnnotation = "status.virtual-server.f5.com/ip"
const IngressSslRedirect = "ingress.kubernetes.io/ssl-redirect"
const IngressAllowHttp = "ingress.kubernetes.io/allow-http"
const HealthMonitorAnnotation = "virtual-server.f5.com/health"
const K8sIngressClass = "kubernetes.io/ingress.class"
const F5VsBindAddrAnnotation = "virtual-server.f5.com/ip"
const F5VsHttpPortAnnotation = "virtual-server.f5.com/http-port"
const F5VsHttpsPortAnnotation = "virtual-server.f5.com/https-port"
const F5VsBalanceAnnotation = "virtual-server.f5.com/balance"
const F5VsPartitionAnnotation = "virtual-server.f5.com/partition"
const F5VsURLRewriteAnnotation = "virtual-server.f5.com/rewrite-target-url"
const F5VsWhitelistSourceRangeAnnotation = "virtual-server.f5.com/whitelist-source-range"
const F5VsAllowSourceRangeAnnotation = "virtual-server.f5.com/allow-source-range"
const F5VsAppRootAnnotation = "virtual-server.f5.com/rewrite-app-root"
const F5ClientSslProfileAnnotation = "virtual-server.f5.com/clientssl"
const F5ServerSslProfileAnnotation = "virtual-server.f5.com/serverssl"
const F5ServerSslSecureAnnotation = "virtual-server.f5.com/secure-serverssl"
const DefaultSslServerCAName = "openshift_route_cluster_default-ca"
const F5VSTranslateServerAddress = "virtual-server.f5.com/translate-server-address"
const F5VsWAFPolicy = "virtual-server.f5.com/waf"
const OprTypeCreate = "create"
const OprTypeUpdate = "update"
const OprTypeDelete = "delete"
const OprTypeDisable = "disable"
const CISControllerName = "f5.com/cntr-ingress-svcs"
const DefaultIngressClass = "ingressclass.kubernetes.io/is-default-class"
const NodePortLocal = "nodeportlocal"
const NodePort = "nodeport"
const PodStatusEnable = "enable"
const PodStatusDisable = "disable"

// Multicluster annotations
const MultiClusterServicesAnnotation = "virtual-server.f5.com/multiClusterServices"

//const DefaultSslServerCAName = "openshift_route_cluster_default-ca"
