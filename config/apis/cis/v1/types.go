package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:subresource:status

// VirtualServer defines the VirtualServer resource.
type VirtualServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualServerSpec   `json:"spec"`
	Status VirtualServerStatus `json:"status,omitempty"`
}

// VirtualServerStatus is the status of the VirtualServer resource.
type VirtualServerStatus struct {
	VSAddress string `json:"vsAddress,omitempty"`
	StatusOk  string `json:"status,omitempty"`
}

// VirtualServerSpec is the spec of the VirtualServer resource.
type VirtualServerSpec struct {
	Host                             string           `json:"host,omitempty"`
	HostGroup                        string           `json:"hostGroup,omitempty"`
	VirtualServerAddress             string           `json:"virtualServerAddress,omitempty"`
	AdditionalVirtualServerAddresses []string         `json:"additionalVirtualServerAddresses,omitempty"`
	IPAMLabel                        string           `json:"ipamLabel,omitempty"`
	VirtualServerName                string           `json:"virtualServerName,omitempty"`
	VirtualServerHTTPPort            int32            `json:"virtualServerHTTPPort,omitempty"`
	VirtualServerHTTPSPort           int32            `json:"virtualServerHTTPSPort,omitempty"`
	DefaultPool                      DefaultPool      `json:"defaultPool,omitempty"`
	Pools                            []VSPool         `json:"pools,omitempty"`
	TLSProfileName                   string           `json:"tlsProfileName,omitempty"`
	HTTPTraffic                      string           `json:"httpTraffic,omitempty"`
	SNAT                             string           `json:"snat,omitempty"`
	ConnectionMirroring              string           `json:"connectionMirroring,omitempty"`
	WAF                              string           `json:"waf,omitempty"`
	RewriteAppRoot                   string           `json:"rewriteAppRoot,omitempty"`
	AllowVLANs                       []string         `json:"allowVlans,omitempty"`
	IRules                           []string         `json:"iRules,omitempty"`
	ServiceIPAddress                 []ServiceAddress `json:"serviceAddress,omitempty"`
	PolicyName                       string           `json:"policyName,omitempty"`
	PersistenceProfile               string           `json:"persistenceProfile,omitempty"`
	ProfileMultiplex                 string           `json:"profileMultiplex,omitempty"`
	DOS                              string           `json:"dos,omitempty"`
	BotDefense                       string           `json:"botDefense,omitempty"`
	Profiles                         ProfileVSSpec    `json:"profiles,omitempty"`
	AllowSourceRange                 []string         `json:"allowSourceRange,omitempty"`
	HttpMrfRoutingEnabled            *bool            `json:"httpMrfRoutingEnabled,omitempty"`
	Partition                        string           `json:"partition,omitempty"`
}

// ServiceAddress Service IP address definition (BIG-IP virtual-address).
type ServiceAddress struct {
	ArpEnabled         bool   `json:"arpEnabled,omitempty"`
	ICMPEcho           string `json:"icmpEcho,omitempty"`
	RouteAdvertisement string `json:"routeAdvertisement,omitempty"`
	TrafficGroup       string `json:"trafficGroup,omitempty"`
	SpanningEnabled    bool   `json:"spanningEnabled,omitempty"`
}

// DefaultPool defines default pool object in BIG-IP.
type DefaultPool struct {
	Name              string             `json:"name,omitempty"`
	Service           string             `json:"service"`
	ServicePort       intstr.IntOrString `json:"servicePort"`
	NodeMemberLabel   string             `json:"nodeMemberLabel,omitempty"`
	Monitors          []Monitor          `json:"monitors"`
	Balance           string             `json:"loadBalancingMethod,omitempty"`
	ServiceNamespace  string             `json:"serviceNamespace,omitempty"`
	ReselectTries     int32              `json:"reselectTries,omitempty"`
	ServiceDownAction string             `json:"serviceDownAction,omitempty"`
	Reference         string             `json:"reference,omitempty"`
}

// VSPool defines a pool object for Virtual Server in BIG-IP.
type VSPool struct {
	Name                 string                         `json:"name,omitempty"`
	Path                 string                         `json:"path,omitempty"`
	Service              string                         `json:"service"`
	ServicePort          intstr.IntOrString             `json:"servicePort"`
	NodeMemberLabel      string                         `json:"nodeMemberLabel,omitempty"`
	Monitor              Monitor                        `json:"monitor"`
	Monitors             []Monitor                      `json:"monitors"`
	MinimumMonitors      intstr.IntOrString             `json:"minimumMonitors,omitempty"`
	Rewrite              string                         `json:"rewrite,omitempty"`
	Balance              string                         `json:"loadBalancingMethod,omitempty"`
	WAF                  string                         `json:"waf,omitempty"`
	ServiceNamespace     string                         `json:"serviceNamespace,omitempty"`
	ReselectTries        int32                          `json:"reselectTries,omitempty"`
	ServiceDownAction    string                         `json:"serviceDownAction,omitempty"`
	HostRewrite          string                         `json:"hostRewrite,omitempty"`
	Weight               *int32                         `json:"weight,omitempty"`
	AlternateBackends    []AlternateBackend             `json:"alternateBackends"`
	MultiClusterServices []MultiClusterServiceReference `json:"extendedServiceReferences,omitempty"`
}

// TSPool defines a pool object for Transport Server in BIG-IP.
type TSPool struct {
	Name                 string                         `json:"name,omitempty"`
	Path                 string                         `json:"path,omitempty"`
	Service              string                         `json:"service"`
	ServicePort          intstr.IntOrString             `json:"servicePort"`
	NodeMemberLabel      string                         `json:"nodeMemberLabel,omitempty"`
	Monitor              Monitor                        `json:"monitor"`
	Monitors             []Monitor                      `json:"monitors"`
	Rewrite              string                         `json:"rewrite,omitempty"`
	Balance              string                         `json:"loadBalancingMethod,omitempty"`
	WAF                  string                         `json:"waf,omitempty"`
	ServiceNamespace     string                         `json:"serviceNamespace,omitempty"`
	ReselectTries        int32                          `json:"reselectTries,omitempty"`
	ServiceDownAction    string                         `json:"serviceDownAction,omitempty"`
	HostRewrite          string                         `json:"hostRewrite,omitempty"`
	Weight               *int32                         `json:"weight,omitempty"`
	MultiClusterServices []MultiClusterServiceReference `json:"extendedServiceReferences,omitempty"`
}

// AlternateBackends lists backend svc of A/B
type AlternateBackend struct {
	Service          string `json:"service"`
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
	Weight           *int32 `json:"weight,omitempty"`
}

type MultiClusterServiceReference struct {
	ClusterName string             `json:"clusterName"`
	SvcName     string             `json:"serviceName"`
	Namespace   string             `json:"namespace"`
	ServicePort intstr.IntOrString `json:"port"`
	Weight      *int               `json:"weight,omitempty"`
}

// Monitor defines a monitor object in BIG-IP.
type Monitor struct {
	Type       string `json:"type"`
	Send       string `json:"send"`
	Recv       string `json:"recv"`
	Interval   int    `json:"interval"`
	Timeout    int    `json:"timeout"`
	TargetPort int32  `json:"targetPort"`
	Name       string `json:"name,omitempty"`
	Reference  string `json:"reference,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VirtualServerList is a list of the VirtualServer resources.
type VirtualServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VirtualServer `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSProfile is a Custom Resource for TLS server
type TLSProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TLSProfileSpec `json:"spec"`
}

// TLSProfileSpec is spec for TLSServer
type TLSProfileSpec struct {
	Hosts []string `json:"hosts"`
	TLS   TLS      `json:"tls"`
}

// TLS contains required fields for TLS termination
type TLS struct {
	Termination string   `json:"termination"`
	ClientSSL   string   `json:"clientSSL"`
	ClientSSLs  []string `json:"clientSSLs"`
	ServerSSL   string   `json:"serverSSL"`
	ServerSSLs  []string `json:"serverSSLs"`
	Reference   string   `json:"reference"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSProfileList is list of TLS servers
type TLSProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []TLSProfile `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IngressLink is a Custom Resource for KIC Ingress
type IngressLink struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressLinkSpec   `json:"spec"`
	Status IngressLinkStatus `json:"status,omitempty"`
}

// IngressLinkStatus is the status of the ingressLink resource.
type IngressLinkStatus struct {
	VSAddress string `json:"vsAddress,omitempty"`
}

// IngressLinkSpec is Spec for IngressLink
type IngressLinkSpec struct {
	VirtualServerAddress string                `json:"virtualServerAddress,omitempty"`
	Host                 string                `json:"host,omitempty"`
	Selector             *metav1.LabelSelector `json:"selector"`
	IRules               []string              `json:"iRules,omitempty"`
	IPAMLabel            string                `json:"ipamLabel"`
	Partition            string                `json:"partition,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IngressLinkList is list of IngressLink
type IngressLinkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []IngressLink `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:subresource:status

// TransportServer defines the VirtualServer resource.
type TransportServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TransportServerSpec   `json:"spec"`
	Status TransportServerStatus `json:"status,omitempty"`
}

// TransportServerStatus is the status of the VirtualServer resource.
type TransportServerStatus struct {
	VSAddress string `json:"vsAddress,omitempty"`
	StatusOk  string `json:"status,omitempty"`
}

// TransportServerSpec is the spec of the VirtualServer resource.
type TransportServerSpec struct {
	VirtualServerAddress string           `json:"virtualServerAddress"`
	VirtualServerPort    int32            `json:"virtualServerPort"`
	VirtualServerName    string           `json:"virtualServerName"`
	Host                 string           `json:"host,omitempty"`
	HostGroup            string           `json:"hostGroup,omitempty"`
	Mode                 string           `json:"mode"`
	SNAT                 string           `json:"snat"`
	ConnectionMirroring  string           `json:"connectionMirroring,omitempty"`
	Pool                 TSPool           `json:"pool"`
	AllowVLANs           []string         `json:"allowVlans,omitempty"`
	Type                 string           `json:"type,omitempty"`
	ServiceIPAddress     []ServiceAddress `json:"serviceAddress"`
	IPAMLabel            string           `json:"ipamLabel"`
	IRules               []string         `json:"iRules,omitempty"`
	PolicyName           string           `json:"policyName,omitempty"`
	PersistenceProfile   string           `json:"persistenceProfile,omitempty"`
	ProfileL4            string           `json:"profileL4,omitempty"`
	DOS                  string           `json:"dos,omitempty"`
	BotDefense           string           `json:"botDefense,omitempty"`
	Profiles             ProfileTSSpec    `json:"profiles,omitempty"`
	Partition            string           `json:"partition,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TransportServerList is list of TransportServer
type TransportServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []TransportServer `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional

// ExternalDNS defines the DNS resource.
type ExternalDNS struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ExternalDNSSpec `json:"spec"`
}

type ExternalDNSSpec struct {
	DomainName            string    `json:"domainName"`
	DNSRecordType         string    `json:"dnsRecordType"`
	LoadBalanceMethod     string    `json:"loadBalanceMethod"`
	PersistenceEnabled    bool      `json:"persistenceEnabled"`
	PersistCidrIPv4       uint8     `json:"persistCidrIpv4"`
	PersistCidrIPv6       uint8     `json:"persistCidrIpv6"`
	TTLPersistence        uint32    `json:"ttlPersistence"`
	ClientSubnetPreferred *bool     `json:"clientSubnetPreferred,omitempty"`
	Pools                 []DNSPool `json:"pools"`
}

type DNSPool struct {
	DataServerName    string    `json:"dataServerName"`
	DNSRecordType     string    `json:"dnsRecordType"`
	LoadBalanceMethod string    `json:"loadBalanceMethod"`
	LBModeFallback    string    `json:"lbModeFallback"`
	PriorityOrder     int       `json:"order"`
	Ratio             int       `json:"ratio"`
	Monitor           Monitor   `json:"monitor"`
	Monitors          []Monitor `json:"monitors"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalDNSList is list of ExternalDNS
type ExternalDNSList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ExternalDNS `json:"items"`
}

type PolicySpec struct {
	L7Policies   L7PolicySpec     `json:"l7Policies,omitempty"`
	L3Policies   L3PolicySpec     `json:"l3Policies,omitempty"`
	LtmPolicies  LtmIRulesSpec    `json:"ltmPolicies,omitempty"`
	IRules       LtmIRulesSpec    `json:"iRules,omitempty"`
	IRuleList    []string         `json:"iRuleList,omitempty"`
	Profiles     ProfileSpec      `json:"profiles,omitempty"`
	SNAT         string           `json:"snat,omitempty"`
	AutoLastHop  string           `json:"autoLastHop,omitempty"`
	PoolSettings PoolSettingsSpec `json:"poolSettings,omitempty"`
}

type PoolSettingsSpec struct {
	ReselectTries        int32                `json:"reselectTries,omitempty"`
	ServiceDownAction    string               `json:"serviceDownAction,omitempty"`
	SlowRampTime         int32                `json:"slowRampTime,omitempty"`
	MultiPoolPersistence MultiPoolPersistence `json:"multiPoolPersistence,omitempty"`
}

type SSLProfiles struct {
	ClientProfiles []string `json:"clientProfiles,omitempty"`
	ServerProfiles []string `json:"serverProfiles,omitempty"`
}

type AnalyticsProfiles struct {
	HTTPAnalyticsProfile string `json:"http,omitempty"`
}

type L7PolicySpec struct {
	WAF string `json:"waf,omitempty"`
}

type L3PolicySpec struct {
	DOS                  string   `json:"dos,omitempty"`
	BotDefense           string   `json:"botDefense,omitempty"`
	FirewallPolicy       string   `json:"firewallPolicy,omitempty"`
	AllowSourceRange     []string `json:"allowSourceRange,omitempty"`
	AllowVlans           []string `json:"allowVlans,omitempty"`
	IpIntelligencePolicy string   `json:"ipIntelligencePolicy,omitempty"`
}

type LtmIRulesSpec struct {
	Secure   string `json:"secure,omitempty"`
	InSecure string `json:"insecure,omitempty"`
	Priority string `json:"priority,omitempty"`
}

type ProfileSpec struct {
	TCP                   ProfileTCP        `json:"tcp,omitempty"`
	UDP                   string            `json:"udp,omitempty"`
	HTTP                  string            `json:"http,omitempty"`
	HTTP2                 ProfileHTTP2      `json:"http2,omitempty"`
	RewriteProfile        string            `json:"rewriteProfile,omitempty"`
	PersistenceProfile    string            `json:"persistenceProfile,omitempty"`
	LogProfiles           []string          `json:"logProfiles,omitempty"`
	ProfileL4             string            `json:"profileL4,omitempty"`
	ProfileMultiplex      string            `json:"profileMultiplex,omitempty"`
	HttpMrfRoutingEnabled *bool             `json:"httpMrfRoutingEnabled,omitempty"`
	SSLProfiles           SSLProfiles       `json:"sslProfiles,omitempty"`
	AnalyticsProfiles     AnalyticsProfiles `json:"analyticsProfiles,omitempty"`
	ProfileWebSocket      string            `json:"profileWebSocket,omitempty"`
}

type ProfileVSSpec struct {
	TCP   ProfileTCP   `json:"tcp,omitempty"`
	HTTP2 ProfileHTTP2 `json:"http2,omitempty"`
}

type ProfileTSSpec struct {
	TCP ProfileTCP `json:"tcp,omitempty"`
}

type MultiPoolPersistence struct {
	Method  string `json:"method,omitempty"`
	TimeOut int32  `json:"timeOut,omitempty"`
}
type ProfileTCP struct {
	Client string `json:"client,omitempty"`
	Server string `json:"server,omitempty"`
}

type ProfileHTTP2 struct {
	Client string `json:"client,omitempty"`
	Server string `json:"server,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Policy describes a Policy custom resource.
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PolicySpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolicyList is list of Policy resources
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Policy `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DeployConfig defines the DeployConfig resource.
type DeployConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DeployConfigSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DeployConfigList is a list of the DeployConfig resources.
type DeployConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []DeployConfig `json:"items"`
}

type DeployConfigSpec struct {
	BaseConfig    BaseConfig    `json:"baseConfig"`
	NetworkConfig NetworkConfig `json:"networkConfig"`
	AS3Config     AS3Config     `json:"as3Config,omitempty"`
	IPAMConfig    IPAMConfig    `json:"ipamConfig,omitempty"`
	BigIpConfig   []BigIpConfig `json:"bigIpConfig,omitempty"`
	ExtendedSpec  ExtendedSpec  `json:"extendedSpec,omitempty"`
}

type BaseConfig struct {
	NamespaceLabel       string `json:"namespaceLabel,omitempty"`
	NodeLabel            string `json:"nodeLabel,omitempty"`
	RouteLabel           string `json:"routeLabel,omitempty"`
	ControllerIdentifier string `json:"controllerIdentifier"`
}

type NetworkConfig struct {
	OrchestrationCNI string        `json:"orchestrationCNI,omitempty"`
	MetaData         CNIConfigMeta `json:"metaData,omitempty"`
}

type CNIConfigMeta struct {
	PoolMemberType    string `json:"poolMemberType,omitempty"`
	TunnelName        string `json:"tunnelName,omitempty"`
	Shared            bool   `json:"shared,omitempty"`
	NetworkCIDR       string `json:"networkCIDR,omitempty"`
	StaticRoutingMode bool   `json:"staticRoutingMode,omitempty"`
}

type AS3Config struct {
	DebugAS3     bool `json:"debugAS3,omitempty"`
	PostDelayAS3 int  `json:"postDelayAS3,omitempty"`
	DocumentAPI  bool `json:"documentAPI,omitempty"`
}

type IPAMConfig struct {
	Host string `json:"host,omitempty"`
}

type BigIpConfig struct {
	BigIpAddress     string `json:"bigIpAddress,omitempty"`
	HaBigIpAddress   string `json:"haBigIpAddress,omitempty"`
	BigIpLabel       string `json:"bigIpLabel,omitempty"`
	DefaultPartition string `json:"defaultPartition,omitempty"`
}

type ExtendedSpec struct {
	ExtendedRouteGroupConfigs []ExtendedRouteGroupConfig `json:"extendedRouteSpec"`
	BaseRouteConfig           `json:"baseRouteSpec"`
	ExternalClustersConfig    []ExternalClusterConfig `json:"externalClustersConfig"`
	HAClusterConfig           HAClusterConfig         `json:"highAvailabilityCIS"`
	HAMode                    HAModeType              `json:"mode"`
	LocalClusterRatio         *int                    `json:"localClusterRatio"`
	LocalClusterAdminState    AdminState              `json:"localClusterAdminState"`
}

type ExtendedRouteGroupConfig struct {
	Namespace              string `json:"namespace"`      // Group Identifier
	NamespaceLabel         string `json:"namespaceLabel"` // Group Identifier
	BigIpPartition         string `json:"bigIpPartition"` // bigip Partition
	ExtendedRouteGroupSpec `json:",inline"`
}

type ExtendedRouteGroupSpec struct {
	VServerName        string `json:"vserverName"`
	VServerAddr        string `json:"vserverAddr"`
	AllowOverride      string `json:"allowOverride"`
	Policy             string `json:"policyCR,omitempty"`
	HTTPServerPolicyCR string `json:"httpServerPolicyCR,omitempty"`
	Meta               Meta   `json:",inline"`
}

type Meta struct {
	DependsOnTLS bool `json:",inline"`
}

type DefaultRouteGroupConfig struct {
	BigIpPartition        string                 `json:"bigIpPartition"` // bigip Partition
	DefaultRouteGroupSpec ExtendedRouteGroupSpec `json:",inline"`
}

type BaseRouteConfig struct {
	TLSCipher               TLSCipher               `json:"tlsCipher"`
	DefaultTLS              DefaultSSLProfile       `json:"defaultTLS,omitempty"`
	DefaultRouteGroupConfig DefaultRouteGroupConfig `json:"defaultRouteGroup,omitempty"`
	AutoMonitor             AutoMonitorType         `json:"autoMonitor,omitempty"`
	AutoMonitorTimeout      int                     `json:"autoMonitorTimeout,omitempty"`
}

type TLSCipher struct {
	TLSVersion  string `json:"tlsVersion,omitempty"`
	Ciphers     string `json:"ciphers,omitempty"`
	CipherGroup string `json:"cipherGroup,omitempty"` // by default this is bigip reference
}
type DefaultSSLProfile struct {
	ClientSSL string `json:"clientSSL,omitempty"`
	ServerSSL string `json:"serverSSL,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type ExternalClusterConfig struct {
	ClusterName string     `json:"clusterName"`
	Secret      string     `json:"secret"`
	Ratio       *int       `json:"ratio"`
	AdminState  AdminState `json:"adminState"`
}

type HAClusterConfig struct {
	// HAMode                 HAMode         `json:"mode"`
	PrimaryClusterEndPoint string         `json:"primaryEndPoint"`
	ProbeInterval          int            `json:"probeInterval"`
	RetryInterval          int            `json:"retryInterval"`
	PrimaryCluster         ClusterDetails `json:"primaryCluster"`
	SecondaryCluster       ClusterDetails `json:"secondaryCluster"`
}

type HAMode struct {
	// type can be active-active, active-standby, ratio
	Type HAModeType `json:"type"`
}

type HAModeType string
type AutoMonitorType string
type AdminState string

type ClusterDetails struct {
	ClusterName string     `json:"clusterName"`
	Secret      string     `json:"secret"`
	Ratio       *int       `json:"ratio"`
	AdminState  AdminState `json:"adminState"`
}
