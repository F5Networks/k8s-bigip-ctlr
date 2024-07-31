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
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/ipmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/networkmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	"net/http"
	"sync"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"

	"k8s.io/apimachinery/pkg/util/intstr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"

	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/teem"

	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	//apm "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type (
	// Controller defines the structure of K-Native and Custom Resource Controller
	Controller struct {
		resources              *ResourceStore
		clientsets             *ClientSets
		namespacesMutex        sync.Mutex
		namespaces             map[string]bool
		initialResourceCount   int
		resourceQueue          workqueue.RateLimitingInterface
		PostParams             PostParams
		RequestHandler         *RequestHandler
		PoolMemberType         string
		UseNodeInternal        bool
		initState              bool
		shareNodes             bool
		ipamHandler            *ipmanager.IPAMHandler
		defaultRouteDomain     int
		TeemData               *teem.TeemsData
		requestMap             *requestMap
		StaticRoutingMode      bool
		OrchestrationCNI       string
		StaticRouteNodeCIDR    string
		cacheIPAMHostSpecs     CacheIPAM
		multiClusterConfigs    *clustermanager.MultiClusterConfig
		multiClusterResources  *MultiClusterResourceStore
		multiClusterMode       string
		haModeType             cisapiv1.HAModeType
		clusterRatio           map[string]*int
		clusterAdminState      map[string]cisapiv1.AdminState
		managedResources       ManagedResources
		resourceSelectorConfig ResourceSelectorConfig
		CMTokenManager         *tokenmanager.TokenManager
		bigIpConfigMap         BigIpConfigMap
		respChan               chan *agentConfig
		networkManager         *networkmanager.NetworkManager
		ControllerIdentifier   string
		resourceContext
	}
	ClientSets struct {
		KubeCRClient  versioned.Interface
		KubeClient    kubernetes.Interface
		RouteClientV1 routeclient.RouteV1Interface
	}
	ManagedResources struct {
		ManageRoutes          bool
		ManageCustomResources bool
		ManageTransportServer bool
		ManageVirtualServer   bool
		ManageEDNS            bool
		ManageIL              bool
		ManageTLSProfile      bool
		ManageSecrets         bool
	}
	ResourceSelectorConfig struct {
		NamespaceLabel         string
		NodeLabel              string
		RouteLabel             string
		nativeResourceSelector labels.Selector
		customResourceSelector labels.Selector
	}
	resourceContext struct {
		resourceQueue             workqueue.RateLimitingInterface
		comInformers              map[string]*CommonInformer
		nrInformers               map[string]*NRInformer
		crInformers               map[string]*CRInformer
		nsInformers               map[string]*NSInformer
		multiClusterPoolInformers map[string]map[string]*MultiClusterPoolInformer
		multiClusterNodeInformers map[string]*NodeInformer
		CISConfigCRKey            string
		namespaceLabelMode        bool
		processedHostPath         *ProcessedHostPath
	}

	// Params defines parameters
	Params struct {
		Config                *rest.Config
		ClientSets            *ClientSets
		Namespaces            []string
		UserAgent             string
		UseNodeInternal       bool
		NodePollInterval      int
		IPAM                  bool
		DefaultRouteDomain    int
		CISConfigCRKey        string
		MultiClusterMode      string
		CMConfigDetails       *CMConfig
		CMTrustedCerts        string
		CMSSLInsecure         bool
		HttpAddress           string
		ManageCustomResources bool
		httpClientMetrics     bool
		IPAMNamespace         string
	}

	// CMConfig defines the Central Manager config
	CMConfig struct {
		URL      string
		UserName string
		Password string
	}

	// CRInformer defines the structure of Custom Resource Informer
	CRInformer struct {
		namespace   string
		stopCh      chan struct{}
		vsInformer  cache.SharedIndexInformer
		tlsInformer cache.SharedIndexInformer
		tsInformer  cache.SharedIndexInformer
		ilInformer  cache.SharedIndexInformer
	}

	CommonInformer struct {
		namespace        string
		stopCh           chan struct{}
		svcInformer      cache.SharedIndexInformer
		epsInformer      cache.SharedIndexInformer
		ednsInformer     cache.SharedIndexInformer
		plcInformer      cache.SharedIndexInformer
		podInformer      cache.SharedIndexInformer
		secretsInformer  cache.SharedIndexInformer
		configCRInformer cache.SharedIndexInformer
	}

	// NRInformer is informer context for Native Resources of Kubernetes/Openshift
	NRInformer struct {
		namespace     string
		stopCh        chan struct{}
		routeInformer cache.SharedIndexInformer
	}

	NodeInformer struct {
		stopCh       chan struct{}
		nodeInformer cache.SharedIndexInformer
		clusterName  string
		oldNodes     []Node
	}

	NSInformer struct {
		stopCh     chan struct{}
		cluster    string
		nsInformer cache.SharedIndexInformer
	}
	rqKey struct {
		namespace      string
		kind           string
		rscName        string
		rsc            interface{}
		event          string
		clusterName    string
		svcPortUpdated bool
	}

	metaData struct {
		Active       bool
		ResourceType string
		// resource name as key, resource kind as value
		baseResources   map[string]string
		namespace       string
		hosts           []string
		Protocol        string
		httpTraffic     string
		defaultPoolType string
	}

	// Virtual server config
	Virtual struct {
		Name                       string                `json:"name"`
		PoolName                   string                `json:"pool,omitempty"`
		Partition                  string                `json:"-"`
		Destination                string                `json:"destination"`
		Enabled                    bool                  `json:"enabled"`
		IpProtocol                 string                `json:"ipProtocol,omitempty"`
		SourceAddrTranslation      SourceAddrTranslation `json:"sourceAddressTranslation,omitempty"`
		Policies                   []nameRef             `json:"policies,omitempty"`
		Profiles                   ProfileRefs           `json:"profiles,omitempty"`
		IRules                     []string              `json:"rules,omitempty"`
		Description                string                `json:"description,omitempty"`
		VirtualAddress             *virtualAddress       `json:"-"`
		AdditionalVirtualAddresses []string              `json:"additionalVirtualAddresses,omitempty"`
		SNAT                       string                `json:"snat,omitempty"`
		ConnectionMirroring        string                `json:"connectionMirroring,omitempty"`
		WAF                        string                `json:"waf,omitempty"`
		Firewall                   string                `json:"firewallPolicy,omitempty"`
		LogProfiles                []string              `json:"logProfiles,omitempty"`
		ProfileL4                  string                `json:"profileL4,omitempty"`
		ProfileMultiplex           string                `json:"profileMultiplex,omitempty"`
		ProfileWebSocket           string                `json:"profileWebSocket,omitempty"`
		ProfileDOS                 string                `json:"profileDOS,omitempty"`
		ProfileBotDefense          string                `json:"profileBotDefense,omitempty"`
		TCP                        ProfileTCP            `json:"tcp,omitempty"`
		HTTP2                      ProfileHTTP2          `json:"http2,omitempty"`
		Mode                       string                `json:"mode,omitempty"`
		TranslateServerAddress     bool                  `json:"translateServerAddress"`
		TranslateServerPort        bool                  `json:"translateServerPort"`
		Source                     string                `json:"source,omitempty"`
		AllowVLANs                 []string              `json:"allowVlans,omitempty"`
		PersistenceProfile         string                `json:"persistenceProfile,omitempty"`
		TLSTermination             string                `json:"-"`
		AllowSourceRange           []string              `json:"allowSourceRange,omitempty"`
		HttpMrfRoutingEnabled      *bool                 `json:"httpMrfRoutingEnabled,omitempty"`
		IpIntelligencePolicy       string                `json:"ipIntelligencePolicy,omitempty"`
		AutoLastHop                string                `json:"lastHop,omitempty"`
		AnalyticsProfiles          AnalyticsProfiles     `json:"analyticsProfiles,omitempty"`
		MultiPoolPersistence       MultiPoolPersistence  `json:"multiPoolPersistence,omitempty"`
	}
	MultiPoolPersistence struct {
		Method  string `json:"method,omitempty"`
		TimeOut int32  `json:"timeOut,omitempty"`
	}
	// Virtuals is slice of virtuals
	Virtuals []Virtual

	AnalyticsProfiles struct {
		HTTPAnalyticsProfile string `json:"http,omitempty"`
	}

	ProfileTCP struct {
		Client string `json:"client,omitempty"`
		Server string `json:"server,omitempty"`
	}

	ProfileHTTP2 struct {
		Client string `json:"client,omitempty"`
		Server string `json:"server,omitempty"`
	}

	// ServiceAddress Service IP address definition (BIG-IP virtual-address).
	ServiceAddress struct {
		ArpEnabled         bool   `json:"arpEnabled,omitempty"`
		ICMPEcho           string `json:"icmpEcho,omitempty"`
		RouteAdvertisement string `json:"routeAdvertisement,omitempty"`
		TrafficGroup       string `json:"trafficGroup,omitempty"`
		SpanningEnabled    bool   `json:"spanningEnabled,omitempty"`
	}

	// SourceAddrTranslation is Virtual Server Source Address Translation
	SourceAddrTranslation struct {
		Type string `json:"type"`
		Pool string `json:"pool,omitempty"`
	}

	// frontend bindaddr and port
	virtualAddress struct {
		BindAddr string `json:"bindAddr,omitempty"`
		Port     int32  `json:"port,omitempty"`
	}

	// nameRef is virtual server policy/profile reference
	nameRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
	}

	// ResourceConfig contains a set of LTM resources to create a Virtual Server
	ResourceConfig struct {
		MetaData       metaData         `json:"-"`
		Virtual        Virtual          `json:"virtual,omitempty"`
		Pools          Pools            `json:"pools,omitempty"`
		Policies       Policies         `json:"policies,omitempty"`
		Monitors       []Monitor        `json:"monitors,omitempty"`
		ServiceAddress []ServiceAddress `json:"serviceAddress,omitempty"`
		IRulesMap      IRulesMap
		IntDgMap       InternalDataGroupMap
		customProfiles map[SecretKey]CustomProfile
	}
	// ResourceConfigs is group of ResourceConfig
	ResourceConfigs []*ResourceConfig

	// ResourceStore contain processed LTM and GTM resource data
	ResourceStore struct {
		bigIpMap      BigIpConfigMap
		bigIpMapCache BigIpConfigMap
		nplStore      NPLStore
		supplementContextCache
	}

	// LTMConfig contain partition based ResourceMap
	LTMConfig map[string]*PartitionConfig

	// PartitionConfig contains ResourceMap and priority of partition
	PartitionConfig struct {
		ResourceMap   ResourceMap
		Priority      *int
		PriorityMutex sync.RWMutex
	}

	// ResourceMap key is resource name, value is pointer to config. May be shared.
	ResourceMap map[string]*ResourceConfig

	// PoolMemberCache key is namespace/service
	PoolMemberCache map[MultiClusterServiceKey]*poolMembersInfo
	// Store of CustomProfiles
	CustomProfileStore struct {
		sync.Mutex
		Profs map[SecretKey]CustomProfile
	}

	// key is namespace/pod. stores list of npl annotation on pod
	NPLStore map[string]NPLAnnoations

	// GTMConfig key is domainName and value is WideIP

	WideIPs struct {
		WideIPs []WideIP `json:"wideIPs"`
	}
	// GTMConfig key is PartitionName
	GTMConfig map[string]GTMPartitionConfig

	GTMPartitionConfig struct {
		// WideIPs: key is domainName, and value is WideIP
		WideIPs map[string]WideIP
	}

	WideIP struct {
		DomainName            string     `json:"name"`
		ClientSubnetPreferred *bool      `json:"clientSubnetPreferred,omitempty"`
		RecordType            string     `json:"recordType"`
		LBMethod              string     `json:"LoadBalancingMode"`
		PersistenceEnabled    bool       `json:"persistenceEnabled"`
		PersistCidrIPv4       uint8      `json:"persistCidrIpv4"`
		PersistCidrIPv6       uint8      `json:"persistCidrIpv6"`
		TTLPersistence        uint32     `json:"ttlPersistence"`
		Pools                 []GSLBPool `json:"pools"`
		UID                   string
	}

	GSLBPool struct {
		Name           string    `json:"name"`
		RecordType     string    `json:"recordType"`
		LBMethod       string    `json:"LoadBalancingMode"`
		LBModeFallBack string    `json:"fallbackMode"`
		PriorityOrder  int       `json:"order"`
		Ratio          int       `json:"ratio"`
		Members        []string  `json:"members"`
		Monitors       []Monitor `json:"monitors,omitempty"`
		DataServer     string
	}

	// ResourceConfigRequest Each BigIPConfig per BigIP HA pair to put into the queue to process
	ResourceConfigRequest struct {
		bigIpConfig         cisapiv1.BigIpConfig
		bigIpResourceConfig BigIpResourceConfig
		reqMeta             requestMeta
		poolMemberType      string
	}

	// BigIpConfigMap Where key is the BigIP structure and value is the bigip-next configuration
	BigIpConfigMap map[cisapiv1.BigIpConfig]BigIpResourceConfig

	// BigIP struct to hold the bigip address and label for HA pairs
	BIGIPConfigs []cisapiv1.BigIpConfig

	// BigIpResourceConfig struct to hold the bigip-next ltm and gtm configuration
	BigIpResourceConfig struct {
		ltmConfig  LTMConfig
		gtmConfig  GTMConfig
		shareNodes bool
	}

	resourceRef struct {
		kind      string
		name      string
		namespace string
	}

	VSSpecProperties struct {
		PoolWAF bool
	}

	// Pool config
	Pool struct {
		Name                 string                                  `json:"name"`
		Partition            string                                  `json:"-"`
		ServiceName          string                                  `json:"-"`
		ServiceNamespace     string                                  `json:"-"`
		ServicePort          intstr.IntOrString                      `json:"-"`
		Balance              string                                  `json:"loadBalancingMethod,omitempty"`
		Members              []PoolMember                            `json:"members"`
		NodeMemberLabel      string                                  `json:"-"`
		MonitorNames         []MonitorName                           `json:"monitors,omitempty"`
		MinimumMonitors      intstr.IntOrString                      `json:"minimumMonitors,omitempty"`
		ReselectTries        int32                                   `json:"reselectTries,omitempty"`
		ServiceDownAction    string                                  `json:"serviceDownAction,omitempty"`
		SlowRampTime         int32                                   `json:"slowRampTime,omitempty"`
		Weight               int32                                   `json:"weight,omitempty"`
		AlternateBackends    []AlternateBackend                      `json:"alternateBackends"`
		MultiClusterServices []cisapiv1.MultiClusterServiceReference `json:"_"`
		Cluster              string                                  `json:"-"`
		ConnectionLimit      int32                                   `json:"-"`
	}
	CacheIPAM struct {
		IPAM *ficV1.IPAM
		sync.Mutex
	}
	// AlternateBackends lists backend svc of A/B
	AlternateBackend struct {
		Service          string `json:"service"`
		ServiceNamespace string `json:"serviceNamespace,omitempty"`
		Weight           int32  `json:"weight,omitempty"`
	}

	// Pools is slice of pool
	Pools []Pool

	portRef struct {
		name string
		port int32
	}
	poolMembersInfo struct {
		svcType   v1.ServiceType
		portSpec  []v1.ServicePort
		memberMap map[portRef][]PoolMember
	}

	// Monitor is Pool health monitor
	Monitor struct {
		Name        string `json:"name"`
		Partition   string `json:"-"`
		Interval    int    `json:"interval,omitempty"`
		Type        string `json:"type,omitempty"`
		Send        string `json:"send,omitempty"`
		Recv        string `json:"recv"`
		Timeout     int    `json:"timeout,omitempty"`
		TargetPort  int32  `json:"targetPort,omitempty"`
		Path        string `json:"path,omitempty"`
		TimeUntilUp *int   `json:"timeUntilUp,omitempty"`
	}
	MonitorName struct {
		Name string `json:"name"`
		// Reference is used to link existing health monitor on bigip
		Reference string `json:"reference,omitempty"`
	}
	// Monitors  is slice of monitor
	Monitors []Monitor

	supplementContextCache struct {
		baseRouteConfig           cisapiv1.BaseRouteConfig
		poolMemCache              PoolMemberCache
		sslContext                map[string]*v1.Secret
		extdSpecMap               extendedSpecMap
		invertedNamespaceLabelMap map[string]string
		processedNativeResources  map[resourceRef]struct{}
		// stores valid externalClustersConfig from extendendCM
		externalClustersConfig map[string]cisapiv1.ExternalClusterConfig
	}

	// key is group identifier
	extendedSpecMap map[string]*extendedParsedSpec

	// Extended Spec for each group of Routes/Ingress
	extendedParsedSpec struct {
		override   bool
		local      *cisapiv1.ExtendedRouteGroupSpec
		global     *cisapiv1.ExtendedRouteGroupSpec
		defaultrg  *cisapiv1.ExtendedRouteGroupSpec
		namespaces []string
		partition  string
	}

	// This is the format for each item in the health monitor annotation used
	// in the ServiceType LB objects.
	ServiceTypeLBHealthMonitor struct {
		Interval int `json:"interval"`
		Timeout  int `json:"timeout"`
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
		WAF       bool   `json:"waf,omitempty"`
		Policy    string `json:"policy,omitempty"`
		Drop      bool   `json:"drop,omitempty"`
		Enabled   *bool  `json:"enabled,omitempty"`
		Log       bool   `json:"log,omitempty"`
		Message   string `json:"message,omitempty"`
	}

	// condition config for a Rule
	condition struct {
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

		SSLExtensionClient bool `json:"-"`
	}

	// Rules is a slice of Rule
	Rules   []*Rule
	ruleMap map[string]*Rule

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
		Type      string                   `json:"-"`
		Records   InternalDataGroupRecords `json:"records"`
	}

	InternalDataGroupRecord struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	InternalDataGroupRecords []InternalDataGroupRecord

	DataGroupNamespaceMap map[string]*InternalDataGroup
	InternalDataGroupMap  map[NameRef]DataGroupNamespaceMap

	// virtual server policy/profile reference
	NameRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
	}

	// Policy Virtual policy
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
	// Policies is slice of policy
	Policies []Policy

	// ProfileRef is a Reference to pre-existing profiles
	ProfileRef struct {
		Name      string `json:"name"`
		Partition string `json:"partition"`
		Context   string `json:"context"` // 'clientside', 'serverside', or 'all'
		// Used as reference to which Namespace/Ingress this profile came from
		// (for deletion purposes)
		Namespace    string `json:"-"`
		BigIPProfile bool   `json:"-"`
	}
	// ProfileRefs is a list of ProfileRef
	ProfileRefs []ProfileRef

	SecretKey struct {
		Name         string
		ResourceName string
	}

	// SSL Profile loaded from Secret or Route object
	CustomProfile struct {
		Name          string `json:"name"`
		Partition     string `json:"-"`
		Context       string `json:"context"` // 'clientside', 'serverside', or 'all'
		Ciphers       string `json:"ciphers,omitempty"`
		CipherGroup   string `json:"cipherGroup,omitempty"`
		TLS1_3Enabled bool   `json:"tls1_3Enabled"`
		ServerName    string `json:"serverName,omitempty"`
		SNIDefault    bool   `json:"sniDefault,omitempty"`
		PeerCertMode  string `json:"peerCertMode,omitempty"`
		CAFile        string `json:"caFile,omitempty"`
		ChainCA       string `json:"chainCA,omitempty"`
		Certificates  []certificate
	}

	certificate struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}

	portStruct struct {
		protocol string
		port     int32
	}

	requestMap struct {
		sync.RWMutex
		requestMap map[cisapiv1.BigIpConfig]requestMeta
	}

	requestMeta struct {
		partitionMap map[string]map[string]string
		id           int
	}

	Node struct {
		Name   string
		Addr   string
		Labels map[string]string
	}
	// NPL information from pod annotation
	NPLAnnotation struct {
		PodPort  int32  `json:"podPort"`
		NodeIP   string `json:"nodeIP"`
		NodePort int32  `json:"nodePort"`
	}

	// List of NPL annotations
	NPLAnnoations []NPLAnnotation

	// Store of CustomProfiles
	ProcessedHostPath struct {
		sync.Mutex
		processedHostPathMap map[string]metav1.Time
		removedHosts         []string
	}
)

type (
	Services        []*v1.Service
	NodeList        []v1.Node
	RouteBackendCxt struct {
		Weight       float64
		Name         string
		Cluster      string
		SvcNamespace string
	}
	SvcBackendCxt struct {
		Weight       float64
		Name         string
		SvcNamespace string `json:"svcNamespace,omitempty"`
		Cluster      string
	}
)

type L3PostManager struct {
}

type (
	RequestHandler struct {
		PostManagers                    PostManagers
		reqChan                         chan ResourceConfigRequest
		userAgent                       string
		PostParams                      PostParams
		respChan                        chan *agentConfig
		CMTokenManager                  *tokenmanager.TokenManager
		HAMode                          bool
		PrimaryClusterHealthProbeParams PrimaryClusterHealthProbeParams
		httpClientMetrics               bool
	}

	PostManager struct {
		AS3PostManager *AS3PostManager
		L3PostManager  *L3PostManager
		tokenManager   *tokenmanager.TokenManager
		// cachedTenantDeclMap,incomingTenantDeclMap hold tenant names and corresponding AS3 config
		cachedTenantDeclMap map[string]as3Tenant
		postChan            chan agentConfig
		defaultPartition    string
		respChan            chan *agentConfig
		PostParams
		postManagerPrefix      string
		tenantDeclarationIDMap map[string]string
	}

	PostManagers struct {
		sync.RWMutex
		PostManagerMap map[cisapiv1.BigIpConfig]*PostManager
	}
	AS3PostManager struct {
		AS3VersionInfo  as3VersionInfo
		AS3Config       cisapiv1.AS3Config
		bigIPAS3Version float64
		firstPost       bool
		bigipLabel      string
	}

	PrimaryClusterHealthProbeParams struct {
		paramLock     *sync.RWMutex
		EndPoint      string
		EndPointType  string
		statusRunning bool
		statusChanged bool
		probeInterval int
		retryInterval int
	}

	PostParams struct {
		HTTPClientMetrics bool
		httpClient        *http.Client
		AS3Config         cisapiv1.AS3Config
		tokenManager      *tokenmanager.TokenManager
		UserAgent         string
	}

	tenantResponse struct {
		agentResponseCode int
		isDeleted         bool
	}

	//agentConfig holds as3config and l3config to put onto post channel
	agentConfig struct {
		as3Config   as3Config
		l3Config    l3Config
		id          int
		BigIpConfig cisapiv1.BigIpConfig
		reqMeta     requestMeta
	}
	//as3Config to put into post channel
	as3Config struct {
		data                  string
		targetAddress         string
		as3APIURL             string
		id                    int
		tenantResponseMap     map[string]tenantResponse
		acceptedTaskId        string
		failedTenants         map[string]struct{}
		incomingTenantDeclMap map[string]as3Tenant
		deleted               bool
	}

	//TODO L3Config to put into post channel. Handle with L3Postmanager implementation
	l3Config struct {
		deployL3Status bool
	}

	// AS3 version struct

	as3VersionInfo struct {
		as3Version       string
		as3SchemaVersion string
		as3Release       string
	}

	as3Declaration string

	as3JSONWithArbKeys map[string]interface{}

	// TODO: Need to remove omitempty tag for the mandatory fields
	// as3JSONDeclaration maps to ADC in AS3 Resources
	as3ADC as3JSONWithArbKeys
	// target bigip
	as3Target as3JSONWithArbKeys
	// as3Tenant maps to Tenant in AS3 Resources
	as3Tenant as3JSONWithArbKeys

	// as3Application maps to Application in AS3 Resources
	as3Application as3JSONWithArbKeys

	// as3EndpointPolicy maps to Endpoint_Policy in AS3 Resources
	as3EndpointPolicy struct {
		Class    string     `json:"class,omitempty"`
		Rules    []*as3Rule `json:"rules,omitempty"`
		Strategy string     `json:"strategy,omitempty"`
	}

	// as3Rule maps to Endpoint_Policy_Rule in AS3 Resources
	as3Rule struct {
		Name       string          `json:"name,omitempty"`
		Conditions []*as3Condition `json:"conditions,omitempty"`
		Actions    []*as3Action    `json:"actions,omitempty"`
	}

	as3ProfileTCP struct {
		Ingress *as3ResourcePointer `json:"ingress,omitempty"`
		Egress  *as3ResourcePointer `json:"egress,omitempty"`
	}

	as3ProfileHTTP2 struct {
		Ingress *as3ResourcePointer `json:"ingress,omitempty"`
		Egress  *as3ResourcePointer `json:"egress,omitempty"`
	}

	// as3Action maps to Policy_Action in AS3 Resources
	as3Action struct {
		Type     string                  `json:"type,omitempty"`
		Event    string                  `json:"event,omitempty"`
		Select   *as3ActionForwardSelect `json:"select,omitempty"`
		Policy   *as3ResourcePointer     `json:"policy,omitempty"`
		Enabled  *bool                   `json:"enabled,omitempty"`
		Location string                  `json:"location,omitempty"`
		Replace  *as3ActionReplaceMap    `json:"replace,omitempty"`
		Write    *as3LogMessage          `json:"write,omitempty"`
	}

	as3ActionReplaceMap struct {
		Value string `json:"value,omitempty"`
		Name  string `json:"name,omitempty"`
		Path  string `json:"path,omitempty"`
	}

	as3LogMessage struct {
		Message string `json:"message,omitempty"`
	}

	// as3Condition maps to Policy_Condition in AS3 Resources
	as3Condition struct {
		Type        string                  `json:"type,omitempty"`
		Name        string                  `json:"name,omitempty"`
		Event       string                  `json:"event,omitempty"`
		All         *as3PolicyCompareString `json:"all,omitempty"`
		Index       int                     `json:"index,omitempty"`
		Host        *as3PolicyCompareString `json:"host,omitempty"`
		PathSegment *as3PolicyCompareString `json:"pathSegment,omitempty"`
		Path        *as3PolicyCompareString `json:"path,omitempty"`
		ServerName  *as3PolicyCompareString `json:"serverName,omitempty"`
		Address     *as3PolicyAddressString `json:"address,omitempty"`
	}

	// as3ActionForwardSelect maps to Policy_Action_Forward_Select in AS3 Resources
	as3ActionForwardSelect struct {
		Pool    *as3ResourcePointer `json:"pool,omitempty"`
		Service *as3ResourcePointer `json:"service,omitempty"`
	}

	// as3MultiTypeParam can be used for parameters that accept values of different types
	// Eg: profileHTTP (string | Service_HTTP_profileHTTP) in Service_HTTP in AS3 Resources
	as3MultiTypeParam interface{}

	// as3PolicyCompareString maps to Policy_Compare_String in AS3 Resources
	as3PolicyCompareString struct {
		CaseSensitive bool     `json:"caseSensitive,omitempty"`
		Values        []string `json:"values,omitempty"`
		Operand       string   `json:"operand"`
	}

	// as3PolicyAddressString maps to Policy_Compare_String in AS3 Resources
	as3PolicyAddressString struct {
		Values []string `json:"values,omitempty"`
	}

	// as3Pool maps to Pool in AS3 Resources
	as3Pool struct {
		Class             string               `json:"class,omitempty"`
		LoadBalancingMode string               `json:"loadBalancingMode,omitempty"`
		Members           []as3PoolMember      `json:"members,omitempty"`
		Monitors          []as3ResourcePointer `json:"monitors,omitempty"`
		SlowRampTime      int32                `json:"slowRampTime,omitempty"`
	}

	// as3PoolMember maps to Pool_Member in AS3 Resources
	as3PoolMember struct {
		AddressDiscovery string   `json:"addressDiscovery,omitempty"`
		ServerAddresses  []string `json:"serverAddresses,omitempty"`
		ServicePort      int32    `json:"servicePort,omitempty"`
		ShareNodes       bool     `json:"shareNodes,omitempty"`
		AdminState       string   `json:"adminState,omitempty"`
		ConnectionLimit  int32    `json:"connectionLimit,omitempty"`
	}

	// as3ResourcePointer maps to following in AS3 Resources
	// - Pointer_*
	// - Service_HTTP_*
	// - Service_HTTPS_*
	// - Service_TCP_*
	// - Service_UDP_*
	as3ResourcePointer struct {
		BigIP string `json:"bigip,omitempty"`
		Use   string `json:"use,omitempty"`
		CM    string `json:"cm,omitempty"`
	}

	// as3Service maps to the following in AS3 Resources
	// - Service_HTTP
	// - Service_HTTPS
	// - Service_TCP
	// - Service_UDP
	as3Service struct {
		Layer4           string              `json:"layer4,omitempty"`
		Class            string              `json:"class,omitempty"`
		VirtualAddresses []as3MultiTypeParam `json:"virtualAddresses,omitempty"`
		VirtualPort      int                 `json:"virtualPort,omitempty"`
		SNAT             as3MultiTypeParam   `json:"snat,omitempty"`
		Mirroring        string              `json:"mirroring,omitempty"`
		PolicyEndpoint   as3MultiTypeParam   `json:"policyEndpoint,omitempty"`
		ClientTLS        as3MultiTypeParam   `json:"clientTLS,omitempty"`
		ServerTLS        as3MultiTypeParam   `json:"serverTLS,omitempty"`
		IRules           as3MultiTypeParam   `json:"iRules,omitempty"`
		Redirect80       *bool               `json:"redirect80,omitempty"`
		//Pool                 *as3ResourcePointer  `json:"pool,omitempty"`
		Pool                 interface{}          `json:"pool,omitempty"`
		WAF                  as3MultiTypeParam    `json:"policyWAF,omitempty"`
		Firewall             as3MultiTypeParam    `json:"policyFirewallEnforced,omitempty"`
		LogProfiles          []as3ResourcePointer `json:"securityLogProfiles,omitempty"`
		ProfileL4            as3MultiTypeParam    `json:"profileL4,omitempty"`
		PersistenceMethods   *[]as3MultiTypeParam `json:"persistenceMethods,omitempty"`
		ProfileTCP           as3MultiTypeParam    `json:"profileTCP,omitempty"`
		ProfileUDP           as3MultiTypeParam    `json:"profileUDP,omitempty"`
		ProfileHTTP          as3MultiTypeParam    `json:"profileHTTP,omitempty"`
		ProfileHTTP2         as3MultiTypeParam    `json:"profileHTTP2,omitempty"`
		ProfileMultiplex     as3MultiTypeParam    `json:"profileMultiplex,omitempty"`
		HttpAnalyticsProfile *as3ResourcePointer  `json:"profileAnalytics,omitempty"`
	}

	// as3ServiceAddress maps to VirtualAddress in AS3 Resources
	as3ServiceAddress struct {
		Class              string `json:"class,omitempty"`
		VirtualAddress     string `json:"virtualAddress,omitempty"`
		ArpEnabled         bool   `json:"arpEnabled"`
		ICMPEcho           string `json:"icmpEcho,omitempty"`
		RouteAdvertisement string `json:"routeAdvertisement,omitempty"`
		TrafficGroup       string `json:"trafficGroup,omitempty"`
		SpanningEnabled    bool   `json:"spanningEnabled"`
	}

	// as3Monitor maps to the following in AS3 Resources
	// - Monitor
	// - Monitor_HTTP
	// - Monitor_HTTPS
	as3Monitor struct {
		Class             string `json:"class,omitempty"`
		Interval          int    `json:"interval,omitempty"`
		MonitorType       string `json:"monitorType,omitempty"`
		Timeout           int    `json:"timeout,omitempty"`
		TimeUnitilUp      *int   `json:"timeUntilUp,omitempty"`
		Receive           string `json:"receive"`
		Send              string `json:"send"`
		ClientCertificate string `json:"clientCertificate,omitempty"`
		Ciphers           string `json:"ciphers,omitempty"`
	}

	// as3CABundle maps to CA_Bundle in AS3 Resources
	as3CABundle struct {
		Class  string `json:"class,omitempty"`
		Bundle string `json:"bundle,omitempty"`
	}

	// as3Certificate maps to Certificate in AS3 Resources
	as3Certificate struct {
		Class       string            `json:"class,omitempty"`
		Certificate as3MultiTypeParam `json:"certificate,omitempty"`
		PrivateKey  as3MultiTypeParam `json:"privateKey,omitempty"`
		ChainCA     as3MultiTypeParam `json:"chainCA,omitempty"`
	}

	// as3TLSServer maps to TLS_Server in AS3 Resources
	as3TLSServer struct {
		Class         string                     `json:"class,omitempty"`
		Certificates  []as3TLSServerCertificates `json:"certificates,omitempty"`
		Ciphers       string                     `json:"ciphers,omitempty"`
		CipherGroup   *as3ResourcePointer        `json:"cipherGroup,omitempty"`
		TLS1_3Enabled bool                       `json:"tls1_3Enabled,omitempty"`
	}

	// as3TLSServerCertificates maps to TLS_Server_certificates in AS3 Resources
	as3TLSServerCertificates struct {
		Certificate string `json:"certificate,omitempty"`
		SNIDefault  bool   `json:"sniDefault,omitempty"`
	}

	// as3TLSClient maps to TLS_Client in AS3 Resources
	as3TLSClient struct {
		Class               string              `json:"class,omitempty"`
		TrustCA             *as3ResourcePointer `json:"trustCA,omitempty"`
		ValidateCertificate bool                `json:"validateCertificate,omitempty"`
		Ciphers             string              `json:"ciphers,omitempty"`
		CipherGroup         *as3ResourcePointer `json:"cipherGroup,omitempty"`
		TLS1_3Enabled       bool                `json:"tls1_3Enabled,omitempty"`
	}

	// as3DataGroup maps to Data_Group in AS3 Resources
	as3DataGroup struct {
		Records     []as3Record `json:"records"`
		KeyDataType string      `json:"keyDataType"`
		Class       string      `json:"class"`
	}

	// as3Record maps to Data_Group_*records in AS3 Resources
	as3Record struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	// as3IRules maps to the following in AS3 Resources
	as3IRules struct {
		Class string `json:"class,omitempty"`
		IRule string `json:"iRule,omitempty"`
	}

	PoolMember struct {
		Address         string `json:"address"`
		Port            int32  `json:"port"`
		MemberType      string `json:"memberType"`
		SvcPort         int32  `json:"svcPort,omitempty"`
		Session         string `json:"session,omitempty"`
		AdminState      string `json:"adminState,omitempty"`
		ConnectionLimit int32  `json:"connectionLimit,omitempty"`
	}
)

type (
	// AS3 GTM

	// as3GLSBDomain maps to GSLB_Domain in AS3 Resources
	as3GLSBDomain struct {
		Class                 string              `json:"class"`
		DomainName            string              `json:"domainName"`
		RecordType            string              `json:"resourceRecordType"`
		LBMode                string              `json:"poolLbMode"`
		PersistenceEnabled    bool                `json:"persistenceEnabled"`
		PersistCidrIPv4       uint8               `json:"persistCidrIpv4"`
		PersistCidrIPv6       uint8               `json:"persistCidrIpv6"`
		TTLPersistence        uint32              `json:"ttlPersistence"`
		ClientSubnetPreferred *bool               `json:"clientSubnetPreferred,omitempty"`
		Pools                 []as3GSLBDomainPool `json:"pools"`
	}

	as3GSLBDomainPool struct {
		Use   string `json:"use"`
		Ratio int    `json:"ratio"`
	}

	// as3GSLBPool maps to GSLB_Pool in AS3 Resources
	as3GSLBPool struct {
		Class          string               `json:"class"`
		RecordType     string               `json:"resourceRecordType"`
		LBMode         string               `json:"lbModeAlternate"`
		LBModeFallback string               `json:"lbModeFallback"`
		Members        []as3GSLBPoolMemberA `json:"members"`
		Monitors       []as3ResourcePointer `json:"monitors"`
	}

	// as3GSLBPoolMemberA maps to GSLB_Pool_Member_A in AS3 Resources
	as3GSLBPoolMemberA struct {
		Enabled       bool               `json:"enabled"`
		Server        as3ResourcePointer `json:"server"`
		VirtualServer string             `json:"virtualServer"`
	}

	as3GSLBMonitor struct {
		Class    string `json:"class"`
		Interval int    `json:"interval"`
		Type     string `json:"monitorType"`
		Send     string `json:"send"`
		Receive  string `json:"receive"`
		Timeout  int    `json:"timeout"`
	}

	// as3GSLBServer maps to GSLB_Server in AS3 Resources
	//as3GSLBServer struct {
	//	Class                     string `json:"class"`
	//	VSDiscoveryMode           string `json:"virtualServerDiscoveryMode"`
	//	ExposeRouteDomainsEnabled string `json:"exposeRouteDomainsEnabled"`
	//
	//	DataCenter as3ResourcePointer `json:"dataCenter"`
	//
	//	//VirtualServers  []as3GSLBVirtualServer `json:"virtualServers"`
	//	//Devices         []as3GSLBServerDevice `json:"devices"`
	//
	//}

	// as3GSLBServerDevice maps to GSLB_Server_Device in AS3 Resources
	//as3GSLBServerDevice struct {
	//	Address string `json:"address"`
	//}

	// as3GSLBVirtualServer maps to GSLB_Virtual_Server in AS3 Resources
	//as3GSLBVirtualServer struct {
	//	Address string               `json:"address"`
	//	Port    int                  `json:"port"`
	//	Name    string               `json:"name"`
	//	Montors []as3ResourcePointer `json:"montors"`
	//}
)

type (
	// TLS Structures

	BigIPSSLProfiles struct {
		clientSSLs               []string
		serverSSLs               []string
		key                      string
		certificate              string
		caCertificate            string
		destinationCACertificate string
		tlsCipher                cisapiv1.TLSCipher
	}

	rgPlcSSLProfiles struct {
		plcNamespace string
		plcName      string
		clientSSLs   []string
		serverSSLs   []string
	}

	poolPathRef struct {
		path           string
		poolName       string
		aliasHostnames []string
	}

	TLSContext struct {
		name             string
		namespace        string
		resourceType     string
		referenceType    string
		vsHostname       string
		httpsPort        int32
		httpPort         int32
		ipAddress        string
		termination      string
		httpTraffic      string
		poolPathRefs     []poolPathRef
		bigIPSSLProfiles BigIPSSLProfiles
	}
)

type AnnotationsUsed struct {
	WAF              bool
	AllowSourceRange bool
}

type TLSVersion string

type (
	PoolIdentifier struct {
		poolName   string
		partition  string
		rsName     string
		path       string
		rsKey      resourceRef
		bigIpLabel string
	}

	MultiClusterResourceStore struct {
		rscSvcMap     map[resourceRef]map[MultiClusterServiceKey]MultiClusterServiceConfig
		clusterSvcMap map[string]map[MultiClusterServiceKey]map[MultiClusterServiceConfig]map[PoolIdentifier]struct{}
		sync.Mutex
	}
	MultiClusterServiceKey struct {
		serviceName string
		clusterName string
		namespace   string
	}
	MultiClusterServiceConfig struct {
		svcPort intstr.IntOrString
	}

	MultiClusterPoolInformer struct {
		namespace   string
		clusterName string
		stopCh      chan struct{}
		svcInformer cache.SharedIndexInformer
		epsInformer cache.SharedIndexInformer
		podInformer cache.SharedIndexInformer
	}
	clusterConfigState struct {
		clusterRatio      map[string]int
		clusterAdminState map[string]cisapiv1.AdminState
	}
)
