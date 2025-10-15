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
	"container/list"
	"net/http"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/tokenmanager"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vxlan"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"

	"k8s.io/apimachinery/pkg/util/intstr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"

	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned"
	apm "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"

	v1 "k8s.io/api/core/v1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type (
	// Controller defines the structure of K-Native and Custom Resource Controller
	Controller struct {
		mode      ControllerMode
		resources *ResourceStore
		*RequestHandler
		kubeCRClient                versioned.Interface
		kubeClient                  kubernetes.Interface
		kubeAPIClient               *extClient.Clientset
		eventNotifier               *apm.EventNotifier
		nativeResourceSelector      labels.Selector
		customResourceSelector      labels.Selector
		namespacesMutex             sync.Mutex
		namespaces                  map[string]bool
		nodeLabelSelector           string
		ciliumTunnelName            string
		vxlanMgr                    *vxlan.VxlanMgr
		initialResourceCount        int
		resourceQueue               workqueue.RateLimitingInterface
		Partition                   string
		PoolMemberType              string
		UseNodeInternal             bool
		initState                   bool
		firstPostResponse           bool
		dgPath                      string
		shareNodes                  bool
		ipamCli                     *ipammachinery.IPAMClient
		ipamClusterLabel            string
		ipamCR                      string
		defaultRouteDomain          int32
		sharedDefaultRouteDomain    bool
		TeemData                    *teem.TeemsData
		requestCounter              int64
		ipamHostSpecEmpty           bool
		StaticRoutingMode           bool
		OrchestrationCNI            string
		StaticRouteNodeCIDR         string
		cacheIPAMHostSpecs          CacheIPAM
		multiClusterHandler         *ClusterHandler
		multiClusterResources       *MultiClusterResourceStore
		multiClusterMode            string
		loadBalancerClass           string
		namespaceLabel              string
		manageLoadBalancerClassOnly bool
		discoveryMode               discoveryMode
		clusterRatio                map[string]*int
		clusterAdminState           map[string]clustermanager.AdminState
		ResourceStatusVSAddressMap  map[resourceRef]string
		respChan                    chan *agentPostConfig
		allowedPartitions           map[string]struct{}
		deniedPartitions            map[string]struct{}
		resourceContext
	}
	resourceContext struct {
		resourceQueue       workqueue.RateLimitingInterface
		globalExtendedCMKey string
		namespaceLabelMode  bool
		processedHostPath   *ProcessedHostPath
	}

	InformerStore struct {
		comInformers     map[string]*CommonInformer
		nrInformers      map[string]*NRInformer
		crInformers      map[string]*CRInformer
		nsInformers      map[string]*NSInformer
		nodeInformer     *NodeInformer
		dynamicInformers *DynamicInformers
	}

	ClusterHandler struct {
		*PrimaryClusterHealthProbeParams
		MultiClusterMode       string
		ClusterConfigs         map[string]*ClusterConfig
		HAPairClusterName      string
		LocalClusterName       string
		uniqueAppIdentifier    map[string]struct{}
		namespaceLabel         string
		namespaces             []string
		nodeLabelSelector      string
		customResourceSelector labels.Selector
		routeLabel             string
		orchestrationCNI       string
		staticRoutingMode      bool
		eventQueue             workqueue.RateLimitingInterface
		statusUpdate           *StatusUpdate
		sync.RWMutex
	}

	//ClusterConfig holds configuration specific for cluster
	ClusterConfig struct {
		clusterDetails         ClusterDetails
		kubeClient             kubernetes.Interface
		kubeCRClient           versioned.Interface
		kubeIPAMClient         *extClient.Clientset
		routeClientV1          routeclient.RouteV1Interface
		dynamicClient          dynamic.Interface
		routeLabel             string
		nativeResourceSelector labels.Selector
		namespaces             map[string]struct{}
		namespaceLabel         string
		nodeLabelSelector      string
		orchestrationCNI       string
		staticRoutingMode      bool
		oldNodes               []Node
		eventNotifier          *EventNotifier
		*InformerStore
	}

	StatusUpdate struct {
		ResourceStatusUpdateTracker sync.Map            // Tracks the last time a resource was updated, helps to ensure latest status update
		ResourceStatusUpdateChan    chan ResourceStatus // Channel holds the resource status
		eventNotifierChan           chan ResourceEvent  // Channel holds the resource events
	}

	ResourceStatus struct {
		ResourceObj       interface{}
		ResourceKey       resourceRef
		UpdateAttempts    int
		Timestamp         metav1.Time
		IPSet             bool // helps in event creation of LB service as it helps to know if the status update is for IP setting or unsetting
		ClearKeyFromCache bool // helps clear the cache in case of delete events
	}

	BlockAffinitycidr struct {
		baName   string
		nodeName string
		cidr     string
	}

	ResourceEvent struct {
		resourceObj interface{}
		eventType   string
		reason      string
		message     string
		clusterName string
	}

	// Params defines parameters
	Params struct {
		Config         *rest.Config
		Namespaces     []string
		NamespaceLabel string
		Partition      string
		// Agent                       *Agent
		PoolMemberType              string
		VXLANName                   string
		VXLANMode                   string
		CiliumTunnelName            string
		UseNodeInternal             bool
		NodePollInterval            int
		NodeLabelSelector           string
		ShareNodes                  bool
		IPAM                        bool
		IPAMClusterLabel            string
		DefaultRouteDomain          int32
		SharedDefaultRouteDomain    bool
		Mode                        ControllerMode
		GlobalExtendedSpecConfigmap string
		RouteLabel                  string
		StaticRoutingMode           bool
		OrchestrationCNI            string
		StaticRouteNodeCIDR         string
		MultiClusterMode            string
		LoadBalancerClass           string
		ManageLoadBalancerClassOnly bool
		IpamNamespace               string
		LocalClusterName            string
		CustomResourceLabel         string
		AllowedPartitions           []string
		DeniedPartitions            []string
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
		namespace       string
		stopCh          chan struct{}
		clusterName     string
		svcInformer     cache.SharedIndexInformer
		epsInformer     cache.SharedIndexInformer
		ednsInformer    cache.SharedIndexInformer
		plcInformer     cache.SharedIndexInformer
		podInformer     cache.SharedIndexInformer
		secretsInformer cache.SharedIndexInformer
		cmInformer      cache.SharedIndexInformer
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
	}

	NSInformer struct {
		stopCh      chan struct{}
		clusterName string
		nsInformer  cache.SharedIndexInformer
	}

	//DynamicInformers holds informers for third party integration
	DynamicInformers struct {
		stopCh                      chan struct{}
		clusterName                 string
		CalicoBlockAffinityInformer informers.GenericInformer
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
		BigIPRouteDomain           int32                 `json:"bigipRouteDomain,omitempty"`
		SNAT                       string                `json:"snat,omitempty"`
		ConnectionMirroring        string                `json:"connectionMirroring,omitempty"`
		WAF                        string                `json:"waf,omitempty"`
		Firewall                   string                `json:"firewallPolicy,omitempty"`
		LogProfiles                []string              `json:"logProfiles,omitempty"`
		RequestLogProfile          string                `json:"requestLogProfile,omitempty"`
		ProfileL4                  string                `json:"profileL4,omitempty"`
		ProfileMultiplex           string                `json:"profileMultiplex,omitempty"`
		HTTPCompressionProfile     string                `json:"profileHTTPCompression,omitempty"`
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
		HTMLProfile                string                `json:"htmlProfile,omitempty"`
		ProfileAccess              string                `json:"profileAccess,omitempty"`
		PolicyPerRequestAccess     string                `json:"policyPerRequestAccess,omitempty"`
		FTPProfile                 string                `json:"ftpProfile,omitempty"`
		ProfileAdapt               ProfileAdapt          `json:"profileAdapt,omitempty"`
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
		Client *string `json:"client,omitempty"`
		Server *string `json:"server,omitempty"`
	}

	ProfileAdapt struct {
		Request  string `json:"request,omitempty"`
		Response string `json:"response,omitempty"`
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
		ltmConfig      LTMConfig
		ltmConfigCache LTMConfig
		gtmConfig      GTMConfig
		gtmConfigCache GTMConfig
		nplStore       NPLStore
		supplementContextCache
	}

	// l4AppConfig contains IP and port to identify unique L4App
	l4AppConfig struct {
		ipOrIPAMKey string
		port        int32
		routeDomain int32
		protocol    string
	}

	// L4AppsStore contains TypeLB service details.key is IP
	L4AppsStore map[l4AppConfig]resourceRef

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

	// static route config
	routeSection struct {
		Entries       []routeConfig `json:"routes"`
		CISIdentifier string        `json:"cis-identifier,omitempty"`
	}

	routeConfig struct {
		Name        string `json:"name"`
		Network     string `json:"network"`
		Gateway     string `json:"gw"`
		Description string `json:"description,omitempty"`
	}
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

	ResourceConfigRequest struct {
		ltmConfig                LTMConfig
		shareNodes               bool
		gtmConfig                GTMConfig
		defaultRouteDomain       int32
		sharedDefaultRouteDomain bool
		reqMeta                  requestMeta
		poolMemberType           string
	}

	resourceRef struct {
		kind        string
		name        string
		namespace   string
		clusterName string
		timestamp   metav1.Time
	}

	VSSpecProperties struct {
		PoolWAF bool
	}

	// Pool config
	Pool struct {
		Name                     string                                  `json:"name"`
		Description              string                                  `json:"description,omitempty"`
		Partition                string                                  `json:"-"`
		ServiceName              string                                  `json:"-"`
		ServiceNamespace         string                                  `json:"-"`
		ServicePort              intstr.IntOrString                      `json:"-"`
		ServicePortUsed          bool                                    `json:"-"`
		Balance                  string                                  `json:"loadBalancingMethod,omitempty"`
		Members                  []PoolMember                            `json:"members"`
		NodeMemberLabel          string                                  `json:"-"`
		MonitorNames             []MonitorName                           `json:"monitors,omitempty"`
		MinimumMonitors          intstr.IntOrString                      `json:"minimumMonitors,omitempty"`
		ReselectTries            int32                                   `json:"reselectTries,omitempty"`
		ServiceDownAction        string                                  `json:"serviceDownAction,omitempty"`
		SlowRampTime             int32                                   `json:"slowRampTime,omitempty"`
		Weight                   int32                                   `json:"weight,omitempty"`
		AlternateBackends        []AlternateBackend                      `json:"alternateBackends"`
		StaticPoolMembers        []StaticPoolMember                      `json:"staticPoolMembers,omitempty"`
		MultiClusterServices     []cisapiv1.MultiClusterServiceReference `json:"_"`
		Cluster                  string                                  `json:"-"`
		ConnectionLimit          int32                                   `json:"-"`
		ImplicitSvcSearchEnabled bool                                    `json:"-"`
		BigIPRouteDomain         int32                                   `json:"bigipRouteDomain,omitempty"`
	}
	StaticPoolMember struct {
		Address string `json:"address"`
		Port    int32  `json:"port"`
	}
	CacheIPAM struct {
		IPAM *ficV1.IPAM
		sync.Mutex
	}
	// AlternateBackends lists backend svc of A/B
	AlternateBackend struct {
		Service           string             `json:"service"`
		ServiceNamespace  string             `json:"serviceNamespace,omitempty"`
		Weight            int32              `json:"weight,omitempty"`
		StaticPoolMembers []StaticPoolMember `json:"staticPoolMembers,omitempty"`
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
		SSLProfile  string `json:"sslProfile,omitempty"`
	}
	MonitorName struct {
		Name string `json:"name"`
		// Reference is used to link existing health monitor on bigip
		Reference string `json:"reference,omitempty"`
	}
	// Monitors  is slice of monitor
	Monitors []Monitor

	supplementContextCache struct {
		baseRouteConfig BaseRouteConfig
		poolMemCache    PoolMemberCache
		processedL4Apps L4AppsStore
		sslContext      map[string]*v1.Secret
		extdSpecMap     extendedSpecMap
		// key of the map is IPSpec.Key
		ipamContext              map[string]ficV1.IPSpec
		processedNativeResources map[resourceRef]struct{}
		routeGroupNamespaceMap   map[string]string
	}

	// key is group identifier
	extendedSpecMap map[string]*extendedParsedSpec

	// Extended Spec for each group of Routes/Ingress
	extendedParsedSpec struct {
		override   bool
		local      *ExtendedRouteGroupSpec
		global     *ExtendedRouteGroupSpec
		defaultrg  *ExtendedRouteGroupSpec
		namespaces map[string]string
		partition  string
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
		Name           string `json:"name,omitEmpty"`
		Key            string `json:"key,omitEmpty"`
		Netmask        string `json:"netmask,omitEmpty"`
		Pool           string `json:"pool,omitempty"`
		HTTPHost       bool   `json:"httpHost,omitempty"`
		HttpReply      bool   `json:"httpReply,omitempty"`
		HTTPURI        bool   `json:"httpUri,omitempty"`
		Forward        bool   `json:"forward,omitempty"`
		Location       string `json:"location,omitempty"`
		Path           string `json:"path,omitempty"`
		Redirect       bool   `json:"redirect,omitempty"`
		Replace        bool   `json:"replace,omitempty"`
		Request        bool   `json:"request,omitempty"`
		Reset          bool   `json:"reset,omitempty"`
		Select         bool   `json:"select,omitempty"`
		Value          string `json:"value,omitempty"`
		WAF            bool   `json:"waf,omitempty"`
		Policy         string `json:"policy,omitempty"`
		Drop           bool   `json:"drop,omitempty"`
		Enabled        bool   `json:"enabled,omitempty"`
		Log            bool   `json:"log,omitempty"`
		Message        string `json:"message,omitempty"`
		PersistMethod  string `json:"method,omitempty"`
		Timeout        int32  `json:"timeout,omitempty"`
		Expiry         string `json:"expiry,omitempty"`
		Length         int32  `json:"length,omitempty"`
		Offset         int32  `json:"offset,omitempty"`
		DisablePersist bool   `json:"disablePersist,omitempty"`
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
		Name                 string `json:"name"`
		Partition            string `json:"-"`
		Context              string `json:"context"` // 'clientside', 'serverside', or 'all'
		Ciphers              string `json:"ciphers,omitempty"`
		CipherGroup          string `json:"cipherGroup,omitempty"`
		TLS1_0Enabled        *bool  `json:"tls1_0Enabled"`
		TLS1_1Enabled        *bool  `json:"tls1_1Enabled"`
		TLS1_2Enabled        *bool  `json:"tls1_2Enabled"`
		TLS1_3Enabled        *bool  `json:"tls1_3Enabled"`
		ServerName           string `json:"serverName,omitempty"`
		SNIDefault           bool   `json:"sniDefault,omitempty"`
		PeerCertMode         string `json:"peerCertMode,omitempty"`
		CAFile               string `json:"caFile,omitempty"`
		ChainCA              string `json:"chainCA,omitempty"`
		Certificates         []certificate
		RenegotiationEnabled *bool `json:"renegotiationEnabled,omitempty"`
	}

	certificate struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}

	portStruct struct {
		protocol string
		port     int32
	}

	requestQueue struct {
		sync.Mutex
		*list.List
	}

	requestMeta struct {
		partitionMap map[string]map[string]string
		id           int64
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
		Weight            float64
		Name              string
		SvcNamespace      string `json:"svcNamespace,omitempty"`
		Cluster           string
		SvcPort           intstr.IntOrString
		StaticPoolMembers []StaticPoolMember
	}
)

type (
	RequestHandler struct {
		PrimaryBigIPWorker              *Agent
		SecondaryBigIPWorker            *Agent
		GTMBigIPWorker                  *Agent
		resources                       *ResourceStore
		reqChan                         chan ResourceConfigRequest
		respChan                        chan *agentPostConfig
		PrimaryClusterHealthProbeParams *PrimaryClusterHealthProbeParams
		agentParams                     AgentParams
		disableARP                      bool
		HAMode                          bool
	}

	agentPostConfig struct {
		data                  string
		targetAddress         string
		as3APIURL             string
		reqMeta               requestMeta
		tenantResponseMap     map[string]tenantResponse
		acceptedTaskId        string
		incomingTenantDeclMap map[string]as3Tenant
		failedTenants         map[string]tenantResponse
		deleted               bool
		agentKind             string
		rscConfigRequest      ResourceConfigRequest
		// timeout is used in BIG IP API is busy
		timeout time.Duration
	}

	Agent struct {
		*APIHandler
		Partition           string
		ConfigWriter        writer.Writer
		EventChan           chan interface{}
		userAgent           string
		HttpAddress         string
		HttpsAddress        string
		EnableIPV6          bool
		ccclGTMAgent        bool
		gtmOnSeparateServer bool
		disableARP          bool
		Type                string
		httpClientMetrics   bool
		PythonDriverPID     int
		StopChan            chan struct{}
	}

	BaseAPIHandler struct {
		apiType    string
		APIHandler ApiTypeHandlerInterface
		*PostManager
	}

	GTMAPIHandler struct {
		*BaseAPIHandler
		Partition string
	}

	LTMAPIHandler struct {
		*BaseAPIHandler
	}

	APIHandler struct {
		GTM *GTMAPIHandler
		LTM *LTMAPIHandler
	}

	AgentParams struct {
		PrimaryParams   PostParams
		SecondaryParams PostParams
		GTMParams       PostParams
		// VxlnParams      VXLANParams
		Partition            string
		LogLevel             string
		VerifyInterval       int
		VXLANName            string
		PythonBaseDir        string
		UserAgent            string
		HttpAddress          string
		HttpsAddress         string
		EnableIPV6           bool
		DisableARP           bool
		CCCLGTMAgent         bool
		StaticRoutingMode    bool
		SharedStaticRoutes   bool
		MultiClusterMode     string
		ApiType              string
		HAMode               bool
		RefreshTokenInterval int
	}

	AS3Handler struct {
		postManagerPrefix   string
		cachedTenantDeclMap map[string]as3Tenant
		*PostManager
		*AS3Parser
	}

	AS3Parser struct {
		AS3VersionInfo   as3VersionInfo
		bigIPAS3Version  float64
		defaultPartition string
	}

	PostManager struct {
		tokenmanager.TokenManagerInterface
		declUpdate sync.Mutex
		httpClient *http.Client
		PostParams
		firstPost         bool
		postManagerPrefix string
		postChan          chan *agentPostConfig
		respChan          chan *agentPostConfig
		httpClientMetrics bool
		apiType           string
	}

	PrimaryClusterHealthProbeParams struct {
		paramLock     sync.RWMutex
		EndPoint      string
		EndPointType  string
		statusRunning bool
		statusChanged bool
		probeInterval int
		retryInterval int
	}

	PostParams struct {
		BIGIPUsername string
		BIGIPPassword string
		BIGIPURL      string
		BIGIPType     string
		TrustedCerts  string
		SSLInsecure   bool
		PostDelay     int
		// Log the response body in Controller logs
		LogResponse       bool
		LogRequest        bool
		HTTPClientMetrics bool
	}

	GTMParams struct {
		GTMBigIpUsername string
		GTMBigIpPassword string
		GTMBigIpUrl      string
	}

	tenantResponse struct {
		agentResponseCode int
		isDeleted         bool
		message           string
	}

	tenantParams struct {
		as3Decl interface{} // to update cachedTenantDeclMap on success
		tenantResponse
	}

	globalSection struct {
		LogLevel           string `json:"log-level,omitempty"`
		VerifyInterval     int    `json:"verify-interval,omitempty"`
		VXLANPartition     string `json:"vxlan-partition,omitempty"`
		DisableLTM         bool   `json:"disable-ltm,omitempty"`
		GTM                bool   `json:"gtm,omitempty"`
		DisableARP         bool   `json:"disable-arp,omitempty"`
		SharedStaticRoutes bool   `json:"shared-static-routes,omitempty"`
		StaticRoutingMode  bool   `json:"static-route-mode,omitempty"`
		MultiClusterMode   string `json:"multi-cluster-mode,omitempty"`
	}

	bigIPSection struct {
		BigIPURL        string   `json:"url,omitempty"`
		BigIPPartitions []string `json:"partitions,omitempty"`
	}

	gtmBigIPSection struct {
		GtmBigIPURL string `json:"url,omitempty"`
	}

	// AS3 version struct

	as3VersionInfo struct {
		as3Version       string
		as3SchemaVersion string
		as3Release       string
		bigIPAS3Version  float64
	}

	as3Declaration string

	as3JSONWithArbKeys map[string]interface{}

	// TODO: Need to remove omitempty tag for the mandatory fields
	// as3JSONDeclaration maps to ADC in AS3 Resources
	as3ADC as3JSONWithArbKeys
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
		Type               string                  `json:"type,omitempty"`
		Event              string                  `json:"event,omitempty"`
		Select             *as3ActionForwardSelect `json:"select,omitempty"`
		Policy             *as3ResourcePointer     `json:"policy,omitempty"`
		Enabled            bool                    `json:"enabled,omitempty"`
		Location           string                  `json:"location,omitempty"`
		Replace            *as3ActionReplaceMap    `json:"replace,omitempty"`
		Write              *as3LogMessage          `json:"write,omitempty"`
		SourceAddress      *PersistMetaData        `json:"sourceAddress,omitempty"`
		DestinationAddress *PersistMetaData        `json:"destinationAddress,omitempty"`
		CookieHash         *PersistMetaData        `json:"cookieHash,omitempty"`
		CookieRewrite      *PersistMetaData        `json:"cookieRewrite,omitempty"`
		CookieInsert       *PersistMetaData        `json:"cookieInsert,omitempty"`
		CookiePassive      *PersistMetaData        `json:"cookiePassive,omitempty"`
		Universal          *PersistMetaData        `json:"universal,omitempty"`
		Hash               *PersistMetaData        `json:"hash,omitempty"`
		Carp               *PersistMetaData        `json:"carp,omitempty"`
		Disable            *PersistMetaData        `json:"disable,omitempty"`
	}

	PersistMetaData struct {
		Name    string `json:"name,omitempty"`
		Netmask string `json:"netmask,omitempty"`
		Key     string `json:"key,omitempty"`
		Timeout int32  `json:"timeout,omitempty"`
		Expiry  string `json:"expiry,omitempty"`
		Offset  int32  `json:"offset,omitempty"`
		Length  int32  `json:"length,omitempty"`
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
		MinimumMonitors   intstr.IntOrString   `json:"minimumMonitors,omitempty"`
		ServiceDownAction string               `json:"serviceDownAction,omitempty"`
		ReselectTries     int32                `json:"reselectTries,omitempty"`
		SlowRampTime      int32                `json:"slowRampTime,omitempty"`
		Remark            string               `json:"remark,omitempty"`
	}

	// as3PoolMember maps to Pool_Member in AS3 Resources
	as3PoolMember struct {
		AddressDiscovery string   `json:"addressDiscovery,omitempty"`
		ServerAddresses  []string `json:"serverAddresses,omitempty"`
		ServicePort      int32    `json:"servicePort,omitempty"`
		ShareNodes       bool     `json:"shareNodes,omitempty"`
		AdminState       string   `json:"adminState,omitempty"`
		ConnectionLimit  int32    `json:"connectionLimit,omitempty"`
		Ratio            int      `json:"ratio,omitempty"`
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
	}

	// as3Service maps to the following in AS3 Resources
	// - Service_HTTP
	// - Service_HTTPS
	// - Service_TCP
	// - Service_UDP
	as3Service struct {
		Layer4                 string               `json:"layer4,omitempty"`
		Source                 string               `json:"source,omitempty"`
		TranslateServerAddress bool                 `json:"translateServerAddress,omitempty"`
		TranslateServerPort    bool                 `json:"translateServerPort,omitempty"`
		Class                  string               `json:"class,omitempty"`
		VirtualAddresses       []as3MultiTypeParam  `json:"virtualAddresses,omitempty"`
		VirtualPort            int                  `json:"virtualPort,omitempty"`
		AutoLastHop            string               `json:"lastHop,omitempty"`
		SNAT                   as3MultiTypeParam    `json:"snat,omitempty"`
		Mirroring              string               `json:"mirroring,omitempty"`
		PolicyEndpoint         as3MultiTypeParam    `json:"policyEndpoint,omitempty"`
		ClientTLS              as3MultiTypeParam    `json:"clientTLS,omitempty"`
		ServerTLS              as3MultiTypeParam    `json:"serverTLS,omitempty"`
		IRules                 as3MultiTypeParam    `json:"iRules,omitempty"`
		Redirect80             *bool                `json:"redirect80,omitempty"`
		Pool                   *as3ResourcePointer  `json:"pool,omitempty"`
		WAF                    as3MultiTypeParam    `json:"policyWAF,omitempty"`
		Firewall               as3MultiTypeParam    `json:"policyFirewallEnforced,omitempty"`
		LogProfiles            []as3ResourcePointer `json:"securityLogProfiles,omitempty"`
		ProfileTrafficLog      as3MultiTypeParam    `json:"profileTrafficLog,omitempty"`
		ProfileL4              as3MultiTypeParam    `json:"profileL4,omitempty"`
		AllowVLANs             []as3ResourcePointer `json:"allowVlans,omitempty"`
		PersistenceMethods     *[]as3MultiTypeParam `json:"persistenceMethods,omitempty"`
		ProfileTCP             as3MultiTypeParam    `json:"profileTCP,omitempty"`
		ProfileUDP             as3MultiTypeParam    `json:"profileUDP,omitempty"`
		ProfileHTTP            as3MultiTypeParam    `json:"profileHTTP,omitempty"`
		ProfileHTTP2           as3MultiTypeParam    `json:"profileHTTP2,omitempty"`
		ProfileMultiplex       as3MultiTypeParam    `json:"profileMultiplex,omitempty"`
		ProfileDOS             as3MultiTypeParam    `json:"profileDOS,omitempty"`
		ProfileBotDefense      as3MultiTypeParam    `json:"profileBotDefense,omitempty"`
		HttpMrfRoutingEnabled  bool                 `json:"httpMrfRoutingEnabled,omitempty"`
		IpIntelligencePolicy   as3MultiTypeParam    `json:"ipIntelligencePolicy,omitempty"`
		HttpAnalyticsProfile   *as3ResourcePointer  `json:"profileAnalytics,omitempty"`
		ProfileWebSocket       as3MultiTypeParam    `json:"profileWebSocket,omitempty"`
		ProfileHTML            as3MultiTypeParam    `json:"profileHTML,omitempty"`
		HTTPCompressionProfile as3MultiTypeParam    `json:"profileHTTPCompression,omitempty"`
		ProfileAccess          as3MultiTypeParam    `json:"profileAccess,omitempty"`
		PolicyPerRequestAccess as3MultiTypeParam    `json:"policyPerRequestAccess,omitempty"`
		ProfileFTP             as3MultiTypeParam    `json:"profileFTP,omitempty"`
		ProfileRequestAdapt    as3MultiTypeParam    `json:"profileRequestAdapt,omitempty"`
		ProfileResponseAdapt   as3MultiTypeParam    `json:"profileResponseAdapt,omitempty"`
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
		Class             string              `json:"class,omitempty"`
		Interval          int                 `json:"interval,omitempty"`
		MonitorType       string              `json:"monitorType,omitempty"`
		TargetAddress     *string             `json:"targetAddress,omitempty"`
		Timeout           int                 `json:"timeout,omitempty"`
		TimeUnitilUp      *int                `json:"timeUntilUp,omitempty"`
		Adaptive          *bool               `json:"adaptive,omitempty"`
		Dscp              *int                `json:"dscp,omitempty"`
		Receive           string              `json:"receive"`
		Send              string              `json:"send"`
		TargetPort        int32               `json:"targetPort,omitempty"`
		ClientCertificate string              `json:"clientCertificate,omitempty"`
		Ciphers           string              `json:"ciphers,omitempty"`
		ClientTLS         *as3ResourcePointer `json:"clientTLS,omitempty"`
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
		Class                string                     `json:"class,omitempty"`
		Certificates         []as3TLSServerCertificates `json:"certificates,omitempty"`
		Ciphers              string                     `json:"ciphers,omitempty"`
		CipherGroup          *as3ResourcePointer        `json:"cipherGroup,omitempty"`
		TLS1_0Enabled        *bool                      `json:"tls1_0Enabled,omitempty"`
		TLS1_1Enabled        *bool                      `json:"tls1_1Enabled,omitempty"`
		TLS1_2Enabled        *bool                      `json:"tls1_2Enabled,omitempty"`
		TLS1_3Enabled        bool                       `json:"tls1_3Enabled,omitempty"`
		RenegotiationEnabled *bool                      `json:"renegotiationEnabled,omitempty"`
	}

	// as3TLSServerCertificates maps to TLS_Server_certificates in AS3 Resources
	as3TLSServerCertificates struct {
		Certificate string `json:"certificate,omitempty"`
		SNIDefault  bool   `json:"sniDefault,omitempty"`
	}

	// as3TLSClient maps to TLS_Client in AS3 Resources
	as3TLSClient struct {
		Class                string              `json:"class,omitempty"`
		TrustCA              *as3ResourcePointer `json:"trustCA,omitempty"`
		ValidateCertificate  bool                `json:"validateCertificate,omitempty"`
		Ciphers              string              `json:"ciphers,omitempty"`
		CipherGroup          *as3ResourcePointer `json:"cipherGroup,omitempty"`
		TLS1_0Enabled        *bool               `json:"tls1_0Enabled,omitempty"`
		TLS1_1Enabled        *bool               `json:"tls1_1Enabled,omitempty"`
		TLS1_2Enabled        *bool               `json:"tls1_2Enabled,omitempty"`
		TLS1_3Enabled        bool                `json:"tls1_3Enabled,omitempty"`
		RenegotiationEnabled *bool               `json:"renegotiationEnabled,omitempty"`
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
		Ratio           int    `json:"ratio,omitempty"`
		PriorityGroup   int    `json:"priorityGroup,omitempty"`
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
		tlsCipher                TLSCipher
		clientSSlParams          cisapiv1.ClientSSLParams
		serverSSlParams          cisapiv1.ServerSSLParams
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
		tlsCipher        TLSCipher
		passthroughVSGrp bool
	}
)

type (
	extendedSpec struct {
		ExtendedRouteGroupConfigs []ExtendedRouteGroupConfig `yaml:"extendedRouteSpec"`
		BaseRouteConfig           `yaml:"baseRouteSpec"`
		ExternalClustersConfig    []ClusterDetails          `yaml:"externalClustersConfig"`
		HAClusterConfig           HAClusterConfig           `yaml:"highAvailabilityCIS"`
		HAMode                    discoveryMode             `yaml:"mode"`
		LocalClusterRatio         *int                      `yaml:"localClusterRatio"`
		LocalClusterAdminState    clustermanager.AdminState `yaml:"localClusterAdminState"`
	}

	ExtendedRouteGroupConfig struct {
		Namespace              string `yaml:"namespace"`      // Group Identifier
		NamespaceLabel         string `yaml:"namespaceLabel"` // Group Identifier
		BigIpPartition         string `yaml:"bigIpPartition"` // bigip Partition
		ExtendedRouteGroupSpec `yaml:",inline"`
	}

	ExtendedRouteGroupSpec struct {
		VServerName        string `yaml:"vserverName"`
		VServerAddr        string `yaml:"vserverAddr"`
		AllowOverride      string `yaml:"allowOverride"`
		Policy             string `yaml:"policyCR,omitempty"`
		HTTPServerPolicyCR string `yaml:"httpServerPolicyCR,omitempty"`
		Meta               Meta
	}

	Meta struct {
		DependsOnTLS bool
	}

	DefaultRouteGroupConfig struct {
		BigIpPartition        string                 `yaml:"bigIpPartition"` // bigip Partition
		DefaultRouteGroupSpec ExtendedRouteGroupSpec `yaml:",inline"`
	}

	BaseRouteConfig struct {
		TLSCipher               TLSCipher               `yaml:"tlsCipher"`
		DefaultTLS              DefaultSSLProfile       `yaml:"defaultTLS,omitempty"`
		DefaultRouteGroupConfig DefaultRouteGroupConfig `yaml:"defaultRouteGroup,omitempty"`
		AutoMonitor             AutoMonitorType         `yaml:"autoMonitor,omitempty"`
		AutoMonitorTimeout      int                     `yaml:"autoMonitorTimeout,omitempty"`
	}

	TLSCipher struct {
		TLSVersion         string   `yaml:"tlsVersion,omitempty"`
		Ciphers            string   `yaml:"ciphers,omitempty"`
		CipherGroup        string   `yaml:"cipherGroup,omitempty"` // by default this is bigip reference
		DisableTLSVersions []string `yaml:"disableTLSVersions,omitempty"`
	}

	DefaultSSLProfile struct {
		ClientSSL string `yaml:"clientSSL,omitempty"`
		ServerSSL string `yaml:"serverSSL,omitempty"`
		Reference string `yaml:"reference,omitempty"`
	}
	AnnotationsUsed struct {
		WAF              bool
		AllowSourceRange bool
	}
)

type TLSVersion string

const (
	TLSVerion1_0 TLSVersion = "1.0"
	TLSVerion1_1 TLSVersion = "1.1"
	TLSVerion1_2 TLSVersion = "1.2"
	TLSVerion1_3 TLSVersion = "1.3"
)

type HAModeType string

const (
	StatusOk    = "OK"
	StatusError = "ERROR"
)

type discoveryMode string
type AutoMonitorType string

const (
	Active          discoveryMode   = "active-active"
	StandBy         discoveryMode   = "active-standby"
	Ratio           discoveryMode   = "ratio"
	DefaultMode     discoveryMode   = "default"
	None            AutoMonitorType = "none"
	ReadinessProbe  AutoMonitorType = "readiness-probe"
	ServiceEndpoint AutoMonitorType = "service-endpoint"
)

const (
	SourceAddress      = "sourceAddress"
	DestinationAddress = "destinationAddress"
	CookieRewrite      = "cookieRewrite"
	CookieInsert       = "cookieInsert"
	CookiePassive      = "cookiePassive"
	CookieHash         = "cookieHash"
	Hash               = "hash"
	Carp               = "carp"
	Universal          = "universal"
	Disable            = "none"
)

type (
	ExternalClusterConfig struct {
		ClusterName string                    `yaml:"clusterName"`
		Secret      string                    `yaml:"secret"`
		Ratio       *int                      `yaml:"ratio"`
		AdminState  clustermanager.AdminState `yaml:"adminState"`
	}

	HAClusterConfig struct {
		//HAMode                 HAMode         `yaml:"mode"`
		PrimaryClusterEndPoint string         `yaml:"primaryEndPoint"`
		ProbeInterval          int            `yaml:"probeInterval"`
		RetryInterval          int            `yaml:"retryInterval"`
		PrimaryCluster         ClusterDetails `yaml:"primaryCluster"`
		SecondaryCluster       ClusterDetails `yaml:"secondaryCluster"`
	}

	HAMode struct {
		// type can be active-active, active-standby, ratio
		Type discoveryMode `yaml:"type"`
	}

	ClusterDetails struct {
		ClusterName            string                    `yaml:"clusterName"`
		Secret                 string                    `yaml:"secret"`
		Ratio                  *int                      `yaml:"ratio"`
		AdminState             clustermanager.AdminState `yaml:"adminState"`
		ServiceTypeLBDiscovery bool                      `yaml:"serviceTypeLBDiscovery"`
	}

	PoolIdentifier struct {
		poolName  string
		partition string
		rsName    string
		path      string
		rsKey     resourceRef
	}

	MultiClusterResourceStore struct {
		rscSvcMap     map[resourceRef]map[MultiClusterServiceKey]map[MultiClusterServiceConfig]struct{}
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
)

var (
	// CalicoBlockaffinity : Calico's BlockAffinity CRD resource identifier
	CalicoBlockaffinity = schema.GroupVersionResource{
		Group:    "crd.projectcalico.org",
		Version:  "v1",
		Resource: "blockaffinities",
	}
)
