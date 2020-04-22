/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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

package crmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type (
	// CRManager defines the structure of Custom Resource Manager
	CRManager struct {
		resources        *Resources
		kubeCRClient     versioned.Interface
		kubeClient       kubernetes.Interface
		crInformers      map[string]*CRInformer
		resourceSelector labels.Selector
		namespaces       []string
		rscQueue         workqueue.RateLimitingInterface
		Partition        string
		Agent            *Agent
		ControllerMode   string
		// map of rules that have been merged
		mergedRulesMap  map[string]map[string]mergedRuleEntry
		nodePoller      pollers.Poller
		oldNodes        []Node
		UseNodeInternal bool
	}
	// Params defines parameters
	Params struct {
		Config            *rest.Config
		Namespaces        []string
		Partition         string
		Agent             *Agent
		ControllerMode    string
		VXLANName         string
		VXLANMode         string
		UseNodeInternal   bool
		NodePollInterval  int
		NodeLabelSelector string
	}
	// CRInformer defines the structure of Custom Resource Informer
	CRInformer struct {
		namespace   string
		stopCh      chan struct{}
		vsInformer  cache.SharedIndexInformer
		svcInformer cache.SharedIndexInformer
		epsInformer cache.SharedIndexInformer
	}

	rqKey struct {
		namespace string
		kind      string
		rscName   string
		rsc       interface{}
	}

	metaData struct {
		Active       bool
		ResourceType string
		rscName      string
	}

	// Virtual Server Key - unique server is Name + Port
	serviceKey struct {
		ServiceName string
		ServicePort int32
		Namespace   string
	}

	// Virtual server config
	Virtual struct {
		Name                  string                `json:"name"`
		PoolName              string                `json:"pool,omitempty"`
		Partition             string                `json:"-"`
		Destination           string                `json:"destination"`
		Enabled               bool                  `json:"enabled"`
		IpProtocol            string                `json:"ipProtocol,omitempty"`
		SourceAddrTranslation SourceAddrTranslation `json:"sourceAddressTranslation,omitempty"`
		Policies              []nameRef             `json:"policies,omitempty"`
		IRules                []string              `json:"rules,omitempty"`
		Description           string                `json:"description,omitempty"`
		VirtualAddress        *virtualAddress       `json:"-"`
	}
	// Virtuals is slice of virtuals
	Virtuals []Virtual

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

	// ResourceConfig is a Config for a single VirtualServer.
	ResourceConfig struct {
		MetaData metaData `json:"-"`
		Virtual  Virtual  `json:"virtual,omitempty"`
		Pools    Pools    `json:"pools,omitempty"`
		Policies Policies `json:"policies,omitempty"`
	}
	// ResourceConfigs is group of ResourceConfig
	ResourceConfigs []*ResourceConfig

	// Pool config
	Pool struct {
		Name        string   `json:"name"`
		Partition   string   `json:"-"`
		ServiceName string   `json:"-"`
		ServicePort int32    `json:"-"`
		Members     []Member `json:"members"`
	}
	// Pools is slice of pool
	Pools []Pool

	// Monitor is Pool health monitor
	Monitor struct {
		Name      string `json:"name"`
		Partition string `json:"-"`
		Interval  int    `json:"interval,omitempty"`
		Type      string `json:"type,omitempty"`
		Send      string `json:"send,omitempty"`
		Recv      string `json:"recv,omitempty"`
		Timeout   int    `json:"timeout,omitempty"`
	}
	// Monitors  is slice of monitor
	Monitors []Monitor

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
	}

	// Rules is a slice of Rule
	Rules   []*Rule
	ruleMap map[string]*Rule

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
)

type (
	Agent struct {
		*PostManager
		Partition       string
		ConfigWriter    writer.Writer
		EventChan       chan interface{}
		PythonDriverPID int
	}

	AgentParams struct {
		PostParams PostParams
		//VxlnParams      VXLANParams
		Partition      string
		LogLevel       string
		VerifyInterval int
		VXLANName      string
		PythonBaseDir  string
	}

	globalSection struct {
		LogLevel       string `json:"log-level,omitempty"`
		VerifyInterval int    `json:"verify-interval,omitempty"`
		VXLANPartition string `json:"vxlan-partition,omitempty"`
	}

	bigIPSection struct {
		BigIPUsername   string   `json:"username,omitempty"`
		BigIPPassword   string   `json:"password,omitempty"`
		BigIPURL        string   `json:"url,omitempty"`
		BigIPPartitions []string `json:"partitions,omitempty"`
	}

	as3Template    string
	as3Declaration string

	poolName   string
	appName    string
	tenantName string

	pool      []Member
	tenant    map[appName][]poolName
	as3Object map[tenantName]tenant

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

	// as3Action maps to Policy_Action in AS3 Resources
	as3Action struct {
		Type     string                  `json:"type,omitempty"`
		Event    string                  `json:"event,omitempty"`
		Select   *as3ActionForwardSelect `json:"select,omitempty"`
		Policy   *as3ResourcePointer     `json:"policy,omitempty"`
		Enabled  *bool                   `json:"enabled,omitempty"`
		Location string                  `json:"location,omitempty"`
		Replace  *as3ActionReplaceMap    `json:"replace,omitempty"`
	}

	as3ActionReplaceMap struct {
		Value string `json:"value,omitempty"`
		Name  string `json:"name,omitempty"`
		Path  string `json:"path,omitempty"`
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

	// as3Pool maps to Pool in AS3 Resources
	as3Pool struct {
		Class             string               `json:"class,omitempty"`
		LoadBalancingMode string               `json:"loadBalancingMode,omitempty"`
		Members           []as3PoolMember      `json:"members,omitempty"`
		Monitors          []as3ResourcePointer `json:"monitors,omitempty"`
	}

	// as3PoolMember maps to Pool_Member in AS3 Resources
	as3PoolMember struct {
		AddressDiscovery string   `json:"addressDiscovery,omitempty"`
		ServerAddresses  []string `json:"serverAddresses,omitempty"`
		ServicePort      int32    `json:"servicePort,omitempty"`
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
		Layer4                 string            `json:"layer4,omitempty"`
		Source                 string            `json:"source,omitempty"`
		TranslateServerAddress bool              `json:"translateServerAddress,omitempty"`
		TranslateServerPort    bool              `json:"translateServerPort,omitempty"`
		Class                  string            `json:"class,omitempty"`
		VirtualAddresses       []string          `json:"virtualAddresses,omitempty"`
		VirtualPort            int               `json:"virtualPort,omitempty"`
		SNAT                   string            `json:"snat,omitempty"`
		PolicyEndpoint         as3MultiTypeParam `json:"policyEndpoint,omitempty"`
		ClientTLS              as3MultiTypeParam `json:"clientTLS,omitempty"`
		ServerTLS              as3MultiTypeParam `json:"serverTLS,omitempty"`
		IRules                 []string          `json:"iRules,omitempty"`
		Redirect80             *bool             `json:"redirect80,omitempty"`
		Pool                   string            `json:"pool,omitempty"`
	}

	// as3Monitor maps to the following in AS3 Resources
	// - Monitor
	// - Monitor_HTTP
	// - Monitor_HTTPS
	as3Monitor struct {
		Class             string  `json:"class,omitempty"`
		Interval          int     `json:"interval,omitempty"`
		MonitorType       string  `json:"monitorType,omitempty"`
		TargetAddress     *string `json:"targetAddress,omitempty"`
		Timeout           int     `json:"timeout,omitempty"`
		TimeUnitilUp      *int    `json:"timeUntilUp,omitempty"`
		Adaptive          *bool   `json:"adaptive,omitempty"`
		Dscp              *int    `json:"dscp,omitempty"`
		Receive           string  `json:"receive,omitempty"`
		Send              string  `json:"send,omitempty"`
		TargetPort        *int    `json:"targetPort,omitempty"`
		ClientCertificate string  `json:"clientCertificate,omitempty"`
		Ciphers           string  `json:"ciphers,omitempty"`
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
		Tls1_3Enabled bool                       `json:"tls1_3Enabled,omitempty"`
	}

	// as3TLSServerCertificates maps to TLS_Server_certificates in AS3 Resources
	as3TLSServerCertificates struct {
		Certificate string `json:"certificate,omitempty"`
	}

	// as3TLSClient maps to TLS_Client in AS3 Resources
	as3TLSClient struct {
		Class               string              `json:"class,omitempty"`
		TrustCA             *as3ResourcePointer `json:"trustCA,omitempty"`
		ValidateCertificate bool                `json:"validateCertificate,omitempty"`
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

	Member struct {
		Address string `json:"address"`
		Port    int32  `json:"port"`
		Session string `json:"session,omitempty"`
	}
)
