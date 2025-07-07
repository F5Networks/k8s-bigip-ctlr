package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// VirtualServer represents the configuration for a VirtualServer resource
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=vs
// +kubebuilder:validation:Optional
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="host",type="string",JSONPath=".spec.host",description="hostname"
// +kubebuilder:printcolumn:name="tlsProfileName",type="string",JSONPath=".spec.tlsProfileName",description="TLS Profile attached"
// +kubebuilder:printcolumn:name="httpTraffic",type="string",JSONPath=".spec.httpTraffic",description="Http Traffic Termination"
// +kubebuilder:printcolumn:name="IPAddress",type="string",JSONPath=".spec.virtualServerAddress",description="IP address of virtualServer"
// +kubebuilder:printcolumn:name="ipamLabel",type="string",JSONPath=".spec.ipamLabel",description="ipamLabel for virtual server"
// +kubebuilder:printcolumn:name="IPAMVSAddress",type="string",JSONPath=".status.vsAddress",description="IP address of virtualServer"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.status",description="status of VirtualServer"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

type VirtualServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualServerSpec    `json:"spec"`
	Status CustomResourceStatus `json:"status,omitempty"`
}

type CustomResourceStatus struct {
	VSAddress   string      `json:"vsAddress,omitempty"`
	Status      string      `json:"status,omitempty"`
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
	Error       string      `json:"error,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.partition) || self.partition != 'Common'",message="The partition cannot be 'Common' if specified."
// +kubebuilder:validation:XValidation:rule="has(self.partition) == has(oldSelf.partition) && (!has(self.partition) || self.partition == oldSelf.partition)",message="partition cannot be modified. Delete the resource and recreate with new partition"
// +kubebuilder:validation:XValidation:rule="!(has(self.serviceAddress) && !has(oldSelf.serviceAddress))",message="'serviceAddress' cannot be added when it is not already present."
// +kubebuilder:validation:XValidation:rule="!(has(oldSelf.serviceAddress) && !has(self.serviceAddress))",message="'serviceAddress' cannot be deleted when it is present."
// +kubebuilder:validation:XValidation:rule="has(self.ipamLabel) || has(self.virtualServerAddress)",message="either ipamLabel or virtualServerAddress needs to be specified."
type VirtualServerSpec struct {
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	Host string `json:"host,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	HostAliases []string `json:"hostAliases,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]*[A-z0-9]*$`
	HostGroup string `json:"hostGroup,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([A-z0-9-._+])*([A-z0-9])$`
	HostGroupVirtualServerName string `json:"hostGroupVirtualServerName,omitempty"`
	// +kubebuilder:validation:Pattern=`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[ PSYCH!0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`
	VirtualServerAddress string `json:"virtualServerAddress,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`
	AdditionalVirtualServerAddresses []string `json:"additionalVirtualServerAddresses,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]+[A-z0-9]+$`
	IPAMLabel string `json:"ipamLabel,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	BigIPRouteDomain int32 `json:"bigipRouteDomain,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([A-z0-9-._+])*([A-z0-9])$`
	VirtualServerName string `json:"virtualServerName,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	VirtualServerHTTPPort int32 `json:"virtualServerHTTPPort,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	VirtualServerHTTPSPort int32       `json:"virtualServerHTTPSPort,omitempty"`
	DefaultPool            DefaultPool `json:"defaultPool,omitempty"`
	Pools                  []VSPool    `json:"pools,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]+[A-z0-9]+$`
	TLSProfileName string `json:"tlsProfileName,omitempty"`
	// +kubebuilder:validation:Enum=allow;none;redirect
	HTTPTraffic string `json:"httpTraffic,omitempty"`
	// +kubebuilder:validation:Pattern=`^$|^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)+$`
	SNAT string `json:"snat,omitempty"`
	// +kubebuilder:validation:Enum=none;L4
	ConnectionMirroring string `json:"connectionMirroring,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	WAF string `json:"waf,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	RewriteAppRoot string `json:"rewriteAppRoot,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.]+\/?)*$`
	AllowVLANs []string `json:"allowVlans,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^none$|^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	IRules []string `json:"iRules,omitempty"`
	// +kubebuilder:validation:MaxItems=1
	ServiceIPAddress []ServiceAddress `json:"serviceAddress,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]+[A-z0-9]+$`
	PolicyName string `json:"policyName,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	PersistenceProfile string `json:"persistenceProfile,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	HTTPCompressionProfile string `json:"httpCompressionProfile,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileMultiplex string `json:"profileMultiplex,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	DOS string `json:"dos,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	BotDefense            string        `json:"botDefense,omitempty"`
	Profiles              ProfileVSSpec `json:"profiles,omitempty"`
	AllowSourceRange      []string      `json:"allowSourceRange,omitempty"`
	HttpMrfRoutingEnabled *bool         `json:"httpMrfRoutingEnabled,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.]+$`
	Partition string `json:"partition,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	HTMLProfile     string          `json:"htmlProfile,omitempty"`
	HostPersistence HostPersistence `json:"hostPersistence,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileAccess string `json:"profileAccess,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	PolicyPerRequestAccess string       `json:"policyPerRequestAccess,omitempty"`
	ProfileAdapt           ProfileAdapt `json:"profileAdapt,omitempty"`
}

type HostPersistence struct {
	// +kubebuilder:validation:Enum=sourceAddress;destinationAddress;cookieInsert;cookieRewrite;cookiePassive;cookieHash;universal;hash;carp;none
	// +kubebuilder:validation:Required
	Method          string          `json:"method,omitempty"`
	PersistMetaData PersistMetaData `json:"metaData,omitempty"`
}

type PersistMetaData struct {
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Pattern=`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`
	Netmask string `json:"netmask,omitempty"`
	Key     string `json:"key,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Timeout int32 `json:"timeout,omitempty"`
	// +kubebuilder:validation:Pattern=`^((?:(?:[0-9]+d))|(?:(?:[0-9]+d)?((?:[01]?[0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9])?)))$`
	Expiry string `json:"expiry,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Offset int32 `json:"offset,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Length int32 `json:"length,omitempty"`
}

type ServiceAddress struct {
	ArpEnabled bool `json:"arpEnabled,omitempty"`
	// +kubebuilder:validation:Enum=enable;disable;selective
	ICMPEcho string `json:"icmpEcho,omitempty"`
	// +kubebuilder:validation:Enum=enable;disable;selective;always;any;all
	RouteAdvertisement string `json:"routeAdvertisement,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	TrafficGroup    string `json:"trafficGroup,omitempty"`
	SpanningEnabled bool   `json:"spanningEnabled,omitempty"`
}

type DefaultPool struct {
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-._+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Pattern=`[a-z]([-a-z0-9]*[a-z0-9])?`
	Service     string             `json:"service"`
	ServicePort intstr.IntOrString `json:"servicePort"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][-A-Za-z0-9_.\/]{0,61}[a-zA-Z0-9]=(\s?|""|[a-zA-Z0-9][-A-Za-z0-9_.]{0,61}[a-zA-Z0-9])$`
	NodeMemberLabel string    `json:"nodeMemberLabel,omitempty"`
	Monitors        []Monitor `json:"monitors"`
	// +kubebuilder:validation:Pattern=`^[a-z]+[a-z_-]+[a-z]+$`
	Balance string `json:"loadBalancingMethod,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([-A-z0-9_.+:])*([A-z0-9])+$`
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	ReselectTries     int32  `json:"reselectTries,omitempty"`
	ServiceDownAction string `json:"serviceDownAction,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=bigip;service
	Reference string `json:"reference"`
}

type VSPool struct {
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([-A-z0-9_.+:])*([A-z0-9])+$`
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	Path string `json:"path,omitempty"`
	// +kubebuilder:validation:Pattern=`[a-z]([-a-z0-9]*[a-z0-9])?`
	Service     string             `json:"service"`
	ServicePort intstr.IntOrString `json:"servicePort"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][-A-Za-z0-9_.\/]{0,61}[a-zA-Z0-9]=(\s?|""|[a-zA-Z0-9][-A-Za-z0-9_.]{0,61}[a-zA-Z0-9])$`
	NodeMemberLabel string             `json:"nodeMemberLabel,omitempty"`
	Monitor         Monitor            `json:"monitor"`
	Monitors        []Monitor          `json:"monitors"`
	MinimumMonitors intstr.IntOrString `json:"minimumMonitors,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	Rewrite string `json:"rewrite,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-z]+[a-z_-]+[a-z]+$`
	Balance string `json:"loadBalancingMethod,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([A-z0-9]+\/?)*$`
	WAF string `json:"waf,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([-A-z0-9_.+:])*([A-z0-9])+$`
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	ReselectTries     int32  `json:"reselectTries,omitempty"`
	ServiceDownAction string `json:"serviceDownAction,omitempty"`
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	HostRewrite string `json:"hostRewrite,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=256
	Weight               *int32                         `json:"weight,omitempty"`
	AlternateBackends    []AlternateBackend             `json:"alternateBackends"`
	MultiClusterServices []MultiClusterServiceReference `json:"multiClusterServices,omitempty"`
}

type TSPool struct {
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([-A-z0-9_.+:])*([A-z0-9])+$`
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	Path string `json:"path,omitempty"`
	// +kubebuilder:validation:Pattern=`[a-z]([-a-z0-9]*[a-z0-9])?`
	Service     string             `json:"service"`
	ServicePort intstr.IntOrString `json:"servicePort"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][-A-Za-z0-9_.\/]{0,61}[a-zA-Z0-9]=(\s?|""|[a-zA-Z0-9][-A-Za-z0-9_.]{0,61}[a-zA-Z0-9])$`
	NodeMemberLabel string    `json:"nodeMemberLabel,omitempty"`
	Monitor         Monitor   `json:"monitor"`
	Monitors        []Monitor `json:"monitors"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	Rewrite string `json:"rewrite,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-z]+[a-z_-]+[a-z]+$`
	Balance string `json:"loadBalancingMethod,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([A-z0-9]+\/?)*$`
	WAF string `json:"waf,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([-A-z0-9_.+:])*([A-z0-9])+$`
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	ReselectTries     int32  `json:"reselectTries,omitempty"`
	ServiceDownAction string `json:"serviceDownAction,omitempty"`
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	HostRewrite string `json:"hostRewrite,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Weight               *int32                         `json:"weight,omitempty"`
	AlternateBackends    []AlternateBackend             `json:"alternateBackends,omitempty"`
	MultiClusterServices []MultiClusterServiceReference `json:"multiClusterServices,omitempty"`
}

type AlternateBackend struct {
	// +kubebuilder:validation:Pattern=`[a-z]([-a-z0-9]*[a-z0-9])?`
	// +kubebuilder:validation:Required
	Service string `json:"service"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([-A-z0-9_.+:])*([A-z0-9])+$`
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=256
	Weight *int32 `json:"weight,omitempty"`
}

type MultiClusterServiceReference struct {
	// +kubebuilder:validation:Required
	ClusterName string `json:"clusterName"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`[a-z]([-a-z0-9]*[a-z0-9])?`
	SvcName string `json:"service"`
	// +kubebuilder:validation:Required
	Namespace   string             `json:"namespace"`
	ServicePort intstr.IntOrString `json:"servicePort,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=256
	Weight *int `json:"weight,omitempty"`
}

type Monitor struct {
	// +kubebuilder:validation:Enum=tcp;udp;http;https
	Type       string `json:"type,omitempty"`
	Send       string `json:"send,omitempty"`
	Recv       string `json:"recv,omitempty"`
	Interval   int    `json:"interval,omitempty"`
	Timeout    int    `json:"timeout,omitempty"`
	TargetPort int32  `json:"targetPort,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Enum=bigip
	Reference string `json:"reference,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([A-z0-9]+\/?)*$`
	SSLProfile string `json:"sslProfile,omitempty"`
}

// +kubebuilder:object:root=true
type VirtualServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []VirtualServer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=tls
type TLSProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TLSProfileSpec `json:"spec"`
}

type TLSProfileSpec struct {
	// +kubebuilder:validation:items:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	Hosts     []string         `json:"hosts"`
	TLS       TLS              `json:"tls"`
	TLSCipher TLSProfileCipher `json:"tlsCipher"`
}

type TLSProfileCipher struct {
	// +kubebuilder:validation:Enum="1.0";"1.1";"1.2";"1.3"
	TLSVersion  string `json:"tlsVersion"`
	Ciphers     string `json:"ciphers"`
	CipherGroup string `json:"cipherGroup"`
	// +kubebuilder:validation:Enum="1.0";"1.1";"1.2";"1.3"
	DisableTLSVersions []string `json:"disableTLSVersions"`
}

type TLSTransportServer struct {
	// +kubebuilder:validation:items:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	ClientSSLs []string `json:"clientSSLs,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	ServerSSLs []string `json:"serverSSLs,omitempty"`
	// +kubebuilder:validation:Enum=bigip;secret
	Reference string `json:"reference,omitempty"`
}

type TLS struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=edge;reencrypt;passthrough
	Termination string `json:"termination"`
	// +kubebuilder:validation:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	ClientSSL string `json:"clientSSL,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	ClientSSLs []string `json:"clientSSLs,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	ServerSSL string `json:"serverSSL,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	ServerSSLs []string `json:"serverSSLs,omitempty"`
	// +kubebuilder:validation:Enum=bigip;secret;hybrid
	Reference       string          `json:"reference,omitempty"`
	ClientSSLParams ClientSSLParams `json:"clientSSLParams,omitempty"`
	ServerSSLParams ServerSSLParams `json:"serverSSLParams,omitempty"`
}

type ClientSSLParams struct {
	RenegotiationEnabled *bool `json:"renegotiationEnabled,omitempty"`
	// +kubebuilder:validation:Enum=bigip;secret
	ProfileReference string `json:"profileReference,omitempty"`
}

type ServerSSLParams struct {
	RenegotiationEnabled *bool `json:"renegotiationEnabled,omitempty"`
	// +kubebuilder:validation:Enum=bigip;secret
	ProfileReference string `json:"profileReference,omitempty"`
}

// +kubebuilder:object:root=true
type TLSProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TLSProfile `json:"items"`
}

// IngressLink represents the configuration for an IngressLink resource
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=il
// +kubebuilder:printcolumn:name="IPAMVSAddress",type="string",JSONPath=".status.vsAddress",description="IP address of virtualServer"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type IngressLink struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IngressLinkSpec      `json:"spec"`
	Status            CustomResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.partition) || self.partition != 'Common'",message="The partition cannot be 'Common' if specified."
// +kubebuilder:validation:XValidation:rule="has(self.partition) == has(oldSelf.partition) && (!has(self.partition) || self.partition == oldSelf.partition)",message="partition cannot be modified. Delete the resource and recreate with new partition"
// +kubebuilder:validation:XValidation:rule="has(self.ipamLabel) || has(self.virtualServerAddress)",message="either ipamLabel or virtualServerAddress needs to be specified."
type IngressLinkSpec struct {
	// +kubebuilder:validation:Pattern=`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`
	VirtualServerAddress string `json:"virtualServerAddress,omitempty"`
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	Host     string                `json:"host,omitempty"`
	Selector *metav1.LabelSelector `json:"selector"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	IRules []string `json:"iRules,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]+[A-z0-9]+$`
	IPAMLabel string `json:"ipamLabel"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	BigIPRouteDomain int32 `json:"bigipRouteDomain,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.]+$`
	Partition            string                         `json:"partition,omitempty"`
	MultiClusterServices []MultiClusterServiceReference `json:"multiClusterServices,omitempty"`
	TLS                  TLSTransportServer             `json:"tls,omitempty"`
	Monitors             []Monitor                      `json:"monitors,omitempty"`
}

// +kubebuilder:object:root=true
type IngressLinkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []IngressLink `json:"items"`
}

// TransportServer represents the configuration for a TransportServer resource
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=ts
// +kubebuilder:validation:Optional
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="virtualServerAddress",type="string",JSONPath=".spec.virtualServerAddress",description="IP address of virtualServer"
// +kubebuilder:printcolumn:name="virtualServerPort",type="integer",JSONPath=".spec.virtualServerPort",description="Port of virtualServer"
// +kubebuilder:printcolumn:name="pool",type="string",JSONPath=".spec.pool.service",description="Name of service"
// +kubebuilder:printcolumn:name="poolPort",type="string",JSONPath=".spec.pool.servicePort",description="Port of service"
// +kubebuilder:printcolumn:name="ipamLabel",type="string",JSONPath=".spec.ipamLabel",description="ipamLabel for transport server"
// +kubebuilder:printcolumn:name="IPAMVSAddress",type="string",JSONPath=".status.vsAddress",description="IP address of transport server"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.status",description="status of TransportServer"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type TransportServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TransportServerSpec  `json:"spec"`
	Status            CustomResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.partition) || self.partition != 'Common'",message="The partition cannot be 'Common' if specified."
// +kubebuilder:validation:XValidation:rule="has(self.partition) == has(oldSelf.partition) && (!has(self.partition) || self.partition == oldSelf.partition)",message="partition cannot be modified. Delete the resource and recreate with new partition"
// +kubebuilder:validation:XValidation:rule="!(has(self.serviceAddress) && !has(oldSelf.serviceAddress))",message="'serviceAddress' cannot be added when it is not already present."
// +kubebuilder:validation:XValidation:rule="!(has(oldSelf.serviceAddress) && !has(self.serviceAddress))",message="'serviceAddress' cannot be deleted when it is present."
// +kubebuilder:validation:XValidation:rule="has(self.ipamLabel) || has(self.virtualServerAddress)",message="either ipamLabel or virtualServerAddress needs to be specified."
type TransportServerSpec struct {
	// +kubebuilder:validation:Pattern=`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`
	VirtualServerAddress string `json:"virtualServerAddress"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	VirtualServerPort int32 `json:"virtualServerPort"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+([A-z0-9-._+])*([A-z0-9])$`
	VirtualServerName string `json:"virtualServerName"`
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	Host string `json:"host,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]*[A-z0-9]*$`
	HostGroup string `json:"hostGroup,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=standard;performance
	Mode string `json:"mode"`
	// +kubebuilder:validation:Pattern=`^$|^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)+$`
	SNAT string `json:"snat"`
	// +kubebuilder:validation:Enum=none;L4
	ConnectionMirroring string `json:"connectionMirroring,omitempty"`
	// +kubebuilder:validation:Required
	Pool TSPool `json:"pool"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.]+\/?)*$`
	AllowVLANs []string `json:"allowVlans,omitempty"`
	// +kubebuilder:validation:Enum=tcp;udp;sctp
	// +kubebuilder:default:=tcp
	Type string `json:"type,omitempty"`
	// +kubebuilder:validation:MaxItems=1
	ServiceIPAddress []ServiceAddress `json:"serviceAddress"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.:]+[A-z0-9]+$`
	IPAMLabel string `json:"ipamLabel"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	BigIPRouteDomain int32 `json:"bigipRouteDomain,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	IRules []string `json:"iRules,omitempty"`
	// +kubebuilder:validation:Pattern=`^([A-z0-9-_+])*([A-z0-9])$`
	PolicyName string `json:"policyName,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	PersistenceProfile string `json:"persistenceProfile,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileL4 string `json:"profileL4,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	DOS string `json:"dos,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	BotDefense string        `json:"botDefense,omitempty"`
	Profiles   ProfileTSSpec `json:"profiles,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z]+[-A-z0-9_.]+$`
	Partition string             `json:"partition,omitempty"`
	TLS       TLSTransportServer `json:"tls,omitempty"`
}

// +kubebuilder:object:root=true
type TransportServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TransportServer `json:"items"`
}

// ExternalDNS represents the configuration for an ExternalDNS resource
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=edns
// +kubebuilder:validation:Optional
// +kubebuilder:printcolumn:name="domainName",type="string",JSONPath=".spec.domainName",description="Domain name of virtual server resource"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="CREATED ON",type="string",JSONPath=".metadata.creationTimestamp"
type ExternalDNS struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ExternalDNSSpec `json:"spec"`
}

type ExternalDNSSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(([a-zA-Z0-9\*]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`
	DomainName string `json:"domainName"`
	// +kubebuilder:validation:Pattern=`A`
	DNSRecordType string `json:"dnsRecordType"`
	// +kubebuilder:validation:Pattern=`^[a-z]+[a-z_-]+[a-z]+$`
	LoadBalanceMethod  string `json:"loadBalanceMethod"`
	PersistenceEnabled bool   `json:"persistenceEnabled"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32
	PersistCidrIPv4 uint8 `json:"persistCidrIpv4"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	PersistCidrIPv6 uint8 `json:"persistCidrIpv6"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	TTLPersistence        uint32    `json:"ttlPersistence"`
	ClientSubnetPreferred *bool     `json:"clientSubnetPreferred,omitempty"`
	Pools                 []DNSPool `json:"pools"`
}

type DNSPool struct {
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	DataServerName string `json:"dataServerName"`
	// +kubebuilder:validation:Pattern=`A`
	DNSRecordType string `json:"dnsRecordType"`
	// +kubebuilder:validation:Pattern=`^[a-z]+[a-z_-]+[a-z]+$`
	LoadBalanceMethod string `json:"loadBalanceMethod"`
	// +kubebuilder:validation:Pattern=`^[a-z]+[a-z_-]+[a-z]+$`
	LBModeFallback string    `json:"lbModeFallback"`
	PriorityOrder  int       `json:"order"`
	Ratio          int       `json:"ratio"`
	Monitor        Monitor   `json:"monitor"`
	Monitors       []Monitor `json:"monitors"`
}

// +kubebuilder:object:root=true
type ExternalDNSList struct {
	metav1.TypeMeta ` promotion:inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ExternalDNS `json:"items"`
}

type PolicySpec struct {
	L7Policies  L7PolicySpec  `json:"l7Policies,omitempty"`
	L3Policies  L3PolicySpec  `json:"l3Policies,omitempty"`
	LtmPolicies LtmIRulesSpec `json:"ltmPolicies,omitempty"`
	IRules      LtmIRulesSpec `json:"iRules,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^none$|^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	IRuleList []string    `json:"iRuleList,omitempty"`
	Profiles  ProfileSpec `json:"profiles,omitempty"`
	// +kubebuilder:validation:Pattern=`^$|^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)+$`
	SNAT string `json:"snat,omitempty"`
	// +kubebuilder:validation:Enum=default;auto;disable
	AutoLastHop  string           `json:"autoLastHop,omitempty"`
	PoolSettings PoolSettingsSpec `json:"poolSettings,omitempty"`
	DefaultPool  DefaultPool      `json:"defaultPool,omitempty"`
}

type PoolSettingsSpec struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	ReselectTries     int32  `json:"reselectTries,omitempty"`
	ServiceDownAction string `json:"serviceDownAction,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=900
	SlowRampTime         int32                `json:"slowRampTime,omitempty"`
	MultiPoolPersistence MultiPoolPersistence `json:"multiPoolPersistence,omitempty"`
}

type SSLProfiles struct {
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ClientProfiles []string `json:"clientProfiles,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ServerProfiles []string `json:"serverProfiles,omitempty"`
}

type AnalyticsProfiles struct {
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	HTTPAnalyticsProfile string `json:"http,omitempty"`
}

type L7PolicySpec struct {
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([A-z0-9]+\/?)*$`
	WAF string `json:"waf,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileAccess string `json:"profileAccess,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	PolicyPerRequestAccess string       `json:"policyPerRequestAccess,omitempty"`
	ProfileAdapt           ProfileAdapt `json:"profileAdapt,omitempty"`
}

type ProfileAdapt struct {
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Request string `json:"request,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Response string `json:"response,omitempty"`
}

type L3PolicySpec struct {
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	DOS string `json:"dos,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	BotDefense string `json:"botDefense,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([A-z0-9]+\/?)*$`
	FirewallPolicy   string   `json:"firewallPolicy,omitempty"`
	AllowSourceRange []string `json:"allowSourceRange,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)*([A-z0-9-_.\s]+\/?)*$`
	AllowVlans []string `json:"allowVlans,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	IpIntelligencePolicy string `json:"ipIntelligencePolicy,omitempty"`
}

type LtmIRulesSpec struct {
	// +kubebuilder:validation:Pattern=`^none$|^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Secure string `json:"secure,omitempty"`
	// +kubebuilder:validation:Pattern=`^none$|^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	InSecure string `json:"insecure,omitempty"`
	// +kubebuilder:validation:Enum=low;high
	Priority string `json:"priority,omitempty"`
}

type ProfileSpec struct {
	TCP ProfileTCP `json:"tcp,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	UDP string `json:"udp,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	HTTP  string       `json:"http,omitempty"`
	HTTP2 ProfileHTTP2 `json:"http2,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([A-z0-9]+\/?)*$`
	RewriteProfile string `json:"rewriteProfile,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/?[a-zA-Z]+([-A-z0-9_+]+\/)*([-A-z0-9_.:]+\/?)*$`
	PersistenceProfile string `json:"persistenceProfile,omitempty"`
	// +kubebuilder:validation:items:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	LogProfiles []string `json:"logProfiles,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileL4 string `json:"profileL4,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileMultiplex      string            `json:"profileMultiplex,omitempty"`
	HttpMrfRoutingEnabled *bool             `json:"httpMrfRoutingEnabled,omitempty"`
	SSLProfiles           SSLProfiles       `json:"sslProfiles,omitempty"`
	AnalyticsProfiles     AnalyticsProfiles `json:"analyticsProfiles,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	ProfileWebSocket string `json:"profileWebSocket,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	HTMLProfile string `json:"htmlProfile,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	FTPProfile string `json:"ftpProfile,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	HTTPCompressionProfile string `json:"httpCompressionProfile,omitempty"`
}

type ProfileVSSpec struct {
	TCP   ProfileTCP   `json:"tcp,omitempty"`
	HTTP2 ProfileHTTP2 `json:"http2,omitempty"`
}

type ProfileTSSpec struct {
	TCP ProfileTCP `json:"tcp,omitempty"`
}

type MultiPoolPersistence struct {
	// +kubebuilder:validation:Enum=uieSourceAddress;hashSourceAddress
	Method string `json:"method,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default:=180
	TimeOut int32 `json:"timeOut,omitempty"`
}

type ProfileTCP struct {
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Client string `json:"client,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/[a-zA-Z]+([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Server string `json:"server,omitempty"`
}

type ProfileHTTP2 struct {
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Client string `json:"client,omitempty"`
	// +kubebuilder:validation:Pattern=`^\/([A-z0-9-_+]+\/)+([-A-z0-9_.:]+\/?)*$`
	Server string `json:"server,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=plc
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PolicySpec `json:"spec"`
}

// +kubebuilder:object:root=true
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Policy `json:"items"`
}
