package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
}

// VirtualServerSpec is the spec of the VirtualServer resource.
type VirtualServerSpec struct {
	Host                   string           `json:"host,omitempty"`
	VirtualServerAddress   string           `json:"virtualServerAddress,omitempty"`
	IPAMLabel              string           `json:"ipamLabel,omitempty"`
	VirtualServerName      string           `json:"virtualServerName,omitempty"`
	VirtualServerHTTPPort  int32            `json:"virtualServerHTTPPort,omitempty"`
	VirtualServerHTTPSPort int32            `json:"virtualServerHTTPSPort,omitempty"`
	Pools                  []Pool           `json:"pools,omitempty"`
	TLSProfileName         string           `json:"tlsProfileName,omitempty"`
	HTTPTraffic            string           `json:"httpTraffic,omitempty"`
	SNAT                   string           `json:"snat,omitempty"`
	WAF                    string           `json:"waf,omitempty"`
	RewriteAppRoot         string           `json:"rewriteAppRoot,omitempty"`
	AllowVLANs             []string         `json:"allowVlans,omitempty"`
	IRules                 []string         `json:"iRules,omitempty"`
	ServiceIPAddress       []ServiceAddress `json:"serviceAddress,omitempty"`
}

// ServiceAddress Service IP address definition (BIG-IP virtual-address).
type ServiceAddress struct {
	ArpEnabled         bool   `json:"arpEnabled,omitempty"`
	ICMPEcho           string `json:"icmpEcho,omitempty"`
	RouteAdvertisement string `json:"routeAdvertisement,omitempty"`
	TrafficGroup       string `json:"trafficGroup,omitempty,omitempty"`
	SpanningEnabled    bool   `json:"spanningEnabled,omitempty"`
}

// Pool defines a pool object in BIG-IP.
type Pool struct {
	Path            string  `json:"path,omitempty"`
	Service         string  `json:"service"`
	ServicePort     int32   `json:"servicePort"`
	NodeMemberLabel string  `json:"nodeMemberLabel,omitempty"`
	Monitor         Monitor `json:"monitor"`
	Rewrite         string  `json:"rewrite,omitempty"`
}

// Monitor defines a monitor object in BIG-IP.
type Monitor struct {
	Type     string `json:"type"`
	Send     string `json:"send"`
	Recv     string `json:"recv"`
	Interval int    `json:"interval"`
	Timeout  int    `json:"timeout"`
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
	Termination string `json:"termination"`
	ClientSSL   string `json:"clientSSL"`
	ServerSSL   string `json:"serverSSL"`
	Reference   string `json:"reference"`
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

	Spec IngressLinkSpec `json:"spec"`
}

// IngressLinkSpec is Spec for IngressLink
type IngressLinkSpec struct {
	VirtualServerAddress string                `json:"virtualServerAddress"`
	Selector             *metav1.LabelSelector `json:"selector"`
	IRules               []string              `json:"iRules,omitempty"`
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

// TransportServer defines the VirtualServer resource.
type TransportServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TransportServerSpec `json:"spec"`
}

// TransportServerSpec is the spec of the VirtualServer resource.
type TransportServerSpec struct {
	VirtualServerAddress string           `json:"virtualServerAddress"`
	VirtualServerPort    int32            `json:"virtualServerPort"`
	VirtualServerName    string           `json:"virtualServerName"`
	Mode                 string           `json:"mode"`
	SNAT                 string           `json:"snat"`
	Pool                 Pool             `json:"pool"`
	AllowVLANs           []string         `json:"allowVlans,omitempty"`
	Type                 string           `json:"type,omitempty"`
	ServiceIPAddress     []ServiceAddress `json:"serviceAddress"`
	IPAMLabel            string           `json:"ipamLabel"`
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
	DomainName        string    `json:"domainName"`
	DNSRecordType     string    `json:"dnsRecordType"`
	LoadBalanceMethod string    `json:"loadBalanceMethod"`
	Pools             []DNSPool `json:"pools"`
}

type DNSPool struct {
	Name              string  `json:"name"`
	DataServerName    string  `json:"dataServerName"`
	DNSRecordType     string  `json:"dnsRecordType"`
	LoadBalanceMethod string  `json:"loadBalanceMethod"`
	Monitor           Monitor `json:"monitor"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalDNSList is list of ExternalDNS
type ExternalDNSList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ExternalDNS `json:"items"`
}
