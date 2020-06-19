package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional

// VirtualServer defines the VirtualServer resource.
type VirtualServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec VirtualServerSpec `json:"spec"`
}

// VirtualServerSpec is the spec of the VirtualServer resource.
type VirtualServerSpec struct {
	Host                 string `json:"host"`
	VirtualServerAddress string `json:"virtualServerAddress"`
	Pools                []Pool `json:"pools"`
	TLSProfileName       string `json:"tlsProfileName"`
	HTTPTraffic          string `json:"httpTraffic,omitempty"`
}

// Pool defines a pool object in BIG-IP.
type Pool struct {
	Path            string  `json:"path"`
	Service         string  `json:"service"`
	ServicePort     int32   `json:"servicePort"`
	NodeMemberLabel string  `json:"nodeMemberLabel"`
	Monitor         Monitor `json:"monitor"`
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
