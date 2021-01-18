package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional

// ExternalDNS defines the DNS resource.
type F5IPAM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   F5IPAMSpec   `json:"spec,omitempty"`
	Status F5IPAMStatus `json:"status,omitempty"`
}

type F5IPAMSpec struct {
	HostSpecs []*HostSpec `json:"hostSpecs,omitempty"`
}

type HostSpec struct {
	Host string `json:"host,omitempty"`
	Cidr string `json:"cidr,omitempty"`
}

type F5IPAMStatus struct {
	IPStatus []*IPSpec `json:"IPStatus,omitempty"`
}

type IPSpec struct {
	Host string `json:"host,omitempty"`
	Cidr string `json:"cidr,omitempty"`
	IP   string `json:"ip,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// F5IPAMList is list of ExternalDNS
type F5IPAMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []F5IPAM `json:"items"`
}
