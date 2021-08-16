/*-
 * Copyright (c) 2021, F5 Networks, Inc.
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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional

// ExternalDNS defines the DNS resource.
type IPAM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IPAMSpec   `json:"spec,omitempty"`
	Status IPAMStatus `json:"status,omitempty"`
}

type IPAMSpec struct {
	HostSpecs []*HostSpec `json:"hostSpecs,omitempty"`
}

type HostSpec struct {
	Host string `json:"host,omitempty"`

	Key       string `json:"key,omitempty"`
	IPAMLabel string `json:"ipamLabel,omitempty"`

	CIDR string `json:"cidr,omitempty"`
}

type IPAMStatus struct {
	IPStatus []*IPSpec `json:"IPStatus,omitempty"`
}

type IPSpec struct {
	IP   string `json:"ip,omitempty"`
	Host string `json:"host,omitempty"`

	Key       string `json:"key,omitempty"`
	IPAMLabel string `json:"ipamLabel,omitempty"`

	CIDR string `json:"cidr,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAMList is list of ExternalDNS
type IPAMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []IPAM `json:"items"`
}
