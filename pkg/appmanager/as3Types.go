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

package appmanager

import (
	"net/http"
)

type (
	as3Template    string
	as3Declaration string

	poolName   string
	appName    string
	tenantName string

	pool      []Member
	tenant    map[appName][]poolName
	as3Object map[tenantName]tenant

	//Rest client creation for big ip
	AS3RESTClient struct {
		client      *http.Client
		baseURL     string
		oldChecksum string
		newChecksum string
	}

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
		Class    string    `json:"class,omitempty"`
		Rules    []as3Rule `json:"rules,omitempty"`
		Strategy string    `json:"strategy,omitempty"`
	}

	// as3Rule maps to Endpoint_Policy_Rule in AS3 Resources
	as3Rule struct {
		Name       string         `json:"name,omitempty"`
		Conditions []as3Condition `json:"conditions,omitempty"`
		Actions    []as3Action    `json:"actions,omitempty"`
	}

	// as3Action maps to Policy_Action in AS3 Resources
	as3Action struct {
		Type   string                  `json:"type,omitempty"`
		Event  string                  `json:"event,omitempty"`
		Select *as3ActionForwardSelect `json:"select,omitempty"`
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
		ProfileHTTP            as3MultiTypeParam `json:"profileHTTP,omitempty"`
		ProfileTCP             as3MultiTypeParam `json:"profileTCP,omitempty"`
		VirtualAddresses       []string          `json:"virtualAddresses,omitempty"`
		VirtualPort            int               `json:"virtualPort,omitempty"`
		SNAT                   string            `json:"snat,omitempty"`
		PolicyEndpoint         as3MultiTypeParam `json:"policyEndpoint,omitempty"`
		ClientTLS              as3MultiTypeParam `json:"clientTLS,omitempty"`
		ServerTLS              as3MultiTypeParam `json:"serverTLS,omitempty"`
		IRules                 []string          `json:"iRules,omitempty"`
		Redirect80             *bool             `json:"redirect80,omitempty"`
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
		Class        string                     `json:"class,omitempty"`
		Certificates []as3TLSServerCertificates `json:"certificates,omitempty"`
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
)
