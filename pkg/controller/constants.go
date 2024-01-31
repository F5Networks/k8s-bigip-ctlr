package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"time"
)

const (

	// DefaultCustomResourceLabel is a label used for F5 Custom Resources.
	DefaultCustomResourceLabel = "f5cr in (true)"
	// VirtualServer is a F5 Custom Resource Kind.
	VirtualServer = "VirtualServer"
	// TLSProfile is a F5 Custom Resource Kind
	TLSProfile = "TLSProfile"
	// IngressLink is a Custom Resource used by both F5 and Nginx
	IngressLink = "IngressLink"
	// TransportServer is a F5 Custom Resource Kind
	TransportServer = "TransportServer"
	// ExternalDNS is a F5 Custom Resource Kind
	ExternalDNS = "ExternalDNS"
	// Policy is collection of BIG-IP profiles, LTM policies and iRules
	CustomPolicy = "CustomPolicy"
	// IPAM is a F5 Custom Resource Kind
	IPAM = "IPAM"
	// Service is a k8s native Service Resource.
	Service = "Service"
	//Pod  is a k8s native object
	Pod = "Pod"
	//Secret  is a k8s native object
	K8sSecret = "Secret"
	// Endpoints is a k8s native Endpoint Resource.
	Endpoints = "Endpoints"
	// Namespace is k8s namespace
	Namespace = "Namespace"
	// ConfigCR is k8s native ConfigCR resource
	ConfigCR = "ConfigCR"
	// Route is OpenShift Route
	Route = "Route"
	// Node update
	NodeUpdate = "Node"

	NodePort = "nodeport"
	Cluster  = "cluster"

	StandAloneCIS = "standalone"
	SecondaryCIS  = "secondary"
	PrimaryCIS    = "primary"
	// Namespace is k8s namespace
	HACIS = "HACIS"

	// Primary cluster health probe
	DefaultProbeInterval = 60
	DefaultRetryInterval = 15

	PolicyControlForward = "forwarding"
	// Namespace for IPAM CRD
	IPAMNamespace = "kube-system"
	//Name for ipam CR
	ipamCRName = "ipam"

	// TLS Terminations
	TLSEdge             = "edge"
	AllowSourceRange    = "allowSourceRange"
	DefaultPool         = "defaultPool"
	TLSReencrypt        = "reencrypt"
	TLSPassthrough      = "passthrough"
	TLSRedirectInsecure = "redirect"
	TLSAllowInsecure    = "allow"
	TLSNoInsecure       = "none"

	LBServiceIPAMLabelAnnotation  = "cis.f5.com/ipamLabel"
	LBServiceHostAnnotation       = "cis.f5.com/host"
	HealthMonitorAnnotation       = "cis.f5.com/health"
	LBServicePolicyNameAnnotation = "cis.f5.com/policyName"

	//Antrea NodePortLocal support
	NPLPodAnnotation = "nodeportlocal.antrea.io"
	NPLSvcAnnotation = "nodeportlocal.antrea.io/enabled"
	NodePortLocal    = "nodeportlocal"

	// AS3 Related constants
	as3SupportedVersion = 3.18
	//Update as3Version,defaultAS3Version,defaultAS3Build while updating AS3 validation schema.
	//While upgrading version update $id value in schema json to https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/master/schema/latest/as3-schema.json
	as3Version        = 3.48
	defaultAS3Version = "3.48.0"
	defaultAS3Build   = "10"
	clusterHealthPath = "/readyz"

	Create = "Create"
	Update = "Update"
	Delete = "Delete"

	// DefaultNativeResourceLabel is a label used for kubernetes/openshift Resources.
	DefaultNativeResourceLabel = "f5nr in (true)"

	Shared = "Shared"

	Local = "local"

	F5RouterName = "F5 BIG-IP"

	HTTP  = "http"
	HTTPS = "https"

	defaultRouteGroupName string = "defaultRouteGroup"

	//OVN K8S CNI
	OVN_K8S                    = "ovn-k8s"
	OVNK8sNodeSubnetAnnotation = "k8s.ovn.org/node-subnets"
	OVNK8sNodeIPAnnotation     = "k8s.ovn.org/node-primary-ifaddr"
	//k8s.ovn.org/host-addresses is changed to k8s.ovn.org/host-cidrs in openshift 4.14
	OVNK8sNodeIPAnnotation2 = "k8s.ovn.org/host-addresses"
	OvnK8sNodeIPAnnotation3 = "k8s.ovn.org/host-cidrs"

	//Cilium CNI
	CILIUM_Static                   = "cilium-static"
	CiliumK8sNodeSubnetAnnotation12 = "io.cilium.network.ipv4-pod-cidr"
	CiliumK8sNodeSubnetAnnotation13 = "network.cilium.io/ipv4-pod-cidr"

	F5VsWAFPolicy                      = "virtual-server.f5.com/waf"
	F5VsAllowSourceRangeAnnotation     = "virtual-server.f5.com/allow-source-range"
	MultiClusterServicesAnnotation     = "virtual-server.f5.com/multiClusterServices"
	F5VsBalanceAnnotation              = "virtual-server.f5.com/balance"
	F5VsAppRootAnnotation              = "virtual-server.f5.com/rewrite-app-root"
	F5VsURLRewriteAnnotation           = "virtual-server.f5.com/rewrite-target-url"
	F5ServerSslProfileAnnotation       = "virtual-server.f5.com/serverssl"
	F5ClientSslProfileAnnotation       = "virtual-server.f5.com/clientssl"
	F5HealthMonitorAnnotation          = "virtual-server.f5.com/health"
	PodConcurrentConnectionsAnnotation = "virtual-server.f5.com/pod-concurrent-connections"

	TLSVerion1_3 TLSVersion = "1.3"

	Active          cisapiv1.HAModeType      = "active-active"
	StandBy         cisapiv1.HAModeType      = "active-standby"
	Ratio           cisapiv1.HAModeType      = "ratio"
	None            cisapiv1.AutoMonitorType = "none"
	ReadinessProbe  cisapiv1.AutoMonitorType = "readiness-probe"
	ServiceEndpoint cisapiv1.AutoMonitorType = "service-endpoint"

	nginxMonitorPort int32 = 8081

	NotEnabled = iota
	InvalidInput
	NotRequested
	Requested
	Allocated

	as3SharedApplication = "Shared"
	gtmPartition         = "Common"
	timeoutSmall         = 5 * time.Second
	timeoutMedium        = 30 * time.Second
	timeoutLarge         = 180 * time.Second
)

const (
	DEFAULT_HTTP_PORT  int32  = 80
	DEFAULT_HTTPS_PORT int32  = 443
	DEFAULT_SNAT       string = "auto"

	// Constants for CustomProfile.Type as defined in CCCL
	CustomProfileClient string = "clientside"
	CustomProfileServer string = "serverside"

	// Constants for CustomProfile.PeerCertMode
	PeerCertRequired = "require"

	// Constants
	HttpRedirectIRuleName = "http_redirect_irule"
	// Constants
	HttpRedirectNoHostIRuleName = "http_redirect_irule_nohost"
	// Internal data group for https redirect
	HttpsRedirectDgName = "https_redirect_dg"
	TLSIRuleName        = "tls_irule"
	ABPathIRuleName     = "ab_deployment_path_irule"
)

// constants for TLS references
const (
	// reference for profiles stored in BIG-IP
	BIGIP = "bigip"
	// reference for profiles stores as secrets in k8s cluster
	Secret = "secret"
	// reference for routes
	Certificate = "certificate"
	// reference for service“
	ServiceRef = "service"
)

// constants for SSL options
const (
	PolicySSLOption           = "policySSL"
	AnnotationSSLOption       = "annotation"
	RouteCertificateSSLOption = "routeCertificate"
	DefaultSSLOption          = "defaultSSL"
	InvalidSSLOption          = "invalid"
)

// Internal data group for default pool of a virtual server.
const DefaultPoolsDgName = "default_pool_servername_dg"

// Internal data group for reencrypt termination.
const ReencryptHostsDgName = "ssl_reencrypt_servername_dg"

// Internal data group for edge termination.
const EdgeHostsDgName = "ssl_edge_servername_dg"

// Internal data group for passthrough termination.
const PassthroughHostsDgName = "ssl_passthrough_servername_dg"

// Internal data group for reencrypt termination that maps the host name to the
// server ssl profile.
const ReencryptServerSslDgName = "ssl_reencrypt_serverssl_dg"

// Internal data group for edge termination that maps the host name to the
// false. This will help Irule to understand ssl should be disabled
// on serverside.
const EdgeServerSslDgName = "ssl_edge_serverssl_dg"

// Internal DataGroup Default Type
const DataGroupType = "string"

// Allow Source Range
const DataGroupAllowSourceRangeType = "ip"
const AllowSourceRangeDgName = "allowSourceRange"

// Internal data group for ab deployment routes.
const AbDeploymentDgName = "ab_deployment_dg"

const BigIPLabel = ""

const CM_DECLARE_API = "/api/v1/spaces/default/appsvcs/documents/"
