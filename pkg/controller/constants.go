package controller

type (
	ControllerMode string
)

const (
	KubernetesMode     ControllerMode = "kubernetes"
	OpenShiftMode      ControllerMode = "openshift"
	CustomResourceMode ControllerMode = "customresource"

	Create = "Create"
	Update = "Update"
	Delete = "Delete"

	// DefaultNativeResourceLabel is a label used for kubernetes/openshift Resources.
	DefaultNativeResourceLabel = "f5nr in (true)"

	Shared = "Shared"

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
	CILIUM_K8S                      = "cilium-k8s"
	CiliumK8sNodeSubnetAnnotation12 = "io.cilium.network.ipv4-pod-cidr"
	CiliumK8sNodeSubnetAnnotation13 = "network.cilium.io/ipv4-pod-cidr"

	//Calico CNI
	CALICO_K8S                  = "calico-k8s"
	CALICO_API_BLOCK_AFFINITIES = "/apis/crd.projectcalico.org/v1/blockaffinities"
	CALICONodeIPAnnotation      = "projectcalico.org/IPv4Address"
	BLOCKAFFINITIES             = "blockaffinities"

	CommonPartition = "Common"
	LocalCluster    = ""
	Retries         = 3
)
