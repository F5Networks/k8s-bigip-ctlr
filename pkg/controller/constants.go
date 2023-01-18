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
)
