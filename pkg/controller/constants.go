package controller

type (
	ControllerMode string
)

const (
	KubernetesMode     ControllerMode = "kubernetes"
	OpenShiftMode      ControllerMode = "openshift"
	CustomResourceMode ControllerMode = "customresource"

	// DefaultNativeResourceLabel is a label used for kubernetes/openshift Resources.
	DefaultNativeResourceLabel = "f5nr in (true)"
)
