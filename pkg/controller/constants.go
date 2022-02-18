package controller

type (
	ControllerMode string
)

const (
	KubernetesMode     ControllerMode = "KubernetesMode"
	OpenShiftMode      ControllerMode = "OpenShiftMode"
	CustomResourceMode ControllerMode = "CustomResourceMode"

	// DefaultNativeResourceLabel is a label used for kubernetes/openshift Resources.
	DefaultNativeResourceLabel = "f5nr in (true)"
)
