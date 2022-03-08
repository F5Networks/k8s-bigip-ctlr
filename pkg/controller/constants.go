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

// Annotation constants
const (
	F5VsBalanceAnnotation              = "virtual-server.f5.com/balance"
	F5VsURLRewriteAnnotation           = "virtual-server.f5.com/rewrite-target-url"
	F5VsAppRootAnnotation              = "virtual-server.f5.com/rewrite-app-root"
	F5VsWhitelistSourceRangeAnnotation = "virtual-server.f5.com/whitelist-source-range"
	F5VsAllowSourceRangeAnnotation     = "virtual-server.f5.com/allow-source-range"
)

// Route constants
const (
	AbDeploymentPathIRuleName    = "ab_deployment_path_irule"
	DefaultSourceAddrTranslation = "automap"
	SnatSourceAddrTranslation    = "snat"
	InsecureRoutesPolicyName     = "openshift_insecure_routes"
	SecureRoutesPolicyName       = "openshift_secure_routes"
	InsecureRoutesName           = "ose_vserver"       // routeHttpVs
	SecureRoutesName             = "https_ose_vserver" //routeHttpsVs
)
