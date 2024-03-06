/*
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/controller"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/health"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	//"github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/cccl"

	v1 "k8s.io/api/core/v1"

	//"net/http"

	cisAgent "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/as3"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	//"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/apimachinery/pkg/labels"

	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
)

type globalSection struct {
	LogLevel          string `json:"log-level,omitempty"`
	VerifyInterval    int    `json:"verify-interval,omitempty"`
	VXLANPartition    string `json:"vxlan-partition,omitempty"`
	DisableLTM        bool   `json:"disable-ltm,omitempty"`
	DisableARP        bool   `json:"disable-arp,omitempty"`
	StaticRoutingMode bool   `json:"static-route-mode,omitempty"`
}

type bigIPSection struct {
	BigIPUsername   string   `json:"username,omitempty"`
	BigIPPassword   string   `json:"password,omitempty"`
	BigIPURL        string   `json:"url,omitempty"`
	BigIPPartitions []string `json:"partitions,omitempty"`
}

// OCP4 Version for TEEM
type (
	Ocp4Version struct {
		Status ClusterVersionStatus `json:"status"`
	}
	ClusterVersionStatus struct {
		History []UpdateHistory `json:"history,omitempty"`
	}
	UpdateHistory struct {
		Version string `json:"version"`
	}
)

const (
	versionPathOpenshiftv3 = "/version/openshift"
	versionPathOpenshiftv4 = "/apis/config.openshift.io/v1/clusterversions/version"
	versionPathk8s         = "/version"
)

var (
	// To be set by build
	version   string
	buildInfo string

	// Flag sets and supported flags
	flags             *pflag.FlagSet
	globalFlags       *pflag.FlagSet
	bigIPFlags        *pflag.FlagSet
	kubeFlags         *pflag.FlagSet
	vxlanFlags        *pflag.FlagSet
	osRouteFlags      *pflag.FlagSet
	gtmBigIPFlags     *pflag.FlagSet
	multiClusterFlags *pflag.FlagSet

	// Custom Resource
	customResourceMode *bool
	controllerMode     *string
	defaultRouteDomain *int

	pythonBaseDir    *string
	logLevel         *string
	ccclLogLevel     *string
	logFile          *string
	verifyInterval   *int
	nodePollInterval *int
	syncInterval     *int
	printVersion     *bool
	httpAddress      *string
	dgPath           string
	disableTeems     *bool
	enableIPV6       *bool

	namespaces             *[]string
	useNodeInternal        *bool
	poolMemberType         *string
	inCluster              *bool
	kubeConfig             *string
	namespaceLabel         *string
	manageRoutes           *bool
	manageConfigMaps       *bool
	manageIngress          *bool
	hubMode                *bool
	nodeLabelSelector      *string
	resolveIngNames        *string
	defaultIngIP           *string
	vsSnatPoolName         *string
	useSecrets             *bool
	schemaLocal            *string
	manageIngressClassOnly *bool
	ingressClass           *string

	bigIPURL                  *string
	bigIPUsername             *string
	bigIPPassword             *string
	bigIPPartitions           *[]string
	credsDir                  *string
	as3Validation             *bool
	sslInsecure               *bool
	ipam                      *bool
	ipamClusterLabel          *string
	enableTLS                 *string
	tls13CipherGroupReference *string
	ciphers                   *string
	trustedCerts              *string
	as3PostDelay              *int

	trustedCertsCfgmap      *string
	agent                   *string
	ccclGtmAgent            *bool
	logAS3Response          *bool
	logAS3Request           *bool
	shareNodes              *bool
	overriderAS3CfgmapName  *string
	filterTenants           *bool
	disableDefaultPartition *bool

	vxlanMode        string
	openshiftSDNName *string
	flannelName      *string
	ciliumTunnelName *string

	routeVserverAddr *string
	routeLabel       *string
	routeHttpVs      *string
	routeHttpsVs     *string
	clientSSL        *string
	serverSSL        *string

	extendedSpecConfigmap *string
	routeSpecConfigmap    *string

	gtmBigIPURL      *string
	gtmBigIPUsername *string
	gtmBigIPPassword *string
	gtmCredsDir      *string

	httpClientMetrics   *bool
	staticRoutingMode   *bool
	orchestrationCNI    *string
	sharedStaticRoutes  *bool
	staticRouteNodeCIDR *string
	// package variables
	isNodePort         bool
	watchAllNamespaces bool
	vxlanName          string
	kubeClient         kubernetes.Interface
	agRspChan          chan interface{}
	eventChan          chan interface{}
	configWriter       writer.Writer
	userAgentInfo      string
	multiClusterMode   *string
)

func _init() {
	flags = pflag.NewFlagSet("main", pflag.PanicOnError)
	globalFlags = pflag.NewFlagSet("Global", pflag.PanicOnError)
	bigIPFlags = pflag.NewFlagSet("BigIP", pflag.PanicOnError)
	kubeFlags = pflag.NewFlagSet("Kubernetes", pflag.PanicOnError)
	vxlanFlags = pflag.NewFlagSet("VXLAN", pflag.PanicOnError)
	osRouteFlags = pflag.NewFlagSet("OpenShift Routes", pflag.PanicOnError)
	gtmBigIPFlags = pflag.NewFlagSet("GTM", pflag.PanicOnError)
	multiClusterFlags = pflag.NewFlagSet("MultiCluster", pflag.PanicOnError)

	// Flag wrapping
	var err error
	var width int
	fd := int(os.Stdout.Fd())
	if terminal.IsTerminal(fd) {
		width, _, err = terminal.GetSize(fd)
		if nil != err {
			width = 0
		}
	}

	// set log-as3-request
	as3RequestFalse := false
	logAS3Request = &as3RequestFalse

	// Global flags
	pythonBaseDir = globalFlags.String("python-basedir", "",
		"DEPRECATED: Optional, directory location of python utilities")
	logLevel = globalFlags.String("log-level", "INFO",
		"Optional, logging level")
	ccclLogLevel = globalFlags.String("cccl-log-level", "",
		"Optional, logging level for cccl")
	logFile = globalFlags.String("log-file", "",
		"Optional, filepath to store the CIS logs")
	verifyInterval = globalFlags.Int("verify-interval", 30,
		"Optional, interval (in seconds) at which to verify the BIG-IP configuration.")
	nodePollInterval = globalFlags.Int("node-poll-interval", 30,
		"Optional, interval (in seconds) at which to poll for cluster nodes.")
	syncInterval = globalFlags.Int("periodic-sync-interval", 30,
		"Optional, interval (in seconds) at which to queue resources.")
	printVersion = globalFlags.Bool("version", false,
		"Optional, print version and exit.")
	httpAddress = globalFlags.String("http-listen-address", "0.0.0.0:8080",
		"Optional, address to serve http based informations (/metrics and /health).")
	disableTeems = globalFlags.Bool("disable-teems", false,
		"Optional, flag to disable sending telemetry data to TEEM")
	staticRoutingMode = globalFlags.Bool("static-routing-mode", false, "Optional, flag to enable configuration of static routes on bigip for pod network subnets")
	orchestrationCNI = globalFlags.String("orchestration-cni", "", "Optional, flag to specify orchestration CNI configured")
	sharedStaticRoutes = globalFlags.Bool("shared-static-routes", false, "Optional, flag to enable configuration of static routes on bigip in common partition")
	staticRouteNodeCIDR = globalFlags.String("static-route-node-cidr", "", "Optional, flag to specify node network cidr to be used for static routing when node has multiple interfaces.This is supported only with CNI ovn-k8s")
	// Custom Resource
	enableIPV6 = globalFlags.Bool("enable-ipv6", false,
		"Optional, flag to enbale ipv6 network support.")
	customResourceMode = globalFlags.Bool("custom-resource-mode", false,
		"Optional, When set to true, controller processes only F5 Custom Resources.")
	controllerMode = globalFlags.String("controller-mode", "",
		"Optional, to put the controller to process desired resources.")
	defaultRouteDomain = globalFlags.Int("default-route-domain", 0,
		"Optional, CIS uses this value as default Route Domain in BIG-IP ")
	routeSpecConfigmap = globalFlags.String("route-spec-configmap", "",
		"Required, specify a configmap that holds additional spec for routes"+
			" if controller-mode is 'openshift'")
	extendedSpecConfigmap = globalFlags.String("extended-spec-configmap", "",
		"Required, specify a configmap that holds additional spec for controller. It's a required parameter if controller-mode is 'openshift'")

	globalFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Global:\n%s\n", globalFlags.FlagUsagesWrapped(width))
	}

	// BigIP flags
	bigIPURL = bigIPFlags.String("bigip-url", "",
		"Required, URL for the Big-IP")
	bigIPUsername = bigIPFlags.String("bigip-username", "",
		"Required, user name for the Big-IP user account.")
	bigIPPassword = bigIPFlags.String("bigip-password", "",
		"Required, password for the Big-IP user account.")
	bigIPPartitions = bigIPFlags.StringArray("bigip-partition", []string{},
		"Required, partition(s) for the Big-IP kubernetes objects.")
	credsDir = bigIPFlags.String("credentials-directory", "",
		"Optional, directory that contains the BIG-IP username, password, and/or "+
			"url files. To be used instead of username, password, and/or url arguments.")
	as3Validation = bigIPFlags.Bool("as3-validation", true,
		"Optional, when set to false, disables as3 template validation on the controller.")
	sslInsecure = bigIPFlags.Bool("insecure", false,
		"Optional, when set to true, enable insecure SSL communication to BIGIP.")
	ipam = bigIPFlags.Bool("ipam", false,
		"Optional, when set to true, enable ipam feature for CRD.")
	ipamClusterLabel = bigIPFlags.String("ipam-cluster-label", "",
		"Optional, Valid for Infoblox IPAM provider only. Prepends the value of this label to form the key. Generally advised to use in MultiCluster Environment")
	as3PostDelay = bigIPFlags.Int("as3-post-delay", 0,
		"Optional, time (in seconds) that CIS waits to post the available AS3 declaration.")
	logAS3Response = bigIPFlags.Bool("log-as3-response", false,
		"Optional, when set to true, add the body of AS3 API response in Controller logs.")
	shareNodes = bigIPFlags.Bool("share-nodes", false,
		"Optional, when set to true, node will be shared among partition.")
	enableTLS = bigIPFlags.String("tls-version", "1.2",
		"Optional, Configure TLS version to be enabled on BIG-IP. TLS1.3 is only supported in tmos version 14.0+.")
	tls13CipherGroupReference = bigIPFlags.String("cipher-group", "/Common/f5-default",
		"Optional, Configures a Cipher Group in BIG-IP and reference it here. cipher-group and ciphers are mutually exclusive, only use one.")
	ciphers = bigIPFlags.String("ciphers", "DEFAULT", "Optional, Configures a ciphersuite selection string. cipher-group and ciphers are mutually exclusive, only use one.")
	trustedCertsCfgmap = bigIPFlags.String("trusted-certs-cfgmap", "",
		"Optional, when certificates are provided, adds them to controller'trusted certificate store.")
	// TODO: Rephrase agent functionality
	agent = bigIPFlags.String("agent", "as3",
		"Optional, when set to cccl, orchestration agent will be CCCL instead of AS3")
	ccclGtmAgent = bigIPFlags.Bool("cccl-gtm-agent", true,
		"Optional, Option to configure GTM objects using CCCL or AS3 Agent. Default Agent is CCCL.")
	overrideAS3UsageStr := "Optional, provide Namespace and Name of that ConfigMap as <namespace>/<configmap-name>." +
		"The JSON key/values from this ConfigMap will override key/values from internally generated AS3 declaration."
	overriderAS3CfgmapName = bigIPFlags.String("override-as3-declaration", "", overrideAS3UsageStr)
	filterTenants = kubeFlags.Bool("filter-tenants", false,
		"Optional, specify whether or not to use tenant filtering API for AS3 declaration")
	httpClientMetrics = bigIPFlags.Bool("http-client-metrics", false,
		"Optional, adds HTTP client metric instrumentation for the k8s-bigip-ctlr")

	bigIPFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  BigIP:\n%s\n", bigIPFlags.FlagUsagesWrapped(width))
	}

	// Kubernetes flags
	namespaces = kubeFlags.StringArray("namespace", []string{},
		"Optional, Kubernetes namespace(s) to watch."+
			"If left blank controller will watch all k8s namespaces")
	useNodeInternal = kubeFlags.Bool("use-node-internal", true,
		"Optional, provide kubernetes InternalIP addresses to pool")
	poolMemberType = kubeFlags.String("pool-member-type", "nodeport",
		"Optional, type of BIG-IP pool members to create. "+
			"'nodeport' will use k8s service NodePort. "+
			"'cluster' will use service endpoints. "+
			"The BIG-IP must be able access the cluster network"+
			"'nodeportlocal' only supported with antrea cni"+
			"'auto' will learn service type(ClusterIP/NodePort/LoadBalancer) automatically")
	inCluster = kubeFlags.Bool("running-in-cluster", true,
		"Optional, if this controller is running in a kubernetes cluster,"+
			"use the pod secrets for creating a Kubernetes client.")
	kubeConfig = kubeFlags.String("kubeconfig", "./config",
		"Optional, absolute path to the kubeconfig file")
	namespaceLabel = kubeFlags.String("namespace-label", "",
		"Optional, used to watch for namespaces with this label")
	manageRoutes = kubeFlags.Bool("manage-routes", false,
		"Optional, specify whether or not to manage Legacy Route resources  "+
			"Please use controller-mode option for NextGen Route Controller ")
	manageIngress = kubeFlags.Bool("manage-ingress", true,
		"Optional, specify whether or not to manage Ingress resources")
	manageConfigMaps = kubeFlags.Bool("manage-configmaps", true,
		"Optional, specify whether or not to manage ConfigMap resources")
	hubMode = kubeFlags.Bool("hubmode", false,
		"Optional, specify whether or not to manage ConfigMap resources in hub-mode")
	nodeLabelSelector = kubeFlags.String("node-label-selector", "",
		"Optional, used to watch only for nodes with this label")
	resolveIngNames = kubeFlags.String("resolve-ingress-names", "",
		"Optional, direct the controller to resolve host names in Ingresses into IP addresses. "+
			"The 'LOOKUP' option will use the controller's built-in DNS. "+
			"Any other string will be used as a custom DNS server, either by name or IP address.")
	defaultIngIP = kubeFlags.String("default-ingress-ip", "",
		"Optional, the controller will configure a virtual server with this IP address for "+
			"any Ingress with the annotation 'virtual-server.f5.com/ip:controller-default'.")
	vsSnatPoolName = kubeFlags.String("vs-snat-pool-name", "",
		"Optional, the controller will configure each virtual server to reference the "+
			"pool with this name.")
	useSecrets = kubeFlags.Bool("use-secrets", true,
		"Optional, enable/disable use of Secrets for Ingress or ConfigMap SSL Profiles.")
	schemaLocal = kubeFlags.String("schema-db-base-dir", "file:///app/vendor/src/f5/schemas/",
		"Optional, where the schema db's locally reside")
	// TODO once ingress extentionv1/beta1 api is deprecated we can remove this deployment parameter
	manageIngressClassOnly = kubeFlags.Bool("manage-ingress-class-only", false,
		"Optional, default `false`. Process all ingress resources without `kubernetes.io/ingress.class`"+
			"annotation and ingresses with annotation `kubernetes.io/ingress.class=f5`.")
	ingressClass = kubeFlags.String("ingress-class", "f5",
		"Optional, default `f5`. A class of the Ingress controller. The Ingress controller only processes Ingress"+
			"resources that belong to its class - i.e. have the annotation `kubernetes.io/ingress.class` equal to the class."+
			"Additionally, the Ingress controller processes Ingress resources that do not have that annotation,"+
			"which can be disabled by setting the `-manage-ingress-class-only` flag")

	// If the flag is specified with no argument, default to LOOKUP
	kubeFlags.Lookup("resolve-ingress-names").NoOptDefVal = "LOOKUP"

	kubeFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Kubernetes:\n%s\n", kubeFlags.FlagUsagesWrapped(width))
	}

	// VXLAN flags
	// FIXME(yacobucci) for now the mode cannot be provided by the user.
	// If the vxlan name is provided it will be set to "maintain" as all
	// we support is updating VTEP entries in the FDB. When we support
	// management of all network objects a flag will be added to support
	// both "maintain" and "manage".
	vxlanMode = ""
	openshiftSDNName = vxlanFlags.String("openshift-sdn-name", "",
		"Must be provided for BigIP SDN integration, "+
			"full path of BigIP OpenShift SDN VxLAN Tunnel")
	ciliumTunnelName = vxlanFlags.String("cilium-name", "",
		"Must be provided for BIGIP Cilium Integration, "+
			"full path of BigIP Cilium VxLAN Tunnel")
	flannelName = vxlanFlags.String("flannel-name", "",
		"Must be provided for BigIP Flannel integration, "+
			"full path of BigIP Flannel VxLAN Tunnel")
	vxlanFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Openshift SDN:\n%s\n", vxlanFlags.FlagUsagesWrapped(width))
	}

	// OpenShift Route flags
	routeVserverAddr = osRouteFlags.String("route-vserver-addr", "",
		"Optional, bind address for virtual server for Route objects.")
	routeLabel = osRouteFlags.String("route-label", "",
		"Optional, label for which Route objects to watch.")
	routeHttpVs = osRouteFlags.String("route-http-vserver", "ose-vserver",
		"Optional, the name to be used for the OpenShift Route http vserver")
	routeHttpsVs = osRouteFlags.String("route-https-vserver", "https-ose-vserver",
		"Optional, the name to be used for the OpenShift Route https vserver")
	clientSSL = osRouteFlags.String("default-client-ssl", "",
		"Optional, specify a user-created client ssl profile to be used as"+
			" default for SNI for Route virtual servers")
	serverSSL = osRouteFlags.String("default-server-ssl", "",
		"Optional, specify a user-created server ssl profile to be used as"+
			" default for SNI for Route virtual servers")
	osRouteFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Openshift Routes:\n%s\n", osRouteFlags.FlagUsagesWrapped(width))
	}

	// GTM Big IP flags
	gtmBigIPURL = gtmBigIPFlags.String("gtm-bigip-url", "",
		"Optional, URL for the GTM Big-IP")
	gtmBigIPUsername = gtmBigIPFlags.String("gtm-bigip-username", "",
		"Optional, user name for the GTM Big-IP user account.")
	gtmBigIPPassword = gtmBigIPFlags.String("gtm-bigip-password", "",
		"Optional, password for the GMT Big-IP user account.")
	gtmCredsDir = gtmBigIPFlags.String("gtm-credentials-directory", "",
		"Optional, directory that contains the GTM BIG-IP username, password, and/or "+
			"url files. To be used instead of username, password, and/or url arguments.")
	gtmBigIPFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  GTM:\n%s\n", gtmBigIPFlags.FlagUsagesWrapped(width))
	}

	// MultiCluster Flags
	multiClusterMode = multiClusterFlags.String("multi-cluster-mode", "",
		"Optional, determines in multi cluster env cis running as standalone/primary/secondary")

	flags.AddFlagSet(globalFlags)
	flags.AddFlagSet(bigIPFlags)
	flags.AddFlagSet(kubeFlags)
	flags.AddFlagSet(vxlanFlags)
	flags.AddFlagSet(osRouteFlags)
	flags.AddFlagSet(gtmBigIPFlags)
	flags.AddFlagSet(multiClusterFlags)

	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s\n", os.Args[0])
		globalFlags.Usage()
		bigIPFlags.Usage()
		kubeFlags.Usage()
		vxlanFlags.Usage()
		osRouteFlags.Usage()
		gtmBigIPFlags.Usage()
		multiClusterFlags.Usage()
	}
}

func initLogger(logLevel, logFile string) error {
	var logger log.Logger
	if len(logFile) > 0 {
		logger = log.NewFileLogger(logFile)
	} else {
		logger = log.NewConsoleLogger()
	}
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, logger)

	if ll := log.NewLogLevel(logLevel); nil != ll {
		if logLevel == "AS3DEBUG" {
			*logAS3Request = true
			*logAS3Response = true
		}
		log.SetLogLevel(*ll)
	} else {
		return fmt.Errorf("Unknown log level requested: %s\n"+
			"    Valid log levels are: AS3DEBUG, DEBUG, INFO, WARNING, ERROR, CRITICAL", logLevel)
	}
	return nil
}

// this is to allow for unit testing
func init() {
	_init()
}

func hasCommonPartition(partitions []string) bool {
	for _, x := range partitions {
		if x == "Common" {
			return true
		}
	}
	return false
}

func verifyTunnelArgs() error {
	var tunnelArgNames []string
	if *openshiftSDNName != "" {
		tunnelArgNames = append(tunnelArgNames, "openshift-sdn-name")
	}
	if *ciliumTunnelName != "" {
		tunnelArgNames = append(tunnelArgNames, "cilium-name")
	}
	if *flannelName != "" {
		tunnelArgNames = append(tunnelArgNames, "flannel-name")
	}
	if len(tunnelArgNames) > 1 {
		return fmt.Errorf("Cannot have %v specified", strings.Join(tunnelArgNames, ","))
	}
	return nil
}

func verifyArgs() error {
	*logLevel = strings.ToUpper(*logLevel)
	logErr := initLogger(*logLevel, *logFile)
	if nil != logErr {
		return logErr
	}

	if len(*poolMemberType) == 0 {
		return fmt.Errorf("missing pool member type")
	}

	if controller.Auto == *poolMemberType && (!*customResourceMode && *controllerMode == "") {
		return fmt.Errorf("--pool-member-type auto is supported in CRD/NextGen routes mode only")
	}

	if len(*bigIPPartitions) == 0 {
		if *agent != cisAgent.AS3Agent || !*manageConfigMaps || *manageRoutes || *manageIngress || *customResourceMode || *poolMemberType == "cluster" {
			return fmt.Errorf("missing a BIG-IP partition")
		} else {
			*disableDefaultPartition = true
		}
	} else if len(*bigIPPartitions) > 0 {
		err := hasCommonPartition(*bigIPPartitions)
		if false != err {
			return fmt.Errorf("Common cannot be one of the specified partitions.")
		}
	}

	if (len(*bigIPURL) == 0 || len(*bigIPUsername) == 0 ||
		len(*bigIPPassword) == 0) && len(*credsDir) == 0 {
		return fmt.Errorf("Missing BIG-IP credentials info")
	}

	if len(*namespaces) != 0 && len(*namespaceLabel) != 0 {
		return fmt.Errorf("Can not specify both namespace and namespace-label")
	}

	if len(*namespaces) == 0 && len(*namespaceLabel) == 0 {
		watchAllNamespaces = true
	} else {
		watchAllNamespaces = false
	}

	if *poolMemberType == "nodeport" || *poolMemberType == controller.Auto {
		isNodePort = true
	} else if *poolMemberType == "cluster" || *poolMemberType == "nodeportlocal" {
		isNodePort = false
	} else {
		return fmt.Errorf("'%v' is not a valid Pool Member Type", *poolMemberType)
	}
	if len(*extendedSpecConfigmap) > 0 {
		if len(strings.Split(*extendedSpecConfigmap, "/")) != 2 {
			return fmt.Errorf("invalid value provided for --extended-spec-configmap" +
				"Usage: --extended-spec-configmap=<namespace>/<configmap-name>")
		}
	}
	if len(*routeSpecConfigmap) > 0 {
		if len(strings.Split(*routeSpecConfigmap, "/")) != 2 {
			return fmt.Errorf("invalid value provided for --route-spec-configmap" +
				"Usage: --route-spec-configmap=<namespace>/<configmap-name>")
		}
	}

	if *multiClusterMode != "standalone" && *multiClusterMode != "primary" && *multiClusterMode != "secondary" && *multiClusterMode != "" {
		return fmt.Errorf("'%v' is not a valid multi cluster mode, allowed values are: standalone/primary/secondary", *multiClusterMode)
	} else if *multiClusterMode != "" {
		log.Infof("[MultiCluster] CIS running with multi-cluster-mode: %s", *multiClusterMode)
	}

	if (len(*routeSpecConfigmap) == 0 && len(*extendedSpecConfigmap) == 0) && *multiClusterMode != "" {
		return fmt.Errorf("missing --extended-spec-configmap parameter in the multiCluster mode. It's a required parameter in multiCluster mode")
	}

	if *staticRoutingMode == true {
		if (isNodePort || *poolMemberType == "nodeportlocal") && *poolMemberType != controller.Auto {
			return fmt.Errorf("Cannot run NodePort mode or nodeportlocal mode while supplying static-routing-mode true " +
				"Must be in Cluster mode if using static route configuration.")
		}
		if len(*openshiftSDNName) > 0 || len(*ciliumTunnelName) > 0 || len(*flannelName) > 0 {
			return fmt.Errorf("Cannot have openshift-sdn-name or cilium-name or flannel-name as static route processing doesnt require tunnel " +
				"configuration.")
		}
	}
	//Verify Tunnel parameters list provided
	err := verifyTunnelArgs()
	if nil != err {
		return fmt.Errorf("%v", err)
	}

	if flags.Changed("openshift-sdn-name") {
		if len(*openshiftSDNName) == 0 && *staticRoutingMode == false {
			return fmt.Errorf("Missing required parameter openshift-sdn-name")
		}
		if isNodePort && *poolMemberType != controller.Auto {
			return fmt.Errorf("Cannot run NodePort mode while supplying openshift-sdn-name. " +
				"Must be in Cluster mode if using VXLAN.")
		}
		vxlanMode = "maintain"
		vxlanName = *openshiftSDNName
	} else if flags.Changed("flannel-name") || flags.Changed("cilium-name") {
		if flags.Changed("flannel-name") && len(*flannelName) == 0 && *staticRoutingMode == false {
			return fmt.Errorf("Missing required parameter flannel-name")
		}
		if flags.Changed("cilium-name") && len(*ciliumTunnelName) == 0 && *staticRoutingMode == false {
			return fmt.Errorf("Missing required parameter cilium-name")
		}
		if *poolMemberType != controller.Auto && isNodePort {
			return fmt.Errorf("Cannot run NodePort mode while supplying cilium-name or flannel-name. " +
				"Must be in Cluster mode if using VXLAN.")
		}
		vxlanMode = "maintain"
		vxlanName = *flannelName
		if len(*ciliumTunnelName) > 0 {
			vxlanName = *ciliumTunnelName
		}
	}

	if *hubMode && !(*manageConfigMaps) {
		return fmt.Errorf("Hubmode is supported only for configmaps")
	}
	if *manageRoutes && *controllerMode == "" {
		if len(*routeVserverAddr) == 0 {
			return fmt.Errorf("Missing required parameter route-vserver-addr")
		}
	}
	if *overriderAS3CfgmapName != "" {
		if len(strings.Split(*overriderAS3CfgmapName, "/")) != 2 {
			return fmt.Errorf("Invalid value provided for --override-as3-declaration" +
				"Usage: --override-as3-declaration=<namespace>/<configmap-name>")
		}
	}
	switch *controllerMode {
	case "",
		string(controller.CustomResourceMode),
		string(controller.KubernetesMode):
		break
	case string(controller.OpenShiftMode):
		if len(*extendedSpecConfigmap) == 0 && len(*routeSpecConfigmap) == 0 {
			return fmt.Errorf("--route-spec-configmap or --extended-spec-configmap parameter is required in openshift mode\n" +
				"Usage: --route-spec-configmap=<namespace>/<configmap-name> or --extended-spec-configmap=<namespace>/<configmap-name>")
		}
		if len(*routeLabel) > 0 {
			*routeLabel = fmt.Sprintf("f5type in (%s)", *routeLabel)
		}
	default:
		return fmt.Errorf("invalid controller-mode is provided")
	}
	return nil
}

func getCredentials() error {
	if len(*credsDir) > 0 {
		var usr, pass, bigipURL string
		var err error
		if strings.HasSuffix(*credsDir, "/") {
			usr = *credsDir + "username"
			pass = *credsDir + "password"
			bigipURL = *credsDir + "url"
		} else {
			usr = *credsDir + "/username"
			pass = *credsDir + "/password"
			bigipURL = *credsDir + "/url"
		}

		setField := func(field *string, filename, fieldType string) error {
			fileBytes, readErr := ioutil.ReadFile(filename)
			if readErr != nil {
				log.Debug(fmt.Sprintf(
					"No %s in credentials directory, falling back to CLI argument", fieldType))
				if len(*field) == 0 {
					return fmt.Errorf(fmt.Sprintf("BIG-IP %s not specified", fieldType))
				}
			} else {
				*field = strings.TrimSpace(string(fileBytes))
			}
			return nil
		}

		err = setField(bigIPUsername, usr, "username")
		if err != nil {
			return err
		}
		err = setField(bigIPPassword, pass, "password")
		if err != nil {
			return err
		}
		err = setField(bigIPURL, bigipURL, "url")
		if err != nil {
			return err
		}
	}
	// Verify URL is valid
	if !strings.HasPrefix(*bigIPURL, "https://") {
		*bigIPURL = "https://" + *bigIPURL
	}
	u, err := url.Parse(*bigIPURL)
	if nil != err {
		return fmt.Errorf("Error parsing url: %s", err)
	}
	if len(u.Path) > 0 && u.Path != "/" {
		return fmt.Errorf("BIGIP-URL path must be empty or '/'; check URL formatting and/or remove %s from path",
			u.Path)
	}
	return nil
}

func getGTMCredentials() {
	if len(*gtmCredsDir) > 0 {
		var usr, pass, gtmBigipURL string
		if strings.HasSuffix(*gtmCredsDir, "/") {
			usr = *gtmCredsDir + "username"
			pass = *gtmCredsDir + "password"
			gtmBigipURL = *gtmCredsDir + "url"
		} else {
			usr = *gtmCredsDir + "/username"
			pass = *gtmCredsDir + "/password"
			gtmBigipURL = *gtmCredsDir + "/url"
		}

		setField := func(field *string, filename, fieldType string) {
			fileBytes, readErr := ioutil.ReadFile(filename)
			if readErr != nil {
				log.Debug(fmt.Sprintf(
					"No %s in credentials directory, falling back to CLI argument", fieldType))
				if len(*field) == 0 {
					log.Errorf(fmt.Sprintf("GTM BIG-IP %s not specified", fieldType))
				}
			} else {
				*field = string(fileBytes)
			}
		}

		setField(gtmBigIPUsername, usr, "username")
		setField(gtmBigIPPassword, pass, "password")
		setField(gtmBigIPURL, gtmBigipURL, "url")
	}

	// Verify URL is valid
	if !strings.HasPrefix(*gtmBigIPURL, "https://") {
		log.Debug("[DEBUG] Adding https at the beginning of the GTM BIG IP URL as it does not start with https.")
		*gtmBigIPURL = "https://" + *gtmBigIPURL
	}
	u, err := url.Parse(*gtmBigIPURL)
	if nil != err {
		log.Errorf("Error parsing url: %s", err)
	}
	if len(u.Path) > 0 && u.Path != "/" {
		log.Errorf("GTM BIGIP-URL path must be empty or '/'; check URL formatting and/or remove %s from path",
			u.Path)
	}
}

func createLabel(label string) (labels.Selector, error) {
	var l labels.Selector
	var err error
	if label == "" {
		l = labels.Everything()
	} else {
		l, err = labels.Parse(label)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Label Selector string: %v", err)
		}
	}
	return l, nil
}

// Get Namespaces we are watching to know the vsQueue Length
func GetNamespaces(appMgr *appmanager.Manager) {
	if len(*namespaces) != 0 && len(*namespaceLabel) == 0 {
		appMgr.WatchedNS.Namespaces = *namespaces
	}
	if len(*namespaces) == 0 && len(*namespaceLabel) != 0 {
		appMgr.WatchedNS.NamespaceLabel = *namespaceLabel
	}
}

// setup the initial watch based off the flags passed in, if no flags then we
// watch all namespaces
func setupWatchers(appMgr *appmanager.Manager, resyncPeriod time.Duration) {
	label := resource.DefaultConfigMapLabel

	err := appMgr.AddNodeInformer(resyncPeriod)
	if nil != err {
		log.Warningf("[INIT] Failed to add node informer for the controller:%v", err)
	}
	if len(*namespaceLabel) == 0 {
		// For periodic monitoring
		// Non monitoring namespaces will not be processed
		ls, err := createLabel("")
		if nil != err {
			log.Warningf("[INIT] Failed to create label selector: %v", err)
		}
		err = appMgr.AddNamespaceLabelInformer(ls, resyncPeriod)
		if nil != err {
			log.Warningf("[INIT] Failed to add label watch for all namespaces:%v", err)
		}
		ls, err = createLabel(label)
		if nil != err {
			log.Warningf("[INIT] Failed to create label selector: %v", err)
		}
		if watchAllNamespaces == true {
			err = appMgr.AddNamespace("", ls, resyncPeriod)
			if nil != err {
				log.Warningf("[INIT] Failed to add informers for all namespaces:%v", err)
			}
		} else {
			for _, namespace := range *namespaces {
				err = appMgr.AddNamespace(namespace, ls, resyncPeriod)
				if nil != err {
					log.Warningf("[INIT] Failed to add informers for namespace %v: %v", namespace, err)
				} else {
					log.Debugf("[INIT] Added informers for namespace %v", namespace)
				}
			}
		}
	} else {
		ls, err := createLabel(*namespaceLabel)
		if nil != err {
			log.Warningf("[INIT] Failed to create label selector: %v", err)
		}
		err = appMgr.AddNamespaceLabelInformer(ls, resyncPeriod)
		if nil != err {
			log.Warningf("[INIT] Failed to add label watch for all namespaces:%v", err)
		}
		appMgr.DynamicNS = true
	}
}

func initController(
	config *rest.Config,
) *controller.Controller {
	postMgrParams := controller.PostParams{
		BIGIPUsername:     *bigIPUsername,
		BIGIPPassword:     *bigIPPassword,
		BIGIPURL:          *bigIPURL,
		TrustedCerts:      "",
		SSLInsecure:       *sslInsecure,
		AS3PostDelay:      *as3PostDelay,
		LogAS3Response:    *logAS3Response,
		LogAS3Request:     *logAS3Request,
		HTTPClientMetrics: *httpClientMetrics,
	}

	GtmParams := controller.PostParams{
		BIGIPUsername:     *gtmBigIPUsername,
		BIGIPPassword:     *gtmBigIPPassword,
		BIGIPURL:          *gtmBigIPURL,
		TrustedCerts:      "",
		SSLInsecure:       *sslInsecure,
		AS3PostDelay:      *as3PostDelay,
		LogAS3Response:    *logAS3Response,
		LogAS3Request:     *logAS3Request,
		HTTPClientMetrics: *httpClientMetrics,
	}

	if *trustedCertsCfgmap != "" {
		postMgrParams.TrustedCerts = getBIGIPTrustedCerts()
		GtmParams.TrustedCerts = getBIGIPTrustedCerts()
	}
	agentParams := controller.AgentParams{
		PostParams:         postMgrParams,
		GTMParams:          GtmParams,
		Partition:          (*bigIPPartitions)[0],
		LogLevel:           *logLevel,
		VerifyInterval:     *verifyInterval,
		VXLANName:          vxlanName,
		PythonBaseDir:      *pythonBaseDir,
		UserAgent:          userAgentInfo,
		HttpAddress:        *httpAddress,
		EnableIPV6:         *enableIPV6,
		CCCLGTMAgent:       *ccclGtmAgent,
		StaticRoutingMode:  *staticRoutingMode,
		SharedStaticRoutes: *sharedStaticRoutes,
		MultiClusterMode:   *multiClusterMode,
	}

	agentParams.DisableARP = true
	// enable arp only for flannel CNI
	if *flannelName != "" {
		agentParams.DisableARP = false
	}

	agent := controller.NewAgent(agentParams)

	var globalSpecConfigMap *string
	if *extendedSpecConfigmap != "" {
		globalSpecConfigMap = extendedSpecConfigmap
	} else {
		globalSpecConfigMap = routeSpecConfigmap
	}

	ctlr := controller.NewController(
		controller.Params{
			Config:                      config,
			Namespaces:                  *namespaces,
			NamespaceLabel:              *namespaceLabel,
			Partition:                   (*bigIPPartitions)[0],
			Agent:                       agent,
			PoolMemberType:              *poolMemberType,
			VXLANName:                   vxlanName,
			VXLANMode:                   vxlanMode,
			CiliumTunnelName:            *ciliumTunnelName,
			UseNodeInternal:             *useNodeInternal,
			NodePollInterval:            *nodePollInterval,
			NodeLabelSelector:           *nodeLabelSelector,
			IPAM:                        *ipam,
			IPAMClusterLabel:            *ipamClusterLabel,
			ShareNodes:                  *shareNodes,
			DefaultRouteDomain:          *defaultRouteDomain,
			Mode:                        controller.ControllerMode(*controllerMode),
			GlobalExtendedSpecConfigmap: *globalSpecConfigMap,
			RouteLabel:                  *routeLabel,
			StaticRoutingMode:           *staticRoutingMode,
			OrchestrationCNI:            *orchestrationCNI,
			StaticRouteNodeCIDR:         *staticRouteNodeCIDR,
			MultiClusterMode:            *multiClusterMode,
		},
		true,
	)

	return ctlr
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()
	err := flags.Parse(os.Args)
	if nil != err {
		os.Exit(1)
	}

	if *printVersion {
		fmt.Printf("Version: %s\nBuild: %s\n", version, buildInfo)
		os.Exit(0)
	}

	err = verifyArgs()
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		flags.Usage()
		os.Exit(1)
	}
	err = getCredentials()
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		flags.Usage()
		os.Exit(1)
	}

	log.Infof("[INIT] Starting: Container Ingress Services - Version: %s, BuildInfo: %s", version, buildInfo)
	// add the warning if both extended-config-map & route-config-map are present
	if len(*routeSpecConfigmap) > 0 && len(*extendedSpecConfigmap) > 0 {
		log.Warningf("extended-spec-configmap and route-spec-configmap both are present. extended-spec-configmap will be given priority over route-spec-configmap")
	}
	if len(*bigIPPartitions) > 0 {
		resource.DEFAULT_PARTITION = (*bigIPPartitions)[0]
	}
	dgPath = resource.DEFAULT_PARTITION
	if strings.ToLower(*agent) == "as3" {
		*agent = "as3"
		dgPath = strings.Join([]string{resource.DEFAULT_PARTITION, "Shared"}, "/")
	}
	appmanager.RegisterBigIPSchemaTypes()

	// If running with Flannel, create an event channel that the appManager
	// uses to send endpoints to the VxlanManager
	if len(*ciliumTunnelName) > 0 || len(*flannelName) > 0 {
		eventChan = make(chan interface{})
	}

	// If running in VXLAN mode, extract the partition name from the tunnel
	// to be used in configuring a net instance of CCCL for that partition
	var vxlanPartition string
	if len(vxlanName) > 0 {
		cleanPath := strings.TrimLeft(vxlanName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos == -1 {
			// No partition
			vxlanPartition = "Common"
		} else {
			// Partition and name
			vxlanPartition = cleanPath[:slashPos]
		}
	}
	if *staticRoutingMode == true {
		//partition provide through args
		vxlanPartition = (*bigIPPartitions)[0]
		if *sharedStaticRoutes == true {
			vxlanPartition = "Common"
		}
	}
	config, err := getKubeConfig()
	if err != nil {
		os.Exit(1)
	}

	kubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("[INIT] error connecting to the client: %v", err)
		os.Exit(1)
	}
	userAgentInfo = getUserAgentInfo()
	td := &teem.TeemsData{
		CisVersion:      version,
		Agent:           *agent,
		PoolMemberType:  *poolMemberType,
		PlatformInfo:    userAgentInfo,
		DateOfCISDeploy: time.Now().UTC().Format(time.RFC3339Nano),
		AccessEnabled:   true,
		ResourceType: teem.ResourceTypes{
			Ingresses:       make(map[string]int),
			Routes:          make(map[string]int),
			Configmaps:      make(map[string]int),
			VirtualServer:   make(map[string]int),
			TransportServer: make(map[string]int),
			ExternalDNS:     make(map[string]int),
			IngressLink:     make(map[string]int),
			IPAMVS:          make(map[string]int),
			IPAMTS:          make(map[string]int),
			IPAMSvcLB:       make(map[string]int),
			NativeRoutes:    make(map[string]int),
			RouteGroups:     make(map[string]int),
		},
	}
	if !(*disableTeems) {
		td.SDNType = getSDNType(config)
		// Post telemetry data request
		//if !td.PostTeemsData() {
		//	td.AccessEnabled = false
		//	log.Error("Unable to post data to TEEM server. Restart CIS once firewall rules permit")
		//}
	} else {
		td.AccessEnabled = false
		log.Debug("Telemetry data reporting to TEEM server is disabled")
	}

	if *customResourceMode || *controllerMode != "" {
		getGTMCredentials()
		ctlr := initController(config)
		ctlr.TeemData = td
		if !(*disableTeems) {
			key, err := ctlr.Agent.GetBigipRegKey()
			if err != nil {
				log.Errorf("%v", err)
			}
			ctlr.TeemData.Lock()
			ctlr.TeemData.RegistrationKey = key
			ctlr.TeemData.Unlock()
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigs
		ctlr.Stop()
		log.Infof("Exiting - signal %v\n", sig)
		return
	}

	// When CIS configured as AS3 agent disable LTM in globalSection
	disableLTM := false
	if *agent == cisAgent.AS3Agent {
		disableLTM = true
	}
	// When CIS configured in OCP cluster mode disable ARP in globalSection
	disableARP := false
	if *openshiftSDNName != "" || *staticRoutingMode == true || *poolMemberType == "nodeport" || *poolMemberType == "nodeportlocal" {
		disableARP = true
	}

	// Python driver disable for the nodeport and nodeportlocal mode
	if *poolMemberType == "cluster" || !disableLTM {
		gs := globalSection{
			LogLevel:          *logLevel,
			VerifyInterval:    *verifyInterval,
			VXLANPartition:    vxlanPartition,
			DisableLTM:        disableLTM,
			DisableARP:        disableARP,
			StaticRoutingMode: *staticRoutingMode,
		}
		// If AS3DEBUG is set, set log level to DEBUG
		if gs.LogLevel == "AS3DEBUG" {
			gs.LogLevel = "DEBUG"
		}
		if *ccclLogLevel != "" {
			gs.LogLevel = *ccclLogLevel
		}
		bs := bigIPSection{
			BigIPUsername:   *bigIPUsername,
			BigIPPassword:   *bigIPPassword,
			BigIPURL:        *bigIPURL,
			BigIPPartitions: *bigIPPartitions,
		}

		subPidCh, err := startPythonDriver(getConfigWriter(), gs, bs, *pythonBaseDir)
		if nil != err {
			log.Fatalf("Could not initialize subprocess configuration: %v", err)
		}
		subPid := <-subPidCh
		defer func(pid int) {
			if 0 != pid {
				var proc *os.Process
				proc, err = os.FindProcess(pid)
				if nil != err {
					log.Warningf("Failed to find sub-process on exit: %v", err)
				}
				err = proc.Signal(os.Interrupt)
				if nil != err {
					log.Warningf("Could not stop sub-process on exit: %d - %v", pid, err)
				}
			}
		}(subPid)

		// Add health check e.g. is Python process still there?
		hc := &health.HealthChecker{
			SubPID: subPid,
		}
		http.Handle("/health", hc.HealthCheckHandler())
	} else { // a new health checker for nodeport and nodeportlocal mode for AS3
		hc := &health.HealthChecker{}
		http.Handle("/health", hc.CISHealthCheckHandler(kubeClient))
	}

	if _, isSet := os.LookupEnv("SCALE_PERF_ENABLE"); isSet {
		now := time.Now()
		log.Infof("[INIT] SCALE_PERF: Started controller at: %d", now.Unix())
	}

	if len(*routeLabel) > 0 {
		*routeLabel = fmt.Sprintf("f5type in (%s)", *routeLabel)
	}

	agRspChan = make(chan interface{}, 1)
	appMgrParms := getAppManagerParams()

	// creates the clientset
	appMgrParms.KubeClient = kubeClient
	if *manageRoutes && *controllerMode == "" {
		var rclient *routeclient.RouteV1Client
		rclient, err = routeclient.NewForConfig(config)
		if nil != err {
			log.Fatalf("[INIT] unable to create route client: err: %+v\n", err)
		}
		appMgrParms.RouteClientV1 = rclient
	}

	appMgr := appmanager.NewManager(&appMgrParms)
	GetNamespaces(appMgr)

	// Agent Initialization
	log.Infof("[INIT] Creating Agent for %v", *agent)
	appMgr.AgentCIS, err = cisAgent.CreateAgent(*agent)
	if err != nil {
		log.Fatalf("[INIT] unable to create agent %v error: err: %+v\n", *agent, err)
		os.Exit(1)
	}

	if err = appMgr.AgentCIS.Init(getAgentParams(*agent)); err != nil {
		log.Fatalf("[INIT] Failed to initialize %v agent, %+v\n", *agent, err)
		os.Exit(1)
	}
	defer appMgr.AgentCIS.DeInit()

	if *filterTenants {
		appMgr.AgentCIS.Clean(resource.DEFAULT_PARTITION)
	}
	if *agent == cisAgent.AS3Agent && !(*disableTeems) {
		key := appMgr.AgentCIS.GetBigipRegKey()
		td.RegistrationKey = key
	}
	appMgr.TeemData = td
	GetNamespaces(appMgr)

	setupWatchers(appMgr, time.Duration(*syncInterval)*time.Second)
	// Expose Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())

	bigIPPrometheus.RegisterMetrics(*httpClientMetrics)
	go func() {
		log.Fatal(http.ListenAndServe(*httpAddress, nil).Error())
	}()

	stopCh := make(chan struct{})

	appMgr.Run(stopCh)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	close(stopCh)
	log.Infof("[INIT] Exiting - signal %v\n", sig)
	log.Close()
}

func getConfigWriter() writer.Writer {
	if configWriter == nil {
		var err error
		configWriter, err = writer.NewConfigWriter()
		if nil != err {
			log.Fatalf("[INIT] Failed creating ConfigWriter tool: %v", err)
			os.Exit(1)
		}
	}
	return configWriter
}

func getRouteConfig() appmanager.RouteConfig {
	return appmanager.RouteConfig{
		RouteVSAddr: *routeVserverAddr,
		RouteLabel:  *routeLabel,
		HttpVs:      *routeHttpVs,
		HttpsVs:     *routeHttpsVs,
		ClientSSL:   *clientSSL,
		ServerSSL:   *serverSSL,
	}
}

func getAppManagerParams() appmanager.Params {
	return appmanager.Params{
		UseNodeInternal:        *useNodeInternal,
		IsNodePort:             isNodePort,
		RouteConfig:            getRouteConfig(),
		NodeLabelSelector:      *nodeLabelSelector,
		ResolveIngress:         *resolveIngNames,
		DefaultIngIP:           *defaultIngIP,
		VsSnatPoolName:         *vsSnatPoolName,
		UseSecrets:             *useSecrets,
		ManageConfigMaps:       *manageConfigMaps,
		ManageIngress:          *manageIngress,
		ManageIngressClassOnly: *manageIngressClassOnly,
		HubMode:                *hubMode,
		IngressClass:           *ingressClass,
		TrustedCertsCfgmap:     *trustedCertsCfgmap,
		DgPath:                 dgPath,
		AgRspChan:              agRspChan,
		SchemaLocal:            *schemaLocal,
		ProcessAgentLabels:     getProcessAgentLabelFunc(),
		DefaultRouteDomain:     *defaultRouteDomain,
		PoolMemberType:         *poolMemberType,
		Agent:                  *agent,
		VXLANMode:              vxlanMode,
		VXLANName:              vxlanName,
		CiliumTunnelName:       *ciliumTunnelName,
		EventChan:              eventChan,
		ConfigWriter:           getConfigWriter(),
		StaticRoutingMode:      *staticRoutingMode,
		OrchestrationCNI:       *orchestrationCNI,
		StaticRouteNodeCIDR:    *staticRouteNodeCIDR,
	}
}

func getAgentParams(agent string) interface{} {
	var params interface{}
	switch agent {
	case cisAgent.AS3Agent:
		params = getAS3Params()
	case cisAgent.CCCLAgent:
		params = getCCCLParams()
	}
	return params
}

func getAS3Params() *as3.Params {
	return &as3.Params{
		SchemaLocal:               *schemaLocal,
		AS3Validation:             *as3Validation,
		EnableTLS:                 *enableTLS,
		TLS13CipherGroupReference: *tls13CipherGroupReference,
		Ciphers:                   *ciphers,
		OverriderCfgMapName:       *overriderAS3CfgmapName,
		FilterTenants:             *filterTenants,
		BIGIPUsername:             *bigIPUsername,
		BIGIPPassword:             *bigIPPassword,
		BIGIPURL:                  *bigIPURL,
		TrustedCerts:              getBIGIPTrustedCerts(),
		SSLInsecure:               *sslInsecure,
		IPAM:                      *ipam,
		AS3PostDelay:              *as3PostDelay,
		LogAS3Response:            *logAS3Response,
		LogAS3Request:             *logAS3Request,
		ShareNodes:                *shareNodes,
		RspChan:                   agRspChan,
		UserAgent:                 userAgentInfo,
		ConfigWriter:              getConfigWriter(),
		EventChan:                 eventChan,
		DefaultRouteDomain:        *defaultRouteDomain,
		PoolMemberType:            *poolMemberType,
		HTTPClientMetrics:         *httpClientMetrics,
		DisableDefaultPartition:   *disableDefaultPartition,
	}
}

func getCCCLParams() *cccl.Params {
	return &cccl.Params{
		ConfigWriter: getConfigWriter(),
		EventChan:    eventChan,
		// ToDo: Remove this post 2.2 release
		BIGIPUsername: *bigIPUsername,
		BIGIPPassword: *bigIPPassword,
		BIGIPURL:      *bigIPURL,
		TrustedCerts:  getBIGIPTrustedCerts(),
		SSLInsecure:   *sslInsecure,
	}
}

func getKubeConfig() (*rest.Config, error) {
	var config *rest.Config
	var err error
	if *inCluster {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeConfig)
	}
	if err != nil {
		log.Fatalf("[INIT] error creating configuration: %v", err)
		return nil, err
	}

	// creates the clientset
	return config, nil
}

// Read certificate from configmap
func getBIGIPTrustedCerts() string {
	namespaceCfgmapSlice := strings.Split(*trustedCertsCfgmap, "/")
	if len(namespaceCfgmapSlice) != 2 {
		log.Debugf("[INIT] Invalid trusted-certs-cfgmap option provided.")
		return ""
	}

	cm, err := getConfigMapUsingNamespaceAndName(namespaceCfgmapSlice[0], namespaceCfgmapSlice[1])
	if err != nil {
		log.Errorf("[INIT] ConfigMap with name %v not found in namespace: %v, error: %v",
			namespaceCfgmapSlice[1], namespaceCfgmapSlice[0], err)
		os.Exit(1)
	}

	var certs string
	// Fetch all certificates from configmap
	for _, v := range cm.Data {
		certs += v + "\n"
	}
	return certs
}

func getConfigMapUsingNamespaceAndName(cfgMapNamespace, cfgMapName string) (*v1.ConfigMap, error) {
	cfgMap, err := kubeClient.CoreV1().ConfigMaps(cfgMapNamespace).Get(context.TODO(), cfgMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return cfgMap, err
}

func getProcessAgentLabelFunc() func(map[string]string, string, string) bool {
	switch *agent {
	case cisAgent.AS3Agent:
		return func(m map[string]string, n, ns string) bool {
			funCMapOptions := func(cfg string) bool {
				if cfg == "" {
					return true
				}
				c := strings.Split(cfg, "/")
				if len(c) == 2 {
					if n == c[1] && ns == c[0] {
						return true
					}
					return false
				}
				return true
			}
			if m["overrideAS3"] == "true" || m["overrideAS3"] == "false" {
				return funCMapOptions(*overriderAS3CfgmapName)
			} else if m["as3"] == "true" || m["as3"] == "false" {
				return true
			}
			return false
		}

	case cisAgent.CCCLAgent:
		return func(m map[string]string, n, ns string) bool {
			if _, ok := m["as3"]; ok {
				return false
			} // Ignore AS3 Cfgmap
			return true
		}
	}
	return nil
}

// Get platform info for TEEM
func getUserAgentInfo() string {
	var versionInfo map[string]string
	var err error
	var vInfo []byte
	rc := kubeClient.Discovery().RESTClient()
	// support for ocp < 3.11
	if vInfo, err = rc.Get().AbsPath(versionPathOpenshiftv3).DoRaw(context.TODO()); err == nil {
		if err = json.Unmarshal(vInfo, &versionInfo); err == nil {
			return fmt.Sprintf("CIS/v%v OCP/%v", version, versionInfo["gitVersion"])
		}
	} else if vInfo, err = rc.Get().AbsPath(versionPathOpenshiftv4).DoRaw(context.TODO()); err == nil {
		// support ocp > 4.0
		var ocp4 Ocp4Version
		if er := json.Unmarshal(vInfo, &ocp4); er == nil {
			if len(ocp4.Status.History) > 0 {
				return fmt.Sprintf("CIS/v%v OCP/v%v", version, ocp4.Status.History[0].Version)
			}
			return fmt.Sprintf("CIS/v%v OCP/v4.0.0", version)
		}
	} else if vInfo, err = rc.Get().AbsPath(versionPathk8s).DoRaw(context.TODO()); err == nil {
		// support k8s
		if er := json.Unmarshal(vInfo, &versionInfo); er == nil {
			return fmt.Sprintf("CIS/v%v K8S/%v", version, versionInfo["gitVersion"])
		}
	}
	log.Warningf("Unable to fetch user agent details. %v", err)
	return fmt.Sprintf("CIS/v%v", version)
}

func getSDNType(config *rest.Config) string {
	var sdnType string
	if isNodePort && *poolMemberType != controller.Auto {
		sdnType = "nodeport-mode"
	} else {
		if *poolMemberType == "nodeportlocal" {
			sdnType = "antrea"
		} else if *orchestrationCNI != "" {
			switch *orchestrationCNI {
			case "cilium-k8s":
				sdnType = "cilium"
			default:
				sdnType = *orchestrationCNI
			}
		} else if len(*openshiftSDNName) > 0 {
			rconfigclient, err := configclient.NewForConfig(config)
			if nil != err {
				log.Errorf("unable to create route config client: err: %+v\n", err)
				return "openshiftSDN"
			}
			sdnType = setSDNTypeForOpenshift(rconfigclient)
		} else if len(*ciliumTunnelName) > 0 {
			sdnType = "cilium"
		} else if len(*flannelName) > 0 {
			sdnType = "flannel"
		} else if *staticRoutingMode {
			sdnType = "staticRoutingMode"
		} else {
			sdnType = "other"
		}

		if *poolMemberType == controller.Auto {
			sdnType = "auto - " + sdnType
		}
	}
	return sdnType
}

func setSDNTypeForOpenshift(rconfigclient *configclient.ConfigV1Client) string {
	networks, err := rconfigclient.Networks().List(context.TODO(), metav1.ListOptions{})
	if nil != err {
		log.Errorf("unable to list networks: err: %+v\n", err)
	}
	if len(networks.Items) > 0 {
		// Putting the first item in the network list
		if strings.ToLower(networks.Items[0].Status.NetworkType) != "openshiftsdn" {
			return networks.Items[0].Status.NetworkType
		}
	}
	return "openshiftSDN"
}
