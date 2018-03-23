/*-
 * Copyright (c) 2017,2018, F5 Networks, Inc.
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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/health"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/pkg/prometheus"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/vxlan"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	clog "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger/console"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/apimachinery/pkg/labels"

	routeclient "github.com/openshift/origin/pkg/client"
	// The import below is required to register the RouteList and Route types.
	_ "github.com/openshift/origin/pkg/route/api/install"
)

type globalSection struct {
	LogLevel       string `json:"log-level,omitempty"`
	VerifyInterval int    `json:"verify-interval,omitempty"`
	VXLANPartition string `json:"vxlan-partition,omitempty"`
}

type bigIPSection struct {
	BigIPUsername   string   `json:"username,omitempty"`
	BigIPPassword   string   `json:"password,omitempty"`
	BigIPURL        string   `json:"url,omitempty"`
	BigIPPartitions []string `json:"partitions,omitempty"`
}

var (
	// To be set by build
	version   string
	buildInfo string

	// Flag sets and supported flags
	flags        *pflag.FlagSet
	globalFlags  *pflag.FlagSet
	bigIPFlags   *pflag.FlagSet
	kubeFlags    *pflag.FlagSet
	vxlanFlags   *pflag.FlagSet
	osRouteFlags *pflag.FlagSet

	pythonBaseDir    *string
	logLevel         *string
	verifyInterval   *int
	nodePollInterval *int
	printVersion     *bool
	httpAddress      *string

	namespaces        *[]string
	useNodeInternal   *bool
	poolMemberType    *string
	inCluster         *bool
	kubeConfig        *string
	namespaceLabel    *string
	manageRoutes      *bool
	nodeLabelSelector *string
	resolveIngNames   *string
	defaultIngIP      *string
	vsSnatPoolName    *string
	useSecrets        *bool
	schemaLocal       *string

	bigIPURL        *string
	bigIPUsername   *string
	bigIPPassword   *string
	bigIPPartitions *[]string

	vxlanMode        string
	openshiftSDNName *string
	flannelName      *string

	routeVserverAddr *string
	routeLabel       *string
	routeHttpVs      *string
	routeHttpsVs     *string
	clientSSL        *string
	serverSSL        *string

	// package variables
	isNodePort         bool
	watchAllNamespaces bool
	vxlanName          string
)

func _init() {
	flags = pflag.NewFlagSet("main", pflag.ContinueOnError)
	globalFlags = pflag.NewFlagSet("Global", pflag.ContinueOnError)
	bigIPFlags = pflag.NewFlagSet("BigIP", pflag.ContinueOnError)
	kubeFlags = pflag.NewFlagSet("Kubernetes", pflag.ContinueOnError)
	vxlanFlags = pflag.NewFlagSet("VXLAN", pflag.ContinueOnError)
	osRouteFlags = pflag.NewFlagSet("OpenShift Routes", pflag.ContinueOnError)

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

	// Global flags
	pythonBaseDir = globalFlags.String("python-basedir", "",
		"DEPRECATED: Optional, directory location of python utilities")
	logLevel = globalFlags.String("log-level", "INFO",
		"Optional, logging level")
	verifyInterval = globalFlags.Int("verify-interval", 30,
		"Optional, interval (in seconds) at which to verify the BIG-IP configuration.")
	nodePollInterval = globalFlags.Int("node-poll-interval", 30,
		"Optional, interval (in seconds) at which to poll for cluster nodes.")
	printVersion = globalFlags.Bool("version", false,
		"Optional, print version and exit.")
	httpAddress = globalFlags.String("http-listen-address", "0.0.0.0:8080",
		"Optional, address to serve http based informations (/metrics and /health).")

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
			"The BIG-IP must be able access the cluster network")
	inCluster = kubeFlags.Bool("running-in-cluster", true,
		"Optional, if this controller is running in a kubernetes cluster,"+
			"use the pod secrets for creating a Kubernetes client.")
	kubeConfig = kubeFlags.String("kubeconfig", "./config",
		"Optional, absolute path to the kubeconfig file")
	namespaceLabel = kubeFlags.String("namespace-label", "",
		"Optional, used to watch for namespaces with this label")
	manageRoutes = kubeFlags.Bool("manage-routes", false,
		"Optional, specify whether or not to manage Route resources")
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

	flags.AddFlagSet(globalFlags)
	flags.AddFlagSet(bigIPFlags)
	flags.AddFlagSet(kubeFlags)
	flags.AddFlagSet(vxlanFlags)
	flags.AddFlagSet(osRouteFlags)

	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s\n", os.Args[0])
		globalFlags.Usage()
		bigIPFlags.Usage()
		kubeFlags.Usage()
		vxlanFlags.Usage()
		osRouteFlags.Usage()
	}
}

func initLogger(logLevel string) error {
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, clog.NewConsoleLogger())

	if ll := log.NewLogLevel(logLevel); nil != ll {
		log.SetLogLevel(*ll)
	} else {
		return fmt.Errorf("Unknown log level requested: %s\n"+
			"    Valid log levels are: DEBUG, INFO, WARNING, ERROR, CRITICAL", logLevel)
	}
	return nil
}

// this is to allow for unit testing
func init() {
	_init()
}

func verifyArgs() error {
	*logLevel = strings.ToUpper(*logLevel)
	logErr := initLogger(*logLevel)
	if nil != logErr {
		return logErr
	}

	if len(*bigIPURL) == 0 || len(*bigIPUsername) == 0 || len(*bigIPPassword) == 0 ||
		len(*bigIPPartitions) == 0 || len(*poolMemberType) == 0 {
		return fmt.Errorf("Missing required parameter")
	}

	if len(*namespaces) != 0 && len(*namespaceLabel) != 0 {
		return fmt.Errorf("Can not specify both namespace and namespace-label")
	}

	if len(*namespaces) == 0 && len(*namespaceLabel) == 0 {
		watchAllNamespaces = true
	} else {
		watchAllNamespaces = false
	}

	u, err := url.Parse(*bigIPURL)
	if nil != err {
		return fmt.Errorf("Error parsing url: %s", err)
	}

	if len(u.Scheme) == 0 {
		*bigIPURL = "https://" + *bigIPURL
		u, err = url.Parse(*bigIPURL)
		if nil != err {
			return fmt.Errorf("Error parsing url: %s", err)
		}
	}

	if u.Scheme != "https" {
		return fmt.Errorf("Invalid BIGIP-URL protocol: '%s' - Must be 'https'",
			u.Scheme)
	}

	if len(u.Path) > 0 && u.Path != "/" {
		return fmt.Errorf("BIGIP-URL path must be empty or '/'; check URL formatting and/or remove %s from path",
			u.Path)
	}

	if *poolMemberType == "nodeport" {
		isNodePort = true
	} else if *poolMemberType == "cluster" {
		isNodePort = false
	} else {
		return fmt.Errorf("'%v' is not a valid Pool Member Type", *poolMemberType)
	}

	if len(*openshiftSDNName) > 0 && len(*flannelName) > 0 {
		return fmt.Errorf("Cannot have both openshift-sdn-name and flannel-name specified.")
	}

	if flags.Changed("openshift-sdn-name") {
		if len(*openshiftSDNName) == 0 {
			return fmt.Errorf("Missing required parameter openshift-sdn-name")
		}
		if isNodePort {
			return fmt.Errorf("Cannot run NodePort mode while supplying openshift-sdn-name. " +
				"Must be in Cluster mode if using VXLAN.")
		}
		vxlanMode = "maintain"
		vxlanName = *openshiftSDNName
	} else if flags.Changed("flannel-name") {
		if len(*flannelName) == 0 {
			return fmt.Errorf("Missing required parameter flannel-name")
		}
		if isNodePort {
			return fmt.Errorf("Cannot run NodePort mode while supplying flannel-name. " +
				"Must be in Cluster mode if using VXLAN.")
		}
		vxlanMode = "maintain"
		vxlanName = *flannelName
	}

	return nil
}

func setupNodePolling(
	appMgr *appmanager.Manager,
	np pollers.Poller,
	eventChan <-chan interface{},
	kubeClient kubernetes.Interface,
) error {
	if appMgr.IsNodePort() {
		err := np.RegisterListener(appMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for nodeport mode: %v",
				err)
		}
	}

	if 0 != len(vxlanMode) {
		// If partition is part of vxlanName, extract just the tunnel name
		tunnelName := vxlanName
		cleanPath := strings.TrimLeft(vxlanName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos != -1 {
			tunnelName = cleanPath[slashPos+1:]
		}
		vxMgr, err := vxlan.NewVxlanMgr(
			vxlanMode,
			tunnelName,
			appMgr.UseNodeInternal(),
			appMgr.ConfigWriter(),
			eventChan,
		)
		if nil != err {
			return fmt.Errorf("error creating vxlan manager: %v", err)
		}

		err = np.RegisterListener(vxMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for vxlan mode: %v",
				err)
		}
		if eventChan != nil {
			vxMgr.ProcessAppmanagerEvents(kubeClient)
		}
	}

	return nil
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

// setup the initial watch based off the flags passed in, if no flags then we
// watch all namespaces
func setupWatchers(appMgr *appmanager.Manager, resyncPeriod time.Duration) {
	label := appmanager.DefaultConfigMapLabel

	if len(*namespaceLabel) == 0 {
		ls, err := createLabel(label)
		if nil != err {
			log.Warningf("Failed to create label selector: %v", err)
		}
		if watchAllNamespaces == true {
			err = appMgr.AddNamespace("", ls, resyncPeriod)
			if nil != err {
				log.Warningf("Failed to add informers for all namespaces:%v", err)
			}
		} else {
			for _, namespace := range *namespaces {
				err = appMgr.AddNamespace(namespace, ls, resyncPeriod)
				if nil != err {
					log.Warningf("Failed to add informers for namespace %v: %v", namespace, err)
				}
			}
		}
	} else {
		ls, err := createLabel(*namespaceLabel)
		if nil != err {
			log.Warningf("Failed to create label selector: %v", err)
		}
		err = appMgr.AddNamespaceLabelInformer(ls, resyncPeriod)
		if nil != err {
			log.Warningf("Failed to add label watch for all namespaces:%v", err)
		}
	}
}

func main() {
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

	log.Infof("Starting: Version: %s, BuildInfo: %s", version, buildInfo)

	appmanager.DEFAULT_PARTITION = (*bigIPPartitions)[0]
	appmanager.RegisterBigIPSchemaTypes()

	if _, isSet := os.LookupEnv("SCALE_PERF_ENABLE"); isSet {
		now := time.Now()
		log.Infof("SCALE_PERF: Started controller at: %d", now.Unix())
	}

	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
	}
	defer configWriter.Stop()

	if len(*routeLabel) > 0 {
		*routeLabel = fmt.Sprintf("f5type in (%s)", *routeLabel)
	}
	var routeConfig = appmanager.RouteConfig{
		RouteVSAddr: *routeVserverAddr,
		RouteLabel:  *routeLabel,
		HttpVs:      *routeHttpVs,
		HttpsVs:     *routeHttpsVs,
		ClientSSL:   *clientSSL,
		ServerSSL:   *serverSSL,
	}

	var appMgrParms = appmanager.Params{
		ConfigWriter:      configWriter,
		UseNodeInternal:   *useNodeInternal,
		IsNodePort:        isNodePort,
		RouteConfig:       routeConfig,
		NodeLabelSelector: *nodeLabelSelector,
		ResolveIngress:    *resolveIngNames,
		DefaultIngIP:      *defaultIngIP,
		VsSnatPoolName:    *vsSnatPoolName,
		UseSecrets:        *useSecrets,
		SchemaLocal:       *schemaLocal,
	}

	// If running with Flannel, create an event channel that the appManager
	// uses to send endpoints to the VxlanManager
	var eventChan chan interface{}
	if len(*flannelName) > 0 {
		eventChan = make(chan interface{})
		appMgrParms.EventChan = eventChan
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

	gs := globalSection{
		LogLevel:       *logLevel,
		VerifyInterval: *verifyInterval,
		VXLANPartition: vxlanPartition,
	}
	bs := bigIPSection{
		BigIPUsername:   *bigIPUsername,
		BigIPPassword:   *bigIPPassword,
		BigIPURL:        *bigIPURL,
		BigIPPartitions: *bigIPPartitions,
	}

	subPidCh, err := startPythonDriver(configWriter, gs, bs, *pythonBaseDir)
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

	var config *rest.Config
	if *inCluster {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeConfig)
	}
	if err != nil {
		log.Fatalf("error creating configuration: %v", err)
	}
	// creates the clientset
	appMgrParms.KubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("error connecting to the client: %v", err)
	}
	if *manageRoutes {
		rclient, err := routeclient.New(config)
		appMgrParms.RouteClientV1 = rclient.RESTClient
		if nil != err {
			log.Fatalf("unable to create route client: err: %+v\n", err)
		}
	}

	appMgr := appmanager.NewManager(&appMgrParms)

	if isNodePort || 0 != len(vxlanMode) {
		intervalFactor := time.Duration(*nodePollInterval)
		np := pollers.NewNodePoller(appMgrParms.KubeClient, intervalFactor*time.Second, *nodeLabelSelector)
		err := setupNodePolling(appMgr, np, eventChan, appMgrParms.KubeClient)
		if nil != err {
			log.Fatalf("Required polling utility for node updates failed setup: %v",
				err)
		}

		np.Run()
		defer np.Stop()
	}

	setupWatchers(appMgr, 30*time.Second)
	// Expose Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	// Add health check e.g. is Python process still there?
	hc := &health.HealthChecker{
		SubPID: subPid,
	}
	http.Handle("/health", hc.HealthCheckHandler())
	bigIPPrometheus.RegisterMetrics()
	go func() {
		log.Fatal(http.ListenAndServe(*httpAddress, nil).Error())
	}()

	stopCh := make(chan struct{})

	appMgr.Run(stopCh)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	close(stopCh)
	log.Infof("Exiting - signal %v\n", sig)
}
