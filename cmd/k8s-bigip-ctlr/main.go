/*-
 * Copyright (c) 2017,2018,2019 F5 Networks, Inc.
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
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/health"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	 bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/pkg/prometheus"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/vxlan"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"
	 "github.com/prometheus/client_golang/prometheus/promhttp"
	 "net/http"
 
	 //"github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/cccl"
	 "io/ioutil"
	 v1 "k8s.io/api/core/v1"
	 //"net/http"
	 "net/url"
	 "os"
	 "os/signal"
	 "strings"
	 "syscall"
	 "time"
 
	 cisAgent "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/as3"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/cccl"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	 "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
 
	 log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	 clog "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger/console"
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
	 dgPath           string
 
	 namespaces             *[]string
	 useNodeInternal        *bool
	 poolMemberType         *string
	 inCluster              *bool
	 kubeConfig             *string
	 namespaceLabel         *string
	 manageRoutes           *bool
	 manageConfigMaps       *bool
	 manageIngress          *bool
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
	 enableTLS                 *string
	 tls13CipherGroupReference *string
	 ciphers                   *string
	 trustedCerts              *string
	 as3PostDelay              *int
 
	 trustedCertsCfgmap *string
	 agent              *string
	 logAS3Response     *bool
	 overrideAS3Decl    *string
	 userDefinedAS3Decl *string
	 filterTenants      *bool
 
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
	 kubeClient         kubernetes.Interface
	 agRspChan          chan interface{}
	 eventChan          chan interface{}
	 configWriter       writer.Writer
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
	 credsDir = bigIPFlags.String("credentials-directory", "",
		 "Optional, directory that contains the BIG-IP username, password, and/or "+
			 "url files. To be used instead of username, password, and/or url arguments.")
	 as3Validation = bigIPFlags.Bool("as3-validation", true,
		 "Optional, when set to false, disables as3 template validation on the controller.")
	 sslInsecure = bigIPFlags.Bool("insecure", false,
		 "Optional, when set to true, enable insecure SSL communication to BIGIP.")
	 as3PostDelay = bigIPFlags.Int("as3-post-delay", 0,
		 "Optional, time (in seconds) that CIS waits to post the available AS3 declaration.")
	 logAS3Response = bigIPFlags.Bool("log-as3-response", false,
		 "Optional, when set to true, add the body of AS3 API response in Controller logs.")
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
	 overrideAS3UsageStr := "Optional, provide Namespace and Name of that ConfigMap as <namespace>/<configmap-name>." +
		 "The JSON key/values from this ConfigMap will override key/values from internally generated AS3 declaration."
	 overrideAS3Decl = bigIPFlags.String("override-as3-declaration", "", overrideAS3UsageStr)
	 userDefinedCfgMapStr := "Optional, provide Namespace and Name of the User Defined ConfigMap as " +
		 "<namespace>/<configmap-name>. The template in this cfgMap is a JSON string with  JSON key/values" +
		 " will be used as a AS3 declaration in CIS."
	 userDefinedAS3Decl = bigIPFlags.String("userdefined-as3-declaration", "", userDefinedCfgMapStr)
	 filterTenants = kubeFlags.Bool("filter-tenants", false,
		 "Optional, specify whether or not to use tenant filtering API for AS3 declaration")
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
	 manageIngress = kubeFlags.Bool("manage-ingress", true,
		 "Optional, specify whether or not to manage Ingress resources")
	 manageConfigMaps = kubeFlags.Bool("manage-configmaps", true,
		 "Optional, specify whether or not to manage ConfigMap resources")
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
 
 func hasCommonPartition(partitions []string) bool {
	 for _, x := range partitions {
		 if x == "Common" {
			 return true
		 }
	 }
	 return false
 }
 
 func verifyArgs() error {
	 *logLevel = strings.ToUpper(*logLevel)
	 logErr := initLogger(*logLevel)
	 if nil != logErr {
		 return logErr
	 }
 
	 if len(*poolMemberType) == 0 {
		 return fmt.Errorf("missing pool member type")
	 }
 
	 if len(*bigIPPartitions) == 0 {
		 return fmt.Errorf("missing a BIG-IP partition")
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
	 if *manageRoutes {
		 if len(*routeVserverAddr) == 0 {
			 return fmt.Errorf("Missing required parameter route-vserver-addr")
		 }
	 }
	 if *overrideAS3Decl != "" {
		 if len(strings.Split(*overrideAS3Decl, "/")) != 2 {
			 return fmt.Errorf("Invalid value provided for --override-as3-declaration" +
				 "Usage: --override-as3-declaration=<namespace>/<configmap-name>")
		 }
	 }
	 if *userDefinedAS3Decl != "" {
		 if len(strings.Split(*userDefinedAS3Decl, "/")) != 2 {
			 return fmt.Errorf("Invalid value provided for --userdefined-as3-declaration" +
				 "Usage: --userdefined-as3-declaration=<namespace>/<configmap-name>")
		 }
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
				 *field = string(fileBytes)
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
	 return nil
 }
 
 func setupNodePolling(
	 appMgr *appmanager.Manager,
	 np pollers.Poller,
	 eventChanl <-chan interface{},
	 kubeClient kubernetes.Interface,
 ) error {
	 // Register appMgr to watch for node updates to keep track of watched nodes
	 err := np.RegisterListener(appMgr.ProcessNodeUpdate)
	 if nil != err {
		 return fmt.Errorf("error registering node update listener: %v",
			 err)
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
			 getConfigWriter(),
			 eventChanl,
		 )
		 if nil != err {
			 return fmt.Errorf("error creating vxlan manager: %v", err)
		 }
 
		 // Register vxMgr to watch for node updates to process fdb records
		 err = np.RegisterListener(vxMgr.ProcessNodeUpdate)
		 if nil != err {
			 return fmt.Errorf("error registering node update listener for vxlan mode: %v",
				 err)
		 }
		 if eventChanl != nil {
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
 
	 if len(*namespaceLabel) == 0 {
		 ls, err := createLabel(label)
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
					 log.Debugf("[INIT] Added informers for namespace %v: %v", namespace, err)
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
	 err = getCredentials()
	 if nil != err {
		 fmt.Fprintf(os.Stderr, "%v\n", err)
		 flags.Usage()
		 os.Exit(1)
	 }
 
	 log.Infof("[INIT] Starting: Version: %s, BuildInfo: %s", version, buildInfo)
 
	 resource.DEFAULT_PARTITION = (*bigIPPartitions)[0]
	 dgPath = resource.DEFAULT_PARTITION
	 if strings.ToLower(*agent) == "as3" {
		 resource.DEFAULT_PARTITION += "_AS3"
		 *agent = "as3"
		 dgPath = strings.Join([]string{resource.DEFAULT_PARTITION, "Shared"}, "/")
	 }
	 appmanager.RegisterBigIPSchemaTypes()
 
	 // If running with Flannel, create an event channel that the appManager
	 // uses to send endpoints to the VxlanManager
	 if len(*flannelName) > 0 {
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
 
	 if _, isSet := os.LookupEnv("SCALE_PERF_ENABLE"); isSet {
		 now := time.Now()
		 log.Infof("[INIT] SCALE_PERF: Started controller at: %d", now.Unix())
	 }
 
	 if len(*routeLabel) > 0 {
		 *routeLabel = fmt.Sprintf("f5type in (%s)", *routeLabel)
	 }
 
	 agRspChan = make(chan interface{}, 1)
	 var appMgrParms = getAppManagerParams()
 
	 config, err := getKubeConfig()
	 if err != nil {
		 os.Exit(1)
	 }
	 kubeClient, err = kubernetes.NewForConfig(config)
	 if err != nil {
		 log.Fatalf("[INIT] error connecting to the client: %v", err)
		 os.Exit(1)
	 }
 
	 // creates the clientset
	 appMgrParms.KubeClient = kubeClient
	 if *manageRoutes {
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
 
	 // Cleanup other agent partitions
	 err = cleanupOtherAgents(*agent, resource.DEFAULT_PARTITION)
	 if err != nil {
		 os.Exit(1)
	 }
 
	 if err = appMgr.AgentCIS.Init(getAgentParams(*agent)); err != nil {
		 log.Fatalf("[INIT] Failed to initialize %v agent, %+v\n", *agent, err)
		 os.Exit(1)
	 }
	 defer appMgr.AgentCIS.DeInit()
	 // Initlize CCCL for L2-L3 if agent is AS3
	 // TODO: this will be removed when L2-L3 support is added in AS3
	 if *agent == cisAgent.AS3Agent {
		 appMgr.AgentCCCL, err = cisAgent.CreateAgent(cisAgent.CCCLAgent)
		 if err = appMgr.AgentCCCL.Init(getAgentParams(cisAgent.CCCLAgent)); err != nil {
			 log.Fatalf("[INIT] Failed to initialize CCCL Agent %v error: err: %+v\n", *agent, err)
			 os.Exit(1)
		 }
		 defer appMgr.AgentCCCL.DeInit()
	 }
 
	 GetNamespaces(appMgr)
	 intervalFactor := time.Duration(*nodePollInterval)
	 np := pollers.NewNodePoller(appMgrParms.KubeClient, intervalFactor*time.Second, *nodeLabelSelector)
	 err = setupNodePolling(appMgr, np, eventChan, appMgrParms.KubeClient)
	 if nil != err {
		 log.Fatalf("Required polling utility for node updates failed setup: %v",
			 err)
	 }
 
	 np.Run()
	 defer np.Stop()
 
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
	 log.Infof("[INIT] Exiting - signal %v\n", sig)
 }
 
 func cleanupOtherAgents(exclAgent, partition string) error {
	 var agentList []string
	 agentList = append(agentList, cisAgent.AS3Agent) // This can include cisAgent.CCCLAgent etc.
	 for _, agent := range agentList {
		 if exclAgent != agent {
			 agentCIS, err := cisAgent.CreateAgent(agent)
			 if err != nil {
				 log.Fatalf("[INIT] Failed to create agent: %v", agent)
				 return err
			 }
			 if err = agentCIS.Init(getAgentParams(agent)); err == nil {
				 agentCIS.Remove(partition)
				 agentCIS.DeInit()
			 }
		 }
	 }
	 return nil
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
		 IngressClass:           *ingressClass,
		 TrustedCertsCfgmap:     *trustedCertsCfgmap,
		 DgPath:                 dgPath,
		 AgRspChan:              agRspChan,
		 SchemaLocal:            *schemaLocal,
		 ProcessAgentLabels:     getProcessAgentLabelFunc(),
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
		 OverrideAS3Decl:           *overrideAS3Decl,
		 UserDefinedAS3Decl:        *userDefinedAS3Decl,
		 FilterTenants:             *filterTenants,
		 BIGIPUsername:             *bigIPUsername,
		 BIGIPPassword:             *bigIPPassword,
		 BIGIPURL:                  *bigIPURL,
		 TrustedCerts:              getBIGIPTrustedCerts(),
		 SSLInsecure:               *sslInsecure,
		 AS3PostDelay:              *as3PostDelay,
		 LogResponse:               *logAS3Response,
		 RspChan:                   agRspChan,
	 }
 }
 
 func getCCCLParams() *cccl.Params {
	 return &cccl.Params{
		 ConfigWriter: getConfigWriter(),
		 EventChan:    eventChan,
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
	 cfgMap, err := kubeClient.CoreV1().ConfigMaps(cfgMapNamespace).Get(cfgMapName, metav1.GetOptions{})
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
			 if m["overrideAS3"] == "true" {
				 return funCMapOptions(*overrideAS3Decl)
			 } else if m["as3"] == "true" {
				 return funCMapOptions(*userDefinedAS3Decl)
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