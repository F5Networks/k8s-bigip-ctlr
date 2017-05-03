/*-
 * Copyright (c) 2017, F5 Networks, Inc.
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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/openshift"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"

	log "f5/vlogger"
	clog "f5/vlogger/console"

	"github.com/spf13/pflag"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/apimachinery/pkg/labels"
)

type globalSection struct {
	LogLevel       string `json:"log-level,omitempty"`
	VerifyInterval int    `json:"verify-interval,omitempty"`
}

type bigIPSection struct {
	BigIPUsername   string   `json:"username,omitempty"`
	BigIPPassword   string   `json:"password,omitempty"`
	BigIPURL        string   `json:"url,omitempty"`
	BigIPPartitions []string `json:"partitions,omitempty"`
}

var (
	// Flag sets and supported flags
	flags             *pflag.FlagSet
	globalFlags       *pflag.FlagSet
	bigIPFlags        *pflag.FlagSet
	kubeFlags         *pflag.FlagSet
	openshiftSDNFlags *pflag.FlagSet

	pythonBaseDir    *string
	logLevel         *string
	verifyInterval   *int
	nodePollInterval *int

	namespaces      *[]string
	useNodeInternal *bool
	poolMemberType  *string
	inCluster       *bool
	kubeConfig      *string
	namespaceLabel  *string

	bigIPURL        *string
	bigIPUsername   *string
	bigIPPassword   *string
	bigIPPartitions *[]string

	openshiftSDNMode string
	openshiftSDNName *string

	// package variables
	isNodePort         bool
	watchAllNamespaces bool
)

func _init() {
	flags = pflag.NewFlagSet("main", pflag.ContinueOnError)
	globalFlags = pflag.NewFlagSet("Global", pflag.ContinueOnError)
	bigIPFlags = pflag.NewFlagSet("BigIP", pflag.ContinueOnError)
	kubeFlags = pflag.NewFlagSet("Kubernetes", pflag.ContinueOnError)
	openshiftSDNFlags = pflag.NewFlagSet("Openshift SDN", pflag.ContinueOnError)

	// Global flags
	pythonBaseDir = globalFlags.String("python-basedir", "/app/python",
		"Optional, directory location of python utilities")
	logLevel = globalFlags.String("log-level", "INFO",
		"Optional, logging level")
	verifyInterval = globalFlags.Int("verify-interval", 30,
		"Optional, interval (in seconds) at which to verify the BIG-IP configuration.")
	nodePollInterval = globalFlags.Int("node-poll-interval", 30,
		"Optional, interval (in seconds) at which to poll for cluster nodes.")

	globalFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Global:\n%s\n", globalFlags.FlagUsages())
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
		fmt.Fprintf(os.Stderr, "  BigIP:\n%s\n", bigIPFlags.FlagUsages())
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
		"Optional, if this controller is running in a kubernetes cluster, use the pod secrets for creating a Kubernetes client.")
	kubeConfig = kubeFlags.String("kubeconfig", "./config",
		"Optional, absolute path to the kubeconfig file")
	namespaceLabel = kubeFlags.String("namespace-label", "",
		"Optional, used to watch for namespaces with this label")

	kubeFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Kubernetes:\n%s\n", kubeFlags.FlagUsages())
	}

	// Openshift SDN flags
	// FIXME(yacobucci) for now the mode cannot be provided by the user.
	// If the vxlan name is provided it will be set to "maintain" as all
	// we support is updating VTEP entries in the FDB. When we support
	// management of all network objects a flag will be added to support
	// both "maintain" and "manage".
	openshiftSDNMode = ""
	openshiftSDNName = openshiftSDNFlags.String("openshift-sdn-name", "",
		"Must be provided for BigIP SDN integration, full path of BigIP VxLAN Tunnel")

	openshiftSDNFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Openshift SDN:\n%s\n", openshiftSDNFlags.FlagUsages())
	}

	flags.AddFlagSet(globalFlags)
	flags.AddFlagSet(bigIPFlags)
	flags.AddFlagSet(kubeFlags)
	flags.AddFlagSet(openshiftSDNFlags)

	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s\n", os.Args[0])
		globalFlags.Usage()
		bigIPFlags.Usage()
		kubeFlags.Usage()
		openshiftSDNFlags.Usage()
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

	if flags.Changed("openshift-sdn-name") {
		if len(*openshiftSDNName) == 0 {
			return fmt.Errorf("Missing required parameter openshift-sdn-name")
		}
		openshiftSDNMode = "maintain"
	}

	return nil
}

func setupNodePolling(
	appMgr *appmanager.Manager,
	np pollers.Poller,
) error {

	if appMgr.IsNodePort() {
		err := np.RegisterListener(appMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for nodeport mode: %v",
				err)
		}
	}

	if 0 != len(openshiftSDNMode) {
		osMgr, err := openshift.NewOpenshiftSDNMgr(
			openshiftSDNMode,
			*openshiftSDNName,
			appMgr.UseNodeInternal(),
			appMgr.ConfigWriter(),
		)
		if nil != err {
			return fmt.Errorf("error creating openshift sdn manager: %v", err)
		}

		err = np.RegisterListener(osMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for openshift mode: %v",
				err)
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

	err = verifyArgs()
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		flags.Usage()
		os.Exit(1)
	}

	if _, isSet := os.LookupEnv("SCALE_PERF_ENABLE"); isSet {
		now := time.Now()
		log.Infof("SCALE_PERF: Started controller at: %d", now.Unix())
	}

	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
	}
	defer configWriter.Stop()
	var appMgrParms = appmanager.Params{
		ConfigWriter:    configWriter,
		UseNodeInternal: *useNodeInternal,
		IsNodePort:      isNodePort,
	}

	gs := globalSection{
		LogLevel:       *logLevel,
		VerifyInterval: *verifyInterval,
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
			proc, err := os.FindProcess(pid)
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

	appMgr := appmanager.NewManager(&appMgrParms)

	if isNodePort || 0 != len(openshiftSDNMode) {
		intervalFactor := time.Duration(*nodePollInterval)
		np := pollers.NewNodePoller(appMgrParms.KubeClient, intervalFactor*time.Second)
		err := setupNodePolling(appMgr, np)
		if nil != err {
			log.Fatalf("Required polling utility for node updates failed setup: %v",
				err)
		}

		np.Run()
		defer np.Stop()
	}

	setupWatchers(appMgr, 30*time.Second)

	stopCh := make(chan struct{})

	appMgr.Run(stopCh)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	close(stopCh)
	log.Infof("Exiting - signal %v\n", sig)
}
