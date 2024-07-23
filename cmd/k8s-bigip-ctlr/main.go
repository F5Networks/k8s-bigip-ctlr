/*
 * Copyright (c) 2017-2023 F5 Networks, Inc.
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
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/controller"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/teem"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

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
	cmIPFlags         *pflag.FlagSet
	kubeFlags         *pflag.FlagSet
	multiClusterFlags *pflag.FlagSet

	logLevel        *string
	logFile         *string
	printVersion    *bool
	disableTeems    *bool
	useNodeInternal *bool

	kubeConfig            *string
	manageCustomResources *bool
	manageRoutes          *bool

	cmURL         *string
	cmUsername    *string
	cmPassword    *string
	credsDir      *string
	sslInsecure   *bool
	ipam          *bool
	ipamNamespace *string

	trustedCertsCfgmap *string

	CISConfigCR *string
	httpAddress *string

	// package variables
	clientSets       controller.ClientSets
	userAgentInfo    string
	multiClusterMode *string
)

func _init() {
	flags = pflag.NewFlagSet("main", pflag.PanicOnError)
	globalFlags = pflag.NewFlagSet("Global", pflag.PanicOnError)
	cmIPFlags = pflag.NewFlagSet("CentralManager", pflag.PanicOnError)
	kubeFlags = pflag.NewFlagSet("Kubernetes", pflag.PanicOnError)
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

	// Global flags
	logLevel = globalFlags.String("log-level", "INFO",
		"Optional, logging level")
	logFile = globalFlags.String("log-file", "",
		"Optional, filepath to store the CIS logs")
	printVersion = globalFlags.Bool("version", false,
		"Optional, print version and exit.")
	disableTeems = globalFlags.Bool("disable-teems", true,
		"Optional, flag to disable sending telemetry data to TEEM")
	useNodeInternal = kubeFlags.Bool("use-node-internal", true,
		"Optional, provide kubernetes InternalIP addresses to pool")
	CISConfigCR = globalFlags.String("deploy-config-cr", "",
		"Required, specify a CRD that holds additional spec for controller.")
	httpAddress = globalFlags.String("http-listen-address", "0.0.0.0:8080",
		"Optional, address to serve http based informations (/metrics and /health).")
	globalFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Global:\n%s\n", globalFlags.FlagUsagesWrapped(width))
	}

	// CentralManager flags
	cmURL = cmIPFlags.String("cm-url", "",
		"Required, URL for the CentralManager")
	cmUsername = cmIPFlags.String("cm-username", "",
		"Required, user name for the CentralManager user account.")
	cmPassword = cmIPFlags.String("cm-password", "",
		"Required, password for the CentralManager user account.")
	credsDir = cmIPFlags.String("credentials-directory", "",
		"Optional, directory that contains the CentralManager username, password, and/or "+
			"url files. To be used instead of username, password, and/or url arguments.")
	sslInsecure = cmIPFlags.Bool("no-verify-ssl", false,
		"Optional, when set to true, enable insecure SSL communication to CentralManager.")
	trustedCertsCfgmap = cmIPFlags.String("trusted-certs-cfgmap", "",
		"Optional, when certificates are provided, adds them to controller trusted certificate store.")
	cmIPFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  CentralManager:\n%s\n", cmIPFlags.FlagUsagesWrapped(width))
	}

	// Kubernetes flags
	kubeConfig = kubeFlags.String("kubeconfig", "./config",
		"Optional, absolute path to the kubeconfig file")
	kubeFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "  Kubernetes:\n%s\n", kubeFlags.FlagUsagesWrapped(width))
	}
	manageCustomResources = kubeFlags.Bool("manage-custom-resources", true,
		"Optional, specify whether or not to manage custom resources i.e. transportserver")
	// setting manageRoutes to false by default
	tmpval := false
	manageRoutes = &tmpval
	ipam = kubeFlags.Bool("ipam", false,
		"Optional, when set to true, enable ipam feature for CRD.")
	ipamNamespace = kubeFlags.String("ipam-namespace", "kube-system",
		"Optional, Specify the namespace of ipam custom resource. Default value is kube-system")
	// MultiCluster Flags
	multiClusterMode = multiClusterFlags.String("multi-cluster-mode", "",
		"Optional, determines in multi cluster env cis running as standalone/primary/secondary")

	flags.AddFlagSet(globalFlags)
	flags.AddFlagSet(cmIPFlags)
	flags.AddFlagSet(kubeFlags)
	flags.AddFlagSet(multiClusterFlags)

	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s\n", os.Args[0])
		cmIPFlags.Usage()
		kubeFlags.Usage()
		globalFlags.Usage()
		multiClusterFlags.Usage()
	}
}

func initLogger(logLevel, logFile string) error {
	var logger log.Logger
	if len(logFile) > 0 {
		logger = log.NewFileLogger(logFile)
	} else {
		logger = log.NewConsoleLoggerExt("", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, logger)

	if ll := log.NewLogLevel(logLevel); nil != ll {
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

func verifyArgs() error {
	*logLevel = strings.ToUpper(*logLevel)
	logErr := initLogger(*logLevel, *logFile)
	if nil != logErr {
		return logErr
	}
	if (len(*cmURL) == 0 || len(*cmUsername) == 0 ||
		len(*cmPassword) == 0) && len(*credsDir) == 0 {
		return fmt.Errorf("Missing CM credentials info")
	}

	if len(*CISConfigCR) == 0 {
		return fmt.Errorf("Missing required argument --deploy-config-cr")
	} else {
		if len(strings.Split(*CISConfigCR, "/")) != 2 {
			return fmt.Errorf("invalid value provided for --deploy-config-cr" +
				"Usage: --deploy-config-cr=<namespace>/<CR-name>")
		}
	}

	if *multiClusterMode != "standalone" && *multiClusterMode != "primary" && *multiClusterMode != "secondary" && *multiClusterMode != "" {
		return fmt.Errorf("'%v' is not a valid multi cluster mode, allowed values are: standalone/primary/secondary", *multiClusterMode)
	} else if *multiClusterMode != "" {
		log.Infof("[MultiCluster] CIS running with multi-cluster-mode: %s", *multiClusterMode)
	}

	return nil
}

func getCredentials() error {
	if len(*credsDir) > 0 {
		var usr, pass, cmCredURL string
		var err error
		if strings.HasSuffix(*credsDir, "/") {
			usr = *credsDir + "username"
			pass = *credsDir + "password"
			cmCredURL = *credsDir + "url"
		} else {
			usr = *credsDir + "/username"
			pass = *credsDir + "/password"
			cmCredURL = *credsDir + "/url"
		}

		setField := func(field *string, filename, fieldType string) error {
			fileBytes, readErr := os.ReadFile(filename)
			if readErr != nil {
				log.Debug(fmt.Sprintf(
					"No %s in credentials directory, falling back to CLI argument", fieldType))
				if len(*field) == 0 {
					return fmt.Errorf(fmt.Sprintf("CentralManager %s not specified", fieldType))
				}
			} else {
				*field = strings.TrimSpace(string(fileBytes))
			}
			return nil
		}

		err = setField(cmUsername, usr, "username")
		if err != nil {
			return err
		}
		err = setField(cmPassword, pass, "password")
		if err != nil {
			return err
		}
		err = setField(cmURL, cmCredURL, "url")
		if err != nil {
			return err
		}
	}
	// Verify URL is valid
	if !strings.HasPrefix(*cmURL, "https://") {
		*cmURL = "https://" + *cmURL
	}
	u, err := url.Parse(*cmURL)
	if nil != err {
		return fmt.Errorf("Error parsing url: %s", err)
	}
	if len(u.Path) > 0 && u.Path != "/" {
		return fmt.Errorf("CM-URL path must be empty or '/'; check URL formatting and/or remove %s from path",
			u.Path)
	}
	return nil
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

	config, err := getKubeConfig()
	if err != nil {
		log.Fatalf("[INIT] error getting the kube config: %v", err)
	}

	err = initClientSets(config)
	if err != nil {
		log.Fatalf("[INIT] error connecting to the client: %v", err)
	}
	userAgentInfo = getUserAgentInfo()
	ctlr := initController(config)

	//TODO initialize and add support for teems data
	initTeems(ctlr)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	ctlr.Stop()
	log.Infof("Exiting - signal %v\n", sig)
}

func initClientSets(config *rest.Config) error {
	var err error

	clientSets.KubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create KubeClient: %v", err)
	}

	if *manageCustomResources {
		clientSets.KubeCRClient, err = versioned.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create Custum Resource KubeClient: %v", err)
		}
	}

	if *manageRoutes {
		clientSets.RouteClientV1, err = routeclient.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create Route Client: %v", err)
		}
	}

	if clientSets.KubeClient != nil {
		log.Debug("Clients Created")
	}
	return nil

}

func initController(
	config *rest.Config,
) *controller.Controller {

	ctlr := controller.RunController(
		controller.Params{
			Config:     config,
			ClientSets: &clientSets,
			UserAgent:  userAgentInfo,
			CMConfigDetails: &controller.CMConfig{
				URL:      *cmURL,
				UserName: *cmUsername,
				Password: *cmPassword,
			},
			CMTrustedCerts:        getBIGIPTrustedCerts(),
			CMSSLInsecure:         *sslInsecure,
			CISConfigCRKey:        *CISConfigCR,
			HttpAddress:           *httpAddress,
			ManageCustomResources: *manageCustomResources,
			UseNodeInternal:       *useNodeInternal,
			MultiClusterMode:      *multiClusterMode,
			IPAM:                  *ipam,
			IPAMNamespace:         *ipamNamespace,
		},
	)

	return ctlr
}

func initTeems(ctlr *controller.Controller) {
	td := &teem.TeemsData{
		CisVersion:      version,
		PoolMemberType:  ctlr.PoolMemberType,
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
		td.SDNType = ctlr.OrchestrationCNI
	} else {
		td.AccessEnabled = false
		log.Debug("Telemetry data reporting to TEEM server is disabled")
	}
	ctlr.TeemData = td
	if !(*disableTeems) {
		ctlr.RequestHandler.PostManagers.RLock()
		for _, pm := range ctlr.RequestHandler.PostManagers.PostManagerMap {
			//TODO: Handle get reg key for each BIG-IP
			key, err := pm.GetBigipRegKey()
			if err != nil {
				log.Errorf("%v", err)
			}
			ctlr.TeemData.Lock()
			ctlr.TeemData.RegistrationKey = key
			ctlr.TeemData.Unlock()
		}
		ctlr.RequestHandler.PostManagers.RUnlock()
	}
}

func getKubeConfig() (*rest.Config, error) {
	var config *rest.Config
	var err error
	config, err = rest.InClusterConfig()
	if err != nil {
		log.Fatalf("[INIT] error creating configuration: %v", err)
		return nil, err
	}

	// creates the clientset
	return config, nil
}

// Get platform info for TEEM
func getUserAgentInfo() string {
	var versionInfo map[string]string
	var err error
	var vInfo []byte
	rc := clientSets.KubeClient.Discovery().RESTClient()
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

// Read certificate from configmap
func getBIGIPTrustedCerts() string {
	if *trustedCertsCfgmap == "" {
		return ""
	}
	namespaceCfgmapSlice := strings.Split(*trustedCertsCfgmap, "/")
	if len(namespaceCfgmapSlice) != 2 {
		log.Debugf("[INIT] either trusted-certs-cfgmap is not provided or provided trusted-certs-cfgmap is invalid.")
		return ""
	}

	cm, err := getConfigMapUsingNamespaceAndName(namespaceCfgmapSlice[0], namespaceCfgmapSlice[1])
	if err != nil {
		log.Fatalf("[INIT] ConfigMap with name %v not found in namespace: %v, error: %v",
			namespaceCfgmapSlice[1], namespaceCfgmapSlice[0], err)
	}

	var certs string
	// Fetch all certificates from configmap
	for _, v := range cm.Data {
		certs += v + "\n"
	}
	return certs
}

// getConfigMapUsingNamespaceAndName fetches and returns the configMap
func getConfigMapUsingNamespaceAndName(cfgMapNamespace, cfgMapName string) (*v1.ConfigMap, error) {
	cfgMap, err := clientSets.KubeClient.CoreV1().ConfigMaps(cfgMapNamespace).Get(context.TODO(), cfgMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return cfgMap, err
}
