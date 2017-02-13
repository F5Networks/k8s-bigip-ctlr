package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"eventStream"
	"openshift"
	"tools/pollers"
	"tools/writer"
	"virtualServer"

	log "velcro/vlogger"
	clog "velcro/vlogger/console"

	// FIXME: Put this back when we actually use the BIG-IP Go API
	// f5 "github.com/scottdware/go-bigip"
	"github.com/spf13/pflag"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/labels"
	"k8s.io/client-go/1.4/rest"
	"k8s.io/client-go/1.4/tools/clientcmd"
)

type GlobalSection struct {
	LogLevel       string `json:"log-level,omitempty"`
	VerifyInterval int    `json:"verify-interval,omitempty"`
}

type BigIPSection struct {
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

	pythonBaseDir  *string
	logLevel       *string
	verifyInterval *int

	namespace       *string
	useNodeInternal *bool
	poolMemberType  *string
	inCluster       *bool
	kubeConfig      *string

	bigIPURL        *string
	bigIPUsername   *string
	bigIPPassword   *string
	bigIPPartitions *[]string

	openshiftSDNMode string
	openshiftSDNName *string

	// package variables
	isNodePort bool
)

func init() {
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
		"Optional, interval at which to verify the BIG-IP configuration.")

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
	namespace = kubeFlags.String("namespace", "",
		"Required, Kubernetes namespace to watch")
	useNodeInternal = kubeFlags.Bool("use-node-internal", true,
		"Optional, provide kubernetes InternalIP addresses to pool")
	poolMemberType = kubeFlags.String("pool-member-type", "nodeport",
		"Optional, type of k8s objects to add to pools, must be 'nodeport' or 'cluster'.")
	inCluster = kubeFlags.Bool("running-in-cluster", true,
		"Optional, if this controller is running in a kubernetes cluster, use the pod secrets for creating a Kubernetes client.")
	kubeConfig = kubeFlags.String("kubeconfig", "./config",
		"Optional, absolute path to the kubeconfig file")

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

func initializeDriverConfig(
	configWriter writer.Writer,
	global GlobalSection,
	bigIP BigIPSection,
) error {
	if nil == configWriter {
		return fmt.Errorf("config writer argument cannot be nil")
	}

	sectionNames := []string{"global", "bigip"}
	for i, v := range []interface{}{global, bigIP} {
		doneCh, errCh, err := configWriter.SendSection(sectionNames[i], v)
		if nil != err {
			return fmt.Errorf("failed writing global config section: %v", err)
		} else {
			select {
			case <-doneCh:
			case e := <-errCh:
				return fmt.Errorf("failed writing section %s - %v: %v",
					sectionNames[i], e, v)
			case <-time.After(1000 * time.Millisecond):
				log.Warning("Did not receive config write response in 1 second")
			}
		}
	}

	return nil
}

func createDriverCmd(
	configFilename string,
	pyCmd string,
) *exec.Cmd {
	cmdName := "python"

	cmdArgs := []string{
		pyCmd,
		"--config-file", configFilename}

	cmd := exec.Command(cmdName, cmdArgs...)

	return cmd
}

func runBigIPDriver(pid chan<- int, cmd *exec.Cmd) {
	defer close(pid)

	// the config driver python logging goes to stderr by default
	cmdOut, err := cmd.StderrPipe()
	scanOut := bufio.NewScanner(cmdOut)
	go func() {
		for true {
			if scanOut.Scan() {
				log.Info(scanOut.Text())
			} else {
				break
			}
		}
	}()

	err = cmd.Start()
	if nil != err {
		log.Fatalf("Internal error: failed to start config driver: %v", err)
	}
	log.Infof("Started config driver sub-process at pid: %d", cmd.Process.Pid)

	pid <- cmd.Process.Pid

	err = cmd.Wait()
	var waitStatus syscall.WaitStatus
	if exitError, ok := err.(*exec.ExitError); ok {
		waitStatus = exitError.Sys().(syscall.WaitStatus)
		if waitStatus.Signaled() {
			log.Fatalf("Config driver signaled to stop: %d - %s",
				waitStatus.Signal(), waitStatus.Signal())
		} else {
			log.Fatalf("Config driver exited: %d", waitStatus.ExitStatus())
		}
	} else if nil != err {
		log.Fatalf("Config driver exited with error: %v", err)
	} else {
		waitStatus = cmd.ProcessState.Sys().(syscall.WaitStatus)
		log.Warningf("Config driver exited normally: %d", waitStatus.ExitStatus())
	}
}

func startPythonDriver(configWriter writer.Writer) (<-chan int, error) {
	err := initializeDriverConfig(
		configWriter,
		GlobalSection{
			LogLevel:       *logLevel,
			VerifyInterval: *verifyInterval,
		},
		BigIPSection{
			BigIPUsername:   *bigIPUsername,
			BigIPPassword:   *bigIPPassword,
			BigIPURL:        *bigIPURL,
			BigIPPartitions: *bigIPPartitions,
		},
	)
	if nil != err {
		return nil, err
	}

	subPidCh := make(chan int)
	pyCmd := fmt.Sprintf("%s/bigipconfigdriver.py", *pythonBaseDir)
	cmd := createDriverCmd(
		configWriter.GetOutputFilename(),
		pyCmd,
	)
	go runBigIPDriver(subPidCh, cmd)

	return subPidCh, nil
}

func verifyArgs() error {
	*logLevel = strings.ToUpper(*logLevel)
	logErr := initLogger(*logLevel)
	if nil != logErr {
		return logErr
	}

	if len(*bigIPURL) == 0 || len(*bigIPUsername) == 0 || len(*bigIPPassword) == 0 ||
		len(*bigIPPartitions) == 0 || len(*namespace) == 0 || len(*poolMemberType) == 0 {
		return fmt.Errorf("Missing required parameter")
	}

	u, err := url.Parse(*bigIPURL)
	if nil != err {
		return fmt.Errorf("Error parsing url: %s", err)
	}

	if len(u.Scheme) == 0 {
		*bigIPURL = "https://" + *bigIPURL
		u, err = url.Parse(*bigIPURL)
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
	kubeClient kubernetes.Interface,
	configWriter writer.Writer,
) (pollers.Poller, error) {
	np := pollers.NewNodePoller(kubeClient, 30*time.Second)

	if isNodePort {
		err := np.RegisterListener(virtualServer.ProcessNodeUpdate)
		if nil != err {
			return nil,
				fmt.Errorf("error registering node update listener for nodeport mode: %v",
					err)
		}
	}

	if 0 != len(openshiftSDNMode) {
		osMgr, err := openshift.NewOpenshiftSDNMgr(
			openshiftSDNMode,
			*openshiftSDNName,
			*useNodeInternal,
			configWriter,
		)
		if nil != err {
			return nil, fmt.Errorf("error creating openshift sdn manager: %v", err)
		}

		err = np.RegisterListener(osMgr.ProcessNodeUpdate)
		if nil != err {
			return nil,
				fmt.Errorf("error registering node update listener for openshift mode: %v",
					err)
		}
	}

	return np, nil
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

	// FIXME(yacobucci) virtualServer should really be an object and not a
	// singleton at some point
	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
	}
	defer configWriter.Stop()

	virtualServer.SetConfigWriter(configWriter)
	virtualServer.SetUseNodeInternal(*useNodeInternal)
	virtualServer.SetNamespace(*namespace)

	subPidCh, err := startPythonDriver(configWriter)
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

	var kubeClient *kubernetes.Clientset
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
	kubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("error connecting to the client: %v", err)
	}

	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	if isNodePort || 0 != len(openshiftSDNMode) {
		poller, err := setupNodePolling(kubeClient, configWriter)
		if nil != err {
			log.Fatalf("Required polling utility for node updates failed setup: %v",
				err)
		}

		poller.Run()
		defer poller.Stop()
	}

	var endptEventStore *eventStream.EventStore

	onServiceChange := func(changeType eventStream.ChangeType, obj interface{}) {
		virtualServer.ProcessServiceUpdate(kubeClient, changeType, obj, isNodePort, endptEventStore)
	}
	serviceEventStream := eventStream.NewServiceEventStream(
		kubeClient.Core(),
		*namespace,
		5*time.Second,
		onServiceChange,
		nil,
		nil)
	serviceEventStream.Run()
	defer serviceEventStream.Stop()

	onConfigMapChange := func(changeType eventStream.ChangeType, obj interface{}) {
		virtualServer.ProcessConfigMapUpdate(kubeClient, changeType, obj, isNodePort, endptEventStore)
	}
	f5ConfigMapSelector, err := labels.Parse("f5type in (virtual-server)")
	if err != nil {
		log.Warningf("failed to parse Label Selector string - controller will not filter for F5 specific objects - label: f5type : virtual-server, err %v", err)
		f5ConfigMapSelector = nil
	}
	configMapEventStream := eventStream.NewConfigMapEventStream(
		kubeClient.Core(),
		*namespace,
		5*time.Second,
		onConfigMapChange,
		f5ConfigMapSelector,
		nil)
	if !isNodePort {
		onEpChange := func(changeType eventStream.ChangeType, obj interface{}) {
			virtualServer.ProcessEndpointsUpdate(kubeClient, changeType, obj, serviceEventStream.Store())
		}
		endptEventStream := eventStream.NewEndpointsEventStream(
			kubeClient.Core(),
			*namespace,
			5*time.Second,
			onEpChange,
			nil,
			nil)
		endptEventStore = endptEventStream.Store()
		endptEventStream.Run()
		defer endptEventStream.Stop()
	}

	configMapEventStream.Run()
	defer configMapEventStream.Stop()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Infof("Exiting - signal %v\n", sig)
}
