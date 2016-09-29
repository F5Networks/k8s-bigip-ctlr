package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"

	"eventStream"
	"virtualServer"

	log "velcro/vlogger"
	clog "velcro/vlogger/console"

	// FIXME: Put this back when we actually use the BIG-IP Go API
	// f5 "github.com/scottdware/go-bigip"
	"github.com/spf13/pflag"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/rest"
	"k8s.io/client-go/1.4/tools/clientcmd"
)

var (
	flags     = pflag.NewFlagSet("", pflag.ExitOnError)
	inCluster = flags.Bool("running-in-cluster", true,
		`Optional, if this controller is running in a kubernetes cluster, use the
		 pod secrets for creating a Kubernetes client.`)
	kubeConfig = flags.String("kubeconfig", "./config",
		"Optional, absolute path to the kubeconfig file")
	namespace = flags.String("namespace", "default",
		"Optional, Kubernetes namespace to watch")
	bigipUrl = flags.String("bigip-url", "",
		`URL for the Big-IP`)
	bigipUsername = flags.String("bigip-username", "",
		`Required, user name for the Big-IP user account.`)
	bigipPassword = flags.String("bigip-password", "",
		`Required, password for the Big-IP user account.`)
	bigipPartition = flags.String("bigip-partition", "velcro",
		`Optional, partition for the Big-IP velcro objects.`)
	pythonBaseDir = flags.String("python-basedir", "/app/python",
		`Optional, directory location of python utilities`)
)

func initLogger() {
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, clog.NewConsoleLogger())
	log.SetLogLevel(log.LL_DEBUG)
}

func runBigIpDriver(pid chan<- int, bigipUsername *string, bigipPassword *string,
	bigipUrl *string, bigipPartition *string, pythonBaseDir *string) {
	defer close(pid)

	cmdName := "python"
	bigipDriver := "bigipconfigdriver.py"

	drvName := fmt.Sprintf("%s/%s", *pythonBaseDir, bigipDriver)

	confName := fmt.Sprintf("/tmp/f5-k8s-controller.config.%d.json", os.Getpid())

	cmdArgs := []string{
		drvName,
		"--username", *bigipUsername,
		"--password", *bigipPassword,
		"--hostname", *bigipUrl,
		"--config-file", confName,
		*bigipPartition}

	cmd := exec.Command(cmdName, cmdArgs...)

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
	if nil != err {
		log.Fatalf("Config driver exited unexpectedly: %v", err)
	}
}

func main() {
	initLogger()
	flags.Parse(os.Args)
	if len(*bigipUrl) == 0 {
		log.Fatalf("The Big-IP URL is required")
	}
	if len(*bigipUsername) == 0 {
		log.Fatalf("The Big-IP user name is required")
	}
	if len(*bigipPassword) == 0 {
		log.Fatalf("The Big-IP password is required")
	}

	subPidCh := make(chan int)
	go runBigIpDriver(subPidCh, bigipUsername, bigipPassword, bigipUrl,
		bigipPartition, pythonBaseDir)
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
	var err error
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

	// Initialize the Node cache
	virtualServer.ProcessNodeUpdate(kubeClient)

	onServiceChange := func(changeType eventStream.ChangeType, obj interface{}) {
		virtualServer.ProcessServiceUpdate(kubeClient, changeType, obj)
	}
	serviceEventStream := eventStream.NewServiceEventStream(kubeClient.Core(), *namespace, 5, onServiceChange, nil, nil)
	serviceEventStream.Run()
	defer serviceEventStream.Stop()

	onConfigMapChange := func(changeType eventStream.ChangeType, obj interface{}) {
		virtualServer.ProcessConfigMapUpdate(kubeClient, changeType, obj)
	}
	configMapEventStream := eventStream.NewConfigMapEventStream(kubeClient.Core(), *namespace, 5, onConfigMapChange, nil, nil)
	configMapEventStream.Run()
	defer configMapEventStream.Stop()

	for {
		time.Sleep(30 * time.Second)

		// Poll for node changes
		virtualServer.ProcessNodeUpdate(kubeClient)
	}
}
