package main

import (
	"os"
	"time"

	"eventStream"

	log "velcro/vlogger"
	clog "velcro/vlogger/console"

	f5 "github.com/scottdware/go-bigip"
	"github.com/spf13/pflag"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/api"
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
)

func initLogger() {
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, clog.NewConsoleLogger())
	log.SetLogLevel(log.LL_DEBUG)
}

func showPods(kubeClient *kubernetes.Clientset) bool {
	pods, err := kubeClient.Core().Pods("").List(api.ListOptions{})
	if err != nil {
		log.Errorf("Unable to get list of pods, err=%+v", err)
		return false
	}

	log.Infof("========================================")
	for _, pod := range pods.Items {
		log.Infof("pod: %v", pod.Name)
		log.Infof("  namespace=%v", pod.Namespace)
		log.Infof("  resourceVersion=%v", pod.ResourceVersion)
		log.Infof("  generation=%v", pod.Generation)
		log.Infof("  creationTimestamp=%v", pod.CreationTimestamp)
		log.Infof("  labels:")
		for k, v := range pod.Labels {
			log.Infof("    %v=%v", k, v)
		}
		log.Infof("  annotations:")
		for k, v := range pod.Annotations {
			log.Infof("    %v=%v", k, v)
		}
		log.Infof("  containers:")
		for _, v := range pod.Spec.Containers {
			log.Infof("    name=%v", v.Name)
			log.Infof("    image=%v", v.Image)
		}
	}
	return true
}

func showVirtualServers(bigip *f5.BigIP) bool {
	vs, err := bigip.VirtualServers()
	if err != nil {
		log.Errorf("failed to get virtual servers: %v", err)
		return false
	}
	log.Infof("----------------------------------------")
	if len(vs.VirtualServers) == 0 {
		log.Infof("No virtual servers are configured")
	} else {
		for _, v := range vs.VirtualServers {
			log.Infof("virtual server: %v", v.Name)
			log.Infof("  enabled=%v", v.Enabled)
			log.Infof("  partition=%v", v.Partition)
			log.Infof("  fullPath=%v", v.FullPath)
			log.Infof("  ipProtocol=%v", v.IPProtocol)
			log.Infof("  destination=%v", v.Destination)
			log.Infof("  netmask=%v", v.Mask)
			log.Infof("  source=%v", v.Source)
		}
	}
	return true
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

	bigip := f5.NewSession(*bigipUrl, *bigipUsername, *bigipPassword)
	serviceEventStream := eventStream.NewServiceEventStream(kubeClient.Core(), *namespace, 5)
	serviceEventStream.Run()
	defer serviceEventStream.Stop()

	configMapEventStream := eventStream.NewConfigMapEventStream(kubeClient.Core(), *namespace, 5)
	configMapEventStream.Run()
	defer configMapEventStream.Stop()

	errCt := 0
	for {
		ok := showPods(kubeClient)
		if !ok {
			errCt += 1
		}

		ok = showVirtualServers(bigip)
		if !ok {
			errCt += 1
		}

		if errCt >= 10 {
			log.Fatalf("Too many errors, exiting")
		}
		time.Sleep(30 * time.Second)
	}
}
