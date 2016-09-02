package main

import (
	"flag"
	"os"
	"time"

	log "velcro/vlogger"
	clog "velcro/vlogger/console"

	f5 "github.com/scottdware/go-bigip"
	"github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/kubectl/cmd/util"
)

var (
	flags     = pflag.NewFlagSet("", pflag.ExitOnError)
	inCluster = flags.Bool("running-in-cluster", true,
		`Optional, if this controller is running in a kubernetes cluster, use the
		 pod secrets for creating a Kubernetes client.`)
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

func showPods(kubeClient *unversioned.Client) bool {
	pods := &api.PodList{}
	var opts api.ListOptions
	err := kubeClient.Get().Namespace("default").Resource("pods").VersionedParams(&opts, api.ParameterCodec).Do().Into(pods)
	if err != nil {
		log.Errorf("err=%+v", err)
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
	flags.AddGoFlagSet(flag.CommandLine)
	flags.Parse(os.Args)
	clientConfig := util.DefaultClientConfig(flags)
	if len(*bigipUrl) == 0 {
		log.Fatalf("The Big-IP URL is required")
	}
	if len(*bigipUsername) == 0 {
		log.Fatalf("The Big-IP user name is required")
	}
	if len(*bigipPassword) == 0 {
		log.Fatalf("The Big-IP password is required")
	}

	var kubeClient *unversioned.Client
	var err error
	if *inCluster {
		kubeClient, err = unversioned.NewInCluster()
	} else {
		config, connErr := clientConfig.ClientConfig()
		if connErr != nil {
			log.Fatalf("error connecting to the client: %v", err)
		}
		kubeClient, err = unversioned.New(config)
	}

	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	bigip := f5.NewSession(*bigipUrl, *bigipUsername, *bigipPassword)

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
