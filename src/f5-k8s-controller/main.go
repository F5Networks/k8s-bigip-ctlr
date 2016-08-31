package main

import (
	"flag"
	"os"
	"time"

	log "velcro/vlogger"
	clog "velcro/vlogger/console"

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

func main() {
	initLogger()
	flags.AddGoFlagSet(flag.CommandLine)
	flags.Parse(os.Args)
	clientConfig := util.DefaultClientConfig(flags)

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

	errCt := 0
	for {
		ok := showPods(kubeClient)
		if !ok {
			errCt += 1
			if errCt >= 10 {
				log.Fatalf("Too many errors, exiting")
			}
		}
		time.Sleep(30 * time.Second)
	}
}
