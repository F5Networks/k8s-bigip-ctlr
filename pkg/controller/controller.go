/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
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

package controller

import (
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"

	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
)

// NewController creates a new Controller Instance.
func NewController(params Params) *Controller {

	ctlr := &Controller{
		resources:             NewResourceStore(),
		UseNodeInternal:       params.UseNodeInternal,
		initState:             true,
		defaultRouteDomain:    params.DefaultRouteDomain,
		multiClusterConfigs:   clustermanager.NewMultiClusterConfig(),
		multiClusterResources: newMultiClusterResourceStore(),
		multiClusterMode:      params.MultiClusterMode,
		clusterRatio:          make(map[string]*int),
		clusterAdminState:     make(map[string]cisapiv1.AdminState),
		respChan:              make(chan *agentConfig, 1),
		CMTokenManager: tokenmanager.NewTokenManager(
			params.CMConfigDetails.URL,
			tokenmanager.Credentials{Username: params.CMConfigDetails.UserName, Password: params.CMConfigDetails.Password},
			params.CMTrustedCerts,
			params.CMSSLInsecure),
		managedResources: ManagedResources{
			ManageCustomResources: true,
			ManageTransportServer: true,
		},
		bigIpMap:   make(BigIpMap),
		PostParams: PostParams{},
	}

	log.Debug("Controller Created")
	// fetch the CM token
	err := ctlr.CMTokenManager.FetchToken()
	if err != nil {
		log.Errorf("Failed to Fetch Token: %v", err)
		os.Exit(1)
	}
	// Sync CM token
	go ctlr.CMTokenManager.SyncToken(make(chan struct{}))
	ctlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "nextgen-resource-controller")

	// set extended spec configCR for all
	ctlr.CISConfigCRKey = params.CISConfigCRKey

	if err := ctlr.setupClients(params.Config); err != nil {
		log.Errorf("Failed to Setup Clients: %v", err)
	}

	// Initialize the controller with base resources in CIS config CR
	ctlr.initController()

	// create the informers for namespaces and node
	if err3 := ctlr.setupInformers(); err3 != nil {
		log.Error("Failed to Setup Informers")
	}

	// start request handler
	ctlr.NewRequestHandler(params.UserAgent, params.httpClientMetrics)
	ctlr.RequestHandler.startRequestHandler()

	// start response handler
	go ctlr.responseHandler(ctlr.respChan)

	// start the networkConfigHandler
	if ctlr.networkManager != nil {
		go ctlr.networkManager.NetworkConfigHandler()
	}
	// setup postmanager for bigip label
	for bigip, _ := range ctlr.bigIpMap {
		ctlr.RequestHandler.startPostManager(bigip)
	}

	// enable http endpoint
	go ctlr.enableHttpEndpoint(params.HttpAddress)

	// setup ipam
	ctlr.setupIPAM(params)

	go ctlr.Start()

	return ctlr
}

func (ctlr *Controller) NewRequestHandler(userAgent string, httpClientMetrics bool) {
	ctlr.RequestHandler = &RequestHandler{
		PostManagers:      PostManagers{sync.RWMutex{}, make(map[BigIpKey]*PostManager)},
		reqChan:           make(chan ResourceConfigRequest, 1),
		userAgent:         userAgent,
		respChan:          ctlr.respChan,
		CMTokenManager:    ctlr.CMTokenManager,
		PostParams:        ctlr.PostParams,
		httpClientMetrics: httpClientMetrics,
	}
}
func (ctlr *Controller) setupIPAM(params Params) {
	if params.IPAM {
		ipamParams := ipammachinery.Params{
			Config:        params.Config,
			EventHandlers: ctlr.getEventHandlerForIPAM(),
			Namespaces:    []string{IPAMNamespace},
		}

		ipamClient := ipammachinery.NewIPAMClient(ipamParams)
		ctlr.ipamCli = ipamClient

		ctlr.registerIPAMCRD()
		time.Sleep(3 * time.Second)
		_ = ctlr.createIPAMResource()
	}
}

// Register IPAM CRD
func (ctlr *Controller) registerIPAMCRD() {
	err := ipammachinery.RegisterCRD(ctlr.clientsets.kubeAPIClient)
	if err != nil {
		log.Errorf("[IPAM] error while registering CRD %v", err)
	}
}

// Create IPAM CRD
func (ctlr *Controller) createIPAMResource() error {

	frameIPAMResourceName := func() string {
		prtn := ""
		for _, ch := range DEFAULT_PARTITION {
			elem := string(ch)
			if unicode.IsUpper(ch) {
				elem = strings.ToLower(elem) + "-"
			}
			prtn += elem
		}
		if string(prtn[len(prtn)-1]) == "-" {
			prtn = prtn + ipamCRName
		} else {
			prtn = prtn + "." + ipamCRName
		}

		prtn = strings.Replace(prtn, "_", "-", -1)
		prtn = strings.Replace(prtn, "--", "-", -1)

		hostsplit := strings.Split(os.Getenv("HOSTNAME"), "-")
		var host string
		if len(hostsplit) > 2 {
			host = strings.Join(hostsplit[0:len(hostsplit)-2], "-")
		} else {
			host = strings.Join(hostsplit, "-")
		}
		return strings.Join([]string{host, prtn}, ".")
	}

	crName := frameIPAMResourceName()
	f5ipam := &ficV1.IPAM{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      crName,
			Namespace: IPAMNamespace,
		},
		Spec: ficV1.IPAMSpec{
			HostSpecs: make([]*ficV1.HostSpec, 0),
		},
		Status: ficV1.IPAMStatus{
			IPStatus: make([]*ficV1.IPSpec, 0),
		},
	}
	ctlr.ipamCR = IPAMNamespace + "/" + crName

	ipamCR, err := ctlr.ipamCli.Create(f5ipam)
	if err == nil {
		log.Debugf("[IPAM] Created IPAM Custom Resource: \n%v\n", ipamCR)
		return nil
	}

	log.Debugf("[IPAM] error while creating IPAM custom resource %v", err.Error())
	return err
}

// createLabelSelector returns label used to identify F5 specific
// Custom Resources.
func createLabelSelector(label string) (labels.Selector, error) {
	var l labels.Selector
	var err error

	if label == "" {
		l = labels.Everything()
	} else {
		l, err = labels.Parse(label)
		if err != nil {
			return labels.Everything(), fmt.Errorf("failed to parse Label Selector string: %v", err)
		}
	}
	return l, nil
}

// setupClients sets Kubernetes Clients.
func (ctlr *Controller) setupClients(config *rest.Config) error {
	var kubeCRClient *versioned.Clientset
	var err error
	kubeCRClient, err = versioned.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create Custum Resource kubeClient: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create kubeClient: %v", err)
	}

	var ipamCRConfig *rest.Config
	if ipamCRConfig, err = rest.InClusterConfig(); err != nil {
		log.Errorf("error creating client configuration: %v", err)
	}
	kubeIPAMClient, err := extClient.NewForConfig(ipamCRConfig)
	if err != nil {
		log.Errorf("Failed to create client: %v", err)
	}

	var rclient *routeclient.RouteV1Client
	if ctlr.managedResources.ManageRoutes {
		rclient, err = routeclient.NewForConfig(config)
		if nil != err {
			return fmt.Errorf("Failed to create Route Client: %v", err)
		}
	}

	log.Debug("Client Created")
	ctlr.clientsets = &ClientSets{
		kubeClient:    kubeClient,
		kubeCRClient:  kubeCRClient,
		kubeAPIClient: kubeIPAMClient,
		routeClientV1: rclient,
	}
	return nil
}

// Start the Controller
func (ctlr *Controller) Start() {
	log.Debugf("Starting Controller")
	defer utilruntime.HandleCrash()
	defer ctlr.resourceQueue.ShutDown()

	// Start Informers
	ctlr.startInformers()

	if ctlr.ipamCli != nil {
		go ctlr.ipamCli.Start()
	}

	stopChan := make(chan struct{})

	go wait.Until(ctlr.nextGenResourceWorker, time.Second, stopChan)

	<-stopChan
	ctlr.Stop()
}

// Stop the Controller
func (ctlr *Controller) Stop() {
	// stop the informers
	ctlr.stopInformers()
	if ctlr.ipamCli != nil {
		ctlr.ipamCli.Stop()
	}

}

// Set the resource count for prometheus metrics
func (ctlr *Controller) setPrometheusResourceCount() {
	prometheus.ManagedServices.Set(float64(len(ctlr.resources.poolMemCache)))
	prometheus.ManagedTransportServers.Set(float64(len(ctlr.TeemData.ResourceType.TransportServer) + len(ctlr.TeemData.ResourceType.IPAMTS)))
}
