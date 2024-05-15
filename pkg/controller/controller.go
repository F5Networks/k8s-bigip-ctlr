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
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/ipmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
)

// RunController creates a new controller and starts it.
func RunController(params Params) *Controller {

	// create the status manager first
	// create the new status manager
	keys := strings.Split(params.CISConfigCRKey, "/")
	statusManager := statusmanager.NewStatusManager(&params.ClientSets.KubeCRClient, keys[0], keys[1])

	// start the status manager
	go statusManager.Start()

	ctlr := NewController(params, statusManager)

	// add the informers for namespaces and node
	ctlr.addInformers()

	// Start Sync CM token Manager
	go ctlr.CMTokenManager.Start(make(chan struct{}))

	// start request handler
	ctlr.RequestHandler.startRequestHandler()

	// start response handler
	go ctlr.responseHandler(ctlr.respChan)

	// start the networkConfigHandler
	if ctlr.networkManager != nil {
		go ctlr.networkManager.NetworkConfigHandler()
	}

	// setup postmanager for bigip label
	for bigip, _ := range ctlr.bigIpConfigMap {
		ctlr.RequestHandler.startPostManager(bigip)
	}

	// enable http endpoint
	go ctlr.enableHttpEndpoint(params.HttpAddress)

	go ctlr.Start()

	return ctlr
}

// NewController creates a new Controller Instance.
func NewController(params Params, statusManager *statusmanager.StatusManager) *Controller {

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
			params.CMSSLInsecure,
			statusManager),
		managedResources: ManagedResources{
			ManageCustomResources: true,
			ManageTransportServer: true,
			ManageIL:              true,
		},
		bigIpConfigMap: make(BigIpConfigMap),
		PostParams:     PostParams{},
		clientsets:     params.ClientSets,
	}

	log.Debug("Controller Created")

	// fetch the CM token
	ctlr.CMTokenManager.SyncToken()

	ctlr.resourceQueue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.DefaultControllerRateLimiter(),
		workqueue.RateLimitingQueueConfig{Name: "nextgen-resource-controller"})

	// set extended spec configCR for all
	ctlr.CISConfigCRKey = params.CISConfigCRKey

	// Initialize the controller with base resources in CIS config CR
	ctlr.initController()

	// create the new request handler
	ctlr.NewRequestHandler(params.UserAgent, params.httpClientMetrics)

	return ctlr
}

func (ctlr *Controller) NewRequestHandler(userAgent string, httpClientMetrics bool) {
	ctlr.RequestHandler = &RequestHandler{
		PostManagers:      PostManagers{sync.RWMutex{}, make(map[cisapiv1.BigIpConfig]*PostManager)},
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

		ctlr.ipamHandler = ipmanager.NewIpamHandler(ctlr.ControllerIdentifier, params.Config, ipamClient)

		ctlr.ipamHandler.RegisterIPAMCRD()
		time.Sleep(3 * time.Second)
		_ = ctlr.ipamHandler.CreateIPAMResource()
	}
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

// Start the Controller
func (ctlr *Controller) Start() {
	log.Debugf("Starting Controller")
	defer utilruntime.HandleCrash()
	defer ctlr.resourceQueue.ShutDown()

	// Start Informers
	ctlr.startInformers()

	if ctlr.ipamHandler != nil {
		go ctlr.ipamHandler.IpamCli.Start()
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
	if ctlr.ipamHandler != nil {
		ctlr.ipamHandler.IpamCli.Stop()
	}
	// Stop the status manager
	ctlr.CMTokenManager.StatusManager.Stop()
}

// Set the resource count for prometheus metrics
func (ctlr *Controller) setPrometheusResourceCount() {
	prometheus.ManagedServices.Set(float64(LenSyncMap(&ctlr.resources.poolMemCache)))
	prometheus.ManagedTransportServers.Set(float64(len(ctlr.TeemData.ResourceType.TransportServer) + len(ctlr.TeemData.ResourceType.IPAMTS)))
}
