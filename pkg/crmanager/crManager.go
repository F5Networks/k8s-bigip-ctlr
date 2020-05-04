/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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

package crmanager

import (
	"fmt"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
)

const (
	// DefaultCustomResourceLabel is a label used for F5 Custom Resources.
	DefaultCustomResourceLabel = "f5cr in (true)"
	// VirtualServer is a F5 Custom Resource Kind.
	VirtualServer = "VirtualServer"
	// Service is a k8s native Service Resource.
	Service = "Service"
	// Endpoints is a k8s native Endpoint Resource.
	Endpoints = "Endpoints"

	NodePortMode = "nodeport"
)

// NewCRManager creates a new CRManager Instance.
func NewCRManager(params Params) *CRManager {

	crMgr := &CRManager{
		namespaces:  params.Namespaces,
		crInformers: make(map[string]*CRInformer),
		rscQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller"),
		resources:       NewResources(),
		Agent:           params.Agent,
		ControllerMode:  params.ControllerMode,
		UseNodeInternal: params.UseNodeInternal,
		initState:       true,
	}

	log.Debug("Custom Resource Manager Created")
	if len(params.Namespaces) == 0 {
		crMgr.namespaces = []string{""}
		log.Debug("No namespaces provided. Watching all namespaces")
	}
	crMgr.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)

	if err := crMgr.setupClients(params.Config); err != nil {
		log.Errorf("Failed to Setup Clients: %v", err)
	}

	if err := crMgr.setupInformers(); err != nil {
		log.Error("Failed to Setup Informers")
	}

	err := crMgr.SetupNodePolling(
		params.NodePollInterval,
		params.NodeLabelSelector,
		params.VXLANMode,
		params.VXLANName,
	)
	if err != nil {
		log.Errorf("Failed to Setup Node Polling: %v", err)
	}
	go crMgr.Start()
	return crMgr
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
func (crMgr *CRManager) setupClients(config *rest.Config) error {
	kubeCRClient, err := versioned.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create Custum Resource kubeClient: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create kubeClient: %v", err)
	}

	log.Debug("Client Created")
	crMgr.kubeCRClient = kubeCRClient
	crMgr.kubeClient = kubeClient
	return nil
}

func (crMgr *CRManager) setupInformers() error {
	for _, n := range crMgr.namespaces {
		if err := crMgr.addNamespacedInformer(n); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v, Error:%v", n, err)
		}
	}
	return nil
}

// Start the Custom Resource Manager
func (crMgr *CRManager) Start() {
	log.Infof("Starting Custom Resource Manager")
	defer utilruntime.HandleCrash()
	defer crMgr.rscQueue.ShutDown()

	for _, inf := range crMgr.crInformers {
		inf.start()
	}

	crMgr.nodePoller.Run()

	stopChan := make(chan struct{})
	go wait.Until(crMgr.customResourceWorker, time.Second, stopChan)

	<-stopChan
	crMgr.Stop()
}

// Stop the Custom Resource Manager.
func (crMgr *CRManager) Stop() {
	for _, inf := range crMgr.crInformers {
		inf.stop()
	}
	crMgr.nodePoller.Stop()
	crMgr.Agent.Stop()
}
