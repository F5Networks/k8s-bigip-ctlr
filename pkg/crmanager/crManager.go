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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
)

const (
	DefaultCustomResourceLabel = "f5cr in (true)"
	VirtualServer              = "VirtualServer"
	Service                    = "Service"
	Endpoint                   = "Endpoint"
)

func NewCRManager(params Params) *CRManager {

	crMgr := &CRManager{
		namespaces:  params.Namespaces,
		crInformers: make(map[string]*CRInformer),
		rscQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller"),
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

	go crMgr.Start()
	return crMgr
}

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

func (crMgr *CRManager) setupClients(config *rest.Config) error {
	kubeClient, err := versioned.NewForConfig(config)

	if err != nil {
		return fmt.Errorf("Failed to create KubeClient: %v", err)
	}

	log.Debug("Client Created")
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

func (crMgr *CRManager) Start() {
	defer utilruntime.HandleCrash()
	defer crMgr.rscQueue.ShutDown()
	for _, inf := range crMgr.crInformers {
		inf.start()
	}

	stopChan := make(chan struct{})
	go wait.Until(crMgr.customResourceWorker, time.Second, stopChan)

	<-stopChan
	crMgr.Stop()
}

func (crMgr *CRManager) Stop() {
	for _, inf := range crMgr.crInformers {
		inf.stop()
	}
}
