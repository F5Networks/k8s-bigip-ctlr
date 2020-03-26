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
	"github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	cistypesv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	cisv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

const (
	DefaultCustomResourceLabel = "f5cr in (true)"
)

func NewCRManager(params Params) *CRManager {

	crMgr := &CRManager{
		namespaces:  params.Namespaces,
		crInformers: make(map[string]*CRInformer),
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

	crMgr.startInformers()
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

func (crMgr *CRManager) watchingAllNamespaces() bool {
	if 0 == len(crMgr.crInformers) {
		// Not watching any namespaces.
		return false
	}
	_, watchingAll := crMgr.crInformers[""]
	return watchingAll
}

func (crMgr *CRManager) addNamespacedInformer(
	namespace string,
) error {
	if crMgr.watchingAllNamespaces() {
		return fmt.Errorf(
			"Cannot add additional namespaces when already watching all.")
	}
	if len(crMgr.crInformers) > 0 && "" == namespace {
		return fmt.Errorf(
			"Cannot watch all namespaces when already watching specific ones.")
	}
	var crInf *CRInformer
	var found bool
	if crInf, found = crMgr.crInformers[namespace]; found {
		return nil
	}
	crInf = crMgr.newInformer(namespace)
	crMgr.crInformers[namespace] = crInf
	return nil
}

func (crMgr *CRManager) newInformer(
	namespace string,
) *CRInformer {
	log.Debugf("Creating Informers for Namespace %v", namespace)
	crOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = crMgr.resourceSelector.String()
	}

	crInf := &CRInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
		vsInformer: cisv1.NewFilteredVirtualServerInformer(
			crMgr.kubeClient,
			namespace,
			0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			crOptions,
		),
	}

	crInf.vsInformer.AddEventHandler(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { crMgr.enqueueVirtualServer(obj) },
			UpdateFunc: func(old, cur interface{}) { crMgr.enqueueVirtualServer(cur) },
			DeleteFunc: func(obj interface{}) { crMgr.enqueueVirtualServer(obj) },
		},
	)

	return crInf
}

func (crMgr *CRManager) enqueueVirtualServer(obj interface{}) {
	vs := obj.(*cistypesv1.VirtualServer)
	log.Infof("Enqueueing VirtualServer: %v", vs)
}

func (crMgr *CRManager) startInformers() {
	for _, inf := range crMgr.crInformers {
		inf.start()
	}
}

func (crMgr *CRManager) Stop() {
	for _, inf := range crMgr.crInformers {
		inf.stop()
	}
}

func (crInfr *CRInformer) start() {
	if crInfr.vsInformer != nil {
		go crInfr.vsInformer.Run(crInfr.stopCh)
	}
}

func (crInfr *CRInformer) stop() {
	close(crInfr.stopCh)
}
