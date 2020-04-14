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

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// start the VirtualServer informer
func (crInfr *CRInformer) start() {
	log.Infof("Starting VirtualServer Informer")
	if crInfr.vsInformer != nil {
		go crInfr.vsInformer.Run(crInfr.stopCh)
	}
	if crInfr.svcInformer != nil {
		go crInfr.svcInformer.Run(crInfr.stopCh)
	}
	if crInfr.epsInformer != nil {
		go crInfr.epsInformer.Run(crInfr.stopCh)
	}
}

func (crInfr *CRInformer) stop() {
	close(crInfr.stopCh)
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
	crMgr.addEventHandlers(crInf)
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
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	resyncPeriod := 0 * time.Second
	restClientv1 := crMgr.kubeClient.CoreV1().RESTClient()

	crInf := &CRInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
		vsInformer: cisinfv1.NewFilteredVirtualServerInformer(
			crMgr.kubeCRClient,
			namespace,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			crOptions,
		),
		svcInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"services",
				namespace,
				everything,
			),
			&corev1.Service{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		epsInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"endpoints",
				namespace,
				everything,
			),
			&corev1.Endpoints{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}

	return crInf
}

func (crMgr *CRManager) addEventHandlers(crInf *CRInformer) {
	crInf.vsInformer.AddEventHandler(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { crMgr.enqueueVirtualServer(obj) },
			UpdateFunc: func(old, cur interface{}) { crMgr.enqueueVirtualServer(cur) },
			DeleteFunc: func(obj interface{}) { crMgr.enqueueVirtualServer(obj) },
		},
	)

	crInf.svcInformer.AddEventHandler(
		&cache.ResourceEventHandlerFuncs{
			// Ignore AddFunc for service as we dont bother about services until they are
			// mapped to VirtualServer. Any new service added and mapped to a VirtualServer
			// will be handled in the VirtualServer Informer AddFunc.
			// AddFunc:    func(obj interface{}) { crMgr.enqueueService(obj) },
			UpdateFunc: func(obj, cur interface{}) { crMgr.enqueueService(cur) },
			DeleteFunc: func(obj interface{}) { crMgr.enqueueService(obj) },
		},
	)

	crInf.epsInformer.AddEventHandler(
		&cache.ResourceEventHandlerFuncs{
			// Ignore AddFunc for endpoint as we dont bother about endpoints until they are
			// mapped to VirtualServer. Any new endpoint added and mapped to a Service
			// will be handled in the Service Informer AddFunc.
			// AddFunc:    func(obj interface{}) { crMgr.enqueueEndpoints(obj) },
			UpdateFunc: func(obj, cur interface{}) { crMgr.enqueueEndpoints(cur) },
			DeleteFunc: func(obj interface{}) { crMgr.enqueueEndpoints(obj) },
		},
	)
}

func (crMgr *CRManager) getNamespaceInformer(
	namespace string,
) (*CRInformer, bool) {
	if crMgr.watchingAllNamespaces() {
		namespace = ""
	}
	crInf, found := crMgr.crInformers[namespace]
	return crInf, found
}

func (crMgr *CRManager) enqueueVirtualServer(obj interface{}) {
	vs := obj.(*cisapiv1.VirtualServer)
	log.Infof("Enqueueing VirtualServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueService(obj interface{}) {
	svc := obj.(*corev1.Service)
	log.Infof("Enqueueing Service: %v", svc)
	key := &rqKey{
		namespace: svc.ObjectMeta.Namespace,
		kind:      Service,
		rscName:   svc.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueEndpoints(obj interface{}) {
	eps := obj.(*corev1.Endpoints)
	log.Infof("Enqueueing Endpoints: %v", eps)
	key := &rqKey{
		namespace: eps.ObjectMeta.Namespace,
		kind:      Endpoints,
		rscName:   eps.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}
