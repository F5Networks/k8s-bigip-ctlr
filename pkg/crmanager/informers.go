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
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func (crInfr *CRInformer) start() {
	if crInfr.vsInformer != nil {
		go crInfr.vsInformer.Run(crInfr.stopCh)
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
		vsInformer: cisinfv1.NewFilteredVirtualServerInformer(
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
	key := rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   vs.ObjectMeta.Name,
	}

	crMgr.rscQueue.Add(key)

}
