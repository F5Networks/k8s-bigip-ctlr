/*-
* Copyright (c) 2016-2020, F5 Networks, Inc.
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

package ipammachinery

import (
	"fmt"
	"time"

	ficInfV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/client/informers/externalversions/fic/v1"
	log "github.com/F5Networks/f5-ipam-controller/pkg/vlogger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// start the ipam informer
func (ipamInfr *IPAMInformer) start() {
	var cacheSyncs []cache.InformerSynced

	if ipamInfr.ipamInformer != nil {
		log.Infof("Starting IPAMClient Informer")
		go ipamInfr.ipamInformer.Run(ipamInfr.stopCh)
		cacheSyncs = append(cacheSyncs, ipamInfr.ipamInformer.HasSynced)
	}

	cache.WaitForNamedCacheSync(
		"F5 IPAMClient Controller",
		ipamInfr.stopCh,
		cacheSyncs...,
	)
}

func (ipamInfr *IPAMInformer) stop() {
	close(ipamInfr.stopCh)
}

func (ipamCli *IPAMClient) watchingAllNamespaces() bool {
	if 0 == len(ipamCli.ipamInformers) {
		// Not watching any namespaces.
		return false
	}
	_, watchingAll := ipamCli.ipamInformers[""]
	return watchingAll
}

func (ipamCli *IPAMClient) addNamespacedInformer(
	namespace string,
	eventHandlers *cache.ResourceEventHandlerFuncs,
) error {
	if ipamCli.watchingAllNamespaces() {
		return fmt.Errorf(
			"Cannot add additional namespaces when already watching all.")
	}
	if len(ipamCli.ipamInformers) > 0 && "" == namespace {
		return fmt.Errorf(
			"Cannot watch all namespaces when already watching specific ones.")
	}
	var crInf *IPAMInformer
	var found bool
	if crInf, found = ipamCli.ipamInformers[namespace]; found {
		return nil
	}
	crInf = ipamCli.newNamespacedInformer(namespace)
	ipamCli.addEventHandlers(crInf, eventHandlers)
	ipamCli.ipamInformers[namespace] = crInf
	return nil
}

func (ipamCli *IPAMClient) newNamespacedInformer(
	namespace string,
) *IPAMInformer {
	log.Debugf("[ipam] Creating Informers for Namespace %v", namespace)
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}

	resyncPeriod := 0 * time.Second
	// restClientv1 := ipamCli.kubeClient.CoreV1().RESTClient()

	ipamInf := &IPAMInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
	}

	ipamInf.ipamInformer = ficInfV1.NewFilteredF5IPAMInformer(
		ipamCli.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		everything,
	)

	return ipamInf
}

func (ipamCli *IPAMClient) addEventHandlers(
	ipamInf *IPAMInformer,
	eventHandlers *cache.ResourceEventHandlerFuncs,
) {
	if ipamInf.ipamInformer != nil {
		ipamInf.ipamInformer.AddEventHandler(
			eventHandlers,
		)
	}
}

func (ipamCli *IPAMClient) getNamespacedInformer(
	namespace string,
) (*IPAMInformer, bool) {
	if ipamCli.watchingAllNamespaces() {
		namespace = ""
	}
	ipamInf, found := ipamCli.ipamInformers[namespace]
	return ipamInf, found
}
