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
	"k8s.io/client-go/rest"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func (poolInfr *MultiClusterPoolInformer) start() {
	var cacheSyncs []cache.InformerSynced
	if poolInfr.svcInformer != nil {
		go poolInfr.svcInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.svcInformer.HasSynced)
	}
	if poolInfr.epsInformer != nil {
		go poolInfr.epsInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.epsInformer.HasSynced)
	}
	if poolInfr.podInformer != nil {
		go poolInfr.podInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.podInformer.HasSynced)
	}
	if poolInfr.nodeInformer != nil {
		go poolInfr.nodeInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.nodeInformer.HasSynced)
	}
	cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		poolInfr.stopCh,
		cacheSyncs...,
	)
}

func (poolInfr *MultiClusterPoolInformer) stop() {
	close(poolInfr.stopCh)
}

func (ctlr *Controller) getMultiClusterNamespacedPoolInformer(
	namespace string,
	clusterName string,
) (*MultiClusterPoolInformer, bool) {
	if ctlr.watchingAllNamespaces() {
		namespace = ""
	}

	if ctlr.multiClusterPoolInformers == nil {
		log.Debugf("informer not found for cluster %v", clusterName)
		return nil, false
	}

	if _, ok := ctlr.multiClusterPoolInformers[clusterName]; ok {
		poolInf, found := ctlr.multiClusterPoolInformers[clusterName][namespace]
		return poolInf, found
	}
	return nil, false
}

func (ctlr *Controller) addMultiClusterNamespacedInformers(
	clusterName string,
	namespace string,
	restClientV1 rest.Interface,
	startInformer bool,
) error {

	// add common informers  in all modes
	if _, found := ctlr.multiClusterPoolInformers[clusterName]; !found {
		ctlr.multiClusterPoolInformers[clusterName] = make(map[string]*MultiClusterPoolInformer)
		poolInfr := ctlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClientV1,
			ctlr.nodeLabelSelector)
		ctlr.addMultiClusterPoolEventHandlers(poolInfr)
		ctlr.multiClusterPoolInformers[clusterName][namespace] = poolInfr
		if startInformer {
			poolInfr.start()
		}
	}

	return nil
}

func (ctlr *Controller) newMultiClusterNamespacedPoolInformer(
	namespace string,
	clusterName string,
	restClientv1 rest.Interface,
	labelSelector string,
) *MultiClusterPoolInformer {
	log.Debugf("Creating multi cluster pool Informers for Namespace: %v", namespace)
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	nodeOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector
	}
	resyncPeriod := 0 * time.Second
	comInf := &MultiClusterPoolInformer{
		namespace:   namespace,
		clusterName: clusterName,
		stopCh:      make(chan struct{}),
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
		nodeInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"nodes",
				"",
				nodeOptions,
			),
			&corev1.Node{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}
	//enable pod informer for nodeport local mode and openshift mode
	if ctlr.PoolMemberType == NodePortLocal || ctlr.mode == OpenShiftMode {
		comInf.podInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"pods",
				namespace,
				everything,
			),
			&corev1.Pod{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}
	// enable endpoint informer in the cluster and nextGen routes mode only
	if ctlr.PoolMemberType == Cluster && ctlr.mode == OpenShiftMode {
		comInf.epsInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"endpoints",
				namespace,
				everything,
			),
			&corev1.Endpoints{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}
	return comInf
}

func (ctlr *Controller) addMultiClusterPoolEventHandlers(poolInf *MultiClusterPoolInformer) {
	if poolInf.svcInformer != nil {
		poolInf.svcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueService(obj, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueUpdatedService(obj, cur, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedService(obj, poolInf.clusterName) },
			},
		)
	}

	if poolInf.epsInformer != nil {
		poolInf.epsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueEndpoints(obj, Create, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueEndpoints(cur, Update, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueEndpoints(obj, Delete, poolInf.clusterName) },
			},
		)
	}
	if poolInf.podInformer != nil {
		poolInf.podInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePod(obj, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePod(cur, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPod(obj, poolInf.clusterName) },
			},
		)
	}

	if poolInf.nodeInformer != nil {
		poolInf.nodeInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.SetupNodeProcessing(poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.SetupNodeProcessing(poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.SetupNodeProcessing(poolInf.clusterName) },
			},
		)
	}
}

// whenever global configmap is modified check for removed cluster configs
// if any of the cluster config is removed from global CM. stop the respective cluster informers
func (ctlr *Controller) stopDeletedGlobalCMMultiClusterInformers() error {

	if ctlr.multiClusterConfigs == nil {
		return nil
	}

	// remove the informers for clusters whose config has been removed
	for clusterName, clsSet := range ctlr.multiClusterPoolInformers {
		// if cluster config not present in global CM remove the informer
		if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[clusterName]; !ok {
			for _, nsPoolInf := range clsSet {
				nsPoolInf.stop()
			}
			delete(ctlr.multiClusterPoolInformers, clusterName)
		}
	}

	return nil
}

func (ctlr *Controller) stopMultiClusterInformers(clusterName string) error {

	// remove the informers for clusters whose config has been removed
	if clsSet, ok := ctlr.multiClusterPoolInformers[clusterName]; ok {
		for _, nsPoolInf := range clsSet {
			nsPoolInf.stop()
			delete(ctlr.multiClusterPoolInformers, clusterName)
		}
	}

	return nil
}

// setup multi cluster informer
func (ctlr *Controller) setupAndStartMultiClusterInformers(clusterName string) error {
	if config, ok := ctlr.multiClusterConfigs.ClusterConfigs[clusterName]; ok {
		restClient := config.KubeClient.CoreV1().RESTClient()
		for n := range ctlr.namespaces {
			if err := ctlr.addMultiClusterNamespacedInformers(clusterName, n, restClient, true); err != nil {
				log.Errorf("unable to setup informer for cluster: %v, namespace: %v, Error: %v", clusterName, n, err)
				return err
			}
		}
	} else {
		return fmt.Errorf("cluster config not found for cluster: %v", clusterName)
	}
	return nil
}
