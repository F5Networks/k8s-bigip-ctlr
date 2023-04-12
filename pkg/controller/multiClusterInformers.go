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

func (comInfr *MultiClusterCommonInformer) start() {
	var cacheSyncs []cache.InformerSynced
	if comInfr.svcInformer != nil {
		go comInfr.svcInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.svcInformer.HasSynced)
	}
	if comInfr.epsInformer != nil {
		go comInfr.epsInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.epsInformer.HasSynced)
	}
	if comInfr.podInformer != nil {
		go comInfr.podInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.podInformer.HasSynced)
	}
	if comInfr.nodeInformer != nil {
		go comInfr.nodeInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.nodeInformer.HasSynced)
	}
	cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		comInfr.stopCh,
		cacheSyncs...,
	)
}

func (comInfr *MultiClusterCommonInformer) stop() {
	close(comInfr.stopCh)
}

func (ctlr *Controller) getNamespacedClusterCommonInformer(
	namespace string,
	cluster string,
) (*MultiClusterCommonInformer, bool) {
	if ctlr.watchingAllNamespaces() {
		namespace = ""
	}

	if ctlr.comMultiClusterInformers == nil {
		log.Debugf("informer not found for cluster %v", cluster)
		return nil, false
	}

	if _, ok := ctlr.comMultiClusterInformers[cluster]; ok {
		comInf, found := ctlr.comMultiClusterInformers[cluster][namespace]
		return comInf, found
	}
	return nil, false
}

func (ctlr *Controller) addMultiClusterNamespacedInformers(
	cluster string,
	namespace string,
	restClientV1 rest.Interface,
	startInformer bool,
) error {

	// add common informers  in all modes
	if _, found := ctlr.comMultiClusterInformers[cluster]; !found {
		ctlr.comMultiClusterInformers[cluster] = make(map[string]*MultiClusterCommonInformer)
		comInf := ctlr.newMultiClusterNamespacedCommonRscInformer(namespace, cluster, restClientV1)
		ctlr.addMultiClusterCommonRscEventHandlers(comInf)
		ctlr.comMultiClusterInformers[cluster][namespace] = comInf
		if startInformer {
			comInf.start()
		}
	}

	return nil
}

func (ctlr *Controller) newMultiClusterNamespacedCommonRscInformer(
	namespace string,
	cluster string,
	restClientv1 rest.Interface,
) *MultiClusterCommonInformer {
	log.Debugf("Creating Common Resource Informers for Namespace: %v", namespace)
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	nodeOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = ctlr.nodeLabelSelector
	}
	resyncPeriod := 0 * time.Second
	comInf := &MultiClusterCommonInformer{
		namespace:   namespace,
		clusterName: cluster,
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

func (ctlr *Controller) addMultiClusterCommonRscEventHandlers(comInf *MultiClusterCommonInformer) {
	if comInf.svcInformer != nil {
		comInf.svcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueService(obj, comInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueUpdatedService(obj, cur, comInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedService(obj, comInf.clusterName) },
			},
		)
	}

	if comInf.epsInformer != nil {
		comInf.epsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueEndpoints(obj, Create, comInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueEndpoints(cur, Update, comInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueEndpoints(obj, Delete, comInf.clusterName) },
			},
		)
	}
	if comInf.podInformer != nil {
		comInf.podInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePod(obj, comInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePod(cur, comInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPod(obj, comInf.clusterName) },
			},
		)
	}

	if comInf.nodeInformer != nil {
		comInf.nodeInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.SetupNodeProcessing(comInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.SetupNodeProcessing(comInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.SetupNodeProcessing(comInf.clusterName) },
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
	for clusterName, clsSet := range ctlr.comMultiClusterInformers {
		// if cluster config not present in global CM remove the informer
		if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[clusterName]; !ok {
			for _, nsComInf := range clsSet {
				nsComInf.stop()
			}
			delete(ctlr.comMultiClusterInformers, clusterName)
		}
	}

	return nil
}

func (ctlr *Controller) stopMultiClusterInformers(clusterName string) error {

	// remove the informers for clusters whose config has been removed
	if clsSet, ok := ctlr.comMultiClusterInformers[clusterName]; ok {
		for _, nsComInf := range clsSet {
			nsComInf.stop()
			delete(ctlr.comMultiClusterInformers, clusterName)
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
