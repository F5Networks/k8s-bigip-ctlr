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

func (ctlr *Controller) setupMultiClusterInformers() error {
	for cluster, config := range ctlr.multiClusterConfigs.ClusterConfigs {
		restClient := config.KubeClient.CoreV1().RESTClient()
		for n := range ctlr.namespaces {
			if err := ctlr.addMultiClusterNamespacedInformers(cluster, n, restClient, false); err != nil {
				log.Errorf("Unable to setup informer for cluster,namespace: %v, %v, Error: %v", cluster, n, err)
				return err
			}
		}
	}
	return nil
}

func (ctlr *Controller) setupMultiClusterNamespaceLabeledInformers() error {
	for cluster, config := range ctlr.multiClusterConfigs.ClusterConfigs {
		restClient := config.KubeClient.CoreV1().RESTClient()
		if err := ctlr.addMultiClusterNamespaceLabeledInformer(ctlr.namespaceLabel, restClient, cluster); err != nil {
			log.Errorf("Unable to setup namespacedLabel informer "+
				"for cluster: %v, %v, Error: %v", cluster, err)
			return err
		}
	}
	return nil
}

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
		namespace: namespace,
		cluster:   cluster,
		stopCh:    make(chan struct{}),
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
	return comInf
}

func (ctlr *Controller) addMultiClusterCommonRscEventHandlers(comInf *MultiClusterCommonInformer) {
	if comInf.svcInformer != nil {
		comInf.svcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueService(obj, comInf.cluster) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueUpdatedService(obj, cur, comInf.cluster) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedService(obj, comInf.cluster) },
			},
		)
	}

	if comInf.epsInformer != nil {
		comInf.epsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueEndpoints(obj, Create, comInf.cluster) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueEndpoints(cur, Update, comInf.cluster) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueEndpoints(obj, Delete, comInf.cluster) },
			},
		)
	}

	if comInf.podInformer != nil {
		comInf.podInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePod(obj, comInf.cluster) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePod(cur, comInf.cluster) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPod(obj, comInf.cluster) },
			},
		)
	}

	if comInf.nodeInformer != nil {
		comInf.nodeInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.SetupNodeProcessing(comInf.cluster) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.SetupNodeProcessing(comInf.cluster) },
				DeleteFunc: func(obj interface{}) { ctlr.SetupNodeProcessing(comInf.cluster) },
			},
		)
	}
}

func (ctlr *Controller) addMultiClusterNamespaceLabeledInformer(label string, restClientv1 rest.Interface,
	cluster string) error {
	selector, err := createLabelSelector(label)
	if err != nil {
		return fmt.Errorf("unable to setup namespace-label informer for label: %v, Error:%v", label, err)
	}
	namespaceOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = selector.String()
	}

	if 0 != len(ctlr.crInformers) {
		return fmt.Errorf("cannot set a namespace label informer when informers " +
			"have been setup for one or more namespaces")
	}

	resyncPeriod := 0 * time.Second

	ctlr.nsMultiClustersInformers[label] = &NSInformer{
		stopCh:  make(chan struct{}),
		cluster: cluster,
		nsInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"namespaces",
				"",
				namespaceOptions,
			),
			&corev1.Namespace{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}

	ctlr.nsMultiClustersInformers[label].nsInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { ctlr.enqueueNamespace(obj, cluster) },
			DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedNamespace(obj, cluster) },
		},
		resyncPeriod,
	)

	return nil
}

func (ctlr *Controller) updateMultiClusterInformers() error {

	// this method can be optimized
	// this needs to be tested in multi cluster environment
	if ctlr.multiClusterConfigs == nil {
		return nil
	}

	newClusters := make([]string, 0)

	// remove the informers for clusters whose config has been removed
	for cluster, clsSet := range ctlr.comMultiClusterInformers {
		// if cluster config not present in global CM remove the informer
		if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[cluster]; !ok {
			for _, nsComInf := range clsSet {
				nsComInf.stop()
			}
			delete(ctlr.comMultiClusterInformers, cluster)
		}
	}

	// set up informers for the clusters which are newly added
	// don't start informers
	for cluster, clsConfig := range ctlr.multiClusterConfigs.ClusterConfigs {
		// if cluster present in global CM and not in common informer - set up the informer
		restClient := clsConfig.KubeClient.CoreV1().RESTClient()
		if _, ok := ctlr.comMultiClusterInformers[cluster]; !ok {
			newClusters = append(newClusters, cluster)
			for n := range ctlr.namespaces {
				if err := ctlr.addMultiClusterNamespacedInformers(cluster, n, restClient, false); err != nil {
					log.Errorf("Unable to setup informer for cluster,namespace: %v, %v, Error: %v", cluster, n, err)
					return err
				}
			}
		}
	}

	if len(newClusters) == 0 {
		return nil
	}

	var refClusters map[string]string
	switch ctlr.mode {
	case OpenShiftMode, KubernetesMode:
		refClusters, _ = ctlr.getRouteSvcClusters()
	default:
		// need to implement this logic when Custom Resources are supported in multi cluster mode
		//clusters, _ = ctlr.getCustomResourceClusters()

	}

	//start the informers for the new cluster references
	for _, cls := range newClusters {
		// if new cluster found in the referred service
		if _, found := refClusters[cls]; found {
			if ctlr.comMultiClusterInformers != nil {
				if _, ok := ctlr.comMultiClusterInformers[cls]; ok {
					for _, clsSet := range ctlr.comMultiClusterInformers[cls] {
						clsSet.start()
					}
				}
			}
		}
	}
	return nil
}
