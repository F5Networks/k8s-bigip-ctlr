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
	"context"
	"fmt"
	"k8s.io/client-go/rest"
	"os"
	"sort"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func (poolInfr *MultiClusterPoolInformer) start() {
	var cacheSyncs []cache.InformerSynced
	if poolInfr.svcInformer != nil {
		log.Infof("[MultiCluster] Starting Service Informer for Cluster:%v", poolInfr.clusterName)
		go poolInfr.svcInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.svcInformer.HasSynced)
	}
	if poolInfr.epsInformer != nil {
		log.Infof("[MultiCluster] Starting Endpoint Informer for Cluster:%v", poolInfr.clusterName)
		go poolInfr.epsInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.epsInformer.HasSynced)
	}
	if poolInfr.podInformer != nil {
		log.Infof("[MultiCluster] Starting Pod Informer for Cluster:%v", poolInfr.clusterName)
		go poolInfr.podInformer.Run(poolInfr.stopCh)
		cacheSyncs = append(cacheSyncs, poolInfr.podInformer.HasSynced)
	}
	// Wait for the all informer caches for the cluster to be synced before proceeding further to ensure it has the latest data.
	// Typically, informer cache synchronization is a fast process.However, if it takes longer than 30 seconds, it may
	// indicate an issue with the API server of the cluster.
	// To avoid CIS getting blocked indefinitely, we are setting a timeout of 30 seconds and then CIS will continue to
	// proceed further after logging the error to indicate the admin which cluster is having issues.
	// However, since we haven't stopped the informers, if the affected API server starts responding later on then CIS
	// will start processing the events as and when it receives those from the affected cluster.
	infSyncCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	log.Debugf("[MultiCluster] Waiting for 30 Seconds for informer caches to sync for Cluster: %s", poolInfr.clusterName)
	if cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		infSyncCtx.Done(),
		cacheSyncs...,
	) {
		log.Debugf("[MultiCluster] Successfully synced informer caches for Cluster: %s", poolInfr.clusterName)
	} else {
		log.Warningf("[MultiCluster] Failed to sync informer caches for Cluster: %s, possibly due to an unavailable "+
			"API server in Cluster: %s", poolInfr.clusterName, poolInfr.clusterName)
	}
}

func (poolInfr *MultiClusterPoolInformer) stop() {
	close(poolInfr.stopCh)
}

//func (ctlr *Controller) getMultiClusterNamespacedPoolInformer(
//	namespace string,
//	clusterName string,
//) (*MultiClusterPoolInformer, bool) {
//	if ctlr.watchingAllNamespaces() {
//		namespace = ""
//	}
//
//	if ctlr.multiClusterPoolInformers == nil {
//		log.Debugf("[MultiCluster] informer not found for cluster %v", clusterName)
//		return nil, false
//	}
//
//	if _, ok := ctlr.multiClusterPoolInformers[clusterName]; ok {
//		poolInf, found := ctlr.multiClusterPoolInformers[clusterName][namespace]
//		return poolInf, found
//	}
//	return nil, false
//}

func (ctlr *Controller) addMultiClusterNamespacedInformers(
	clusterName string,
	namespace string,
	restClientV1 rest.Interface,
	startInformer bool,
) error {

	// add common informers  in all modes
	if _, found := ctlr.multiClusterPoolInformers[clusterName]; !found {
		ctlr.multiClusterPoolInformers[clusterName] = make(map[string]*MultiClusterPoolInformer)
	}
	if _, found := ctlr.multiClusterPoolInformers[clusterName][namespace]; !found {
		poolInfr := ctlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClientV1)
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
) *MultiClusterPoolInformer {
	log.Debugf("[MultiCluster] Creating multi cluster pool Informers for Namespace: %v %v", namespace, getClusterLog(clusterName))
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
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
	}
	//enable pod informer for nodeport local mode and openshift mode
	if ctlr.PoolMemberType == NodePortLocal {
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
	if ctlr.PoolMemberType == Cluster {
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
}

// whenever global configCR is modified check for removed cluster configs
// if any of the cluster config is removed from global CM. stop the respective cluster informers
func (ctlr *Controller) stopDeletedGlobalCRMultiClusterInformers() error {

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
	if _, ok := ctlr.multiClusterNodeInformers[clusterName]; ok {
		delete(ctlr.multiClusterNodeInformers, clusterName)
	}
	return nil
}

// setup multi cluster informer
func (ctlr *Controller) setupAndStartMultiClusterInformers(svcKey MultiClusterServiceKey) error {
	if config, ok := ctlr.multiClusterConfigs.ClusterConfigs[svcKey.clusterName]; ok {
		restClient := config.KubeClient.CoreV1().RESTClient()
		if err := ctlr.addMultiClusterNamespacedInformers(svcKey.clusterName, svcKey.namespace, restClient, true); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", svcKey.clusterName, svcKey.namespace, err)
			return err
		}
		err := ctlr.setupMultiClusterNodeInformers(svcKey.clusterName)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("[MultiCluster] cluster config not found for cluster: %v", svcKey.clusterName)
	}
	return nil
}

// setupAndStartHAClusterInformers sets up and starts informers for the HA pair cluster
func (ctlr *Controller) setupAndStartHAClusterInformers(clusterName string) error {
	restClient := ctlr.multiClusterConfigs.ClusterConfigs[clusterName].KubeClient.CoreV1().RESTClient()
	// Setup informers with namespaces which are watched by CIS
	for n := range ctlr.namespaces {
		if err := ctlr.addMultiClusterNamespacedInformers(clusterName, n, restClient, true); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", clusterName, n, err)
			return err
		}
	}
	err := ctlr.setupMultiClusterNodeInformers(clusterName)
	if err != nil {
		return err
	}
	return nil
}

// setupMultiClusterNodeInformers sets up and starts node informers for cluster if it hasn't been started
func (ctlr *Controller) setupMultiClusterNodeInformers(clusterName string) error {
	if _, ok := ctlr.multiClusterNodeInformers[clusterName]; !ok {
		nodeInf := ctlr.getNodeInformer(clusterName)
		ctlr.addNodeEventUpdateHandler(&nodeInf)
		nodeInf.start()
		time.Sleep(100 * time.Millisecond)
		ctlr.multiClusterNodeInformers[clusterName] = &nodeInf
		nodesIntfc := nodeInf.nodeInformer.GetIndexer().List()
		var nodesList []corev1.Node
		for _, obj := range nodesIntfc {
			node := obj.(*corev1.Node)
			nodesList = append(nodesList, *node)
		}
		sort.Sort(NodeList(nodesList))
		nodes, err := ctlr.getNodes(nodesList)
		if err != nil {
			return err
		}
		nodeInf.oldNodes = nodes
	}
	return nil
}

// if CIS is running in secondary then endPoint is mandatory
// if endPoint is configured then CIS will exit
func (ctlr *Controller) checkSecondaryCISConfig() {
	if ctlr.multiClusterMode == SecondaryCIS && ctlr.Agent.PrimaryClusterHealthProbeParams.EndPoint == "" {
		log.Debugf("[MultiCluster] error: cis running in secondary mode and missing primaryEndPoint under highAvailabilityCIS section. ")
		os.Exit(1)
	}
}

func (ctlr *Controller) getNamespaceMultiClusterPoolInformer(
	namespace string, clusterName string,
) (*MultiClusterPoolInformer, bool) {
	// CIS may be watching all namespaces in case of HA clusters only
	if clusterName == ctlr.multiClusterConfigs.HAPairClusterName && ctlr.watchingAllNamespaces() {
		namespace = ""
	}
	nsPoolInf, ok := ctlr.multiClusterPoolInformers[clusterName]
	if !ok {
		return nil, false
	}
	poolInf, found := nsPoolInf[namespace]
	return poolInf, found
}
