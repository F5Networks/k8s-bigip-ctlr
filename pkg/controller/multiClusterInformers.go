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
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/informers/externalversions/cis/v1"
	"os"
	"sort"
	"time"

	"k8s.io/client-go/rest"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func (ctlr *Controller) addMultiClusterNamespacedInformers(
	clusterName string,
	namespace string,
	restClientV1 rest.Interface,
	startInformer, apiServerUnreachable bool,
) error {

	// add common informers  in all modes
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(clusterName)
	informerStore := clusterConfig.InformerStore
	if informerStore == nil {
		informerStore = initInformerStore()
		ctlr.multiClusterHandler.addInformerStore(clusterName, informerStore)
	}
	// add informer for the namespace
	if _, found := informerStore.comInformers[namespace]; !found {
		poolInfr := ctlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClientV1)
		ctlr.addMultiClusterPoolEventHandlers(poolInfr)
		informerStore.comInformers[namespace] = poolInfr
		if startInformer {
			poolInfr.start(ctlr.multiClusterHandler.LocalClusterName, apiServerUnreachable)
		}
	}
	return nil
}

func (ctlr *Controller) newMultiClusterNamespacedPoolInformer(
	namespace string,
	clusterName string,
	restClientv1 rest.Interface,
) *CommonInformer {
	log.Debugf("[MultiCluster] Creating multi cluster pool Informers for Namespace: %v %v", namespace, getClusterLog(clusterName))
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	resyncPeriod := 0 * time.Second
	comInf := &CommonInformer{
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
	if ctlr.PoolMemberType == Cluster || ctlr.PoolMemberType == Auto {
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
	clusterConfigs := ctlr.multiClusterHandler.getClusterConfig(clusterName)
	crOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = ctlr.multiClusterHandler.customResourceSelector.String()
	}
	//Enable policy informer if serviceTypeLB is enabled.
	if ctlr.discoveryMode == DefaultMode && clusterConfigs.clusterDetails.ServiceTypeLBDiscovery {
		comInf.plcInformer = cisinfv1.NewFilteredPolicyInformer(
			clusterConfigs.kubeCRClient,
			namespace,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			crOptions,
		)
	}
	return comInf
}

func (ctlr *Controller) addMultiClusterPoolEventHandlers(poolInf *CommonInformer) {
	if poolInf.svcInformer != nil {
		poolInf.svcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueService(obj, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueUpdatedService(obj, cur, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedService(obj, poolInf.clusterName) },
			},
		)
		poolInf.svcInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Service, poolInf.clusterName))
	}

	if poolInf.epsInformer != nil {
		poolInf.epsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueEndpoints(obj, Create, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueEndpoints(cur, Update, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueEndpoints(obj, Delete, poolInf.clusterName) },
			},
		)
		poolInf.epsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Endpoints, poolInf.clusterName))
	}
	if poolInf.podInformer != nil {
		poolInf.podInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePod(obj, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePod(cur, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPod(obj, poolInf.clusterName) },
			},
		)
		poolInf.podInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Pod, poolInf.clusterName))
	}

	if poolInf.plcInformer != nil {
		poolInf.plcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePolicy(obj, Create, poolInf.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePolicy(cur, Update, poolInf.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPolicy(obj, poolInf.clusterName) },
			},
		)
		poolInf.plcInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(CustomPolicy, poolInf.clusterName))
	}

}

func (ctlr *Controller) stopMultiClusterPoolInformers(clusterName string, stopInformer bool) error {

	// remove the pool informers for clusters whose config has been removed
	if infStore := ctlr.multiClusterHandler.getInformerStore(clusterName); infStore != nil {
		for ns, nsPoolInf := range infStore.comInformers {
			if stopInformer {
				nsPoolInf.stop()
			}
			delete(infStore.comInformers, ns)
		}
	}
	return nil
}

func (ctlr *Controller) stopMultiClusterNodeInformer(clusterName string) error {
	// remove the pool informers for clusters whose config has been removed
	if infStore := ctlr.multiClusterHandler.getInformerStore(clusterName); infStore != nil {
		if infStore.nodeInformer != nil {
			infStore.nodeInformer.stop()
			infStore.nodeInformer = nil
		}
	}
	return nil
}

// setup multi cluster informer
func (ctlr *Controller) setupAndStartMultiClusterInformers(svcKey MultiClusterServiceKey, startInformer bool) error {
	if config := ctlr.multiClusterHandler.getClusterConfig(svcKey.clusterName); config != nil {

		if svcKey.clusterName == ctlr.multiClusterHandler.LocalClusterName {
			return nil
		}
		var apiServerUnreachable bool
		var err error
		if startInformer {
			_, err = config.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				log.Warningf("[MultiCluster] kube-api server is not reachable for cluster %v due to error: %v", svcKey.clusterName, err)
				apiServerUnreachable = true
			}
		}
		restClient := config.kubeClient.CoreV1().RESTClient()
		if err = ctlr.addMultiClusterNamespacedInformers(svcKey.clusterName, svcKey.namespace, restClient, startInformer, apiServerUnreachable); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", svcKey.clusterName, svcKey.namespace, err)
			return err
		}
		err = ctlr.setupMultiClusterNodeInformers(svcKey.clusterName, startInformer, apiServerUnreachable)
		if err != nil {
			log.Errorf("[MultiCluster] unable to setup node informer for cluster: %v, Error: %v", svcKey.clusterName, err)
			return err
		}
	} else {
		log.Debugf("[MultiCluster] cluster config not found for cluster: %v", svcKey.clusterName)
		return fmt.Errorf("[MultiCluster] cluster config not found for cluster: %v", svcKey.clusterName)
	}
	return nil
}

// setupAndStartExternalClusterInformers sets up and starts pool and node informers for the external cluster
func (ctlr *Controller) setupAndStartExternalClusterInformers(clusterName string) error {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(clusterName)
	if clusterConfig.InformerStore == nil {
		clusterConfig.InformerStore = initInformerStore()
	}
	restClient := clusterConfig.kubeClient.CoreV1().RESTClient()
	//handle namespace informer creation
	ctlr.handleNsInformersforCluster(clusterName, true)
	var apiServerUnreachable bool
	_, err := clusterConfig.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
	if err != nil {
		log.Warningf("[MultiCluster] kube-api server is not reachable for cluster %v due to error: %v", clusterName, err)
		apiServerUnreachable = true
	}
	// Setup informers with namespaces which are watched by CIS
	for n := range clusterConfig.namespaces {
		if err = ctlr.addMultiClusterNamespacedInformers(clusterName, n, restClient, true, apiServerUnreachable); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", clusterName, n, err)
			return err
		}
	}
	err = ctlr.setupMultiClusterNodeInformers(clusterName, true, apiServerUnreachable)
	if err != nil {
		log.Errorf("[MultiCluster] unable to setup node informer for cluster: %v, Error: %v", clusterName, err)
		return err
	}

	return nil
}

// updateMultiClusterInformers starts/stops the informers for the given namespace for external clusters including HA peer cluster
func (ctlr *Controller) updateMultiClusterInformers(namespace string, startInformer bool) error {
	for clusterName, config := range ctlr.multiClusterHandler.ClusterConfigs {
		var apiServerUnreachable bool
		var err error
		// For local cluster maintain some placeholder value, as the informers are already maintained in the controller object
		if clusterName == ctlr.multiClusterHandler.LocalClusterName {
			return nil
		}
		restClient := config.kubeClient.CoreV1().RESTClient()
		if startInformer {
			_, err = config.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				log.Warningf("[MultiCluster] kube-api server is not reachable for cluster %v due to error: %v", clusterName, err)
				apiServerUnreachable = true
			}
		}
		// Setup informer with the namespace
		if err = ctlr.addMultiClusterNamespacedInformers(clusterName, namespace, restClient, startInformer, apiServerUnreachable); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", clusterName, namespace, err)
			return err
		}
		// setup the node informer if nil
		if config.InformerStore.nodeInformer == nil {
			err = ctlr.setupMultiClusterNodeInformers(clusterName, startInformer, apiServerUnreachable)
			if err != nil {
				log.Errorf("[MultiCluster] unable to setup node informer for cluster: %v, Error: %v", clusterName, err)
				return err
			}
		}
	}
	return nil
}

// setupMultiClusterNodeInformers sets up and starts node informers for cluster if it hasn't been started
func (ctlr *Controller) setupMultiClusterNodeInformers(clusterName string, startInformer, apiServerUnreachable bool) error {
	informerStore := ctlr.multiClusterHandler.getInformerStore(clusterName)
	if informerStore != nil && informerStore.nodeInformer == nil {
		nodeInf := ctlr.setNodeInformer(clusterName)
		if startInformer {
			nodeInf.start(apiServerUnreachable)
			time.Sleep(100 * time.Millisecond)
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
			clusterConfig := ctlr.multiClusterHandler.getClusterConfig(clusterName)
			clusterConfig.oldNodes = nodes
		}
	}
	return nil
}

// if CIS is running in secondary then endPoint is mandatory
// if endPoint is configured then CIS will exit
func (ctlr *Controller) checkSecondaryCISConfig() {
	if ctlr.multiClusterMode == SecondaryCIS && ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint == "" {
		log.Debugf("[MultiCluster] error: cis running in secondary mode and missing primaryEndPoint under highAvailabilityCIS section. ")
		os.Exit(1)
	}
}

func (ctlr *Controller) getNamespaceMultiClusterPoolInformer(
	namespace string, clusterName string,
) (*CommonInformer, bool) {
	// CIS may be watching all namespaces in case of HA clusters
	if ctlr.watchingAllNamespaces(ctlr.multiClusterHandler.LocalClusterName) && ctlr.discoveryMode != DefaultMode {
		namespace = ""
	}
	//check for default mode and serviceTypeLBEnabled will be watching all namespaces.
	if ctlr.discoveryMode == DefaultMode && ctlr.watchingAllNamespaces(ctlr.multiClusterHandler.LocalClusterName) {
		if config := ctlr.multiClusterHandler.getClusterConfig(clusterName); config != nil {
			if config.clusterDetails.ServiceTypeLBDiscovery {
				namespace = ""
			}
		}

	}
	infStore := ctlr.multiClusterHandler.getInformerStore(clusterName)
	if infStore == nil {
		return nil, false
	}
	if infStore.comInformers != nil {
		poolInf, found := infStore.comInformers[namespace]
		return poolInf, found
	}
	return nil, false
}
