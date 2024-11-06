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
	startInformer bool,
) error {

	// add common informers  in all modes
	informerStore := ctlr.multiClusterConfigs.getInformerStore(clusterName)
	if informerStore == nil {
		informerStore = initInformerStore()
		ctlr.multiClusterConfigs.addInformerStore(clusterName, informerStore)
	}
	// add informer for the namespace
	if _, found := informerStore.comInformers[namespace]; !found {
		poolInfr := ctlr.newMultiClusterNamespacedPoolInformer(namespace, clusterName, restClientV1)
		ctlr.addMultiClusterPoolEventHandlers(poolInfr)
		informerStore.comInformers[namespace] = poolInfr
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
	clusterConfigs := ctlr.multiClusterConfigs.getClusterConfig(clusterName)
	crOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = clusterConfigs.customResourceSelector.String()
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

// whenever global configmap is modified check for removed cluster configs
// if any of the cluster config is removed from global CM. stop the respective cluster informers
func (ctlr *Controller) stopDeletedGlobalCMMultiClusterInformers() error {

	if ctlr.multiClusterConfigs == nil {
		return nil
	}
	ctlr.multiClusterConfigs.Lock()
	// remove the  pool informers for clusters whose config has been removed
	for clusterName, InfSet := range ctlr.multiClusterConfigs.ClusterConfigs {
		// if cluster config not present in global CM remove the informer
		if config, ok := ctlr.multiClusterConfigs.ClusterConfigs[clusterName]; !ok {
			for ns, nsPoolInf := range InfSet.comInformers {
				nsPoolInf.stop()
				delete(ctlr.multiClusterConfigs.ClusterConfigs[clusterName].comInformers, ns)
			}
		} else {
			// delete informers for cluster if serviceTypeLBDiscovery is disabled in default mode
			if ctlr.discoveryMode == DefaultMode && !config.clusterDetails.ServiceTypeLBDiscovery {
				//for HA pair dont remove pool informers.
				if clusterName == ctlr.multiClusterConfigs.HAPairClusterName || clusterName == ctlr.multiClusterConfigs.LocalClusterName || clusterName == "" {
					continue
				} else {
					for ns, nsPoolInf := range InfSet.comInformers {
						nsPoolInf.stop()
						delete(ctlr.multiClusterConfigs.ClusterConfigs[clusterName].comInformers, ns)
					}
				}
			}
		}
	}
	ctlr.multiClusterConfigs.Unlock()

	return nil
}

func (ctlr *Controller) stopMultiClusterInformers(clusterName string, stopInformer bool) error {

	// remove the pool informers for clusters whose config has been removed
	if infStore := ctlr.multiClusterConfigs.getInformerStore(clusterName); infStore != nil {
		for ns, nsPoolInf := range infStore.comInformers {
			if stopInformer {
				nsPoolInf.stop()
			}
			delete(infStore.comInformers, ns)
		}
	}
	return nil
}

// setup multi cluster informer
func (ctlr *Controller) setupAndStartMultiClusterInformers(svcKey MultiClusterServiceKey, startInformer bool) error {
	if config := ctlr.multiClusterConfigs.getClusterConfig(svcKey.clusterName); config != nil {
		if svcKey.clusterName == "" {
			return nil
		}
		restClient := config.kubeClient.CoreV1().RESTClient()
		if err := ctlr.addMultiClusterNamespacedInformers(svcKey.clusterName, svcKey.namespace, restClient, startInformer); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", svcKey.clusterName, svcKey.namespace, err)
			return err
		}
		err := ctlr.setupMultiClusterNodeInformers(svcKey.clusterName, startInformer)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("[MultiCluster] cluster config not found for cluster: %v", svcKey.clusterName)
	}
	return nil
}

// setupAndStartExternalClusterInformers sets up and starts pool and node informers for the external cluster
func (ctlr *Controller) setupAndStartExternalClusterInformers(clusterName string) error {
	clusterConfig := ctlr.multiClusterConfigs.getClusterConfig(clusterName)
	restClient := clusterConfig.kubeClient.CoreV1().RESTClient()
	// Setup informers with namespaces which are watched by CIS
	for n := range clusterConfig.namespaces {
		if err := ctlr.addMultiClusterNamespacedInformers(clusterName, n, restClient, true); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", clusterName, n, err)
			return err
		}
	}
	err := ctlr.setupMultiClusterNodeInformers(clusterName, true)
	if err != nil {
		return err
	}
	return nil
}

// updateMultiClusterInformers starts/stops the informers for the given namespace for external clusters including HA peer cluster
func (ctlr *Controller) updateMultiClusterInformers(namespace string, startInformer bool) error {
	for clusterName, config := range ctlr.multiClusterConfigs.ClusterConfigs {
		// For local cluster maintain some placeholder value, as the informers are already maintained in the controller object
		if clusterName == "" {
			return nil
		}
		restClient := config.kubeClient.CoreV1().RESTClient()
		// Setup informer with the namespace
		if err := ctlr.addMultiClusterNamespacedInformers(clusterName, namespace, restClient, startInformer); err != nil {
			log.Errorf("[MultiCluster] unable to setup informer for cluster: %v, namespace: %v, Error: %v", clusterName, namespace, err)
			return err
		}
	}
	return nil
}

// setupMultiClusterNodeInformers sets up and starts node informers for cluster if it hasn't been started
func (ctlr *Controller) setupMultiClusterNodeInformers(clusterName string, startInformer bool) error {
	informerStore := ctlr.multiClusterConfigs.getInformerStore(clusterName)
	if informerStore != nil && informerStore.nodeInformer == nil {
		nodeInf := ctlr.setNodeInformer(clusterName)
		if startInformer {
			nodeInf.start()
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
			clusterConfig := ctlr.multiClusterConfigs.getClusterConfig(clusterName)
			clusterConfig.oldNodes = nodes
		}
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
) (*CommonInformer, bool) {
	// CIS may be watching all namespaces in case of HA clusters
	if clusterName == ctlr.multiClusterConfigs.HAPairClusterName && ctlr.watchingAllNamespaces(clusterName) && ctlr.discoveryMode != DefaultMode {
		namespace = ""
	}
	//check for default mode and serviceTypeLBEnabled will be watching all namespaces.
	if ctlr.discoveryMode == DefaultMode && ctlr.watchingAllNamespaces(clusterName) {
		if config := ctlr.multiClusterConfigs.getClusterConfig(clusterName); config != nil {
			if config.clusterDetails.ServiceTypeLBDiscovery {
				namespace = ""
			}
		}

	}
	infStore := ctlr.multiClusterConfigs.getInformerStore(clusterName)
	if infStore == nil {
		return nil, false
	}
	if infStore.comInformers != nil {
		poolInf, found := infStore.comInformers[namespace]
		return poolInf, found
	}
	return nil, false
}
