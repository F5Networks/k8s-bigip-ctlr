package controller

import (
	"context"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

// NewClusterHandler initializes the ClusterHandler with the required structures for each cluster.
func NewClusterHandler(LocalClusterName string) *ClusterHandler {
	handler := &ClusterHandler{
		ClusterConfigs:      make(map[string]*ClusterConfig),
		uniqueAppIdentifier: make(map[string]struct{}),
		eventQueue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		LocalClusterName:    LocalClusterName,
	}
	return handler
}

// fetch cluster name for given secret if it holds kubeconfig of the cluster.
func (ch *ClusterHandler) getClusterForSecret(name, namespace string) ClusterDetails {
	ch.RLock()
	defer ch.RUnlock()
	for _, mcc := range ch.ClusterConfigs {
		// Skip empty/nil configs processing
		if mcc.clusterDetails == (ClusterDetails{}) {
			continue
		}
		// Check if the secret holds the kubeconfig for a cluster by checking if it's referred in the multicluster config
		// if so then return the cluster name associated with the secret
		if mcc.clusterDetails.Secret == (namespace + "/" + name) {
			return mcc.clusterDetails
		}
	}
	return ClusterDetails{}
}

// addClusterConfig adds a new cluster configuration to the ClusterHandler.
func (ch *ClusterHandler) addClusterConfig(clusterName string, config *ClusterConfig) {
	ch.Lock()
	config.namespaceLabel = ch.namespaceLabel
	config.nodeLabelSelector = ch.nodeLabelSelector
	config.routeLabel = ch.routeLabel
	config.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
	config.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
	ch.ClusterConfigs[clusterName] = config
	ch.Unlock()
}

// deleteClusterConfig removes a cluster configuration from the ClusterHandler.
func (ch *ClusterHandler) deleteClusterConfig(clusterName string) {
	ch.Lock()
	delete(ch.ClusterConfigs, clusterName)
	ch.Unlock()
}

// getClusterConfig returns the cluster configuration for the specified cluster.
func (ch *ClusterHandler) getClusterConfig(clusterName string) *ClusterConfig {
	ch.RLock()
	defer ch.RUnlock()
	if _, exists := ch.ClusterConfigs[clusterName]; !exists {
		return nil
	}
	return ch.ClusterConfigs[clusterName]
}

// addInformerStore adds a new InformerStore to the ClusterHandler.
func (ch *ClusterHandler) addInformerStore(clusterName string, store *InformerStore) {
	ch.Lock()
	if clusterConfig, ok := ch.ClusterConfigs[clusterName]; ok {
		clusterConfig.InformerStore = store
	}
	ch.Unlock()
}

// getInformerStore returns the InformerStore for the specified cluster.
func (ch *ClusterHandler) getInformerStore(clusterName string) *InformerStore {
	ch.RLock()
	defer ch.RUnlock()
	if clusterConfig, exists := ch.ClusterConfigs[clusterName]; exists {
		return clusterConfig.InformerStore
	}
	return nil
}

// enqueueEvent adds an event to the eventQueue after checking for uniqueness.
func (ch *ClusterHandler) enqueueEvent(clusterName string, obj interface{}) {
	key := fmt.Sprintf("%s/%s", clusterName, "")
	if _, exists := ch.uniqueAppIdentifier[key]; exists {
		fmt.Printf("Duplicate event discarded: %s\n", key)
		return
	}
	ch.uniqueAppIdentifier[key] = struct{}{}
	ch.eventQueue.Add(obj)
	fmt.Printf("Event queued: %s\n", key)
}

// ProcessEvents processes events from the eventQueue, applying deduplication and passing unique events to the controller.
func (ch *ClusterHandler) ProcessEvents() {
	for {
		obj, shutdown := ch.eventQueue.Get()
		if shutdown {
			break
		}

		// Process event
		ch.processEvent(obj)
		ch.eventQueue.Done(obj)
	}
}

// processEvent handles individual events, simulating sending to a controller.
func (ch *ClusterHandler) processEvent(obj interface{}) {
	// Here you would handle the business logic for the event.
	fmt.Printf("Processing event: %v\n", obj)
	// Add actual controller handling logic here.
}

// remove any cluster which is not provided in externalClustersConfig or not part of the HA cluster
func (ch *ClusterHandler) cleanClusterCache(primaryClusterName, secondaryClusterName string, activeClusters map[string]bool) {
	ch.Lock()
	defer ch.Unlock()
	for clusterName, clusterConfig := range ch.ClusterConfigs {
		// Avoid deleting HA cluster related configs
		if clusterName == primaryClusterName || clusterName == secondaryClusterName || clusterName == "" {
			continue
		}
		// Avoid deleting active clusters
		if serviceLBStatus, exists := activeClusters[clusterName]; exists {
			// remove the informers for service LB when service discovery is disabled for a cluster
			if !serviceLBStatus && clusterConfig.InformerStore != nil && clusterConfig.InformerStore.comInformers != nil {
				for ns, nsPoolInf := range clusterConfig.InformerStore.comInformers {
					nsPoolInf.stop()
					delete(clusterConfig.InformerStore.comInformers, ns)
				}
			}
			continue
		}
		log.Infof("[MultiCluster] Removing the cluster config for cluster %s from CIS Cache", clusterName)
		for ns, nsPoolInf := range clusterConfig.InformerStore.comInformers {
			nsPoolInf.stop()
			delete(clusterConfig.InformerStore.comInformers, ns)
		}
		delete(ch.ClusterConfigs, clusterName)
	}
}

// function to get the count of edns resources from all the active clusters for a namespace
func (ch *ClusterHandler) getEDNSCount(clusterConfig *ClusterConfig, ns string) int {
	rscCount := 0
	if clusterConfig != nil && clusterConfig.InformerStore != nil && clusterConfig.comInformers != nil {
		if comInf, ok := clusterConfig.comInformers[ns]; ok && comInf.ednsInformer != nil {
			edns, err := comInf.ednsInformer.GetIndexer().ByIndex("namespace", ns)
			if err == nil {
				rscCount += len(edns)
			}
		}
	}
	return rscCount
}

// function to return if cluster informers are ready
func (ch *ClusterHandler) isClusterInformersReady() bool {
	if ch.ClusterConfigs == nil {
		return false
	}
	return true
}

// function to return the list of all nodes from all the active clusters
func (ch *ClusterHandler) getAllNodesUsingInformers() []interface{} {
	ch.RLock()
	defer ch.RUnlock()
	var nodes []interface{}
	for _, infSet := range ch.ClusterConfigs {
		nodes = append(nodes, infSet.nodeInformer.nodeInformer.GetIndexer().List()...)
	}
	return nodes
}

// function to return the list of all nodes using the rest client
func (ch *ClusterHandler) getAllNodesUsingRestClient() []interface{} {
	ch.RLock()
	defer ch.RUnlock()
	var nodes []interface{}
	for clusterName, config := range ch.ClusterConfigs {
		nodesObj, err := config.kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: config.nodeLabelSelector})
		if err != nil {
			log.Debugf("[MultiCluster] Unable to fetch nodes for cluster %v with err %v", clusterName, err)
		} else {
			for _, node := range nodesObj.Items {
				nodes = append(nodes, &node)
			}
		}
	}
	return nodes
}

// function to return the cluster counts
func (ch *ClusterHandler) getClusterCount() int {
	ch.RLock()
	defer ch.RUnlock()
	return len(ch.ClusterConfigs)
}

// function to return the list of monitored namespaces for ingress resources
func (ch *ClusterHandler) getMonitoredNamespaces(clusterName string) map[string]struct{} {
	ch.RLock()
	defer ch.RUnlock()
	ns := make(map[string]struct{})
	if config, ok := ch.ClusterConfigs[clusterName]; ok {
		ns = config.namespaces
	}
	return ns
}

func (ch *ClusterHandler) getClusterNames() map[string]struct{} {
	ch.RLock()
	defer ch.RUnlock()
	clusterNames := make(map[string]struct{})
	for clusterName, config := range ch.ClusterConfigs {
		if config.clusterDetails.ServiceTypeLBDiscovery {
			clusterNames[clusterName] = struct{}{}
		}
	}
	return clusterNames
}
