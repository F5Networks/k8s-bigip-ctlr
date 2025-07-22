package controller

import (
	"context"
	"fmt"
	cisv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	"sync"
	"time"
)

// NewClusterHandler initializes the ClusterHandler with the required structures for each cluster.
func NewClusterHandler(LocalClusterName string) *ClusterHandler {
	return &ClusterHandler{
		PrimaryClusterHealthProbeParams: &PrimaryClusterHealthProbeParams{
			paramLock: sync.RWMutex{},
		},
		ClusterConfigs:      make(map[string]*ClusterConfig),
		uniqueAppIdentifier: make(map[string]struct{}),
		eventQueue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		LocalClusterName:    LocalClusterName,
		statusUpdate:        NewStatusUpdater(),
	}
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
	config.orchestrationCNI = ch.orchestrationCNI
	config.staticRoutingMode = ch.staticRoutingMode
	config.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
	ch.ClusterConfigs[clusterName] = config
	ch.Unlock()
}

//// deleteClusterConfig removes a cluster configuration from the ClusterHandler.
//func (ch *ClusterHandler) deleteClusterConfig(clusterName string) {
//	ch.Lock()
//	delete(ch.ClusterConfigs, clusterName)
//	ch.Unlock()
//}

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
//func (ch *ClusterHandler) enqueueEvent(clusterName string, obj interface{}) {
//	key := fmt.Sprintf("%s/%s", clusterName, "")
//	if _, exists := ch.uniqueAppIdentifier[key]; exists {
//		fmt.Printf("Duplicate event discarded: %s\n", key)
//		return
//	}
//	ch.uniqueAppIdentifier[key] = struct{}{}
//	ch.eventQueue.Add(obj)
//	fmt.Printf("Event queued: %s\n", key)
//}

//// ProcessEvents processes events from the eventQueue, applying deduplication and passing unique events to the controller.
//func (ch *ClusterHandler) ProcessEvents() {
//	for {
//		obj, shutdown := ch.eventQueue.Get()
//		if shutdown {
//			break
//		}
//
//		// Process event
//		ch.processEvent(obj)
//		ch.eventQueue.Done(obj)
//	}
//}

// processEvent handles individual events, simulating sending to a controller.
//func (ch *ClusterHandler) processEvent(obj interface{}) {
//	// Here you would handle the business logic for the event.
//	fmt.Printf("Processing event: %v\n", obj)
//	// Add actual controller handling logic here.
//}

// remove any cluster which is not provided in externalClustersConfig or not part of the HA cluster
func (ch *ClusterHandler) cleanClusterCache(primaryClusterName, secondaryClusterName string, activeClusters map[string]bool) {
	ch.Lock()
	defer ch.Unlock()
	for clusterName, clusterConfig := range ch.ClusterConfigs {
		// Avoid deleting HA cluster related configs
		if clusterName == primaryClusterName || clusterName == secondaryClusterName || clusterName == ch.LocalClusterName {
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
		if infSet.InformerStore == nil {
			continue
		}
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

// function to return the list of all nodes from all the active clusters
func (ch *ClusterHandler) getAllBlockAffinitiesUsingInformers() []interface{} {
	ch.RLock()
	defer ch.RUnlock()
	var ba []interface{}
	for _, infSet := range ch.ClusterConfigs {
		if infSet.InformerStore == nil || infSet.InformerStore.dynamicInformers == nil ||
			infSet.InformerStore.dynamicInformers.CalicoBlockAffinityInformer == nil {
			continue
		}
		ba = append(ba, infSet.dynamicInformers.CalicoBlockAffinityInformer.Informer().GetIndexer().List()...)
	}
	return ba
}

// function to return the list of all nodes using the rest client
func (ch *ClusterHandler) getAllBlockAffinitiesUsingRestClient() []interface{} {
	ch.RLock()
	defer ch.RUnlock()
	var blockAffinitiesStore []interface{}
	for clusterName, config := range ch.ClusterConfigs {
		blockAffinities, err := config.dynamicClient.Resource(CalicoBlockaffinity).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Debugf("[MultiCluster] Unable to fetch blockaffinities for cluster %v with err %v", clusterName, err)
		} else {
			for _, ba := range blockAffinities.Items {
				blockAffinitiesStore = append(blockAffinitiesStore, &ba)
			}
		}
	}
	return blockAffinitiesStore
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

//func (ch *ClusterHandler) getClusterNames() map[string]struct{} {
//	ch.RLock()
//	defer ch.RUnlock()
//	clusterNames := make(map[string]struct{})
//	for clusterName, config := range ch.ClusterConfigs {
//		if config.clusterDetails.ServiceTypeLBDiscovery {
//			clusterNames[clusterName] = struct{}{}
//		}
//	}
//	return clusterNames
//}

// ResourceStatusUpdater is a go routine that listens to the resourceStatusUpdateChan
func (ch *ClusterHandler) ResourceStatusUpdater() {
	for rscStatus := range ch.statusUpdate.ResourceStatusUpdateChan {
		if rscStatus.UpdateAttempts > 3 {
			log.Errorf("Resource %v status update attempts exceeded 3 times.", rscStatus.ResourceObj)
			continue
		}
		if timestamp, ok := ch.statusUpdate.ResourceStatusUpdateTracker.Load(rscStatus.ResourceKey); ok {
			if timestamp.(metav1.Time).After(rscStatus.Timestamp.Time) {
				log.Debugf("Resource %v status already updated after time: %v. Skipping status update.",
					rscStatus.ResourceObj, rscStatus.Timestamp)
				continue
			}
		}
		// Update the timestamp
		if !rscStatus.ClearKeyFromCache {
			ch.statusUpdate.ResourceStatusUpdateTracker.Store(rscStatus.ResourceKey, rscStatus.Timestamp)
		} else {
			// If ClearKeyFromCache is true, it means the resource has been deleted so the associated key has to be removed
			ch.statusUpdate.ResourceStatusUpdateTracker.Delete(rscStatus.ResourceKey)
		}
		go ch.UpdateResourceStatus(rscStatus)
	}
}

// UpdateResourceStatus updates the status of the resource
func (ch *ClusterHandler) UpdateResourceStatus(rscStatus ResourceStatus) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic while updating status for resource %s/%s in cluster %s with err %v",
				rscStatus.ResourceKey.namespace, rscStatus.ResourceKey.name, rscStatus.ResourceKey.clusterName, r)
		}
	}()
	clusterConfig := ch.getClusterConfig(rscStatus.ResourceKey.clusterName)
	if clusterConfig == nil {
		log.Errorf("Failed while updating status of %s/%s. Error: Unable to get cluster config for cluster:%s",
			rscStatus.ResourceKey.namespace, rscStatus.ResourceKey.name, rscStatus.ResourceKey.clusterName)
		return
	}

	if rscStatus.UpdateAttempts > 0 {
		// Waiting for few milliseconds before retrying the status update mitigates chances of hitting resource version
		// modified error especially in scenarios where the resource is getting updated very rapidly.
		log.Debugf("Waiting for %d Milliseconds before retrying status update for %+v", rscStatus.UpdateAttempts, rscStatus.ResourceKey)
		time.Sleep(time.Duration(rscStatus.UpdateAttempts) * time.Millisecond)
	}
	var updateErr error
	switch rscStatus.ResourceKey.kind {
	case VirtualServer:
		informer := ch.getCRInformerForCluster(rscStatus.ResourceKey.clusterName, rscStatus.ResourceKey.namespace)
		if informer == nil {
			updateErr = fmt.Errorf("failed to get informer")
			break
		}
		var vs *cisv1.VirtualServer
		var found bool
		// Get the latest version of the resource.
		// If status update is for delete event which is indicated by clearKeyFromCache flag, then use kubeclient as it
		// helps in identifying whether resource is actually deleted or it's label has been removed, otherwise use informers,
		// which is usually faster.
		if !rscStatus.ClearKeyFromCache {
			item, exists, err := informer.vsInformer.GetIndexer().GetByKey(rscStatus.ResourceKey.namespace + "/" + rscStatus.ResourceKey.name)
			if err != nil {
				updateErr = fmt.Errorf("failed to fetch VS. %v", err)
				break
			} else if !exists {
				// Object is deleted
				return
			}
			vs, found = item.(*cisv1.VirtualServer)
		} else {
			var err error
			vs, err = clusterConfig.kubeCRClient.CisV1().VirtualServers(rscStatus.ResourceKey.namespace).Get(context.Background(), rscStatus.ResourceKey.name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					// Resource is not found indicates it's actually deleted, so it eliminates the case of watch label
					// removal from the resource. So, no need to go for status update.
					return
				} else {
					updateErr = fmt.Errorf("failed to fetch VS. %v", err)
					break
				}
			}
			found = true
		}
		if found {
			vs.Status = rscStatus.ResourceObj.(cisv1.CustomResourceStatus)
		}
		_, updateErr = clusterConfig.kubeCRClient.CisV1().VirtualServers(vs.ObjectMeta.Namespace).UpdateStatus(context.TODO(), vs, metav1.UpdateOptions{})
	case TransportServer:
		informer := ch.getCRInformerForCluster(rscStatus.ResourceKey.clusterName, rscStatus.ResourceKey.namespace)
		if informer == nil {
			updateErr = fmt.Errorf("failed to get informer")
			break
		}
		var ts *cisv1.TransportServer
		var found bool
		// Get the latest version of the resource.
		// If status update is for delete event which is indicated by clearKeyFromCache flag, then use kubeclient as it
		// helps in identifying whether resource is actually deleted or it's label has been removed, otherwise use informers,
		// which is usually faster.
		if !rscStatus.ClearKeyFromCache {
			item, exists, err := informer.tsInformer.GetIndexer().GetByKey(rscStatus.ResourceKey.namespace + "/" + rscStatus.ResourceKey.name)
			if err != nil {
				updateErr = fmt.Errorf("failed to fetch TS. %v", err)
				break
			} else if !exists {
				// Object is deleted
				return
			}
			ts, found = item.(*cisv1.TransportServer)
		} else {
			var err error
			ts, err = clusterConfig.kubeCRClient.CisV1().TransportServers(rscStatus.ResourceKey.namespace).Get(context.Background(), rscStatus.ResourceKey.name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					// Resource is not found indicates it's actually deleted, so it eliminates the case of watch label
					// removal from the resource. So, no need to go for status update.
					return
				} else {
					updateErr = fmt.Errorf("failed to fetch TS. %v", err)
					break
				}
			}
			found = true
		}
		if found {
			ts.Status = rscStatus.ResourceObj.(cisv1.CustomResourceStatus)
		}
		_, updateErr = clusterConfig.kubeCRClient.CisV1().TransportServers(ts.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ts, metav1.UpdateOptions{})
	case IngressLink:
		informer := ch.getCRInformerForCluster(rscStatus.ResourceKey.clusterName, rscStatus.ResourceKey.namespace)
		if informer == nil {
			updateErr = fmt.Errorf("failed to get informer")
			break
		}
		var il *cisv1.IngressLink
		var found bool
		// Get the latest version of the resource.
		// If status update is for delete event which is indicated by clearKeyFromCache flag, then use kubeclient as it
		// helps in identifying whether resource is actually deleted or it's label has been removed, otherwise use informers,
		// which is usually faster.
		if !rscStatus.ClearKeyFromCache {
			item, exists, err := informer.ilInformer.GetIndexer().GetByKey(rscStatus.ResourceKey.namespace + "/" + rscStatus.ResourceKey.name)
			if err != nil {
				updateErr = fmt.Errorf("failed to fetch IL. %v", err)
				break
			} else if !exists {
				// Object is deleted
				return
			}
			il, found = item.(*cisv1.IngressLink)
		} else {
			var err error
			il, err = clusterConfig.kubeCRClient.CisV1().IngressLinks(rscStatus.ResourceKey.namespace).Get(context.Background(), rscStatus.ResourceKey.name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					// Resource is not found indicates it's actually deleted, so it eliminates the case of watch label
					// removal from the resource. So, no need to go for status update.
					return
				} else {
					updateErr = fmt.Errorf("failed to fetch IL. %v", err)
					break
				}
			}
			found = true
		}
		if found {
			il.Status = rscStatus.ResourceObj.(cisv1.CustomResourceStatus)
		}
		_, updateErr = clusterConfig.kubeCRClient.CisV1().IngressLinks(il.ObjectMeta.Namespace).UpdateStatus(context.TODO(), il, metav1.UpdateOptions{})
	case Service:
		informer := ch.getCommonInformerForCluster(rscStatus.ResourceKey.clusterName, rscStatus.ResourceKey.namespace)
		if informer == nil {
			updateErr = fmt.Errorf("failed to get informer")
			break
		}
		var svc *v1.Service
		var found bool
		// Get the latest version of the resource.
		// If status update is for delete event which is indicated by clearKeyFromCache flag, then use kubeclient as it
		// helps in identifying whether resource is actually deleted or it's label has been removed, otherwise use informers,
		// which is usually faster.
		if !rscStatus.ClearKeyFromCache {
			item, exists, err := informer.svcInformer.GetIndexer().GetByKey(rscStatus.ResourceKey.namespace + "/" + rscStatus.ResourceKey.name)
			if err != nil {
				updateErr = fmt.Errorf("failed to fetch LB Service. %v", err)
				break
			} else if !exists {
				// Object is deleted
				return
			}
			svc, found = item.(*v1.Service)
		} else {
			var err error
			svc, err = clusterConfig.kubeClient.CoreV1().Services(rscStatus.ResourceKey.namespace).Get(context.Background(), rscStatus.ResourceKey.name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					// Resource is not found indicates it's actually deleted, so it eliminates the case of IP annotation
					// removal from the resource. So, no need to go for status update.
					return
				} else {
					updateErr = fmt.Errorf("failed to fetch LB service. %v", err)
					break
				}
			}
			found = true
		}
		if found {
			svc.Status = rscStatus.ResourceObj.(v1.ServiceStatus)
		}
		_, updateErr = clusterConfig.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
		if nil != updateErr {
			var warning string
			if rscStatus.IPSet {
				warning = fmt.Sprintf("Error when assigning Service LB Ingress status IP: %v", updateErr)
			} else {
				warning = fmt.Sprintf("Error when unassigning Service LB Ingress status IP: %v", updateErr)
			}
			log.Warning(warning)
			ch.statusUpdate.eventNotifierChan <- ResourceEvent{
				svc,
				v1.EventTypeWarning,
				"StatusIPError",
				warning,
				rscStatus.ResourceKey.clusterName,
			}
		} else {
			var message string
			if rscStatus.IPSet {
				message = fmt.Sprintf("F5 CIS assigned Service LB Ingress status IP for service: %s in namespace:%s",
					svc.Name, svc.Namespace)
			} else {
				message = fmt.Sprintf("F5 CIS unassigned Service LB Ingress status IP for service: %s in namespace:%s",
					svc.Name, svc.Namespace)
			}
			ch.statusUpdate.eventNotifierChan <- ResourceEvent{
				svc,
				v1.EventTypeNormal,
				"ExternalIP",
				message,
				rscStatus.ResourceKey.clusterName,
			}
		}
	case Route:
		informer := ch.getNRInformerForCluster(rscStatus.ResourceKey.clusterName, rscStatus.ResourceKey.namespace)
		if informer == nil {
			updateErr = fmt.Errorf("failed to get informer")
			break
		}
		var route *routeapi.Route
		var found bool
		// Get the latest version of the resource.
		// If status update is for delete event which is indicated by clearKeyFromCache flag, then use kubeclient as it
		// helps in identifying whether resource is actually deleted or it's label has been removed, otherwise use informers,
		// which is usually faster.
		if !rscStatus.ClearKeyFromCache {
			item, exists, err := informer.routeInformer.GetIndexer().GetByKey(rscStatus.ResourceKey.namespace + "/" + rscStatus.ResourceKey.name)
			if err != nil {
				updateErr = fmt.Errorf("failed to fetch Route. %v", err)
				break
			} else if !exists {
				// Object is deleted
				return
			}
			route, found = item.(*routeapi.Route)
		} else {
			var err error
			route, err = clusterConfig.routeClientV1.Routes(rscStatus.ResourceKey.namespace).Get(context.Background(), rscStatus.ResourceKey.name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					// Resource is not found indicates it's actually deleted, so it eliminates the case of watch label
					// removal from the resource. So, no need to go for status update.
					return
				} else {
					updateErr = fmt.Errorf("failed to fetch Route. %v", err)
					break
				}
			}
			found = true
		}
		if found {
			route.Status = rscStatus.ResourceObj.(routeapi.RouteStatus)
		}
		_, updateErr = clusterConfig.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(),
			route, metav1.UpdateOptions{})
	default:
		log.Errorf("unknown resource %s/%s of Cluster:%s received for Status Update", rscStatus.ResourceKey.namespace,
			rscStatus.ResourceKey.name, rscStatus.ResourceKey.clusterName)
		return
	}
	// Retry the update if it fails
	if nil != updateErr {
		log.Warningf("Failed to update the status of %s:%s/%s in Cluster %s. Error: %v. Retry will be attempted.", rscStatus.ResourceKey.kind,
			rscStatus.ResourceKey.namespace, rscStatus.ResourceKey.name, rscStatus.ResourceKey.clusterName, updateErr)
		rscStatus.UpdateAttempts++
		ch.statusUpdate.ResourceStatusUpdateChan <- rscStatus
	} else {
		log.Infof("Successfully updated status of %s:%s/%s in Cluster %s", rscStatus.ResourceKey.kind,
			rscStatus.ResourceKey.namespace, rscStatus.ResourceKey.name, rscStatus.ResourceKey.clusterName)
	}
}

// NewStatusUpdater creates a new statusUpdater
func NewStatusUpdater() *StatusUpdate {
	return &StatusUpdate{
		ResourceStatusUpdateChan:    make(chan ResourceStatus),
		ResourceStatusUpdateTracker: sync.Map{},
		eventNotifierChan:           make(chan ResourceEvent),
	}
}

// ResourceEventWatcher watches for resource events
func (ch *ClusterHandler) ResourceEventWatcher() {
	for resourceEvent := range ch.statusUpdate.eventNotifierChan {
		ch.RecordEvent(resourceEvent)
	}
}

// RecordEvent handles all supported resource events, currently only serviceTypeLB events are handled
func (ch *ClusterHandler) RecordEvent(resourceEvent ResourceEvent) {
	switch resourceEvent.resourceObj.(type) {
	case *v1.Service:
		svc := resourceEvent.resourceObj.(*v1.Service)
		go ch.recordLBServiceIngressEvent(svc, resourceEvent.eventType, resourceEvent.reason, resourceEvent.message, resourceEvent.clusterName)
	default:
		log.Errorf("unknown resource type %T received for Event", resourceEvent.resourceObj)
	}
}

// recordLBServiceIngressEvent record the event for LB service
func (ch *ClusterHandler) recordLBServiceIngressEvent(
	svc *v1.Service,
	eventType string,
	reason string,
	message string,
	clusterName string,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic while recording event for LB Service %v/%v in recordLBServiceIngressEvent: %v",
				svc.Namespace, svc.Name, r)
		}
	}()
	namespace := svc.ObjectMeta.Namespace
	// Create the event
	if config := ch.getClusterConfig(clusterName); config != nil {
		evNotifier := config.eventNotifier.CreateNotifierForNamespace(
			namespace, config.kubeClient.CoreV1())
		evNotifier.RecordEvent(svc, eventType, reason, message)
	}
}

// getCRInformerForCluster returns the custom resource informers for cluster
func (ch *ClusterHandler) getCRInformerForCluster(clusterName string, namespace string) *CRInformer {
	var infStore *InformerStore
	if infStore = ch.getInformerStore(clusterName); infStore == nil {
		return nil
	}
	if informer, ok := infStore.crInformers[namespace]; ok {
		return informer
	} else if informer, ok = infStore.crInformers[""]; ok {
		return informer
	}
	return nil
}

// getCommonInformerForCluster returns the commonInformers for a cluster
func (ch *ClusterHandler) getCommonInformerForCluster(clusterName string, namespace string) *CommonInformer {
	var infStore *InformerStore
	if infStore = ch.getInformerStore(clusterName); infStore == nil {
		return nil
	}
	if informer, ok := infStore.comInformers[namespace]; ok {
		return informer
	} else if informer, ok = infStore.comInformers[""]; ok {
		return informer
	}
	return nil
}

// getNRInformerForCluster returns the native resource informers for cluster
func (ch *ClusterHandler) getNRInformerForCluster(clusterName string, namespace string) *NRInformer {
	var infStore *InformerStore
	if infStore = ch.getInformerStore(clusterName); infStore == nil {
		return nil
	}
	if informer, ok := infStore.nrInformers[namespace]; ok {
		return informer
	} else if informer, ok = infStore.nrInformers[""]; ok {
		return informer
	}
	return nil
}
