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
	"strings"
	"sync"
)

// NewClusterHandler initializes the ClusterHandler with the required structures for each cluster.
func NewClusterHandler(LocalClusterName string) *ClusterHandler {
	return &ClusterHandler{
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

// ResourceStatusUpdater is a go routine that listens to the resourceStatusUpdateChan
func (ch *ClusterHandler) ResourceStatusUpdater() {
	for rscStatus := range ch.statusUpdate.ResourceStatusUpdateChan {
		if rscStatus.UpdateAttempts > 3 {
			log.Errorf("Resource %v status update attempts exceeded 3 times.", rscStatus.ResourceObj)
			continue
		}
		rscKey := ch.GetResourceKeyForStatusUpdate(rscStatus.ResourceObj, rscStatus.ClusterName)
		if timestamp, ok := ch.statusUpdate.ResourceStatusUpdateTracker.Load(rscKey); ok {
			if timestamp.(metav1.Time).After(rscStatus.Timestamp.Time) {
				log.Debugf("Resource %v status already updated after time: %v. Skipping status update.",
					rscStatus.ResourceObj, rscStatus.Timestamp)
				continue
			}
		}
		// Update the timestamp
		if !rscStatus.ClearKeyFromCache {
			ch.statusUpdate.ResourceStatusUpdateTracker.Store(rscKey, rscStatus.Timestamp)
		} else {
			// If ClearKeyFromCache is true, it means the resource has been deleted so the associated key has to be removed
			ch.statusUpdate.ResourceStatusUpdateTracker.Delete(rscKey)
		}
		go ch.UpdateResourceStatus(rscStatus)
	}
}

// GetResourceKeyForStatusUpdate returns the key for resource for ResourceStatusUpdateTracker
func (ch *ClusterHandler) GetResourceKeyForStatusUpdate(rsc interface{}, clusterName string) string {
	switch rsc.(type) {
	case *cisv1.VirtualServer:
		vs := rsc.(*cisv1.VirtualServer)
		return fmt.Sprintf("%s/%s/%s", clusterName, vs.ObjectMeta.Namespace, vs.ObjectMeta.Name)
	case *cisv1.TransportServer:
		ts := rsc.(*cisv1.TransportServer)
		return fmt.Sprintf("%s/%s/%s", clusterName, ts.ObjectMeta.Namespace, ts.ObjectMeta.Name)
	case *cisv1.IngressLink:
		il := rsc.(*cisv1.IngressLink)
		return fmt.Sprintf("%s/%s/%s", clusterName, il.ObjectMeta.Namespace, il.ObjectMeta.Name)
	case *v1.Service:
		svc := rsc.(*v1.Service)
		return fmt.Sprintf("%s/%s/%s", clusterName, svc.ObjectMeta.Namespace, svc.ObjectMeta.Name)
	case *routeapi.Route:
		route := rsc.(*routeapi.Route)
		return fmt.Sprintf("%s/%s/%s", clusterName, route.ObjectMeta.Namespace, route.ObjectMeta.Name)
	default:
		log.Errorf("unknown resource type %T received for Status Update", rsc)
		return ""
	}
}

// UpdateResourceStatus updates the status of the resource
func (ch *ClusterHandler) UpdateResourceStatus(rscStatus ResourceStatus) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic while updating status for resource %v from cluster %v with err %v", rscStatus.ResourceObj,
				rscStatus.ClusterName, r)
		}
	}()
	clusterConfig := ch.getClusterConfig(rscStatus.ClusterName)
	if clusterConfig == nil {
		log.Errorf("Error while updating %T status. Error: Unable to get cluster config for cluster:%v",
			rscStatus.ResourceObj, rscStatus.ClusterName)
		return
	}
	var updateErr error
	switch rscStatus.ResourceObj.(type) {
	case *cisv1.VirtualServer:
		vs := rscStatus.ResourceObj.(*cisv1.VirtualServer)
		_, updateErr = clusterConfig.kubeCRClient.CisV1().VirtualServers(vs.ObjectMeta.Namespace).UpdateStatus(context.TODO(), vs, metav1.UpdateOptions{})
	case *cisv1.TransportServer:
		ts := rscStatus.ResourceObj.(*cisv1.TransportServer)
		_, updateErr = clusterConfig.kubeCRClient.CisV1().TransportServers(ts.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ts, metav1.UpdateOptions{})
	case *cisv1.IngressLink:
		il := rscStatus.ResourceObj.(*cisv1.IngressLink)
		_, updateErr = clusterConfig.kubeCRClient.CisV1().IngressLinks(il.ObjectMeta.Namespace).UpdateStatus(context.TODO(), il, metav1.UpdateOptions{})
	case *v1.Service:
		svc := rscStatus.ResourceObj.(*v1.Service)
		_, updateErr = clusterConfig.kubeClient.CoreV1().Services(svc.ObjectMeta.Namespace).UpdateStatus(context.TODO(), svc, metav1.UpdateOptions{})
		if nil != updateErr {
			// 1. Observed that service create event is followed by endpoint create event. Since CIS processes the service
			// on endpoint create event as well the service status update is attempted multiple times.
			// 2. On LB service update events which lead to delete and create events by CIS, the old service is used for
			// the delete event, thus causing the error object has been modified.
			// In such cases it's better to update the status in the latest version of the service.
			// 3. StorageError: invalid object is observed when resource is deleted before status update, in this case log and return
			if strings.Contains(updateErr.Error(), "object has been modified") {
				log.Debugf("failed to udpate update service: %s in namespace:%s from cluster:%s : Warning:%v",
					svc.Name, svc.Namespace, rscStatus.ClusterName, updateErr.Error())
				latestSvc, err := clusterConfig.kubeClient.CoreV1().Services(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})
				if err == nil {
					latestSvc.Status = svc.Status
					rscStatus.ResourceObj = latestSvc
					rscStatus.UpdateAttempts++
					ch.statusUpdate.ResourceStatusUpdateChan <- rscStatus
					return
				} else {
					// Skip status update in case of service is not found
					if !errors.IsNotFound(err) {
						log.Debugf("failed to fetch service %s/%s from cluster:%s for status update: Warning: %v. "+
							"The resource might have been deleted.", svc.Namespace, svc.Name, rscStatus.ClusterName, err)
						return
					}
				}
			} else if strings.Contains(updateErr.Error(), "StorageError: invalid object") {
				log.Debugf("Failed while updating service: %s in namespace:%s from cluster:%s. Service might have "+
					"been deleted before status update: Error: %v", svc.Name, svc.Namespace, rscStatus.ClusterName, updateErr.Error())
				return
			}
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
				rscStatus.ClusterName,
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
				rscStatus.ClusterName,
			}
		}
	case *routeapi.Route:
		route := rscStatus.ResourceObj.(*routeapi.Route)
		_, updateErr := clusterConfig.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(),
			route, metav1.UpdateOptions{})
		if updateErr == nil {
			log.Infof("Admitted Route -  %v/%v", route.ObjectMeta.Namespace, route.ObjectMeta.Name)
			return
		}
	default:
		updateErr = fmt.Errorf("unknown resource type %T received for Status Update", rscStatus.ResourceObj)
	}
	// Retry the update if it fails
	if nil != updateErr {
		log.Errorf("Error while updating %T status from cluster %s: Error: %v", rscStatus.ResourceObj,
			rscStatus.ClusterName, updateErr)
		rscStatus.UpdateAttempts++
		ch.statusUpdate.ResourceStatusUpdateChan <- rscStatus
	} else {
		log.Infof("Successfully updated status of %T from cluster: %s", rscStatus.ResourceObj, rscStatus.ClusterName)
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
