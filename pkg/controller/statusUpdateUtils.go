package controller

import (
	"context"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
)

// updateVSStatus prepares the status update VS
func (ctlr *Controller) updateVSStatus(vs *cisapiv1.VirtualServer, ip string, status string, err error) {
	vsStatus := cisapiv1.VirtualServerStatus{
		Status:      status,
		LastUpdated: metav1.Now(),
	}
	if err != nil {
		vsStatus.Error = err.Error()
	} else if ip != "" {
		vsStatus.VSAddress = ip
	} else {
		vsStatus.Error = fmt.Sprintf("Missing label f5cr on VS %v/%v", vs.Namespace, vs.Name)
	}
	vs.Status = vsStatus
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj: vs,
		ClusterName: ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:   metav1.Now(),
	}
}

// updateTSStatus prepares the status update TS
func (ctlr *Controller) updateTSStatus(ts *cisapiv1.TransportServer, ip string, status string, err error) {
	tsStatus := cisapiv1.TransportServerStatus{
		Status:      status,
		LastUpdated: metav1.Now(),
	}
	if err != nil {
		tsStatus.Error = err.Error()
	} else if ip != "" {
		tsStatus.VSAddress = ip
	} else {
		tsStatus.Error = fmt.Sprintf("Missing label f5cr on TS %v/%v", ts.Namespace, ts.Name)
	}
	ts.Status = tsStatus
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj: ts,
		ClusterName: ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:   metav1.Now(),
	}
}

// updateILStatus prepares the status update IL
func (ctlr *Controller) updateILStatus(il *cisapiv1.IngressLink, ip string, status string, err error) {
	ilStatus := cisapiv1.IngressLinkStatus{
		Status:      status,
		LastUpdated: metav1.Now(),
	}
	if err != nil {
		ilStatus.Error = err.Error()
	} else if ip != "" {
		ilStatus.VSAddress = ip
	} else {
		ilStatus.Error = fmt.Sprintf("Missing label f5cr on il %v/%v", il.Namespace, il.Name)
	}
	il.Status = ilStatus
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj: il,
		ClusterName: ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:   metav1.Now(),
	}
}

// updateLBServiceStatus prepares the status update LB service
func (ctlr *Controller) updateLBServiceStatus(svc *v1.Service, ip string, clusterName string, setStatus bool) {
	if _, ok := ctlr.shouldProcessServiceTypeLB(svc, clusterName, true); !ok {
		return
	}
	// CIS has to set the status of LB Service
	if setStatus {
		// Set the ingress status to include the virtual IP
		lbIngress := v1.LoadBalancerIngress{IP: ip}
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, lbIngress)
		} else if svc.Status.LoadBalancer.Ingress[0].IP != ip {
			svc.Status.LoadBalancer.Ingress[0] = lbIngress
		}
		if config := ctlr.multiClusterHandler.getClusterConfig(clusterName); config != nil {
			ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
				ResourceObj: svc,
				ClusterName: clusterName,
				Timestamp:   metav1.Now(),
				IPSet:       setStatus,
			}
		}
	} else {
		// Unset status
		// CIS has to clear the status of LB Service
		index := -1
		for i, lbIng := range svc.Status.LoadBalancer.Ingress {
			if lbIng.IP == ip {
				index = i
				break
			}
		}

		if index != -1 {
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress[:index],
				svc.Status.LoadBalancer.Ingress[index+1:]...)
			// If status of LB needs to be cleaned then either the service LB's key fields have been updated for which
			// CIS might have created delete and create events is  SvcLB resource for CIS, or it's been actually deleted
			// In both the cases the case the status cache needs to be cleaned or else the stale entry will remain forever
			if config := ctlr.multiClusterHandler.getClusterConfig(clusterName); config != nil {
				ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
					ResourceObj:       svc,
					ClusterName:       clusterName,
					Timestamp:         metav1.Now(),
					IPSet:             setStatus,
					ClearKeyFromCache: true,
				}
			}
		}
	}
}

// update route admit status
func (ctlr *Controller) updateRouteAdmitStatus(
	rscKey string,
	reason string,
	message string,
	status v1.ConditionStatus,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("CIS recovered from the panic caused by status update for route:%s.\n", rscKey)
		}
	}()
	route := ctlr.fetchRoute(rscKey)
	if route == nil {
		return
	}
	Admitted := false
	now := metav1.Now().Rfc3339Copy()
	var routeStatusIngress []routeapi.RouteIngress
	for _, routeIngress := range route.Status.Ingress {
		if routeIngress.RouterName == F5RouterName {
			for _, condition := range routeIngress.Conditions {
				if condition.Status == status {
					Admitted = true
				}
			}
		} else {
			routeStatusIngress = append(routeStatusIngress, routeIngress)
		}
	}
	if Admitted {
		return
	}
	routeStatusIngress = append(routeStatusIngress, routeapi.RouteIngress{
		RouterName: F5RouterName,
		Host:       route.Spec.Host,
		Conditions: []routeapi.RouteIngressCondition{{
			Type:               routeapi.RouteAdmitted,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: &now,
		}},
	})
	// updating to the new status
	route.Status.Ingress = routeStatusIngress
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj: route,
		ClusterName: ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:   metav1.Now(),
	}
}

// remove the route admit status for routes which are not monitored by CIS anymore
func (ctlr *Controller) eraseAllRouteAdmitStatus() {
	// Get the list of all unwatched Routes from all NS.
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	if clusterConfig == nil {
		log.Errorf("Error while clearing status for all the unmonitored Routes: Error: clusterConfig "+
			"could not found for the cluster:%v", ctlr.multiClusterHandler.LocalClusterName)
		return
	}
	unmonitoredOptions := metav1.ListOptions{
		LabelSelector: strings.ReplaceAll(clusterConfig.routeLabel, " in ", " notin "),
	}
	unmonitoredRoutes, err := clusterConfig.routeClientV1.Routes("").List(context.TODO(), unmonitoredOptions)
	if err != nil {
		log.Errorf("[CORE] Error listing all Routes: %v", err)
		return
	}
	for _, route := range unmonitoredRoutes.Items {
		ctlr.eraseRouteAdmitStatus(&route)
	}
}

// eraseRouteAdmitStatus clears the Admit Status for Route
func (ctlr *Controller) eraseRouteAdmitStatus(route *routeapi.Route) {
	// Fetching the latest copy of route
	if route == nil {
		return
	}
	routeLatest := ctlr.fetchRoute(route.Namespace + "/" + route.Name)
	if routeLatest == nil {
		log.Warningf("Failed to fetch the route %v/%v for status update", route.ObjectMeta.Namespace, route.ObjectMeta.Name)
		return
	}
	// Take the latest route object
	route = routeLatest
	defer func() {
		// This removes the deleted route's entry from host-path map
		// update the processedHostPathMap if the route is deleted
		var key string
		if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
			key = route.Spec.Host
		} else {
			key = route.Spec.Host + route.Spec.Path
		}
		ctlr.processedHostPath.Lock()
		if timestamp, ok := ctlr.processedHostPath.processedHostPathMap[key]; ok && timestamp == route.ObjectMeta.CreationTimestamp {
			delete(ctlr.processedHostPath.processedHostPathMap, key)
		}
		ctlr.processedHostPath.Unlock()
	}()

	for i := 0; i < len(route.Status.Ingress); i++ {
		if route.Status.Ingress[i].RouterName == F5RouterName {
			route.Status.Ingress = append(route.Status.Ingress[:i], route.Status.Ingress[i+1:]...)
			ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
				ResourceObj:       route,
				ClusterName:       ctlr.multiClusterHandler.LocalClusterName,
				Timestamp:         metav1.Now(),
				ClearKeyFromCache: true,
			}
			break
		}
	}
}

// clearAllUnmonitoredVirtualServerStatus clears status for all the unmonitored Virtual Servers
func (ctlr *Controller) clearAllUnmonitoredVirtualServerStatus() {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	if clusterConfig == nil {
		log.Errorf("Error while clearing status for all the unmonitored Virtual Server CRs: Error: clusterConfig "+
			"could not found for the cluster:%v", ctlr.multiClusterHandler.LocalClusterName)
		return
	}
	unmonitoredOptions := metav1.ListOptions{
		LabelSelector: strings.ReplaceAll(clusterConfig.customResourceSelector.String(), " in ", " notin "),
	}
	unmonitoredVS, err := clusterConfig.kubeCRClient.CisV1().VirtualServers("").List(context.TODO(), unmonitoredOptions)
	if err != nil {
		log.Errorf("Error while fetching unmonitored virtual servers: %v %v", err, unmonitoredVS)
	}

	for _, virtualServer := range unmonitoredVS.Items {
		ctlr.clearVirtualServerStatus(&virtualServer)
	}
}

// clearVirtualServerStatus clears status for the Virtual Server
func (ctlr *Controller) clearVirtualServerStatus(virtualServer *cisapiv1.VirtualServer) {
	virtualServer.Status = cisapiv1.VirtualServerStatus{
		Error: fmt.Sprintf("Missing label f5cr on VS %v/%v", virtualServer.Namespace, virtualServer.Name),
	}
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj:       virtualServer,
		ClusterName:       ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:         metav1.Now(),
		ClearKeyFromCache: true,
	}
}

// updateAllUnmonitoredTransportServerStatus clears status for all the unmonitored Transport Servers
func (ctlr *Controller) updateAllUnmonitoredTransportServerStatus() {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	if clusterConfig == nil {
		log.Errorf("Error while clearing status for all the unmonitored Transport Server CRs: Error: clusterConfig "+
			"could not found for the cluster:%v", ctlr.multiClusterHandler.LocalClusterName)
		return
	}
	unmonitoredOptions := metav1.ListOptions{
		LabelSelector: strings.ReplaceAll(clusterConfig.customResourceSelector.String(), " in ", " notin "),
	}
	unmonitoredTS, err := clusterConfig.kubeCRClient.CisV1().TransportServers("").List(context.TODO(), unmonitoredOptions)
	if err != nil {
		log.Errorf("Error while fetching unmonitored transport servers: %v %v", err, unmonitoredTS)
	}

	for _, transportServer := range unmonitoredTS.Items {
		ctlr.clearTransportServerStatus(&transportServer)
	}
}

// clearTransportServerStatus clears status for the Transport Server
func (ctlr *Controller) clearTransportServerStatus(transportServer *cisapiv1.TransportServer) {
	transportServer.Status = cisapiv1.TransportServerStatus{
		Error: fmt.Sprintf("Missing label f5cr on TS %v/%v", transportServer.Namespace, transportServer.Name),
	}
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj:       transportServer,
		ClusterName:       ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:         metav1.Now(),
		ClearKeyFromCache: true,
	}
}

// updateAllUnmonitoredIngressLinkStatus clears status for all the unmonitored IngressLink
func (ctlr *Controller) updateAllUnmonitoredIngressLinkStatus() {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	if clusterConfig == nil {
		log.Errorf("Error while clearing status for all the unmonitored Transport Server CRs: Error: clusterConfig "+
			"could not found for the cluster:%v", ctlr.multiClusterHandler.LocalClusterName)
		return
	}
	unmonitoredOptions := metav1.ListOptions{
		LabelSelector: strings.ReplaceAll(clusterConfig.customResourceSelector.String(), " in ", " notin "),
	}
	unmonitoredIL, err := clusterConfig.kubeCRClient.CisV1().IngressLinks("").List(context.TODO(), unmonitoredOptions)
	if err != nil {
		log.Errorf("Error while fetching unmonitored transport servers: %v %v", err, unmonitoredIL)
	}

	for _, ingressLink := range unmonitoredIL.Items {
		ctlr.clearIngressLinkStatus(&ingressLink)
	}
}

// clearIngressLinkStatus clears status for the IngressLink
func (ctlr *Controller) clearIngressLinkStatus(ingressLink *cisapiv1.IngressLink) {
	ingressLink.Status = cisapiv1.IngressLinkStatus{
		Error: fmt.Sprintf("Missing label f5cr on IngressLink %v/%v", ingressLink.Namespace, ingressLink.Name),
	}
	ctlr.multiClusterHandler.statusUpdate.ResourceStatusUpdateChan <- ResourceStatus{
		ResourceObj:       ingressLink,
		ClusterName:       ctlr.multiClusterHandler.LocalClusterName,
		Timestamp:         metav1.Now(),
		ClearKeyFromCache: true,
	}
}

// cleanupUnmonitoredResourceStatus clears status for all the unmonitored resources
func (ctlr *Controller) cleanupUnmonitoredResourceStatus() {
	log.Debugf("Cleaning up unmonitored resource status")
	ctlr.clearAllUnmonitoredVirtualServerStatus()
	ctlr.updateAllUnmonitoredTransportServerStatus()
	if ctlr.mode == OpenShiftMode {
		ctlr.eraseAllRouteAdmitStatus()
	}
}
