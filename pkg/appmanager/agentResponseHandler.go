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

package appmanager

import (
	"context"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
)

const (
	F5RouterName = "F5 BIG-IP"
)

// erase all the route admit status submitted by F5 BIG-IP router
func (appMgr *Manager) eraseRouteAdmitStatus(rscKey string) {
	// Fetching the latest copy of route
	route := appMgr.fetchRoute(rscKey)
	if route == nil {
		return
	}
	for i := 0; i < len(route.Status.Ingress); i++ {
		if route.Status.Ingress[i].RouterName == F5RouterName {
			route.Status.Ingress = append(route.Status.Ingress[:i], route.Status.Ingress[i+1:]...)
			erased := false
			retryCount := 0
			for !erased && retryCount < 3 {
				_, err := appMgr.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(), route, metaV1.UpdateOptions{})
				if err != nil {
					log.Errorf("[CORE] Error while Erasing Route Admit Status: %v\n", err)
					retryCount++
					route = appMgr.fetchRoute(rscKey)
					if route == nil {
						return
					}
				} else {
					erased = true
					log.Debugf("[CORE] Admit Status Erased for Route - %v\n", route.ObjectMeta.Name)
				}
			}
			i-- // Since we just deleted a[i], we must redo that index
		}
	}
}

// For any route added, the Ingress is not populated unless it is admitted by a Router.
// This must be populated by CIS based on BIG-IP response 200 OK.
// If BIG-IP response is an error, do care update Ingress.
// Don't update an existing Ingress object when BIG-IP response is not 200 OK. Its already consumed.
func (appMgr *Manager) updateRouteAdmitStatusAll() {
	processedRoutes := make(map[string]struct{})
	appMgr.processedResourcesMutex.Lock()
	defer appMgr.processedResourcesMutex.Unlock()
	for key, processedStatus := range appMgr.processedResources {
		dashSplit := strings.Split(key, "_")
		if dashSplit[0] == Routes && processedStatus {
			appMgr.updateRouteAdmitStatus(dashSplit[1], "", "", v1.ConditionTrue)
		}
		processedRoutes[dashSplit[1]] = struct{}{}
	}

	// Get the list of Routes from all NS and remove updated metadata.
	allOptions := metaV1.ListOptions{
		LabelSelector: "",
	}
	allNamespaces := ""
	allRoutes, err := appMgr.routeClientV1.Routes(allNamespaces).List(context.TODO(), allOptions)
	if err != nil {
		log.Errorf("[CORE] Error listing Routes: %v", err)
		return
	}
	// Check whether we are processing this route.
	// Else, clean the route metadata if we add any in the past.
	for _, aRoute := range allRoutes.Items {
		routeKey := fmt.Sprintf("%v/%v", aRoute.Namespace, aRoute.Name)
		if _, ok := processedRoutes[routeKey]; !ok {
			appMgr.eraseRouteAdmitStatus(routeKey)
			// update the processedHostPathMap if the route is deleted
			var key string
			if aRoute.Spec.Path == "/" || len(aRoute.Spec.Path) == 0 {
				key = aRoute.Spec.Host
			} else {
				key = aRoute.Spec.Host + aRoute.Spec.Path
			}
			appMgr.processedHostPath.Lock()
			if timestamp, ok := appMgr.processedHostPath.processedHostPathMap[key]; ok && timestamp == aRoute.ObjectMeta.CreationTimestamp {
				delete(appMgr.processedHostPath.processedHostPathMap, key)
			}
			appMgr.processedHostPath.Unlock()
		}
	}
}

// update the specified route admit status to a single route
func (appMgr *Manager) updateRouteAdmitStatus(
	rscKey string,
	reason string,
	message string,
	status v1.ConditionStatus,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("CIS recovered from the panic caused by route status update: %v\n")
		}
	}()
	for retryCount := 0; retryCount < 3; retryCount++ {
		route := appMgr.fetchRoute(rscKey)
		if route == nil {
			return
		}
		Admitted := false
		now := metaV1.Now().Rfc3339Copy()
		for _, routeIngress := range route.Status.Ingress {
			if routeIngress.RouterName == F5RouterName {
				for _, condition := range routeIngress.Conditions {
					if condition.Status == status {
						Admitted = true
					} else {
						// remove all multiple route admit status submitted earlier
						appMgr.eraseRouteAdmitStatus(rscKey)
					}
				}
			}
		}
		if Admitted {
			return
		}
		route.Status.Ingress = append(route.Status.Ingress, routeapi.RouteIngress{
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
		_, err := appMgr.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(), route, metaV1.UpdateOptions{})
		if err == nil {
			log.Debugf("Admitted Route -  %v", route.ObjectMeta.Name)
			return
		}
		log.Errorf("Error while Updating Route Admit Status: %v\n", err)
	}
}

// Fetch the latest copy of route
func (appMgr *Manager) fetchRoute(rscKey string) *routeapi.Route {
	ns := strings.Split(rscKey, "/")[0]
	appInf, haveNamespace := appMgr.getNamespaceInformer(ns)
	if !haveNamespace {
		return nil
	}
	obj, exist, err := appInf.routeInformer.GetIndexer().GetByKey(rscKey)
	if err != nil {
		log.Debugf("Error while fetching Route: %v: %v",
			rscKey, err)
		return nil
	}
	if !exist {
		log.Debugf("Route Not Found: %v", rscKey)
		return nil
	}
	return obj.(*routeapi.Route)
}

// agentResponseWorker is a go routine blocks on agent Response Chan
// get unblocked when Agent post agent Response Message on agRspChan
func (appMgr *Manager) agentResponseWorker() {
	log.Debugf("[CORE] Agent Response Worker started and blocked on channel  %v", appMgr.agRspChan)
	for msgRsp := range appMgr.agRspChan {
		rspMsg := msgRsp.(resource.MessageResponse).ResourceResponse
		// If admit status is set and if routes are configured appManager
		// would process route admit status, by default appManager would
		// process ARP handling aloing with Admit Status for both k8s or OSCP
		if rspMsg.IsResponseSuccessful == true {
			// if route is configured in appManager
			if appMgr.routeClientV1 != nil {
				log.Debugf("[CORE] Updating Route Admit Status")
				appMgr.updateRouteAdmitStatusAll()
			}
		}
	}
}
