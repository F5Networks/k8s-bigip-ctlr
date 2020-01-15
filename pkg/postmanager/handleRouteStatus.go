/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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

package postmanager

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Get the RFC3339Copy of the timestamp for updating the OpenShift Routes
func getRfc3339Timestamp() metaV1.Time {
	return metaV1.Now().Rfc3339Copy()
}

// Check whether we are processing this route.
// Else, clean the route metadata if we add any in past.
func isProcessedRoute(route routeapi.Route, routes []*routeapi.Route) bool {
	for _, rt := range routes {
		if route.ObjectMeta.Name == rt.ObjectMeta.Name && route.ObjectMeta.Namespace == rt.ObjectMeta.Namespace {
			return true
		}
	}
	return false
}

// Clean the MetaData for routes processed in the past and
// not considered now.
func (postMgr *PostManager) cleanupMetadata(route routeapi.Route) {
	if len(route.Status.Ingress) > 1 {
		for i := 0; i < len(route.Status.Ingress); i++ {
			if route.Status.Ingress[i].RouterName == F5RouterName {
				route.Status.Ingress = append(route.Status.Ingress[:i], route.Status.Ingress[i+1:]...)
				i--
			}
		}
		postMgr.RouteClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(&route)
	}
}

// For any route added, the Ingress is not populated unless it is admitted by a Router.
// This must be populated by CIS based on BIG-IP response 200 OK.
// If BIG-IP response is an error, do care update Ingress.
// Don't update an existing Ingress object when BIG-IP response is not 200 OK. Its already consumed.
func (postMgr *PostManager) updateRouteAdmitStatus(routes []*routeapi.Route) {
	now := getRfc3339Timestamp()
	for _, route := range routes {
		Admitted := false
		if len(route.Status.Ingress) != 0 {
			for _, routeIngress := range route.Status.Ingress {
				if routeIngress.RouterName == F5RouterName {
					Admitted = true
					break
				}
			}
			if !Admitted {
				route.Status.Ingress = append(route.Status.Ingress, routeapi.RouteIngress{
					RouterName: F5RouterName,
					Host:       route.Spec.Host,
					Conditions: []routeapi.RouteIngressCondition{{
						Type:               routeapi.RouteAdmitted,
						Status:             v1.ConditionTrue,
						LastTransitionTime: &now,
					}},
				})
				postMgr.RouteClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(route)
				log.Debugf("[AS3] Admitted Route -  %v", route.ObjectMeta.Name)
			}
		}
	}
	// Get the list of Routes from all NS and remove updated metadata.
	allOptions := metaV1.ListOptions{
		LabelSelector: "",
	}
	allNamespaces := ""
	allRoutes, err := postMgr.RouteClientV1.Routes(allNamespaces).List(allOptions)
	if err != nil {
		log.Errorf("[AS3]Error listing Routes: %v", err)
	}
	for _, aRoute := range allRoutes.Items {
		if !isProcessedRoute(aRoute, routes) {
			postMgr.cleanupMetadata(aRoute)
		}
	}
}
