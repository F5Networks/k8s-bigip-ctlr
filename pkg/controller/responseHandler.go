package controller

import (
	"container/list"
	"context"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"sync"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
)

func (ctlr *Controller) enqueueReq(config ResourceConfigRequest) int {
	rm := requestMeta{
		meta: make(map[string]string, len(config.ltmConfig)),
	}
	if ctlr.requestQueue.Len() == 0 {
		rm.id = 1
	} else {
		rm.id = ctlr.requestQueue.Back().Value.(requestMeta).id + 1
	}

	for _, rsMap := range config.ltmConfig {
		for _, cfg := range rsMap {
			for key, val := range cfg.MetaData.baseResources {
				rm.meta[key] = val
			}
		}
	}
	if len(rm.meta) > 0 {
		ctlr.requestQueue.Lock()
		ctlr.requestQueue.PushBack(rm)
		ctlr.requestQueue.Unlock()
	}
	return rm.id
}

func (ctlr *Controller) responseHandler(respChan chan int) {
	ctlr.requestQueue = &requestQueue{sync.Mutex{}, list.New()}

	for id := range respChan {
		var rm requestMeta
		for ctlr.requestQueue.Len() > 0 && ctlr.requestQueue.Front().Value.(requestMeta).id <= id {
			ctlr.requestQueue.Lock()
			rm = ctlr.requestQueue.Remove(ctlr.requestQueue.Front()).(requestMeta)
			ctlr.requestQueue.Unlock()
		}

		for rscKey, kind := range rm.meta {
			ns := strings.Split(rscKey, "/")[0]
			switch kind {
			case VirtualServer:
				// update status
				crInf, ok := ctlr.getNamespacedInformer(ns)
				if !ok {
					log.Debugf("VirtualServer Informer not found for namespace: %v", ns)
					continue
				}
				obj, exist, err := crInf.vsInformer.GetIndexer().GetByKey(rscKey)
				if err != nil {
					log.Debugf("Could not fetch VirtualServer: %v: %v", rscKey, err)
					continue
				}
				if !exist {
					log.Debugf("VirtualServer Not Found: %v", rscKey)
					continue
				}
				virtual := obj.(*cisapiv1.VirtualServer)
				if virtual.Namespace+"/"+virtual.Name == rscKey {
					ctlr.updateVirtualServerStatus(virtual, virtual.Status.VSAddress, "Ok")
				}
			case TransportServer:
				// update status
				crInf, ok := ctlr.getNamespacedInformer(ns)
				if !ok {
					log.Debugf("TransportServer Informer not found for namespace: %v", ns)
					continue
				}
				obj, exist, err := crInf.tsInformer.GetIndexer().GetByKey(rscKey)
				if err != nil {
					log.Debugf("Could not fetch TransportServer: %v: %v", rscKey, err)
					continue
				}
				if !exist {
					log.Debugf("TransportServer Not Found: %v", rscKey)
					continue
				}
				virtual := obj.(*cisapiv1.TransportServer)
				if virtual.Namespace+"/"+virtual.Name == rscKey {
					ctlr.updateTransportServerStatus(virtual, virtual.Status.VSAddress, "Ok")
				}
			case Route:
				nrInf, ok := ctlr.getNamespacedNativeInformer(ns)
				if !ok {
					log.Debugf("Informer not found for namespace: %v, failed to update Route status", ns)
					continue
				}
				obj, exist, err := nrInf.routeInformer.GetIndexer().GetByKey(rscKey)
				if err != nil {
					log.Debugf("Error while fetching Route: %v: %v, failed to update Route status",
						rscKey, err)
					continue
				}
				if !exist {
					log.Debugf("Route Not Found: %v, failed to update Route status", rscKey)
					continue
				}

				route := obj.(*routeapi.Route)
				now := metaV1.Now().Rfc3339Copy()
				route.Status.Ingress = append(route.Status.Ingress, routeapi.RouteIngress{
					RouterName: F5RouterName,
					Host:       route.Spec.Host,
					Conditions: []routeapi.RouteIngressCondition{{
						Type:               routeapi.RouteAdmitted,
						Status:             v1.ConditionTrue,
						LastTransitionTime: &now,
					}},
				})
				_, err = ctlr.routeClientV1.Routes(route.ObjectMeta.Namespace).UpdateStatus(context.TODO(), route, metaV1.UpdateOptions{})
				if err != nil {
					log.Errorf("Error while Updating Route Admit Status: %v\n", err)
				} else {
					log.Debugf("Admitted Route -  %v", route.ObjectMeta.Name)
				}
			}
		}
	}
}
