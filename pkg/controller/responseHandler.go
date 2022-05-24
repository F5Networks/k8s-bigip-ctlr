package controller

import (
	"container/list"
	"strings"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"

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

func (ctlr *Controller) responseHandler(respChan chan resourceStatusMeta) {
	// todo: update only when there is a change(success to fail or vice versa) in tenant status
	ctlr.requestQueue = &requestQueue{sync.Mutex{}, list.New()}
	for rscUpdateMeta := range respChan {

		rm := ctlr.dequeueReq(rscUpdateMeta.id, len(rscUpdateMeta.failedTenants))

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
				if _, found := rscUpdateMeta.failedTenants[ns]; found {
					// TODO : distinguish between a 503 and an actual failure
					go ctlr.updateRouteAdmitStatus(rscKey, "Failure while updating config", "Please check logs for more information", v1.ConditionFalse)
				} else {
					go ctlr.updateRouteAdmitStatus(rscKey, "", "", v1.ConditionTrue)
				}
			}
		}
	}
}

func (ctlr *Controller) dequeueReq(id int, failedTenantsLen int) requestMeta {
	var rm requestMeta
	if id == 0 {
		// request initiated from a retried tenant
		ctlr.requestQueue.Lock()

		if ctlr.requestQueue.Len() == 1 && failedTenantsLen > 0 {
			// Retain the last request in the queue to update the config in later stages when retry is successful
			rm = ctlr.requestQueue.Front().Value.(requestMeta)
		} else if ctlr.requestQueue.Len() > 0 {
			rm = ctlr.requestQueue.Remove(ctlr.requestQueue.Front()).(requestMeta)
		}
		ctlr.requestQueue.Unlock()
		return rm
	}

	for ctlr.requestQueue.Len() > 0 && ctlr.requestQueue.Front().Value.(requestMeta).id <= id {
		ctlr.requestQueue.Lock()
		if ctlr.requestQueue.Len() == 1 && failedTenantsLen > 0 {
			// Retain the last request in the queue to update the config in later stages when retry is successful
			rm = ctlr.requestQueue.Front().Value.(requestMeta)
			ctlr.requestQueue.Unlock()
			break
		} else {
			rm = ctlr.requestQueue.Remove(ctlr.requestQueue.Front()).(requestMeta)
		}
		ctlr.requestQueue.Unlock()
	}

	return rm
}
