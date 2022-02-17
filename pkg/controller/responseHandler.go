package controller

import (
	"container/list"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

func (ctlr *Controller) enqueueReq(config ResourceConfigRequest) int {
	rm := requestMeta{
		meta: make([]metaData, len(config.rsCfgs)),
	}
	if ctlr.requestQueue.Len() == 0 {
		rm.id = 1
	} else {
		rm.id = ctlr.requestQueue.Back().Value.(requestMeta).id + 1
	}
    isNewEntry := false
	for _, cfg := range config.rsCfgs {
		if len(cfg.MetaData.rscName) == 0 || len(cfg.MetaData.namespace) == 0 {
			continue
		}
		if ctlr.isEntryExistsInQueue(cfg.MetaData,rm) {
			continue
		}
		rm.meta = append(rm.meta, cfg.MetaData)
		isNewEntry = true
	}

	if isNewEntry {
		ctlr.requestQueue.Lock()
		ctlr.requestQueue.PushBack(rm)
		ctlr.requestQueue.Unlock()
		return rm.id
	} else {
		// As not added in the queue
		return rm.id-1
	}
}

func (ctlr *Controller) responseHandler(respChan chan int) {
	ctlr.requestQueue = &requestQueue{sync.Mutex{}, list.New()}

	for id := range respChan {
		var rm requestMeta
		if ctlr.requestQueue.Len() > 0 {
			if !ctlr.isRequestIDExists(id) {
				return
			}
		}
		for ctlr.requestQueue.Len() > 0 {
			ctlr.requestQueue.Lock()
			rm = ctlr.requestQueue.Remove(ctlr.requestQueue.Front()).(requestMeta)
			ctlr.requestQueue.Unlock()
			for _, item := range rm.meta {
				switch item.ResourceType {
				case VirtualServer:
					// update status
					vsKey := item.namespace + "/" + item.rscName
					crInf, ok := ctlr.getNamespacedInformer(item.namespace)
					if !ok {
						log.Errorf("Informer not found for namespace: %v, failed to update VS status", item.namespace)
						continue
					}
					obj, exist, err := crInf.vsInformer.GetIndexer().GetByKey(vsKey)
					if err != nil {
						log.Errorf("Error while fetching VirtualServer: %v: %v, failed to update VS status",
							vsKey, err)
						continue
					}
					if !exist {
						log.Errorf("VirtualServer Not Found: %v, failed to update VS status", vsKey)
						continue
					}
					virtual := obj.(*cisapiv1.VirtualServer)

					if virtual.Name == item.rscName && virtual.Namespace == item.namespace {
						if rm.id < id && virtual.Status.StatusOk == "Ok" {
							continue
						}
						ctlr.updateVirtualServerStatus(virtual, virtual.Status.VSAddress, "Ok")
					}
				case TransportServer:
					// update status
					vsKey := item.namespace + "/" + item.rscName
					crInf, ok := ctlr.getNamespacedInformer(item.namespace)
					if !ok {
						log.Errorf("Informer not found for namespace: %v, failed to update TS status", item.namespace)
						continue
					}
					obj, exist, err := crInf.tsInformer.GetIndexer().GetByKey(vsKey)
					if err != nil {
						log.Errorf("Error while fetching TransportServer: %v: %v, failed to update TS status",
							vsKey, err)
						continue
					}
					if !exist {
						log.Errorf("TransportServer Not Found: %v, failed to update TS status", vsKey)
						continue
					}
					virtual := obj.(*cisapiv1.TransportServer)
					if virtual.Name == item.rscName && virtual.Namespace == item.namespace {
						if rm.id < id && virtual.Status.StatusOk == "Ok" {
							continue
						}
						ctlr.updateTransportServerStatus(virtual, virtual.Status.VSAddress, "Ok")
					}
				}
			}
			if id == rm.id {
				break
			}
		}
	}
}

func (ctlr *Controller) isEntryExistsInQueue(cfg metaData, rm requestMeta) bool {
	// Verify in local rm.meta
	for _, item := range rm.meta {
		if item.rscName == cfg.rscName && item.namespace == cfg.namespace {
			return true
		}
	}
	// Verify in Queue
	if ctlr.requestQueue.Len() > 0 {
		for e := ctlr.requestQueue.Front(); e != nil; e = e.Next() {
			for _,item := range e.Value.(requestMeta).meta {
				if item.rscName == cfg.rscName && item.namespace == cfg.namespace {
					return true
				}
			}
		}
	}
	return false
}

func (ctlr *Controller) isRequestIDExists(id int) bool {
	for e := ctlr.requestQueue.Front(); e != nil ; e = e.Next() {
		if e.Value.(requestMeta).id == id {
			return true
		}
	}
	return false
}
