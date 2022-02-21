package controller

import (
	"container/list"
	"sync"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

func (ctlr *Controller) enqueueReq(config ResourceConfigRequest) {
	rm := requestMeta{
		meta: make([]metaData, len(config.rsCfgs)),
	}
	if ctlr.requestQueue.Len() == 0 {
		rm.id = 1
	} else {
		rm.id = ctlr.requestQueue.Back().Value.(requestMeta).id + 1
	}

	isEmptyMetadata := true
	for _, cfg := range config.rsCfgs {
		if cfg.MetaData.rscName != "" && cfg.MetaData.namespace != "" {
			rm.meta = append(rm.meta, cfg.MetaData)
			isEmptyMetadata = false
		}
	}
	if !isEmptyMetadata {
		ctlr.requestQueue.Lock()
		ctlr.requestQueue.PushBack(rm)
		ctlr.requestQueue.Unlock()
	}
}

func (ctlr *Controller) responseHandler(respChan chan int) {
	ctlr.requestQueue = &requestQueue{sync.Mutex{}, list.New()}

	for id := range respChan {
		var rm requestMeta
		for ctlr.requestQueue.Len() > 0 {
			ctlr.requestQueue.Lock()
			rm = ctlr.requestQueue.Remove(ctlr.requestQueue.Front()).(requestMeta)
			ctlr.requestQueue.Unlock()
			if id == rm.id {
				break
			}
		}

		for _, item := range rm.meta {
			switch item.ResourceType {
			case VirtualServer:
				// update status
				vsKey := item.namespace + "/" + item.rscName
				crInf, ok := ctlr.getNamespacedInformer(item.namespace)
				if !ok {
					log.Errorf("Informer not found for namespace: %v, failed to update VS status", item.namespace)
					break
				}
				obj, exist, err := crInf.vsInformer.GetIndexer().GetByKey(vsKey)
				if err != nil {
					log.Errorf("Error while fetching VirtualServer: %v: %v, failed to update VS status",
						vsKey, err)
					break
				}
				if !exist {
					log.Errorf("VirtualServer Not Found: %v, failed to update VS status", vsKey)
					break
				}
				virtual := obj.(*cisapiv1.VirtualServer)
				if virtual.Name == item.rscName && virtual.Namespace == item.namespace {
					ctlr.updateVirtualServerStatus(virtual, virtual.Status.VSAddress, "Ok")
				}
			case TransportServer:
				// update status
				vsKey := item.namespace + "/" + item.rscName
				crInf, ok := ctlr.getNamespacedInformer(item.namespace)
				if !ok {
					log.Errorf("Informer not found for namespace: %v, failed to update TS status", item.namespace)
					break
				}
				obj, exist, err := crInf.tsInformer.GetIndexer().GetByKey(vsKey)
				if err != nil {
					log.Errorf("Error while fetching TransportServer: %v: %v, failed to update TS status",
						vsKey, err)
					break
				}
				if !exist {
					log.Errorf("TransportServer Not Found: %v, failed to update TS status", vsKey)
					break
				}
				virtual := obj.(*cisapiv1.TransportServer)
				if virtual.Name == item.rscName && virtual.Namespace == item.namespace {
					ctlr.updateTransportServerStatus(virtual, virtual.Status.VSAddress, "Ok")
				}

			}
		}
	}
}
