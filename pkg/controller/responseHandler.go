package controller

import (
	"container/list"
	"sync"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

func (ctlr *Controller) enqueueReq(config ResourceConfigRequest) int {
	rm := requestMeta{
		meta: make(map[string]metaData, len(config.ltmConfig)),
	}
	if ctlr.requestQueue.Len() == 0 {
		rm.id = 1
	} else {
		rm.id = ctlr.requestQueue.Back().Value.(requestMeta).id + 1
	}

	for _, rsMap := range config.ltmConfig {
		for _, cfg := range rsMap {
			for key, _ := range cfg.MetaData.baseResources {
				rm.meta[key] = cfg.MetaData
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

		for rscKey, item := range rm.meta {
			switch item.ResourceType {
			case VirtualServer:
				// update status
				crInf, ok := ctlr.getNamespacedInformer(item.namespace)
				if !ok {
					log.Debugf("VirtualServer Informer not found for namespace: %v", item.namespace)
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
				crInf, ok := ctlr.getNamespacedInformer(item.namespace)
				if !ok {
					log.Debugf("TransportServer Informer not found for namespace: %v", item.namespace)
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

			}
		}
	}
}
