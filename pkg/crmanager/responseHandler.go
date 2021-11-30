package crmanager

import (
	"container/list"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"sync"
)

type requestQueueData struct {
	sync.Mutex
	*list.List
}

type requestMeta struct {
	meta []metaData
	id   int
}

func (crMgr *CRManager) enqueueReq(config ResourceConfigWrapper) {
	rm := requestMeta{
		meta: make([]metaData, len(config.rsCfgs)),
	}
	if crMgr.requestQueue.Len() == 0 {
		rm.id = 1
	} else {
		rm.id = crMgr.requestQueue.Back().Value.(requestMeta).id + 1
	}

	isEmptyMetadata := true
	for _, cfg := range config.rsCfgs {
		if cfg.MetaData.rscName != "" && cfg.MetaData.namespace != "" {
			rm.meta = append(rm.meta, cfg.MetaData)
			isEmptyMetadata = false
		}
	}
	if !isEmptyMetadata {
		crMgr.requestQueue.Lock()
		crMgr.requestQueue.PushBack(rm)
		crMgr.requestQueue.Unlock()
	}
}

func (crMgr *CRManager) responseHandler(respChan chan int) {
	crMgr.requestQueue = &requestQueueData{sync.Mutex{},list.New()}

	for id := range respChan {
		var rm requestMeta
		for crMgr.requestQueue.Len() > 0 {
			crMgr.requestQueue.Lock()
			rm = crMgr.requestQueue.Remove(crMgr.requestQueue.Front()).(requestMeta)
			crMgr.requestQueue.Unlock()
			if id == rm.id {
				break
			}
		}
		for _, item := range rm.meta {
			switch item.ResourceType {
			case VirtualServer:
				// update status
				vsKey := item.namespace + "/" + item.rscName
				crInf, ok := crMgr.getNamespacedInformer(item.namespace)
				if !ok {
					log.Errorf("Informer not found for namespace: %v", item.namespace)
				}
				obj, exist, err := crInf.vsInformer.GetIndexer().GetByKey(vsKey)
				if err != nil {
					log.Errorf("Error while fetching VirtualServer: %v: %v",
						vsKey, err)
				}
				if !exist {
					log.Errorf("VirtualServer Not Found: %v", vsKey)
				}
				virtual := obj.(*cisapiv1.VirtualServer)
				if virtual.Name == item.rscName && virtual.Namespace == item.namespace {
					crMgr.updateVirtualServerStatus(virtual, virtual.Status.VSAddress, "Ok")
				}
			case TransportServer:
				// update status
				vsKey := item.namespace + "/" + item.rscName
				crInf, ok := crMgr.getNamespacedInformer(item.namespace)
				if !ok {
					log.Errorf("Informer not found for namespace: %v", item.namespace)
				}
				obj, exist, err := crInf.tsInformer.GetIndexer().GetByKey(vsKey)
				if err != nil {
					log.Errorf("Error while fetching TransportServer: %v: %v",
						vsKey, err)
				}
				if !exist {
					log.Errorf("TransportServer Not Found: %v", vsKey)
				}
				virtual := obj.(*cisapiv1.TransportServer)
				if virtual.Name == item.rscName && virtual.Namespace == item.namespace {
					crMgr.updateTransportServerStatus(virtual, virtual.Status.VSAddress, "Ok")
				}

			}
		}
	}
}

