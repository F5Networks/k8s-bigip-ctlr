package controller

import (
	"container/list"
	"strings"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
)

func (ctlr *Controller) enqueueReq(config ResourceConfigRequest) int {
	rm := requestMeta{
		partitionMap: make(map[string]map[string]string, len(config.ltmConfig)),
	}
	if ctlr.requestQueue.Len() == 0 {
		rm.id = 1
	} else {
		rm.id = ctlr.requestQueue.Back().Value.(requestMeta).id + 1
	}

	metaPresent := false
	for partition, partitionConfig := range config.ltmConfig {
		rm.partitionMap[partition] = make(map[string]string)
		for _, cfg := range partitionConfig.ResourceMap {
			for key, val := range cfg.MetaData.baseResources {
				rm.partitionMap[partition][key] = val
				metaPresent = true
			}
		}
	}
	if metaPresent {
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
		for partition, meta := range rm.partitionMap {
			// Check if it's a priority tenant and not in failedTenants map, if so then update the priority back to zero
			// Priority tenant doesn't have any meta
			if _, found := rscUpdateMeta.failedTenants[partition]; !found && len(meta) == 0 {
				// updating the tenant priority back to zero if it's not in failed tenants
				ctlr.resources.updatePartitionPriority(partition, 0)
				continue
			}
			for rscKey, kind := range meta {
				ns := strings.Split(rscKey, "/")[0]
				switch kind {
				case VirtualServer:
					// update status
					crInf, ok := ctlr.getNamespacedCRInformer(ns)
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
						if _, found := rscUpdateMeta.failedTenants[partition]; !found {
							// update the status for virtual server as tenant posting is success
							ctlr.updateVirtualServerStatus(virtual, virtual.Status.VSAddress, "Ok")
							// Update Corresponding Service Status of Type LB
							for _, pool := range virtual.Spec.Pools {
								var svcNamespace string
								if pool.ServiceNamespace != "" {
									svcNamespace = pool.ServiceNamespace
								} else {
									svcNamespace = virtual.Namespace
								}
								svc := ctlr.GetService(svcNamespace, pool.Service)
								if svc != nil && svc.Spec.Type == v1.ServiceTypeLoadBalancer {
									ctlr.setLBServiceIngressStatus(svc, virtual.Status.VSAddress)
								}
							}
						}
					}

				case TransportServer:
					// update status
					crInf, ok := ctlr.getNamespacedCRInformer(ns)
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
						if _, found := rscUpdateMeta.failedTenants[partition]; !found {
							// update the status for transport server as tenant posting is success
							ctlr.updateTransportServerStatus(virtual, virtual.Status.VSAddress, "Ok")
							// Update Corresponding Service Status of Type LB
							var svcNamespace string
							if virtual.Spec.Pool.ServiceNamespace != "" {
								svcNamespace = virtual.Spec.Pool.ServiceNamespace
							} else {
								svcNamespace = virtual.Namespace
							}
							svc := ctlr.GetService(svcNamespace, virtual.Spec.Pool.Service)
							if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
								ctlr.setLBServiceIngressStatus(svc, virtual.Status.VSAddress)
							}
						}
					}
				case Route:
					if _, found := rscUpdateMeta.failedTenants[partition]; found {
						// TODO : distinguish between a 503 and an actual failure
						go ctlr.updateRouteAdmitStatus(rscKey, "Failure while updating config", "Please check logs for more information", v1.ConditionFalse)
					} else {
						go ctlr.updateRouteAdmitStatus(rscKey, "", "", v1.ConditionTrue)
					}
					//case IngressLink:
					//	if _, found := rscUpdateMeta.failedTenants[partition]; !found {
					//		// updating the tenant priority back to zero if it's not in failed tenants
					//		ctlr.resources.updatePartitionPriority(partition, 0)
					//	}
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
