package controller

import (
	"strings"
	"sync"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
)

func (ctlr *Controller) enqueueReq(config BigIpResourceConfig, bigIpConfig cisapiv1.BigIpConfig) requestMeta {
	rm := requestMeta{
		partitionMap: make(map[string]map[string]string, len(config.ltmConfig)),
	}
	ctlr.requestMap.Lock()
	if reqId, found := ctlr.requestMap.requestMap[bigIpConfig]; found {
		rm.id = reqId.id + 1
	} else {
		rm.id = 1
	}
	for partition, partitionConfig := range config.ltmConfig {
		rm.partitionMap[partition] = make(map[string]string)
		for _, cfg := range partitionConfig.ResourceMap {
			for key, val := range cfg.MetaData.baseResources {
				rm.partitionMap[partition][key] = val
			}
		}
	}
	ctlr.requestMap.requestMap[bigIpConfig] = rm
	ctlr.requestMap.Unlock()
	return rm
}

func (ctlr *Controller) responseHandler(respChan chan *agentConfig) {
	// todo: update only when there is a change(success to fail or vice versa) in tenant status
	ctlr.requestMap = &requestMap{sync.RWMutex{}, make(map[cisapiv1.BigIpConfig]requestMeta)}
	//TODO: Need to get bigipLabel from rspchan
	bigipLabel := BigIPLabel
	bigipConfig := ctlr.getBIGIPConfig(bigipLabel)
	for config := range respChan {
		ctlr.requestMap.Lock()
		latestRequestMeta, _ := ctlr.requestMap.requestMap[config.BigIpConfig]
		ctlr.requestMap.Unlock()
		if len(config.as3Config.failedTenants) > 0 && latestRequestMeta.id == config.id {
			// if the current request id is same as the failed tenant request id, then retry the failed tenants
			ctlr.RequestHandler.PostManagers.RLock()
			pm := ctlr.RequestHandler.PostManagers.PostManagerMap[config.BigIpConfig]
			// Delay the retry of failed tenants
			<-time.After(timeoutMedium)
			pm.postChan <- *config
			ctlr.RequestHandler.PostManagers.RUnlock()
		}
		if latestRequestMeta.id >= config.id && len(config.as3Config.failedTenants) == 0 {
			// Handle the network routes after successful post of tenants
			ctlr.processStaticRouteUpdate()
			// if the current request id is less than or equal to the latest request id, then udpate the status for current request
			for partition, meta := range config.reqMeta.partitionMap {
				// Check if it's a priority tenant and not in failedTenants map, if so then update the priority back to zero
				// Priority tenant doesn't have any meta
				if _, found := config.as3Config.failedTenants[partition]; !found && len(meta) == 0 {
					// updating the tenant priority back to zero if it's not in failed tenants
					ctlr.resources.updatePartitionPriority(partition, 0, bigipConfig)
					continue
				}
				for rscKey, kind := range meta {
					if ctlr.ipamHandler != nil && (kind == VirtualServer || kind == TransportServer) {
						ctlr.ipamHandler.RemoveUnusedIPAMEntries()
					}
					ns := strings.Split(rscKey, "/")[0]
					switch kind {
					//case VirtualServer:
					//	// update status
					//	crInf, ok := ctlr.getNamespacedCRInformer(ns)
					//	if !ok {
					//		log.Debugf("VirtualServer Informer not found for namespace: %v", ns)
					//		continue
					//	}
					//	obj, exist, err := crInf.vsInformer.GetIndexer().GetByKey(rscKey)
					//	if err != nil {
					//		log.Debugf("Could not fetch VirtualServer: %v: %v", rscKey, err)
					//		continue
					//	}
					//	if !exist {
					//		log.Debugf("VirtualServer Not Found: %v", rscKey)
					//		continue
					//	}
					//	virtual := obj.(*cisapiv1.VirtualServer)
					//	if virtual.Namespace+"/"+virtual.Name == rscKey {
					//		if _, found := config.as3Config.failedTenants[partition]; !found {
					//			// update the status for virtual server as tenant posting is success
					//			ctlr.updateVirtualServerStatus(virtual, virtual.Status.VSAddress, "Ok")
					//			// Update Corresponding Service Status of Type LB
					//			for _, pool := range virtual.Spec.Pools {
					//				var svcNamespace string
					//				if pool.ServiceNamespace != "" {
					//					svcNamespace = pool.ServiceNamespace
					//				} else {
					//					svcNamespace = virtual.Namespace
					//				}
					//				svc := ctlr.GetService(svcNamespace, pool.Service)
					//				if svc != nil {
					//					ctlr.setLBServiceIngressStatus(svc, virtual.Status.VSAddress)
					//				}
					//			}
					//		}
					//	}

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
							if _, found := config.as3Config.failedTenants[partition]; !found {
								// update the status for transport server as tenant posting is success
								ctlr.updateResourceStatus(TransportServer, virtual, virtual.Status.VSAddress, Ok, nil)
								// Update Corresponding Service Status of Type LB
								var svcNamespace string
								if virtual.Spec.Pool.ServiceNamespace != "" {
									svcNamespace = virtual.Spec.Pool.ServiceNamespace
								} else {
									svcNamespace = virtual.Namespace
								}
								svc := ctlr.GetService(svcNamespace, virtual.Spec.Pool.Service)
								if svc != nil {
									ctlr.setLBServiceIngressStatus(svc, virtual.Status.VSAddress)
								}
							}
						}
					case IngressLink:
						// update status
						crInf, ok := ctlr.getNamespacedCRInformer(ns)
						if !ok {
							log.Debugf("IngressLink Informer not found for namespace: %v", ns)
							continue
						}
						obj, exist, err := crInf.ilInformer.GetIndexer().GetByKey(rscKey)
						if err != nil {
							log.Debugf("Could not fetch IngressLink: %v: %v", rscKey, err)
							continue
						}
						if !exist {
							log.Debugf("IngressLink Not Found: %v", rscKey)
							continue
						}
						il := obj.(*cisapiv1.IngressLink)
						if il.Namespace+"/"+il.Name == rscKey {
							if _, found := config.as3Config.failedTenants[partition]; !found {
								// update the status for transport server as tenant posting is success
								ctlr.updateResourceStatus(IngressLink, il, il.Status.VSAddress, Ok, nil)
							}
						}
						//case Route:
						//	if _, found := config.as3Config.failedTenants[partition]; found {
						//		// TODO : distinguish between a 503 and an actual failure
						//		go ctlr.updateRouteAdmitStatus(rscKey, "Failure while updating config", "Please check logs for more information", v1.ConditionFalse)
						//	} else {
						//		go ctlr.updateRouteAdmitStatus(rscKey, "", "", v1.ConditionTrue)
						//	}
					}
				}
			}
		}
	}
}
