package controller

import (
	"container/list"
	"errors"
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"strings"
	"sync"
	"time"
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
	for partition, partitionConfig := range config.ltmConfig {
		rm.partitionMap[partition] = make(map[string]string)
		for _, cfg := range partitionConfig.ResourceMap {
			for key, val := range cfg.MetaData.baseResources {
				rm.partitionMap[partition][key] = val
			}
		}
	}

	ctlr.requestQueue.Lock()
	ctlr.requestQueue.PushBack(rm)
	ctlr.requestQueue.Unlock()

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
				ctlr.removeUnusedIPAMEntries(kind)
				ns := strings.Split(rscKey, "/")[0]
				switch kind {
				case VirtualServer:
					// update status
					crInf, ok := ctlr.getNamespacedCRInformer(ns, ctlr.multiClusterHandler.LocalClusterName)
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
						if tenantResponse, found := rscUpdateMeta.failedTenants[partition]; found {
							// update the status for virtual server as tenant posting is failed
							ctlr.updateVSStatus(virtual, "", StatusError, errors.New(tenantResponse.message))
						} else {
							// update the status for virtual server as tenant posting is success
							ctlr.updateVSStatus(virtual, virtual.Status.VSAddress, StatusOk, nil)
							// Update Corresponding Service Status of Type LB
							if !ctlr.isAddingPoolRestricted(ctlr.multiClusterHandler.LocalClusterName) {
								// set status of all the LB services associated with this VS
								go ctlr.updateLBServiceStatusForVSorTS(virtual, virtual.Status.VSAddress, true)
							}
						}
					}

				case TransportServer:
					// update status
					crInf, ok := ctlr.getNamespacedCRInformer(ns, ctlr.multiClusterHandler.LocalClusterName)
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
						if tenantResponse, found := rscUpdateMeta.failedTenants[partition]; found {
							// update the status for transport server as tenant posting is failed
							ctlr.updateTSStatus(virtual, "", StatusError, errors.New(tenantResponse.message))
						} else {
							// update the status for transport server as tenant posting is success
							ctlr.updateTSStatus(virtual, virtual.Status.VSAddress, StatusOk, nil)
							// set status of all the LB services associated with this TS
							go ctlr.updateLBServiceStatusForVSorTS(virtual, virtual.Status.VSAddress, true)
						}
					}

				case IngressLink:
					// update status
					crInf, ok := ctlr.getNamespacedCRInformer(ns, ctlr.multiClusterHandler.LocalClusterName)
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
						if tenantResponse, found := rscUpdateMeta.failedTenants[partition]; found {
							// update the status for ingresslink as tenant posting is failed
							ctlr.updateILStatus(il, "", StatusError, errors.New(tenantResponse.message))
						} else {
							// update the status for ingresslink as tenant posting is success
							ctlr.updateILStatus(il, il.Status.VSAddress, StatusOk, nil)
						}
					}

				case Route:
					if _, found := rscUpdateMeta.failedTenants[partition]; found {
						// TODO : distinguish between a 503 and an actual failure
						go ctlr.updateRouteAdmitStatus(rscKey, "Failure while updating config", "Please check logs for more information", v1.ConditionFalse)
					} else {
						go ctlr.updateRouteAdmitStatus(rscKey, "", "", v1.ConditionTrue)
					}
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

func (ctlr *Controller) removeUnusedIPAMEntries(kind string) {
	// Remove Unused IPAM entries in IPAM CR after CIS restarts, applicable to only first PostCall
	if !ctlr.firstPostResponse && ctlr.ipamCli != nil && (kind == VirtualServer || kind == TransportServer) {
		ctlr.firstPostResponse = true
		toRemoveIPAMEntries := &ficV1.IPAM{
			ObjectMeta: metav1.ObjectMeta{
				Labels: make(map[string]string),
			},
		}
		ipamCR := ctlr.getIPAMCR()
		for _, hostSpec := range ipamCR.Spec.HostSpecs {
			found := false
			ctlr.cacheIPAMHostSpecs.Lock()
			for cacheIndex, cachehostSpec := range ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs {
				if (hostSpec.IPAMLabel == cachehostSpec.IPAMLabel && hostSpec.Host == cachehostSpec.Host) ||
					(hostSpec.IPAMLabel == cachehostSpec.IPAMLabel && hostSpec.Key == cachehostSpec.Key) ||
					(hostSpec.IPAMLabel == cachehostSpec.IPAMLabel && hostSpec.Key == cachehostSpec.Key && hostSpec.Host == cachehostSpec.Host) {
					if len(ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs) > cacheIndex {
						ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs = append(ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs[:cacheIndex], ctlr.cacheIPAMHostSpecs.IPAM.Spec.HostSpecs[cacheIndex+1:]...)
					}
					found = true
					break
				}
			}
			ctlr.cacheIPAMHostSpecs.Unlock()
			if !found {
				// To remove
				toRemoveIPAMEntries.Spec.HostSpecs = append(toRemoveIPAMEntries.Spec.HostSpecs, hostSpec)
			}
		}
		for _, removeIPAMentry := range toRemoveIPAMEntries.Spec.HostSpecs {
			ipamCR = ctlr.getIPAMCR()
			for index, hostSpec := range ipamCR.Spec.HostSpecs {
				if (hostSpec.IPAMLabel == removeIPAMentry.IPAMLabel && hostSpec.Host == removeIPAMentry.Host) ||
					(hostSpec.IPAMLabel == removeIPAMentry.IPAMLabel && hostSpec.Key == removeIPAMentry.Key) ||
					(hostSpec.IPAMLabel == removeIPAMentry.IPAMLabel && hostSpec.Key == removeIPAMentry.Key && hostSpec.Host == removeIPAMentry.Host) {
					_, err := ctlr.RemoveIPAMCRHostSpec(ipamCR, removeIPAMentry.Key, index)
					if err != nil {
						log.Errorf("[IPAM] ipam hostspec update error: %v", err)
					}
					break
				}
			}
		}
		// Delete cacheIPAMHostSpecs
		ctlr.cacheIPAMHostSpecs = CacheIPAM{}
	}
}

// handleConfigFailures handles any failure that occurred in posting of configuration to BigIP
//  1. It ensures that the failed config is re-queued only if it's the latest config
//  2. It decides the waiting time for the requeue of failed config based on the response code from BigIP
//  3. It is flexible to handle any type of config, currently AS3 config failure handling is supported, but it can be
//     extended to any other configurations in the future
func (ctlr *Controller) handleConfigFailures(agentConfig AgentConfig) {
	latestRequestMeta, _ := ctlr.requestMap.requestMap[agentConfig.getBigIPConfig()]
	switch agentConfig.getConfigType() {
	case AS3:
		// If there are failed tenants and no new config request is generated then handle the failure
		if len(agentConfig.getFailedTenants()) > 0 && latestRequestMeta.id == agentConfig.getRequestMeta().id {
			// if the current request id is same as the failed tenant request id, then retry the failed tenants

			// This logic needs to be updated according to the AgentWorker and Postmanager implementation
			aw := ctlr.RequestHandler.AgentWorker[agentConfig.getBigIPConfig()]
			aw.RLock()
			// Get the config
			config := agentConfig.getConfig()
			as3Config := config.(as3Config)
			// Delay the retry of failed tenants based on the response code received from BigIP
			// If BigIP is not available then wait for 1 min, otherwise wait for 30 seconds
			timeout := timeoutSmall
			for tenant, _ := range agentConfig.getFailedTenants() {
				if res, ok := as3Config.tenantResponseMap[tenant]; ok && res.agentResponseCode == http.StatusServiceUnavailable {
					timeout = timeoutMedium
				}
			}
			<-time.After(timeout)
			// Again check after timeout if this is still the latest config or new config is available
			latestRequestMeta, _ := ctlr.requestMap.requestMap[agentConfig.getBigIPConfig()]
			if latestRequestMeta.id == agentConfig.getRequestMeta().id {
				aw.PostChan <- agentConfig
			}
			aw.RUnlock()
		}
	default:
		log.Warningf("Config posting Failure handling is not implemented for %s", agentConfig.getConfigType())
	}
}
