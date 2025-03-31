package controller

import (
	"errors"
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"time"
)

func (ctlr *Controller) enqueueReq(config ResourceConfigRequest) requestMeta {
	ctlr.requestCounter = ctlr.requestCounter + 1
	rm := requestMeta{
		partitionMap: make(map[string]map[string]string, len(config.ltmConfig)),
		id:           ctlr.requestCounter,
	}
	for partition, partitionConfig := range config.ltmConfig {
		rm.partitionMap[partition] = make(map[string]string)
		for _, cfg := range partitionConfig.ResourceMap {
			for key, val := range cfg.MetaData.baseResources {
				rm.partitionMap[partition][key] = val
			}
		}
	}
	return rm
}

func (ctlr *Controller) responseHandler() {
	for agentConfig := range ctlr.respChan {
		for partition, meta := range agentConfig.reqMeta.partitionMap {
			for rscKey, kind := range meta {
				ctlr.removeUnusedIPAMEntries(kind)
				ns := strings.Split(rscKey, "/")[0]
				var resourceStatus string
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
						if tenantResponse, found := agentConfig.failedTenants[partition]; found {
							// update the status for virtual server as tenant posting is failed
							resourceStatus = StatusError
							ctlr.updateVSStatus(virtual, "", StatusError, errors.New(tenantResponse.message))
						} else {
							// update the status for virtual server as tenant posting is success
							resourceStatus = StatusOk
							ctlr.updateVSStatus(virtual, ctlr.ResourceStatusVSAddressMap[resourceRef{
								name:      virtual.Name,
								namespace: virtual.Namespace,
								kind:      VirtualServer,
							}], StatusOk, nil)
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
						if tenantResponse, found := agentConfig.failedTenants[partition]; found {
							resourceStatus = StatusError
							// update the status for transport server as tenant posting is failed
							ctlr.updateTSStatus(virtual, "", StatusError, errors.New(tenantResponse.message))
						} else {
							resourceStatus = StatusOk
							// update the status for transport server as tenant posting is success
							ctlr.updateTSStatus(virtual, ctlr.ResourceStatusVSAddressMap[resourceRef{
								name:      virtual.Name,
								namespace: virtual.Namespace,
								kind:      TransportServer,
							}], StatusOk, nil)
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
						if tenantResponse, found := agentConfig.failedTenants[partition]; found {
							resourceStatus = StatusError
							// update the status for ingresslink as tenant posting is failed
							ctlr.updateILStatus(il, "", StatusError, errors.New(tenantResponse.message))
						} else {
							resourceStatus = StatusOk
							// update the status for ingresslink as tenant posting is success
							ctlr.updateILStatus(il, ctlr.ResourceStatusVSAddressMap[resourceRef{
								name:      il.Name,
								namespace: il.Namespace,
								kind:      IngressLink,
							}], StatusOk, nil)
						}
					}

				case Route:
					if _, found := agentConfig.failedTenants[partition]; found {
						resourceStatus = StatusError
						// TODO : distinguish between a 503 and an actual failure
						go ctlr.updateRouteAdmitStatus(rscKey, "Failure while updating config", "Please check logs for more information", v1.ConditionFalse)
					} else {
						resourceStatus = StatusOk
						go ctlr.updateRouteAdmitStatus(rscKey, "", "", v1.ConditionTrue)
					}
				}
				if resourceStatus == StatusOk {
					switch agentConfig.agentKind {
					case GTMBigIP:
						// add gtm config to the cccl worker if ccclGTMAgent is true for GTMBigIPWorker
						if ctlr.RequestHandler.GTMBigIPWorker.ccclGTMAgent {
							log.Debugf("%v Posting GTM config to cccl agent: %+v\n", ctlr.RequestHandler.GTMBigIPWorker.APIHandler.LTM.postManagerPrefix, agentConfig.rscConfigRequest)
							ctlr.RequestHandler.GTMBigIPWorker.PostGTMConfigWithCccl(agentConfig.rscConfigRequest)
						}
						if !ctlr.RequestHandler.GTMBigIPWorker.disableARP {
							go ctlr.RequestHandler.GTMBigIPWorker.updateARPsForPoolMembers(agentConfig.rscConfigRequest)
						}
					case PrimaryBigIP:
						// add gtm config to the cccl worker if ccclGTMAgent is true for GTMBigIPWorker
						if ctlr.RequestHandler.PrimaryBigIPWorker.ccclGTMAgent {
							log.Debugf("%v Posting GTM config to cccl agent: %+v\n", ctlr.RequestHandler.PrimaryBigIPWorker.APIHandler.LTM.postManagerPrefix, agentConfig.rscConfigRequest)
							ctlr.RequestHandler.PrimaryBigIPWorker.PostGTMConfigWithCccl(agentConfig.rscConfigRequest)
						}
						if !ctlr.RequestHandler.PrimaryBigIPWorker.disableARP {
							go ctlr.RequestHandler.PrimaryBigIPWorker.updateARPsForPoolMembers(agentConfig.rscConfigRequest)
						}
					case SecondaryBigIP:
						// add gtm config to the cccl worker if ccclGTMAgent is true for SecondaryBigIPWorker
						if ctlr.RequestHandler.SecondaryBigIPWorker.ccclGTMAgent {
							log.Debugf("%v Posting GTM config to cccl agent: %+v\n", ctlr.RequestHandler.SecondaryBigIPWorker.APIHandler.LTM.postManagerPrefix, agentConfig.rscConfigRequest)
							ctlr.RequestHandler.SecondaryBigIPWorker.PostGTMConfigWithCccl(agentConfig.rscConfigRequest)
						}
						if !ctlr.RequestHandler.SecondaryBigIPWorker.disableARP {
							go ctlr.RequestHandler.SecondaryBigIPWorker.updateARPsForPoolMembers(agentConfig.rscConfigRequest)
						}
					}
				}
			}
		}
		if len(agentConfig.failedTenants) > 0 && ctlr.requestCounter == agentConfig.reqMeta.id {
			// Delay the retry of failed tenants
			<-time.After(timeoutMedium)
			switch agentConfig.agentKind {
			case GTMBigIP:
				ctlr.RequestHandler.GTMBigIPWorker.getPostManager().postChan <- agentConfig
			case PrimaryBigIP:
				ctlr.RequestHandler.PrimaryBigIPWorker.getPostManager().postChan <- agentConfig
			case SecondaryBigIP:
				ctlr.RequestHandler.SecondaryBigIPWorker.getPostManager().postChan <- agentConfig
			}
		}
	}
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
