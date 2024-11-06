package controller

import (
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

func (ctlr *Controller) processResourceExternalClusterServices(rscKey resourceRef, clusterSvcs []cisapiv1.MultiClusterServiceReference) {

	// if no external cluster is configured skip processing
	if len(ctlr.multiClusterConfigs.ClusterConfigs) == 0 {
		log.Debugf("[MultiCluster] There is no externalClustersConfig section or there are no clusters defined in it.")
		return
	}

	ctlr.multiClusterResources.Lock()
	defer ctlr.multiClusterResources.Unlock()

	for _, svc := range clusterSvcs {
		if ctlr.checkValidMultiClusterService(svc, true) != nil {
			// Skip processing invalid extended service
			continue
		}
		if svc.ClusterName == ctlr.multiClusterConfigs.LocalClusterName {
			svc.ClusterName = ""
		}
		if ctlr.multiClusterConfigs.getClusterConfig(svc.ClusterName) != nil {
			svcKey := MultiClusterServiceKey{
				serviceName: svc.SvcName,
				namespace:   svc.Namespace,
				clusterName: svc.ClusterName,
			}
			// init informer store for cluster
			informerStore := ctlr.multiClusterConfigs.getInformerStore(svc.ClusterName)
			if informerStore == nil {
				informerStore = initInformerStore()
				ctlr.multiClusterConfigs.addInformerStore(svc.ClusterName, informerStore)
			}
			if ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName] == nil {
				ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName] = make(map[MultiClusterServiceKey]map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})
			}

			if _, ok := ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName][svcKey]; !ok {
				ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName][svcKey] = make(map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})
			}

			// update the multi cluster resource map
			if _, ok := ctlr.multiClusterResources.rscSvcMap[rscKey]; !ok {
				ctlr.multiClusterResources.rscSvcMap[rscKey] = make(map[MultiClusterServiceKey]MultiClusterServiceConfig)
			}
			ctlr.multiClusterResources.rscSvcMap[rscKey][svcKey] = MultiClusterServiceConfig{
				svcPort: svc.ServicePort,
			}

			// if informer not found for cluster, setup and start informer
			if len(informerStore.comInformers) == 0 {
				ctlr.setupAndStartMultiClusterInformers(svcKey, true)
			} else if _, found := informerStore.comInformers[svc.Namespace]; !found {
				ctlr.setupAndStartMultiClusterInformers(svcKey, true)
			}
		} else {
			log.Warningf("[MultiCluster] invalid cluster reference found cluster: %v resource:%v", svc.ClusterName, rscKey)
		}
	}

}

//func (ctlr *Controller) deleteResourceExternalClusterSvcReference(mSvcKey MultiClusterServiceKey) {
//
//	if mSvcKey.clusterName != "" && ctlr.multiClusterResources == nil {
//		return
//	}
//	ctlr.multiClusterResources.Lock()
//	defer ctlr.multiClusterResources.Unlock()
//	// for service referring to resource, remove the resource from clusterSvcMap
//	delete(ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName], mSvcKey)
//}

func (ctlr *Controller) deleteResourceExternalClusterSvcRouteReference(rsKey resourceRef) {
	ctlr.multiClusterResources.Lock()
	defer ctlr.multiClusterResources.Unlock()
	// remove resource and service mapping
	if svcs, ok := ctlr.multiClusterResources.rscSvcMap[rsKey]; ok {
		// for service referring to resource, remove the resource from clusterSvcMap
		for mSvcKey, port := range svcs {
			if _, ok = ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName]; ok {
				if _, ok = ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName][mSvcKey]; ok {
					if poolIdsMap, found := ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName][mSvcKey][port]; found {
						for poolId := range poolIdsMap {
							if poolId.rsKey == rsKey {
								delete(poolIdsMap, poolId)
							}
						}
						if len(poolIdsMap) == 0 {
							delete(ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName][mSvcKey], port)
							//delete the poolMem Cache as well
							log.Debugf("Deleting Service '%v' from CIS cache as it's not referenced by monitored resources", mSvcKey)
							delete(ctlr.resources.poolMemCache, mSvcKey)
							// delete the pod cache as well in nodePortLocal mode
							if ctlr.PoolMemberType == NodePortLocal {
								pods := ctlr.GetPodsForService(mSvcKey.namespace, mSvcKey.serviceName, mSvcKey.clusterName, true)
								for _, pod := range pods {
									ctlr.processPod(pod, true)
								}
							}
						} else {
							ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName][mSvcKey][port] = poolIdsMap
						}
					}
				}
			}
			if len(ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName][mSvcKey]) == 0 {
				delete(ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName], mSvcKey)
			}
		}
		//remove resource entry
		delete(ctlr.multiClusterResources.rscSvcMap, rsKey)
	}
}

// when route is processed check for the clusters whose services references are removed
// if any cluster is present with no references of services, stop the cluster informers
func (ctlr *Controller) deleteUnrefereedMultiClusterInformers() {

	ctlr.multiClusterResources.Lock()
	defer ctlr.multiClusterResources.Unlock()

	for clusterName, svcs := range ctlr.multiClusterResources.clusterSvcMap {
		// If no services are referenced from this cluster and this isn't HA peer cluster in case of active-active/ratio
		// then remove the clusterName key from the clusterSvcMap and stop the informers for this cluster
		if len(svcs) == 0 && ((ctlr.discoveryMode == StandAloneCIS || ctlr.discoveryMode == StandBy) ||
			ctlr.multiClusterConfigs.HAPairClusterName != clusterName) {
			delete(ctlr.multiClusterResources.clusterSvcMap, clusterName)
			ctlr.stopMultiClusterInformers(clusterName, true)
		}
	}
}

func (ctlr *Controller) getSvcPortFromHACluster(svcNameSpace, svcName, portName, rscType string) (int32, error) {
	obj, exists, err := ctlr.getSvcFromHACluster(svcNameSpace, svcName)
	if exists {
		svc := obj.(*v1.Service)
		if portName != "" {
			for _, port := range svc.Spec.Ports {
				if port.Name == portName {
					return port.Port, nil
				}
			}
			return 0,
				fmt.Errorf("Could not find service port '%s' on service '%s'", portName, svcNameSpace+"/"+svcName)
		} else if rscType == resource.ResourceTypeRoute {
			return svc.Spec.Ports[0].Port, nil
		}
	} else if err != nil {
		return 0, err
	}
	return 0, nil
}

func (ctlr *Controller) getSvcFromHACluster(svcNameSpace, svcName string) (interface{}, bool, error) {

	if ctlr.discoveryMode != Active || ctlr.multiClusterConfigs.ClusterConfigs == nil {
		return nil, false, nil
	}

	key := svcNameSpace + "/" + svcName
	informerStore := ctlr.multiClusterConfigs.getInformerStore(ctlr.multiClusterConfigs.HAPairClusterName)
	if informerStore == nil {
		return nil, false, fmt.Errorf("[MultiCluster] Informer not found for cluster %s'",
			ctlr.multiClusterConfigs.HAPairClusterName)
	}
	if informerStore.comInformers == nil {
		return nil, false, fmt.Errorf("[MultiCluster] Informer not found for cluster %s'",
			ctlr.multiClusterConfigs.HAPairClusterName)
	}
	ns := svcNameSpace
	if ctlr.watchingAllNamespaces("") {
		ns = ""
	}

	if poolInf, found := informerStore.comInformers[ns]; found {
		obj, exists, err := poolInf.svcInformer.GetIndexer().GetByKey(key)

		if nil != err {
			return nil, false, fmt.Errorf("[MultiCluster] Error looking for service '%s': %v", key, err)
		}

		if !exists {
			return nil, false, fmt.Errorf("[MultiCluster] Could not find service %v in cluster %v", key, ctlr.multiClusterConfigs.HAPairClusterName)
		}

		return obj, exists, nil

	} else {
		return nil, false, fmt.Errorf("[MultiCluster] Informer not found for cluster/namespace: %s/%s'",
			ctlr.multiClusterConfigs.HAPairClusterName, svcNameSpace)
	}
}
