package controller

import log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
import "encoding/json"

func (ctlr *Controller) processResourceExternalClusterServices(rscKey resourceRef, annotation string) {

	// if no external cluster is configured skip processing
	if len(ctlr.multiClusterConfigs.ClusterConfigs) == 0 {
		log.Debugf("no external cluster configuration found.")
		return
	}

	if ctlr.multiClusterResources == nil {
		ctlr.multiClusterResources = newMultiClusterResourceStore()
	}

	var clusterSvcs []MultiClusterServiceReference
	err := json.Unmarshal([]byte(annotation), &clusterSvcs)
	if err == nil {
		ctlr.multiClusterResources.Lock()
		defer ctlr.multiClusterResources.Unlock()

		for _, svc := range clusterSvcs {
			if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[svc.ClusterName]; ok {
				svcKey := MultiClusterServiceKey{
					serviceName: svc.SvcName,
					namespace:   svc.Namespace,
					clusterName: svc.ClusterName,
				}

				if ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName] == nil {
					ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName] = make(map[MultiClusterServiceKey]map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})
				}
				ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName][svcKey] = make(map[MultiClusterServiceConfig]map[PoolIdentifier]struct{})

				// update the multi cluster resource map
				ctlr.multiClusterResources.rscSvcMap[rscKey] = make(map[MultiClusterServiceKey]MultiClusterServiceConfig)
				ctlr.multiClusterResources.rscSvcMap[rscKey][svcKey] = MultiClusterServiceConfig{
					svcPort: svc.ServicePort,
				}

				// if informer not found for cluster, setup and start informer
				if _, found := ctlr.multiClusterPoolInformers[svc.ClusterName]; !found {
					ctlr.setupAndStartMultiClusterInformers(svcKey)
				}
			} else {
				log.Debugf("invalid cluster reference found cluster: %v resource:%v", svc.ClusterName, rscKey)
			}
		}
	} else {
		log.Debugf("unable to read service mapping for resource %v", rscKey)
	}
}

func (ctlr *Controller) deleteResourceExternalClusterSvcReference(mSvcKey MultiClusterServiceKey) {

	if mSvcKey.clusterName != "" && ctlr.multiClusterResources == nil {
		return
	}
	ctlr.multiClusterResources.Lock()
	defer ctlr.multiClusterResources.Unlock()
	// for service referring to resource, remove the resource from clusterSvcMap
	delete(ctlr.multiClusterResources.clusterSvcMap[mSvcKey.clusterName], mSvcKey)
}

func (ctlr *Controller) deleteResourceExternalClusterSvcRouteReference(rsKey resourceRef) {

	if ctlr.multiClusterResources == nil {
		return
	}

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
							delete(ctlr.resources.poolMemCache, mSvcKey)
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

	if ctlr.multiClusterResources == nil {
		return
	}

	ctlr.multiClusterResources.Lock()
	defer ctlr.multiClusterResources.Unlock()

	for clusterName, svcs := range ctlr.multiClusterResources.clusterSvcMap {
		if len(svcs) == 0 {
			// if all services references removed from cluster
			// delete and stop cluster informers
			delete(ctlr.multiClusterResources.clusterSvcMap, clusterName)
			ctlr.stopMultiClusterInformers(clusterName)
		}
	}
}
