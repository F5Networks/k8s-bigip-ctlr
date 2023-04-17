package controller

import log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
import "encoding/json"

func (ctlr *Controller) processResourceExternalClusterServices(namespace string, rscName string, annotation string,
	resourceType string) {

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

				rscKey := ResourceKey{
					rscName:   rscName,
					namespace: namespace,
					rscType:   Route,
				}
				svcKey := MultiClusterServiceKey{
					serviceName: svc.SvcName,
					namespace:   svc.Namespace,
					clusterName: svc.ClusterName,
				}

				if ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName] == nil {
					ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName] = make(map[MultiClusterServiceKey]struct{})
				}
				ctlr.multiClusterResources.clusterSvcMap[svc.ClusterName][svcKey] = struct{}{}

				// update the multi cluster resource map
				ctlr.multiClusterResources.rscSvcMap[rscKey] = make(map[MultiClusterServiceKey]MultiClusterServiceConfig)
				ctlr.multiClusterResources.rscSvcMap[rscKey][svcKey] = MultiClusterServiceConfig{
					svcPort: svc.ServicePort,
				}
				ctlr.multiClusterResources.svcResourceMap[svcKey] = rscKey

				// if informer not found for cluster, setup and start informer
				if _, found := ctlr.multiClusterPoolInformers[svc.ClusterName]; !found {
					go ctlr.setupAndStartMultiClusterInformers(svc.ClusterName)
				}
			} else {
				log.Debugf("invalid cluster reference found cluster: %v namespace:%v, %v: %v", svc.ClusterName, namespace,
					resourceType, rscName)
			}
		}
	} else {
		log.Debugf("unable to read service mapping annotation from namespace/%v: %v/%v",
			resourceType, namespace, rscName)
	}
}

func (ctlr *Controller) deleteResourceExternalClusterSvcReference(namespace string, rscName string) {

	if ctlr.multiClusterResources == nil {
		return
	}

	ctlr.multiClusterResources.Lock()
	defer ctlr.multiClusterResources.Unlock()

	// remove resource and service mapping
	if svcs, ok := ctlr.multiClusterResources.rscSvcMap[ResourceKey{
		rscName:   rscName,
		namespace: namespace,
		rscType:   Route,
	}]; ok {

		// for service referring to resource, remove all entries
		for svc := range svcs {
			delete(ctlr.multiClusterResources.clusterSvcMap[svc.clusterName], svc)
			delete(ctlr.multiClusterResources.svcResourceMap, svc)
		}
		//remove resource entry
		delete(ctlr.multiClusterResources.rscSvcMap, ResourceKey{
			rscName:   rscName,
			namespace: namespace,
			rscType:   Route,
		})
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
