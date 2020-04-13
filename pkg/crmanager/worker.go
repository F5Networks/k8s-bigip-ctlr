/*-
* Copyright (c) 2016-2019, F5 Networks, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 */

package crmanager

import (
	"fmt"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

func (crMgr *CRManager) customResourceWorker() {
	log.Debugf("Starting Custom Resource Worker")
	for crMgr.processResource() {
	}
}

// processResource gets resources from the rscQueue and processes the resource depending  on its kind.
func (crMgr *CRManager) processResource() bool {

	key, quit := crMgr.rscQueue.Get()
	if quit {
		// The controller is shutting down.
		log.Debugf("Resource Queue is empty, Going to StandBy Mode")
		return false
	}
	defer crMgr.rscQueue.Done(key)
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)

	// Check the type of resource and process accordingly.
	switch rKey.kind {
	case VirtualServer:
		err := crMgr.syncVirtualServer(rKey)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
		}
		crMgr.rscQueue.Forget(key)
		return true
	case Service:
		// TODO
		crMgr.rscQueue.Forget(key)
		return true
	case Endpoints:
		// TODO
		crMgr.rscQueue.Forget(key)
		return true
	default:
		log.Errorf("Unknown resource Kind: %v", rKey.kind)
	}

	crMgr.rscQueue.AddRateLimited(key)

	return true
}

func (crMgr *CRManager) syncVirtualServer(rkey *rqKey) error {

	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing virtual servers %+v (%v)",
			rkey, endTime.Sub(startTime))
	}()
	// check if the virutal server matches all the requirements.
	vkey := rkey.namespace + "/" + rkey.rscName
	valid := crMgr.checkValidVirtualServer(rkey)
	if false == valid {
		log.Infof("Ignoring VirtualServer %s, invalid configuration or deleted", vkey)
	}

	// Get the VirtualServer object.
	vs := rkey.rsc
	virtual := vs.(*cisapiv1.VirtualServer)

	// Get a list of dependencies removed so their pools can be removed.
	objKey, objDeps := NewObjectDependencies(virtual)

	virtualLookupFunc := func(key ObjectDependency) bool {
		return false
	}

	// TODO ==> UpdateDependencies to get the added and removed deps.
	_, depsRemoved := crMgr.resources.UpdateDependencies(
		objKey, objDeps, virtualLookupFunc)

	// Depending on the ports defined, TLS type or Unsecured we will populate the resource config.
	portStructs := crMgr.virtualPorts(virtual)
	for _, portStruct := range portStructs {
		rsCfg := crMgr.createRSConfigFromVirtualServer(
			virtual,
			crMgr.resources,
			rkey.namespace,
			portStruct,
		)
		if rsCfg == nil {
			// Currently, an error is returned only if the VirtualServer is one we
			// do not care about
			continue
		}

		// Collect all service names on this VirtualServer.
		// Used in handleConfigForType.
		var svcs []string
		for _, pl := range virtual.Spec.Pools {
			svcs = append(svcs, pl.Service)

		}

		// Remove any dependencies no longer used by this VirtualServer
		for _, dep := range depsRemoved {
			if dep.Kind == RuleDep {
				for _, pol := range rsCfg.Policies {
					for _, rl := range pol.Rules {
						if rl.FullURI == dep.Name {
							rsCfg.DeleteRuleFromPolicy(pol.Name, rl, crMgr.mergedRulesMap)
						}
					}
				}
			}
		}

		/** TODO ==> To be implemented in ALPHA later stage
		if ok, found, updated := crMgr.handleConfigForType(
			rsCfg, rsMap, rsName,
			crInf, virtual); !ok {
			stats.vsUpdated += updated
			continue
		} else {
			if updated > 0 && !appMgr.processAllMultiSvc(len(rsCfg.Pools),
				rsCfg.GetName()) {
				updated -= 1
			}
			stats.vsFound += found
			stats.vsUpdated += updated
			if updated > 0 {
				msg := fmt.Sprintf(
					"Created a ResourceConfig '%v' for the Ingress.",
					rsCfg.GetName())
				appMgr.recordIngressEvent(ing, "ResourceConfigured", msg)
			}
		}
		// Set the Ingress Status IP address
		appMgr.setIngressStatus(ing, rsCfg)
		**/

	}

	/** TODO ==> To be implemented in ALPHA later stage
	// rsMap stores all resources currently in Resources matching sKey, indexed by port.
	// At the end of processing, rsMap should only contain configs we want to delete.
	// If we have a valid config, then we remove it from rsMap.
	rsMap := appMgr.getResourcesForKey(sKey)
	dgMap := make(InternalDataGroupMap)

	var stats vsSyncStats
	appMgr.rsrcSSLCtxt = make(map[string]*v1.Secret)
	// Update internal data groups if changed
	appMgr.syncDataGroups(&stats, dgMap, sKey.Namespace)
	// Delete IRules if necessary
	appMgr.syncIRules()


	if len(rsMap) > 0 {
		// We get here when there are ports defined in the service that don't
		// have a corresponding config map.
		stats.vsDeleted += appMgr.deleteUnusedConfigs(sKey, rsMap)
		stats.vsUpdated += appMgr.deleteUnusedResources(sKey, svcFound)

	} else if !svcFound {
		stats.vsUpdated += appMgr.deleteUnusedResources(sKey, svcFound)
	}

	log.Debugf("Updated %v of %v virtual server configs, deleted %v",
		stats.vsUpdated, stats.vsFound, stats.vsDeleted)

	// delete any custom profiles that are no longer referenced
	appMgr.deleteUnusedProfiles(appInf, sKey.Namespace, &stats)

	switch {
	case stats.vsUpdated > 0,
		stats.vsDeleted > 0,
		stats.cpUpdated > 0,
		stats.dgUpdated > 0,
		stats.poolsUpdated > 0,
		!appMgr.steadyState && appMgr.processedItems >= appMgr.queueLen:
		{
			appMgr.outputConfig()
		}
	}
	**/

	return nil
}
