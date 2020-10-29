/*-
* Copyright (c) 2016-2020, F5 Networks, Inc.
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
	"reflect"
	"sort"
	"strings"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// customResourceWorker starts the Custom Resource Worker.
func (crMgr *CRManager) nccResourceWorker() {
	log.Debugf("Starting Custom Resource Worker")
	for crMgr.processNCCResource() {
	}
}

func (crMgr *CRManager) processNCCResource() bool {

	key, quit := crMgr.rscQueue.Get()
	if quit {
		// The controller is shutting down.
		log.Debugf("Resource Queue is empty, Going to StandBy Mode")
		return false
	}
	var isLastInQueue, isError bool

	if crMgr.rscQueue.Len() == 0 {
		isLastInQueue = true
	}
	defer crMgr.rscQueue.Done(key)
	rKey := key.(*rqKey)
	log.Debugf("Processing Key: %v", rKey)

	// Check the type of resource and process accordingly.
	switch rKey.kind {
	case NginxCisConnector:
		ncc := rKey.rsc.(*cisapiv1.NginxCisConnector)
		log.Infof("Worker got NginxCisConnector: %v\n", ncc)
		log.Infof("NginxCisConnector Selector: %v\n", ncc.Spec.Selector.String())
		err := crMgr.syncNginxCisConnector(ncc, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case Service, Endpoints:
		nccs := crMgr.getAllNginxCisConnectors(rKey.namespace)

		if nccs == nil {
			break
		}

		var svc *v1.Service
		svc, ok := rKey.rsc.(*v1.Service)
		if !ok {
			ep := rKey.rsc.(*v1.Endpoints)
			svc = crMgr.syncEndpoints(ep)
			// No Services are effected with the change in service.
			if nil == svc {
				break
			}
		}

		var err error

		for _, ncc := range nccs {
			matched := true
			for k, v := range ncc.Spec.Selector.MatchLabels {
				if svc.ObjectMeta.Labels[k] != v {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			err = crMgr.syncNginxCisConnector(ncc, false)
			if err != nil {
				// TODO
				utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
				isError = true
			}
		}
	}

	if isError {
		crMgr.rscQueue.AddRateLimited(key)
	} else {
		crMgr.rscQueue.Forget(key)
	}

	if isLastInQueue && !reflect.DeepEqual(
		crMgr.resources.rsMap,
		crMgr.resources.oldRsMap,
	) {

		config := ResourceConfigWrapper{
			rsCfgs:         crMgr.resources.GetAllResources(),
			iRuleMap:       crMgr.irulesMap,
			intDgMap:       crMgr.intDgMap,
			customProfiles: crMgr.customProfiles,
		}

		crMgr.Agent.PostConfig(config)
		crMgr.initState = false
		crMgr.resources.updateOldConfig()
	}
	return true
}

type Services []v1.Service

//sort services by timestamp
func (svcs Services) Len() int {
	return len(svcs)
}

func (svcs Services) Less(i, j int) bool {
	d1 := svcs[i].GetCreationTimestamp()
	d2 := svcs[j].GetCreationTimestamp()
	return d1.Before(&d2)
}

func (svcs Services) Swap(i, j int) {
	svcs[i], svcs[j] = svcs[j], svcs[i]
}

func (crMgr *CRManager) getKICServiceOfNCC(ncc *cisapiv1.NginxCisConnector) (*v1.Service, error) {
	selector := ""
	for k, v := range ncc.Spec.Selector.MatchLabels {
		selector += fmt.Sprintf("%v=%v,", k, v)
	}
	selector = selector[:len(selector)-1]

	svcListOptions := metav1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matches the given label
	serviceList, err := crMgr.kubeClient.CoreV1().Services(ncc.ObjectMeta.Namespace).List(svcListOptions)

	if err != nil {
		log.Errorf("Error getting service list From NginxCisConnector. Error: %v", err)
		return nil, err
	}

	if len(serviceList.Items) == 0 {
		log.Infof("No services for with labels : %v", ncc.Spec.Selector.MatchLabels)
		return nil, nil
	}

	if len(serviceList.Items) == 1 {
		return &serviceList.Items[0], nil
	}

	sort.Sort(Services(serviceList.Items))
	return &serviceList.Items[0], nil
}

func (crMgr *CRManager) syncNginxCisConnector(
	ncc *cisapiv1.NginxCisConnector,
	isNCCDeleted bool,
) error {

	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing NginxCisController %+v (%v)",
			ncc, endTime.Sub(startTime))
	}()

	if isNCCDeleted {
		var delRes []string
		for k, _ := range crMgr.resources.rsMap {
			rsName := "ncc_" + formatVirtualServerName(
				ncc.Spec.VirtualServerAddress,
				0,
			)
			if strings.HasPrefix(k, rsName[:len(rsName)-1]) {
				delRes = append(delRes, k)
			}
		}
		for _, rsname := range delRes {
			delete(crMgr.resources.rsMap, rsname)
		}
		return nil
	}

	svc, err := crMgr.getKICServiceOfNCC(ncc)
	if err != nil {
		return err
	}

	if svc == nil {
		return nil
	}

	for _, port := range svc.Spec.Ports {
		rsName := "ncc_" + formatVirtualServerName(
			ncc.Spec.VirtualServerAddress,
			port.Port,
		)

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = crMgr.Partition
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
		if len(ncc.Spec.IRules) > 0 {
			rsCfg.Virtual.IRules = ncc.Spec.IRules
		}
		rsCfg.Virtual.SetVirtualAddress(
			ncc.Spec.VirtualServerAddress,
			port.Port,
		)

		pool := Pool{
			Name: formatVirtualServerPoolName(
				svc.ObjectMeta.Namespace,
				svc.ObjectMeta.Name,
				port.Port,
				"",
			),
			Partition:   rsCfg.Virtual.Partition,
			ServiceName: svc.ObjectMeta.Name,
			ServicePort: port.Port,
		}
		rsCfg.Virtual.PoolName = pool.Name
		rsCfg.Pools = append(rsCfg.Pools, pool)

		crMgr.resources.rsMap[rsName] = rsCfg

		if crMgr.ControllerMode == NodePortMode {
			crMgr.updatePoolMembersForNodePort(rsCfg, ncc.ObjectMeta.Namespace)
		} else {
			crMgr.updatePoolMembersForCluster(rsCfg, ncc.ObjectMeta.Namespace)
		}
	}

	return nil
}

func (crMgr *CRManager) getAllNginxCisConnectors(namespace string) []*cisapiv1.NginxCisConnector {
	var allNCCs []*cisapiv1.NginxCisConnector

	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	// Get list of VirtualServers and process them.
	orderedNCCs, err := crInf.nccInformer.GetIndexer().ByIndex("namespace", namespace)
	if err != nil {
		log.Errorf("Unable to get list of VirtualServers for namespace '%v': %v",
			namespace, err)
		return nil
	}

	for _, obj := range orderedNCCs {
		ncc := obj.(*cisapiv1.NginxCisConnector)
		// TODO
		// Validate the NginxCisController List to check if all the vs are valid.

		allNCCs = append(allNCCs, ncc)
	}

	return allNCCs
}
