/*-
* Copyright (c) 2016-2021, F5 Networks, Inc.
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

// ilResourceWorker starts the Custom Resource Worker.
func (crMgr *CRManager) ilResourceWorker() {
	log.Debugf("Starting Custom Resource Worker")
	for crMgr.processILResource() {
	}
}

func (crMgr *CRManager) processILResource() bool {

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
	case IngressLink:
		ingLink := rKey.rsc.(*cisapiv1.IngressLink)
		log.Infof("Worker got IngressLink: %v\n", ingLink)
		log.Infof("IngressLink Selector: %v\n", ingLink.Spec.Selector.String())
		err := crMgr.syncIngressLink(ingLink, rKey.rscDelete)
		if err != nil {
			// TODO
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
			isError = true
		}
	case Service, Endpoints:
		ingLinks := crMgr.getAllIngressLinks(rKey.namespace)

		if ingLinks == nil {
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

		for _, ingLink := range ingLinks {
			matched := true
			for k, v := range ingLink.Spec.Selector.MatchLabels {
				if svc.ObjectMeta.Labels[k] != v {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			err = crMgr.syncIngressLink(ingLink, false)
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

func (crMgr *CRManager) getKICServiceOfIngressLink(ingLink *cisapiv1.IngressLink) (*v1.Service, error) {
	selector := ""
	for k, v := range ingLink.Spec.Selector.MatchLabels {
		selector += fmt.Sprintf("%v=%v,", k, v)
	}
	selector = selector[:len(selector)-1]

	svcListOptions := metav1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matches the given label
	serviceList, err := crMgr.kubeClient.CoreV1().Services(ingLink.ObjectMeta.Namespace).List(svcListOptions)

	if err != nil {
		log.Errorf("Error getting service list From IngressLink. Error: %v", err)
		return nil, err
	}

	if len(serviceList.Items) == 0 {
		log.Infof("No services for with labels : %v", ingLink.Spec.Selector.MatchLabels)
		return nil, nil
	}

	if len(serviceList.Items) == 1 {
		return &serviceList.Items[0], nil
	}

	sort.Sort(Services(serviceList.Items))
	return &serviceList.Items[0], nil
}

func (crMgr *CRManager) syncIngressLink(
	ingLink *cisapiv1.IngressLink,
	isILDeleted bool,
) error {

	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing Ingress Links %+v (%v)",
			ingLink, endTime.Sub(startTime))
	}()

	if isILDeleted {
		var delRes []string
		for k, _ := range crMgr.resources.rsMap {
			rsName := "ingress_link_" + formatVirtualServerName(
				ingLink.Spec.VirtualServerAddress,
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

	svc, err := crMgr.getKICServiceOfIngressLink(ingLink)
	if err != nil {
		return err
	}

	if svc == nil {
		return nil
	}

	for _, port := range svc.Spec.Ports {
		rsName := "ingress_link_" + formatVirtualServerName(
			ingLink.Spec.VirtualServerAddress,
			port.Port,
		)

		rsCfg := &ResourceConfig{}
		rsCfg.Virtual.Partition = crMgr.Partition
		rsCfg.MetaData.ResourceType = "TransportServer"
		rsCfg.Virtual.Mode = "standard"
		rsCfg.Virtual.TranslateServerAddress = true
		rsCfg.Virtual.TranslateServerPort = true
		rsCfg.Virtual.Source = "0.0.0.0/0"
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = rsName
		rsCfg.Virtual.SNAT = DEFAULT_SNAT
		if len(ingLink.Spec.IRules) > 0 {
			rsCfg.Virtual.IRules = ingLink.Spec.IRules
		}
		rsCfg.Virtual.SetVirtualAddress(
			ingLink.Spec.VirtualServerAddress,
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
			crMgr.updatePoolMembersForNodePort(rsCfg, ingLink.ObjectMeta.Namespace)
		} else {
			crMgr.updatePoolMembersForCluster(rsCfg, ingLink.ObjectMeta.Namespace)
		}
	}

	return nil
}

func (crMgr *CRManager) getAllIngressLinks(namespace string) []*cisapiv1.IngressLink {
	var allIngLinks []*cisapiv1.IngressLink

	crInf, ok := crMgr.getNamespacedInformer(namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil
	}
	// Get list of VirtualServers and process them.
	orderedIngLinks, err := crInf.ilInformer.GetIndexer().ByIndex("namespace", namespace)
	if err != nil {
		log.Errorf("Unable to get list of VirtualServers for namespace '%v': %v",
			namespace, err)
		return nil
	}

	for _, obj := range orderedIngLinks {
		ingLink := obj.(*cisapiv1.IngressLink)
		// TODO
		// Validate the IngressLink List to check if all the vs are valid.

		allIngLinks = append(allIngLinks, ingLink)
	}

	return allIngLinks
}
