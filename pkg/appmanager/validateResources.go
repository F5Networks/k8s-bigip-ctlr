/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
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

package appmanager

import (
	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (appMgr *Manager) checkValidConfigMap(
	obj interface{},
) (bool, []*serviceQueueKey) {
	// Identify the specific service being referenced, and return it if it's
	// one we care about.
	cm := obj.(*v1.ConfigMap)
	namespace := cm.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	cfg, err := parseConfigMap(cm)
	if nil != err {
		if handleConfigMapParseFailure(appMgr, cm, cfg, err) {
			// resources is updated if true is returned, write out the config.
			appMgr.outputConfig()
		}
		return false, nil
	}
	key := &serviceQueueKey{
		ServiceName: cfg.Pools[0].ServiceName,
		Namespace:   namespace,
	}
	var keyList []*serviceQueueKey
	keyList = append(keyList, key)
	return true, keyList
}

func (appMgr *Manager) checkValidService(
	obj interface{},
) (bool, []*serviceQueueKey) {
	// Check if the service to see if we care about it.
	svc := obj.(*v1.Service)
	namespace := svc.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	key := &serviceQueueKey{
		ServiceName: svc.ObjectMeta.Name,
		Namespace:   namespace,
	}
	var keyList []*serviceQueueKey
	keyList = append(keyList, key)
	return true, keyList
}

func (appMgr *Manager) checkValidEndpoints(
	obj interface{},
) (bool, []*serviceQueueKey) {
	eps := obj.(*v1.Endpoints)
	namespace := eps.ObjectMeta.Namespace
	// Check if the service to see if we care about it.
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	key := &serviceQueueKey{
		ServiceName: eps.ObjectMeta.Name,
		Namespace:   namespace,
	}
	var keyList []*serviceQueueKey
	keyList = append(keyList, key)
	return true, keyList
}

func (appMgr *Manager) checkValidIngress(
	obj interface{},
) (bool, []*serviceQueueKey) {
	ing := obj.(*v1beta1.Ingress)
	namespace := ing.ObjectMeta.Namespace
	appInf, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	var allKeys []*serviceQueueKey
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	for _, portStruct := range appMgr.virtualPorts(ing) {
		var keyList []*serviceQueueKey
		rsCfg := createRSConfigFromIngress(ing, namespace,
			appInf.svcInformer.GetIndexer(), portStruct)
		rsName := formatIngressVSName(ing, portStruct.protocol)
		if rsCfg == nil {
			if nil == ing.Spec.Rules { //single-service
				serviceName := ing.Spec.Backend.ServiceName
				servicePort := ing.Spec.Backend.ServicePort.IntVal
				sKey := serviceKey{serviceName, servicePort, ing.ObjectMeta.Namespace}
				if _, ok := appMgr.resources.Get(sKey, rsName); ok {
					appMgr.resources.Delete(sKey, rsName)
					appMgr.outputConfigLocked()
				}
			} else { //multi-service
				_, keys := appMgr.resources.GetAllWithName(rsName)
				for _, key := range keys {
					appMgr.resources.Delete(key, rsName)
					appMgr.outputConfigLocked()
				}
			}
			return false, nil
		}

		for _, pool := range rsCfg.Pools {
			key := &serviceQueueKey{
				ServiceName: pool.ServiceName,
				Namespace:   namespace,
			}
			keyList = append(keyList, key)
		}
		// Check if we have a key that contains this config that is no longer
		// being used; if so, delete the config for that key
		_, keys := appMgr.resources.GetAllWithName(rsName)
		found := false
		if len(keys) > len(keyList) {
			for _, key := range keys {
				for _, sKey := range keyList {
					if sKey.ServiceName == key.ServiceName &&
						sKey.Namespace == key.Namespace {
						found = true
						break
					}
				}
				if found == false {
					appMgr.resources.Delete(key, rsName)
				}
				found = false
			}
		}
		if len(allKeys) > 0 {
			// Append if not in list
			for _, k := range keyList {
				var keyFound bool
				for _, ele := range allKeys {
					if ele.Namespace == k.Namespace &&
						ele.ServiceName == k.ServiceName {
						keyFound = true
						break
					}
				}
				if !keyFound {
					allKeys = append(allKeys, k)
				}
			}
		} else {
			allKeys = append(allKeys, keyList...)
		}
	}
	return true, allKeys
}

func (appMgr *Manager) checkValidRoute(
	obj interface{},
) (bool, *serviceQueueKey) {
	route := obj.(*routeapi.Route)
	namespace := route.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	key := &serviceQueueKey{
		ServiceName: route.Spec.To.Name,
		Namespace:   namespace,
	}
	return true, key
}
