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

package appmanager

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (appMgr *Manager) checkValidConfigMap(
	obj interface{},
) (bool, []*serviceQueueKey) {
	// Identify the specific service being referenced, and return it if it's
	// one we care about.
	var keyList []*serviceQueueKey
	cm := obj.(*v1.ConfigMap)
	namespace := cm.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	//check as3 config map.
	// if ok, add cfgMap name and data to serviceQueueKey.
	if ok := appMgr.checkAS3ConfigMap(obj); ok {
		log.Debugf("[as3_log] Found AS3 ConfigMap - %s.", cm.ObjectMeta.Name)
		key := &serviceQueueKey{
			Namespace: namespace,
			AS3Name:   cm.ObjectMeta.Name,
			AS3Data:   cm.Data["template"],
		}
		keyList = append(keyList, key)
		return true, keyList
	}
	cfg, err := parseConfigMap(cm, appMgr.schemaLocal, appMgr.vsSnatPoolName)
	if nil != err {
		if handleConfigMapParseFailure(appMgr, cm, cfg, err) {
			// resources is updated if true is returned, write out the config.
			appMgr.outputConfig()
		}
		return false, nil
	}
	// This ensures that pool-only mode only logs the message below the first
	// time we see a config.
	rsName := formatConfigMapVSName(cm)
	// Checking for annotation in VS, not iApp
	if _, exists := appMgr.resources.GetByName(rsName); !exists &&
		cfg.MetaData.ResourceType != "iapp" &&
		cfg.Virtual.VirtualAddress != nil &&
		cfg.Virtual.VirtualAddress.BindAddr == "" {
		// Check for IP annotation provided by IPAM system
		if _, ok := cm.ObjectMeta.Annotations[f5VsBindAddrAnnotation]; !ok {
			log.Infof("No virtual IP was specified for the virtual server %s creating pool only.",
				rsName)
		}
	}
	key := &serviceQueueKey{
		ServiceName: cfg.Pools[0].ServiceName,
		Namespace:   namespace,
	}
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

	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[f5VsBindAddrAnnotation]; ok {
		bindAddr = addr
	}
	var keyList []*serviceQueueKey
	// Depending on the Ingress, we may loop twice here, once for http and once for https
	for _, portStruct := range appMgr.virtualPorts(ing) {
		rsCfg := appMgr.createRSConfigFromIngress(
			ing,
			appMgr.resources,
			namespace,
			appInf.svcInformer.GetIndexer(),
			portStruct,
			appMgr.defaultIngIP,
			appMgr.vsSnatPoolName,
		)
		var rsType int
		rsName := formatIngressVSName(bindAddr, portStruct.port)
		// If rsCfg is nil, delete any resources tied to this Ingress
		if rsCfg == nil {
			if nil == ing.Spec.Rules { //single-service
				rsType = singleServiceIngressType
				serviceName := ing.Spec.Backend.ServiceName
				servicePort := ing.Spec.Backend.ServicePort.IntVal
				sKey := serviceKey{serviceName, servicePort, namespace}
				if _, ok := appMgr.resources.Get(sKey, rsName); ok {
					appMgr.resources.Delete(sKey, rsName)
					appMgr.outputConfigLocked()
				}
			} else { //multi-service
				rsType = multiServiceIngressType
				_, keys := appMgr.resources.GetAllWithName(rsName)
				for _, key := range keys {
					appMgr.resources.Delete(key, rsName)
					appMgr.outputConfigLocked()
				}
			}
			return false, nil
		}

		// Validate url-rewrite annotations
		if urlRewrite, ok := ing.ObjectMeta.Annotations[f5VsURLRewriteAnnotation]; ok {
			if rsType == multiServiceIngressType {
				urlRewriteMap := parseAppRootURLRewriteAnnotations(urlRewrite)
				validateURLRewriteAnnotations(rsType, urlRewriteMap)
			} else {
				log.Warning("Single service ingress does not support url-rewrite annotation, not processing")
			}
		}

		// Validate app-root annotations
		if appRoot, ok := ing.ObjectMeta.Annotations[f5VsAppRootAnnotation]; ok {
			appRootMap := parseAppRootURLRewriteAnnotations(appRoot)
			if rsType == singleServiceIngressType {
				if len(appRootMap) > 1 {
					log.Warning("Single service ingress does not support multiple app-root annotation values, not processing")
				} else {
					if _, ok := appRootMap["single"]; ok {
						validateAppRootAnnotations(rsType, appRootMap)
					} else {
						log.Warningf("App root annotation: %s does not support targeted values for single service ingress, not processing", appRoot)
					}
				}
			} else {
				validateAppRootAnnotations(rsType, appRootMap)
			}
		}

		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if _, exists := appMgr.resources.GetByName(rsName); !exists && bindAddr == "" {
			log.Infof("No virtual IP was specified for the virtual server %s, creating pool only.",
				rsName)
		}

		// If we have a config for this IP:Port, and either that config or the current config
		// is for a single service ingress, then we don't allow the new Ingress to share the VS
		// It doesn't make sense for single service Ingresses to share a VS
		if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
			if (oldCfg.Virtual.PoolName != "" || ing.Spec.Rules == nil) &&
				oldCfg.MetaData.ingName != ing.ObjectMeta.Name &&
				oldCfg.Virtual.VirtualAddress.BindAddr != "" {
				log.Warningf(
					"Single-service Ingress cannot share the IP and port: '%s:%d'.",
					oldCfg.Virtual.VirtualAddress.BindAddr, oldCfg.Virtual.VirtualAddress.Port)
				return false, nil
			}
		}

		// Create a list of keys for all pools
		for _, pool := range rsCfg.Pools {
			key := &serviceQueueKey{
				ServiceName: pool.ServiceName,
				Namespace:   namespace,
			}
			exists := false
			for _, k := range keyList {
				if k.ServiceName == key.ServiceName &&
					k.Namespace == key.Namespace {
					exists = true
					break
				}
			}
			if !exists {
				keyList = append(keyList, key)
			}
		}
	}
	return true, keyList
}

func (appMgr *Manager) checkValidNode(
	obj interface{},
) (bool, []*serviceQueueKey) {
	// Check if an active configMap exists.
	// if existis get it from appMgr struct and return.
	// if not existis return false, nil.
	if "" != appMgr.activeCfgMap.Name && "" != appMgr.activeCfgMap.Data {
		key := &serviceQueueKey{
			AS3Name: appMgr.activeCfgMap.Name,
			AS3Data: appMgr.activeCfgMap.Data,
		}
		var keyList []*serviceQueueKey
		keyList = append(keyList, key)
		log.Debugf("[as3_log] NodeInformer: ConfigMap '%s' placed in Queue.", appMgr.activeCfgMap.Name)
		return true, keyList
	}
	return false, nil
}

func (appMgr *Manager) checkValidRoute(
	obj interface{},
) (bool, []*serviceQueueKey) {
	var allKeys []*serviceQueueKey
	route := obj.(*routeapi.Route)
	namespace := route.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}

	// Validate url-rewrite annotations
	uri := route.Spec.Host + route.Spec.Path
	if urlRewrite, ok := route.ObjectMeta.Annotations[f5VsURLRewriteAnnotation]; ok {
		urlRewriteMap := parseAppRootURLRewriteAnnotations(urlRewrite)
		if len(urlRewriteMap) > 1 {
			log.Warning(
				"Routes do not support multiple app-root annotation values, " +
					"not processing")
		} else {
			urlRewriteMap[uri] = urlRewriteMap["single"]
			if _, ok := urlRewriteMap["single"]; ok {
				delete(urlRewriteMap, "single")
				validateURLRewriteAnnotations(routeType, urlRewriteMap)
			} else {
				log.Warningf(
					"URL rewrite annotation: %s does not support targeted values "+
						"for routes, not processing", urlRewrite)
			}
		}
	}

	// Validate app-root annotations
	if appRoot, ok := route.ObjectMeta.Annotations[f5VsAppRootAnnotation]; ok {
		appRootMap := parseAppRootURLRewriteAnnotations(appRoot)
		if len(appRootMap) > 1 {
			log.Warning(
				"Single service ingress does not support multiple url-rewrite " +
					"annotation values, not processing")
		} else {
			appRootMap[uri] = appRootMap["single"]
			if _, ok := appRootMap["single"]; ok {
				delete(appRootMap, "single")
				validateAppRootAnnotations(routeType, appRootMap)
			} else {
				log.Warningf(
					"App root annotation: %s does not support targeted values "+
						"for routes, not processing", appRoot)
			}
		}
	}

	svcNames := getRouteServiceNames(route)
	for _, svcName := range svcNames {
		key := &serviceQueueKey{
			ServiceName: svcName,
			Namespace:   namespace,
		}
		allKeys = append(allKeys, key)
	}
	return true, allKeys
}

func validateURLRewriteAnnotations(rsType int, entries map[string]string) {
	for k, v := range entries {
		targetURL := parseAnnotationURL(k)
		valueURL := parseAnnotationURL(v)

		if rsType == multiServiceIngressType && targetURL.Host == "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host target for url-rewrite annotation "+
					"for multi-service ingress, skipping", k, v)
			return
		}
		if rsType == multiServiceIngressType && targetURL.Path == "" && valueURL.Path != "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host and path target for url-rewrite "+
					"annotation with path for multi-service ingress, skipping", k, v)
			return
		}
		if rsType == routeType && targetURL.Path == "" && valueURL.Path != "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a path target for url-rewrite annotation "+
					"with path for route, skipping", k, v)
			return
		}
		if rsType == routeType && targetURL.Host == "" && valueURL.Host != "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host target for url-rewrite annotation "+
					"with host for route, skipping",
				k, v)
			return
		}
		if valueURL.Host == "" && valueURL.Path == "" {
			log.Warningf(
				"Invalid annotation: %s=%s empty values for url-rewrite "+
					"annotation, skipping", k, v)
			return
		}
	}
}

func validateAppRootAnnotations(rsType int, entries map[string]string) {
	for k, v := range entries {
		targetURL := parseAnnotationURL(k)
		valueURL := parseAnnotationURL(v)

		if rsType == multiServiceIngressType && targetURL.Host == "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host target for app-root "+
					"annotation for multi-service ingress, skipping", k, v)
			return
		}
		if rsType == routeType && targetURL.Path != "" {
			log.Warningf(
				"Invalid annotation: %s=%s can not target path for app-root "+
					"annotation for route, skipping", k, v)
			return
		}
		if valueURL.Host != "" {
			log.Warningf(
				"Invalid annotation: %s=%s can not specify host for app root "+
					"annotation value, skipping", k, v)
			return
		}
		if valueURL.Path == "" {
			log.Warningf(
				"Invalid annotation: %s=%s must specify path for app root "+
					"annotation value, skipping", k, v)
			return
		}
	}
}

// name:       checkAS3ConfigMap
// arguments:  obj interface{} - ConfigMap Object
// return val: bool - is it AS3 or not
// description: This function validates configmap be AS3 specific or not

func (appMgr *Manager) checkAS3ConfigMap(
	obj interface{},
) bool {
	// check for metadata.labels has 'as3' and that 'as3' is set to 'true'
	cm := obj.(*v1.ConfigMap)
	labels := cm.ObjectMeta.Labels
	if val, ok := labels["as3"]; ok {
		log.Debugf("[as3_log] Found AS3 config map...")
		if val == "true" {
			return true
		}
	}
	return false
}
