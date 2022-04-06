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

package appmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"

	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	netv1 "k8s.io/api/networking/v1"
)

func (appMgr *Manager) checkValidConfigMap(
	obj interface{}, oprType string,
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
	//check if config map is agent specific implementation.
	//if ok, add cfgMap name and data to serviceQueueKey.
	if ok := appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap); ok {
		//check if configmap has valid json and ignore the cfmap if invalid.
		if oprType != OprTypeDelete {
			err := validateConfigJson(cm.Data["template"])
			if err != nil {
				log.Errorf("Error processing configmap %v in namespace: %v with err: %v", cm.Name, cm.Namespace, err)
				return false, nil
			}
		}
		if ok := appMgr.processAgentLabels(cm.Labels, cm.Name, namespace); ok {
			key := &serviceQueueKey{
				Namespace:     namespace,
				Operation:     oprType,
				ResourceKind:  Configmaps,
				ResourceName:  cm.Name,
				LastTimeStamp: cm.ObjectMeta.GetCreationTimestamp().Time,
			}
			keyList = append(keyList, key)
			return true, keyList
		}
		return false, nil
	} else {
		// In case of CCCL Agent
		if !appMgr.processAgentLabels(cm.Labels, cm.Name, namespace) {
			return false, nil
		}
	}

	cfg, err := ParseConfigMap(cm, appMgr.schemaLocal, appMgr.vsSnatPoolName)
	if nil != err {
		if handleConfigMapParseFailure(appMgr, cm, cfg, err) {
			// resources is updated if true is returned, write out the config.
			// appMgr.outputConfig()
			appMgr.deployResource()
		}
		return false, nil
	}
	// This ensures that pool-only mode only logs the message below the first
	// time we see a config.
	rsName := FormatConfigMapVSName(cm)
	// Checking for annotation in VS, not iApp
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if _, exists := appMgr.resources.GetByName(rsName); !exists &&
		cfg.MetaData.ResourceType != "iapp" &&
		cfg.Virtual.VirtualAddress != nil &&
		cfg.Virtual.VirtualAddress.BindAddr == "" {
		// Check for IP annotation provided by IPAM system
		if _, ok := cm.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; !ok {
			log.Infof("[CORE] No virtual IP was specified for the virtual server %s creating pool only.",
				rsName)
		}
	}
	for _, pool := range cfg.Pools {
		key := &serviceQueueKey{
			ServiceName:   pool.ServiceName,
			Namespace:     namespace,
			ResourceKind:  Configmaps,
			ResourceName:  cm.Name,
			LastTimeStamp: cm.ObjectMeta.GetCreationTimestamp().Time,
		}

		keyList = append(keyList, key)
	}
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
		ServiceName:   svc.ObjectMeta.Name,
		Namespace:     namespace,
		ResourceKind:  Services,
		ResourceName:  svc.Name,
		LastTimeStamp: svc.ObjectMeta.GetCreationTimestamp().Time,
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
		ServiceName:   eps.ObjectMeta.Name,
		Namespace:     namespace,
		ResourceKind:  Endpoints,
		ResourceName:  eps.Name,
		LastTimeStamp: eps.ObjectMeta.GetCreationTimestamp().Time,
	}
	var keyList []*serviceQueueKey
	keyList = append(keyList, key)
	return true, keyList
}

//checks for NPLPodAnnotation and populates nplstore, later used for poolmembers
//if valid adds the related svc keys to queue.
func (appMgr *Manager) checkValidPod(
	obj interface{}, operation string,
) (bool, []*serviceQueueKey) {
	pod := obj.(*v1.Pod)
	namespace := pod.ObjectMeta.Namespace
	podkey := namespace + "/" + pod.Name
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	//delete annotations from nplstore
	if operation == OprTypeDelete {
		appMgr.nplStoreMutex.Lock()
		delete(appMgr.nplStore, podkey)
		appMgr.nplStoreMutex.Unlock()
	} else {
		ann := pod.GetAnnotations()
		var annotations []NPLAnnotation
		if val, ok := ann[NPLPodAnnotation]; ok {
			if err := json.Unmarshal([]byte(val), &annotations); err != nil {
				log.Errorf("key: %s, got error while unmarshaling NPL annotations: %v", err)
			}
			appMgr.nplStoreMutex.Lock()
			appMgr.nplStore[podkey] = annotations
			appMgr.nplStoreMutex.Unlock()
		} else {
			log.Info("key: %s, NPL annotation not found for Pod")
			appMgr.nplStoreMutex.Lock()
			delete(appMgr.nplStore, podkey)
			appMgr.nplStoreMutex.Unlock()
		}
	}
	svcs := appMgr.GetServicesForPod(pod)
	var keyList []*serviceQueueKey
	for _, svc := range svcs {
		key := &serviceQueueKey{
			ServiceName:   svc.ObjectMeta.Name,
			Namespace:     namespace,
			ResourceKind:  Pod,
			ResourceName:  pod.Name,
			LastTimeStamp: pod.ObjectMeta.GetCreationTimestamp().Time,
		}
		keyList = append(keyList, key)
	}
	return true, keyList
}

func (appMgr *Manager) getSecretServiceQueueKeyForConfigMap(secret *v1.Secret) []*serviceQueueKey {
	var keyList []*serviceQueueKey
	// We will be adding ResourceKind as Configmaps so that particular Configmaps can be re-synced
	if !appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap) {
		appInf, ok := appMgr.getNamespaceInformer(secret.ObjectMeta.Namespace)
		if !ok || appInf.cfgMapInformer == nil {
			return keyList
		}
		configmaps := appInf.cfgMapInformer.GetIndexer().List()
		for _, obj := range configmaps {
			cm := obj.(*v1.ConfigMap)
			if appMgr.processAgentLabels(cm.Labels, cm.Name, cm.Namespace) {
				cfg, err := ParseConfigMap(cm, appMgr.schemaLocal, appMgr.vsSnatPoolName)
				if nil == err {
					for _, profile := range cfg.Virtual.Profiles {
						if profile.Name == secret.Name {
							key := &serviceQueueKey{
								ServiceName:   cfg.Pools[0].ServiceName,
								Namespace:     cm.Namespace,
								ResourceKind:  Configmaps,
								ResourceName:  cm.Name,
								LastTimeStamp: cm.ObjectMeta.GetCreationTimestamp().Time,
							}
							keyList = append(keyList, key)
						}
					}
				}
			}
		}
	}
	return keyList
}

func (appMgr *Manager) getSecretServiceQueueKeyForIngress(secret *v1.Secret) []*serviceQueueKey {
	var keyList []*serviceQueueKey
	// We will be adding ResourceKind as Ingress so that particular ingress can be re-synced
	appInf, ok := appMgr.getNamespaceInformer(secret.ObjectMeta.Namespace)
	if !ok || appInf.ingInformer == nil {
		return keyList
	}
	ingresses := appInf.ingInformer.GetIndexer().List()
	for _, obj := range ingresses {
		// TODO remove the switch and v1beta1 once v1beta1.Ingress is deprecated in k8s 1.22
		switch obj.(type) {
		case *v1beta1.Ingress:
			ingress := obj.(*v1beta1.Ingress)
			var tlsSecret v1beta1.IngressTLS
			for _, tlsSecret = range ingress.Spec.TLS {
				if tlsSecret.SecretName == secret.Name {
					if ingress.Spec.Backend != nil {
						key := &serviceQueueKey{
							ServiceName:   ingress.Spec.Backend.ServiceName,
							Namespace:     secret.ObjectMeta.Namespace,
							ResourceKind:  Ingresses,
							ResourceName:  ingress.Name,
							LastTimeStamp: ingress.ObjectMeta.GetCreationTimestamp().Time,
						}
						keyList = append(keyList, key)
					} else {
						var rule v1beta1.IngressRule
						for _, rule = range ingress.Spec.Rules {
							var path v1beta1.HTTPIngressPath
							for _, path = range rule.IngressRuleValue.HTTP.Paths {
								if len(path.Backend.ServiceName) > 0 {
									key := &serviceQueueKey{
										ServiceName:   path.Backend.ServiceName,
										Namespace:     secret.ObjectMeta.Namespace,
										ResourceKind:  Ingresses,
										ResourceName:  ingress.Name,
										LastTimeStamp: ingress.ObjectMeta.GetCreationTimestamp().Time,
									}
									keyList = append(keyList, key)
								}
							}
						}
					}
				}
			}
		default:
			ingress := obj.(*netv1.Ingress)
			var tlsSecret netv1.IngressTLS
			for _, tlsSecret = range ingress.Spec.TLS {
				if tlsSecret.SecretName == secret.Name {
					if ingress.Spec.DefaultBackend != nil {
						key := &serviceQueueKey{
							ServiceName:   ingress.Spec.DefaultBackend.Service.Name,
							Namespace:     secret.ObjectMeta.Namespace,
							ResourceKind:  Ingresses,
							ResourceName:  ingress.Name,
							LastTimeStamp: ingress.ObjectMeta.GetCreationTimestamp().Time,
						}
						keyList = append(keyList, key)
					} else {
						var rule netv1.IngressRule
						for _, rule = range ingress.Spec.Rules {
							var path netv1.HTTPIngressPath
							for _, path = range rule.IngressRuleValue.HTTP.Paths {
								if len(path.Backend.Service.Name) > 0 {
									key := &serviceQueueKey{
										ServiceName:   path.Backend.Service.Name,
										Namespace:     secret.ObjectMeta.Namespace,
										ResourceKind:  Ingresses,
										ResourceName:  ingress.Name,
										LastTimeStamp: ingress.ObjectMeta.GetCreationTimestamp().Time,
									}
									keyList = append(keyList, key)
								}
							}
						}
					}
				}
			}

		}
	}
	return keyList
}

func (appMgr *Manager) checkValidSecrets(
	obj interface{}) (bool, []*serviceQueueKey) {
	secret := obj.(*v1.Secret)
	// Check if secret contains certificates and key
	if _, ok := secret.Data["tls.crt"]; !ok {
		return false, nil
	}
	if _, ok := secret.Data["tls.key"]; !ok {
		return false, nil
	}
	if appMgr.useSecrets {
		// Getting the ServiceQueue key for ingresses
		keyList := appMgr.getSecretServiceQueueKeyForIngress(secret)
		// appending the ServiceQueue key for configmaps
		keyList = append(keyList, appMgr.getSecretServiceQueueKeyForConfigMap(secret)...)

		if len(keyList) > 0 {
			return true, keyList
		}
	}
	// As no Virtual server is using this secret we will skip processing
	return false, nil
}

func (appMgr *Manager) checkValidIngress(
	obj interface{},
) (bool, []*serviceQueueKey) {
	//TODO remove the switch case and checkV1beta1Ingress function
	switch obj.(type) {
	case *v1beta1.Ingress:
		return appMgr.checkV1beta1Ingress(obj.(*v1beta1.Ingress))
	default:
		return appMgr.checkV1Ingress(obj.(*netv1.Ingress))
	}
}

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) checkV1beta1Ingress(
	ing *v1beta1.Ingress,
) (bool, []*serviceQueueKey) {
	namespace := ing.ObjectMeta.Namespace
	appInf, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}

	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok {
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
		rsName := FormatIngressVSName(bindAddr, portStruct.port)
		// If rsCfg is nil, delete any resources tied to this Ingress
		if rsCfg == nil {
			if nil == ing.Spec.Rules { //single-service
				rsType = SingleServiceIngressType
				serviceName := ing.Spec.Backend.ServiceName
				servicePort := ing.Spec.Backend.ServicePort.IntVal
				sKey := ServiceKey{ServiceName: serviceName, ServicePort: servicePort, Namespace: namespace}
				if _, ok := appMgr.resources.Get(sKey, rsName); ok {
					appMgr.resources.Delete(sKey, rsName)
					appMgr.deployResource()
				}
			} else { //multi-service
				rsType = MultiServiceIngressType
				_, keys := appMgr.resources.GetAllWithName(rsName)
				for _, key := range keys {
					appMgr.resources.Delete(key, rsName)
					appMgr.deployResource()
				}
			}
			return false, nil
		}

		// Validate url-rewrite annotations
		if urlRewrite, ok := ing.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
			if rsType == MultiServiceIngressType {
				urlRewriteMap := ParseAppRootURLRewriteAnnotations(urlRewrite)
				validateURLRewriteAnnotations(rsType, urlRewriteMap)
			} else {
				log.Warning("Single service ingress does not support url-rewrite annotation, not processing")
			}
		}

		// Validate app-root annotations
		if appRoot, ok := ing.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
			appRootMap := ParseAppRootURLRewriteAnnotations(appRoot)
			if rsType == SingleServiceIngressType {
				if len(appRootMap) > 1 {
					log.Warning("Single service ingress does not support multiple app-root annotation values, not processing")
				} else {
					if _, ok := appRootMap["single"]; ok {
						validateAppRootAnnotations(rsType, appRootMap)
					} else {
						log.Warningf("[CORE] App root annotation: %s does not support targeted values for single service ingress, not processing", appRoot)
					}
				}
			} else {
				validateAppRootAnnotations(rsType, appRootMap)
			}
		}

		// This ensures that pool-only mode only logs the message below the first
		// time we see a config.
		if _, exists := appMgr.resources.GetByName(rsName); !exists && bindAddr == "" {
			log.Infof("[CORE] No virtual IP was specified for the virtual server %s, creating pool only.",
				rsName)
		}

		// If we have a config for this IP:Port, and either that config or the current config
		// is for a single service ingress, then we don't allow the new Ingress to share the VS
		// It doesn't make sense for single service Ingresses to share a VS
		if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
			if (oldCfg.Virtual.PoolName != "" || ing.Spec.Rules == nil) &&
				oldCfg.MetaData.IngName != ing.ObjectMeta.Name &&
				oldCfg.Virtual.VirtualAddress.BindAddr != "" {
				log.Warningf(
					"Single-service Ingress cannot share the IP and port: '%s:%d'.",
					oldCfg.Virtual.VirtualAddress.BindAddr, oldCfg.Virtual.VirtualAddress.Port)
				return false, nil
			}
		}
	}
	//Get svc keys to queue
	svcs := getIngressBackend(ing)
	for _, svc := range svcs {
		key := &serviceQueueKey{
			ServiceName:   svc,
			Namespace:     namespace,
			ResourceKind:  Ingresses,
			ResourceName:  ing.Name,
			LastTimeStamp: ing.ObjectMeta.GetCreationTimestamp().Time,
		}
		keyList = append(keyList, key)
	}

	return true, keyList
}

func (appMgr *Manager) checkV1Beta1SingleServivceIngress(
	ing *v1beta1.Ingress,
) bool {
	bindAddr := ""
	if addr, ok := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]; ok {
		bindAddr = addr
	}
	// Depending on the Ingress, we may loop twice here, once for http and once for https
	for _, portStruct := range appMgr.virtualPorts(ing) {
		rsName := FormatIngressVSName(bindAddr, portStruct.port)
		// If we have a config for this IP:Port, and either that config or the current config
		// is for a single service ingress, then we don't allow the new Ingress to share the VS
		// It doesn't make sense for single service Ingresses to share a VS
		if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
			if (oldCfg.Virtual.PoolName != "" || ing.Spec.Rules == nil) &&
				oldCfg.MetaData.IngName != ing.ObjectMeta.Name &&
				oldCfg.Virtual.VirtualAddress.BindAddr != "" {
				log.Warningf(
					"Single-service Ingress cannot share the IP and port: '%s:%d'.",
					oldCfg.Virtual.VirtualAddress.BindAddr, oldCfg.Virtual.VirtualAddress.Port)
				return false
			}
		}
	}
	return true
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

	_, sslAnnotation := route.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]
	// Validate hostname if certificate is not provided in SSL annotations
	if nil != route.Spec.TLS && !sslAnnotation && route.Spec.TLS.Termination != routeapi.TLSTerminationPassthrough {
		ok := checkCertificateHost(route.Spec.Host, route.Spec.TLS.Certificate, route.Spec.TLS.Key)
		if !ok {
			//Invalid certificate and key
			log.Debugf("[CORE] Invalid certificate and key for route: %v", route.ObjectMeta.Name)
			return false, nil
		}
	}
	// Validate url-rewrite annotations
	uri := route.Spec.Host + route.Spec.Path
	if urlRewrite, ok := route.ObjectMeta.Annotations[F5VsURLRewriteAnnotation]; ok {
		urlRewriteMap := ParseAppRootURLRewriteAnnotations(urlRewrite)
		if len(urlRewriteMap) > 1 {
			log.Warning(
				"Routes do not support multiple app-root annotation values, " +
					"not processing")
		} else {
			urlRewriteMap[uri] = urlRewriteMap["single"]
			if _, ok := urlRewriteMap["single"]; ok {
				delete(urlRewriteMap, "single")
				validateURLRewriteAnnotations(RouteType, urlRewriteMap)
			} else {
				log.Warningf(
					"URL rewrite annotation: %s does not support targeted values "+
						"for routes, not processing", urlRewrite)
			}
		}
	}

	// Validate app-root annotations
	if appRoot, ok := route.ObjectMeta.Annotations[F5VsAppRootAnnotation]; ok {
		appRootMap := ParseAppRootURLRewriteAnnotations(appRoot)
		if len(appRootMap) > 1 {
			log.Warning(
				"Single service ingress does not support multiple url-rewrite " +
					"annotation values, not processing")
		} else {
			appRootMap[uri] = appRootMap["single"]
			if _, ok := appRootMap["single"]; ok {
				delete(appRootMap, "single")
				validateAppRootAnnotations(RouteType, appRootMap)
			} else {
				log.Warningf(
					"App root annotation: %s does not support targeted values "+
						"for routes, not processing", appRoot)
			}
		}
	}

	svcNames := GetRouteServiceNames(route)
	for _, svcName := range svcNames {
		key := &serviceQueueKey{
			ServiceName:   svcName,
			Namespace:     namespace,
			ResourceKind:  Routes,
			ResourceName:  route.Name,
			LastTimeStamp: route.ObjectMeta.GetCreationTimestamp().Time,
		}
		allKeys = append(allKeys, key)
	}
	return true, allKeys
}

func validateURLRewriteAnnotations(rsType int, entries map[string]string) {
	for k, v := range entries {
		targetURL := ParseAnnotationURL(k)
		valueURL := ParseAnnotationURL(v)

		if rsType == MultiServiceIngressType && targetURL.Host == "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host target for url-rewrite annotation "+
					"for multi-service ingress, skipping", k, v)
			return
		}
		if rsType == MultiServiceIngressType && targetURL.Path == "" && valueURL.Path != "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host and path target for url-rewrite "+
					"annotation with path for multi-service ingress, skipping", k, v)
			return
		}
		if rsType == RouteType && targetURL.Path == "" && valueURL.Path != "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a path target for url-rewrite annotation "+
					"with path for route, skipping", k, v)
			return
		}
		if rsType == RouteType && targetURL.Host == "" && valueURL.Host != "" {
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
		targetURL := ParseAnnotationURL(k)
		valueURL := ParseAnnotationURL(v)

		if rsType == MultiServiceIngressType && targetURL.Host == "" {
			log.Warningf(
				"Invalid annotation: %s=%s need a host target for app-root "+
					"annotation for multi-service ingress, skipping", k, v)
			return
		}
		if rsType == RouteType && targetURL.Path != "" {
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

//Validate certificate hostname
func checkCertificateHost(host string, certificate string, key string) bool {
	cert, certErr := tls.X509KeyPair([]byte(certificate), []byte(key))
	if certErr != nil {
		log.Errorf("[CORE] Failed to validate TLS cert and key: %v", certErr)
		return false
	}
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Errorf("[CORE] Failed to parse certificate for host %v : %s", host, err)
		return false
	}
	ok := x509cert.VerifyHostname(host)
	if ok != nil {
		log.Debugf("[CORE] Error: Hostname in route does not match with certificate hostname: %v", ok)
	}
	return true
}

//validate config json
func validateConfigJson(tmpConfig string) error {
	var tmp interface{}
	err := json.Unmarshal([]byte(tmpConfig), &tmp)
	return err
}
