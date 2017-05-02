/*-
 * Copyright (c) 2017, F5 Networks, Inc.
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

package main

import (
	"appmanager"

	log "f5/vlogger"

	"k8s.io/client-go/pkg/api/v1"
)

// Implementation for the cache.ResourceEventHandler interface for namespaces
type namespaceEventHandler struct {
	appMgr *appmanager.Manager
}

func NewNamespaceEventHandler(
	appMgr *appmanager.Manager,
) *namespaceEventHandler {
	return &namespaceEventHandler{appMgr: appMgr}
}

func (eh *namespaceEventHandler) OnAdd(obj interface{}) {
	var ns *v1.Namespace
	label := "f5type in (virtual-server)"
	ns = obj.(*v1.Namespace)
	namespace := ns.ObjectMeta.Name
	handlers := appmanager.NewEventHandler(eh.appMgr)
	st, err := eh.appMgr.WatchManager().Add(namespace, "configmaps", label, &v1.ConfigMap{}, handlers)
	if nil != err {
		log.Warningf("Failed to add configmaps watch for namespace %v: %v", namespace, err)
		return
	}
	if len(st.ListKeys()) > 0 {
		items := st.List()
		for _, item := range items {
			obj := appmanager.ChangedObject{Old: nil, New: item}
			eh.appMgr.ProcessConfigMapUpdate(0, obj)
		}
	}
}

func (eh *namespaceEventHandler) OnUpdate(oldObj, newObj interface{}) {
	// Unimplemented function
}

func (eh *namespaceEventHandler) OnDelete(obj interface{}) {
	var ns *v1.Namespace
	ns = obj.(*v1.Namespace)
	eh.appMgr.WatchManager().Remove(ns.ObjectMeta.Name, "namespaces")
	eh.appMgr.RemoveNamespace(ns.ObjectMeta.Name)
}
