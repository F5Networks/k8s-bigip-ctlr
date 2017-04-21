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
	"virtualServer"

	log "f5/vlogger"

	"k8s.io/client-go/pkg/api/v1"
)

type eventHandler struct{}

func (eh *eventHandler) OnAdd(obj interface{}) {
	var ns *v1.Namespace
	label := "f5type in (virtual-server)"
	ns = obj.(*v1.Namespace)
	namespace := ns.ObjectMeta.Name
	handlers := virtualServer.NewEventHandler(isNodePort)
	st, err := watchManager.Add(namespace, "configmaps", label, &v1.ConfigMap{}, handlers)
	if nil != err {
		log.Warningf("Failed to add configmaps watch for namespace %v: %v", namespace, err)
		return
	}
	if len(st.ListKeys()) > 0 {
		items := st.List()
		for _, item := range items {
			obj := virtualServer.ChangedObject{Old: nil, New: item}
			virtualServer.ProcessConfigMapUpdate(0, obj, isNodePort)
		}
	}
}

func (eh *eventHandler) OnUpdate(oldObj, newObj interface{}) {
	// Unimplemented function
}

func (eh *eventHandler) OnDelete(obj interface{}) {
	var ns *v1.Namespace
	ns = obj.(*v1.Namespace)
	watchManager.Remove(ns.ObjectMeta.Name, "namespaces")
	virtualServer.RemoveNamespace(ns.ObjectMeta.Name)
}
