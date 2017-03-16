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

package virtualServer

import (
	"reflect"

	log "f5/vlogger"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

type (
	resourceType   int
	resourceStores [3]cache.Store

	eventHandler struct {
		client     kubernetes.Interface
		isNodePort bool
		stores     resourceStores
	}

	changedObject struct {
		Old interface{}
		New interface{}
	}
	changeType int
)

const (
	Endpoints resourceType = iota
	Services
	Configmaps
)

const (
	added changeType = iota
	updated
	deleted
)

func NewEventHandler(
	kubeClient kubernetes.Interface,
	isNodePort bool,
) *eventHandler {
	return &eventHandler{
		client:     kubeClient,
		isNodePort: isNodePort,
	}
}

func (eh *eventHandler) SetStore(resource resourceType, s cache.Store) {
	eh.stores[resource] = s
}

func (eh *eventHandler) delegator(
	change changeType,
	resource reflect.Type,
	changed changedObject,
) {
	log.Debugf("Delegating type %v to virtual server processors", resource)

	if resource == reflect.TypeOf(&v1.Endpoints{}) {
		ProcessEndpointsUpdate(
			eh.client,
			change,
			changed,
			eh.stores[Services],
		)
	} else if resource == reflect.TypeOf(&v1.ConfigMap{}) {
		ProcessConfigMapUpdate(
			eh.client,
			change,
			changed,
			eh.isNodePort,
			eh.stores[Endpoints],
		)
	} else if resource == reflect.TypeOf(&v1.Service{}) {
		ProcessServiceUpdate(
			eh.client,
			change,
			changed,
			eh.isNodePort,
			eh.stores[Endpoints],
		)
	} else {
		log.Warningf("Unexpected object type received through event handler: %v", resource)
	}
}

func (eh *eventHandler) OnAdd(obj interface{}) {
	eh.delegator(added, reflect.TypeOf(obj), changedObject{Old: nil, New: obj})
}

func (eh *eventHandler) OnUpdate(oldObj, newObj interface{}) {
	eh.delegator(updated, reflect.TypeOf(newObj), changedObject{Old: oldObj, New: newObj})
}

func (eh *eventHandler) OnDelete(obj interface{}) {
	eh.delegator(deleted, reflect.TypeOf(obj), changedObject{Old: obj, New: nil})
}
