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

package appmanager

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

type (
	NamespaceEventNotifierMap map[string]*NamespaceEventNotifier

	NewBroadcasterFunc func() record.EventBroadcaster

	EventNotifier struct {
		mutex           sync.Mutex
		notifierMap     map[string]*NamespaceEventNotifier
		broadcasterFunc NewBroadcasterFunc
	}

	NamespaceEventNotifier struct {
		broadcaster record.EventBroadcaster
		recorder    record.EventRecorder
	}
)

func NewEventNotifier(bfunc NewBroadcasterFunc) *EventNotifier {
	if nil == bfunc {
		// No broadcaster func provided (unit testing), use real one.
		bfunc = record.NewBroadcaster
	}
	return &EventNotifier{
		notifierMap:     make(map[string]*NamespaceEventNotifier),
		broadcasterFunc: bfunc,
	}
}

// Create a notifier for a namespace, or return the existing one
func (en *EventNotifier) createNotifierForNamespace(
	namespace string,
	coreIntf corev1.CoreV1Interface,
) *NamespaceEventNotifier {

	en.mutex.Lock()
	defer en.mutex.Unlock()

	evNotifier, found := en.notifierMap[namespace]
	if !found {
		source := v1.EventSource{Component: "k8s-bigip-ctlr"}
		broadcaster := en.broadcasterFunc()
		recorder := broadcaster.NewRecorder(scheme.Scheme, source)
		evNotifier = &NamespaceEventNotifier{
			broadcaster: broadcaster,
			recorder:    recorder,
		}
		en.notifierMap[namespace] = evNotifier
		broadcaster.StartRecordingToSink(&corev1.EventSinkImpl{
			Interface: coreIntf.Events(namespace),
		})
	}
	return evNotifier
}

// Get the notifier for a namespace
func (en *EventNotifier) getNotifierForNamespace(
	namespace string,
) *NamespaceEventNotifier {

	en.mutex.Lock()
	defer en.mutex.Unlock()

	evNotifier, found := en.notifierMap[namespace]
	if !found {
		return nil
	}
	return evNotifier
}

func (en *EventNotifier) deleteNotifierForNamespace(namespace string) {
	en.mutex.Lock()
	defer en.mutex.Unlock()
	delete(en.notifierMap, namespace)
}

func (nen *NamespaceEventNotifier) recordEvent(
	obj runtime.Object,
	eventType,
	reason,
	message string,
) {
	nen.recorder.Event(obj, eventType, reason, message)
}

// This function expects either an Ingress resource or the name of a VS for
// an Ingress.
func (appMgr *Manager) recordIngressEvent(
	ing *v1beta1.Ingress,
	reason,
	message string,
) {
	namespace := ing.ObjectMeta.Namespace
	// Create the event
	evNotifier := appMgr.eventNotifier.createNotifierForNamespace(
		namespace, appMgr.kubeClient.CoreV1())
	evNotifier.recordEvent(ing, v1.EventTypeNormal, reason, message)
}
