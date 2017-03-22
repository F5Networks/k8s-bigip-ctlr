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

package watchmanager

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	log "f5/vlogger"

	"k8s.io/client-go/pkg/labels"
	"k8s.io/client-go/pkg/runtime"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Manager is our interface to the watchManager
type Manager interface {
	Add(
		namespace string,
		resource string,
		label string,
		returnObj runtime.Object,
		eventHandler cache.ResourceEventHandler,
	) (cache.Store, error)
	Remove(namespace string, resource string)
	GetStoreItem(namespace string, resource string, serviceName string) (interface{}, bool, error)
	NamespaceExists(namespace string, rt runtime.Object) bool
}

// watchManager holds our controllers and stores
type watchManager struct {
	mu          sync.RWMutex
	controllers map[string]cache.Controller
	stores      map[string]cache.Store
	namespaces  map[string][]runtime.Object
	RESTClient  rest.Interface
	debugMode   bool
}

// NewwatchManager creates the Manager, we don't require the entire kubeclient here
// as we are only making api calls, this also eases the pain of unit testing
func NewWatchManager(
	rc rest.Interface,
) Manager {
	m := &watchManager{
		controllers: make(map[string]cache.Controller),
		stores:      make(map[string]cache.Store),
		namespaces:  make(map[string][]runtime.Object),
		RESTClient:  rc,
	}
	m.debugMode = setDebugMode()
	return m
}

// Add a watcher to the watchManager
func (m *watchManager) Add(
	namespace string,
	resource string,
	label string,
	returnObj runtime.Object,
	eventHandler cache.ResourceEventHandler,
) (cache.Store, error) {
	var rs cache.Store
	var controller *cache.Controller
	var ok bool
	// TODO: Should this check for a valid resource?
	if resource == "" {
		return nil, errors.New("resource can not be empty")
	}
	n := m.createName(namespace, resource)
	l, err := m.createLabel(label)
	if nil != err {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	rs, ok = m.stores[n]
	if !ok {
		// Setup the watcher
		watcher := newListWatchWithLabelSelector(
			m.RESTClient,
			resource,
			namespace,
			l,
		)
		// FIXME: (ramich) we do not resync due to issue 108, once logs are smarter
		// add resync time or pass in requirement
		rs, controller = cache.NewInformer(watcher, returnObj, 0, eventHandler)
		// FIXME: (ramich) client.go has a known memory leak where stopping the controller
		// will not end both go routines that are created. Once this is fixed
		// save this off in a tuple with the channel and store for closing watches
		stopWatcher := make(chan struct{})
		go controller.Run(stopWatcher)

		m.controllers[n] = *controller
		m.stores[n] = rs
	}

	log.Debugf("Add watch of namespace %v and resource %v, store exists:%v",
		namespace, resource, ok)

	// Add the namespace to known list of valid namespaces, used to gate check
	// in virtual server after listeners are established but no longer cared about
	m.addNamespace(namespace, returnObj)

	// return the store if it exists or the newly created one
	return rs, nil
}

// Remove deletes the namespace from the map of namespaces we care about, this
// does not stop the watch, see notes above for why
func (m *watchManager) Remove(namespace string, resource string) {
	// Currently we only supports one event handler per namespace/runtime.Object
	// but future state is to support add/remove of multiple handlers
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.debugMode {
		_, ok := m.namespaces[namespace]
		log.Debugf("Remove namespace %v requested, namespace exists:%v", namespace, ok)
	}
	delete(m.namespaces, namespace)
}

// GetStoreItem returns an item from the specified store
func (m *watchManager) GetStoreItem(
	namespace string,
	resource string,
	serviceName string,
) (interface{}, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := m.createName(namespace, resource)
	s, ok := m.stores[n]
	if ok {
		item, exists, err := s.GetByKey(namespace + "/" + serviceName)
		return item, exists, err
	}
	return nil, false, fmt.Errorf("there is no store for %v", n)
}

// NamespaceExists verifies the namespace is in the map of namespaces we care about
func (m *watchManager) NamespaceExists(namespace string, rt runtime.Object) bool {
	var found bool
	m.mu.RLock()
	defer m.mu.RUnlock()
	ns, ok := m.namespaces[namespace]
	if ok {
		for _, obj := range ns {
			if reflect.TypeOf(rt) == reflect.TypeOf(obj) {
				found = true
			}
		}
	}
	return found
}

func (m *watchManager) createLabel(label string) (labels.Selector, error) {
	var l labels.Selector
	var err error
	if label == "" {
		l = labels.Everything()
	} else {
		l, err = labels.Parse(label)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Label Selector string: %v", err)
		}
	}
	return l, nil
}

func (m *watchManager) createName(namespace string, resource string) string {
	_namespace := namespace
	if namespace == "" {
		_namespace = "*"
	}
	n := fmt.Sprintf("%v_%v", _namespace, resource)
	return n
}

func (m *watchManager) addNamespace(namespace string, rt runtime.Object) {
	ns, ok := m.namespaces[namespace]
	if ok {
		for _, obj := range ns {
			if reflect.TypeOf(rt) == reflect.TypeOf(obj) {
				return
			}
		}
		m.namespaces[namespace] = append(m.namespaces[namespace], rt)
	} else {
		m.namespaces[namespace] = []runtime.Object{rt}
	}
}

func setDebugMode() bool {
	ll := log.NewLogLevel("debug")
	if *ll == log.GetLogLevel() {
		return true
	}
	return false
}
