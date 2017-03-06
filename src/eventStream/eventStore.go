/*-
 * Copyright (c) 2016, F5 Networks, Inc.
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

package eventStream

import (
	"k8s.io/client-go/1.4/tools/cache"
)

// ChangeType defines the possible types of changes.
type ChangeType string

const (
	Added    ChangeType = "ADDED"
	Updated  ChangeType = "UPDATED"
	Deleted  ChangeType = "DELETED"
	Replaced ChangeType = "REPLACED"
)

type ChangedObject struct {
	Old interface{}
	New interface{}
}

// Function used to handle stream update events after the store is updated.
type OnChangeFunc func(changeType ChangeType, obj interface{})

// Storage for the current state of objects, gets updated by cache.Reflector,
// works with the cache.Store interface.
type EventStore struct {
	storage      cache.ThreadSafeStore // pointer to the storage used by the reflector, needs to be thread-safe
	keyFunc      cache.KeyFunc
	onChangeFunc OnChangeFunc
}

func NewEventStore(keyFunc cache.KeyFunc, onChangeFunc OnChangeFunc) *EventStore {
	storage := cache.NewThreadSafeStore(cache.Indexers{}, cache.Indices{})
	return &EventStore{
		storage:      storage,
		keyFunc:      keyFunc,
		onChangeFunc: onChangeFunc,
	}
}

// Implementation of cache.Store interface for EventStore that also
// triggers events on a EventStoreListener. This is essentially the cache.Store
// implementation with the addition of calls to onChangeFunc().
func (es *EventStore) Add(obj interface{}) error {
	key, err := es.keyFunc(obj)
	if err != nil {
		return cache.KeyError{obj, err}
	}
	es.storage.Add(key, obj)
	if es.onChangeFunc != nil {
		es.onChangeFunc(Added, ChangedObject{
			nil,
			obj,
		})
	}
	return nil
}
func (es *EventStore) Update(obj interface{}) error {
	key, err := es.keyFunc(obj)
	if err != nil {
		return cache.KeyError{obj, err}
	}
	oldObj, _ := es.storage.Get(key)
	es.storage.Update(key, obj)
	if es.onChangeFunc != nil {
		es.onChangeFunc(Updated, ChangedObject{
			oldObj,
			obj,
		})
	}
	return nil
}
func (es *EventStore) Delete(obj interface{}) error {
	key, err := es.keyFunc(obj)
	if err != nil {
		return cache.KeyError{obj, err}
	}
	es.storage.Delete(key)
	if es.onChangeFunc != nil {
		es.onChangeFunc(Deleted, ChangedObject{
			obj,
			nil,
		})
	}
	return nil
}
func (es *EventStore) List() []interface{} {
	return es.storage.List()
}
func (es *EventStore) ListKeys() []string {
	return es.storage.ListKeys()
}
func (es *EventStore) Get(obj interface{}) (item interface{}, exists bool, err error) {
	key, err := es.keyFunc(obj)
	if err != nil {
		return nil, false, cache.KeyError{obj, err}
	}
	return es.GetByKey(key)
}
func (es *EventStore) GetByKey(key string) (item interface{}, exists bool, err error) {
	item, exists = es.storage.Get(key)
	return item, exists, nil
}
func (es *EventStore) Replace(list []interface{}, resourceVersion string) error {
	items := map[string]interface{}{}
	for _, item := range list {
		key, err := es.keyFunc(item)
		if err != nil {
			return cache.KeyError{item, err}
		}
		items[key] = item
	}
	es.storage.Replace(items, resourceVersion)
	if es.onChangeFunc != nil {
		es.onChangeFunc(Replaced, list)
	}
	return nil
}
func (es *EventStore) Resync() error {
	return es.storage.Resync()
}
