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

/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package eventStream

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"k8s.io/client-go/1.4/pkg/util/sets"

	"k8s.io/client-go/1.4/tools/cache"
)

// This test suite is k8s.io/client-go/1.4/tools/cache/store_test.go modified
// to test EventStore

// Test public interface
func doTestStore(t *testing.T, store *EventStore) {
	mkObj := func(id string, val string) testStoreObject {
		return testStoreObject{id: id, val: val}
	}

	store.Add(mkObj("foo", "bar"))
	item, ok, _ := store.Get(mkObj("foo", ""))
	require.True(t, ok, "Didn't find inserted item")

	e, a := "bar", item.(testStoreObject).val
	assert.Equal(t, e, a, "Expected %v, got %v", e, a)

	store.Update(mkObj("foo", "baz"))
	item, ok, _ = store.Get(mkObj("foo", ""))
	require.True(t, ok, "Didn't find inserted item")

	e, a = "baz", item.(testStoreObject).val
	assert.Equal(t, e, a, "Expected %v, got %v", e, a)

	store.Delete(mkObj("foo", ""))
	_, ok, _ = store.Get(mkObj("foo", ""))
	require.False(t, ok, "Found deleted item??")

	// Test List.
	store.Add(mkObj("a", "b"))
	store.Add(mkObj("c", "d"))
	store.Add(mkObj("e", "e"))
	{
		found := sets.String{}
		for _, item := range store.List() {
			found.Insert(item.(testStoreObject).val)
		}
		assert.True(t, found.HasAll("b", "d", "e"), "Missing items, found: %v", found)
		assert.Equal(t, 3, len(found), "Extra items")
	}

	// Test Replace.
	store.Replace([]interface{}{
		mkObj("foo", "foo"),
		mkObj("bar", "bar"),
	}, "0")

	{
		found := sets.String{}
		for _, item := range store.List() {
			found.Insert(item.(testStoreObject).val)
		}
		assert.True(t, found.HasAll("foo", "bar"), "Missing items, found: %v", found)
		assert.Equal(t, 2, len(found), "Extra items")
	}
}

// Test public interface
func doTestIndex(t *testing.T, indexer cache.Indexer) {
	mkObj := func(id string, val string) testStoreObject {
		return testStoreObject{id: id, val: val}
	}

	// Test Index
	expected := map[string]sets.String{}
	expected["b"] = sets.NewString("a", "c")
	expected["f"] = sets.NewString("e")
	expected["h"] = sets.NewString("g")
	indexer.Add(mkObj("a", "b"))
	indexer.Add(mkObj("c", "b"))
	indexer.Add(mkObj("e", "f"))
	indexer.Add(mkObj("g", "h"))
	{
		for k, v := range expected {
			found := sets.String{}
			indexResults, err := indexer.Index("by_val", mkObj("", k))
			assert.Nil(t, err, "Unexpected error %v", err)
			for _, item := range indexResults {
				found.Insert(item.(testStoreObject).id)
			}
			items := v.List()
			assert.True(t, found.HasAll(items...),
				"Missing items, index %s, expected %v but found %v", k, items, found.List())
		}
	}
}

func testStoreKeyFunc(obj interface{}) (string, error) {
	return obj.(testStoreObject).id, nil
}

func testStoreIndexFunc(obj interface{}) ([]string, error) {
	return []string{obj.(testStoreObject).val}, nil
}

func testStoreIndexers() cache.Indexers {
	indexers := cache.Indexers{}
	indexers["by_val"] = testStoreIndexFunc
	return indexers
}

type testStoreObject struct {
	id  string
	val string
}

func TestCache(t *testing.T) {
	doTestStore(t, NewEventStore(testStoreKeyFunc, nil))
}

func TestCacheListeners(t *testing.T) {
	expected := map[ChangeType]int{
		Added:    4,
		Updated:  1,
		Deleted:  1,
		Replaced: 1,
	}
	changes := map[ChangeType]int{
		Added:   0,
		Updated: 0,
		Deleted: 0,
	}
	onChange := func(changeType ChangeType, obj interface{}) {
		if Replaced != changeType {
			_, ok := obj.(ChangedObject)
			require.True(t, ok, "Updates should callback with old and new objects")
		}
		changes[changeType] += 1
	}
	doTestStore(t, NewEventStore(testStoreKeyFunc, onChange))
	assert.Equal(t, expected, changes, "Expected changes %v, but got %v", expected, changes)
}
func TestIndex(t *testing.T) {
	doTestIndex(t, cache.NewIndexer(testStoreKeyFunc, testStoreIndexers()))
}
