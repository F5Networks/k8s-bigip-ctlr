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
	"reflect"
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
	if item, ok, _ := store.Get(mkObj("foo", "")); !ok {
		t.Errorf("didn't find inserted item")
	} else {
		if e, a := "bar", item.(testStoreObject).val; e != a {
			t.Errorf("expected %v, got %v", e, a)
		}
	}
	store.Update(mkObj("foo", "baz"))
	if item, ok, _ := store.Get(mkObj("foo", "")); !ok {
		t.Errorf("didn't find inserted item")
	} else {
		if e, a := "baz", item.(testStoreObject).val; e != a {
			t.Errorf("expected %v, got %v", e, a)
		}
	}
	store.Delete(mkObj("foo", ""))
	if _, ok, _ := store.Get(mkObj("foo", "")); ok {
		t.Errorf("found deleted item??")
	}

	// Test List.
	store.Add(mkObj("a", "b"))
	store.Add(mkObj("c", "d"))
	store.Add(mkObj("e", "e"))
	{
		found := sets.String{}
		for _, item := range store.List() {
			found.Insert(item.(testStoreObject).val)
		}
		if !found.HasAll("b", "d", "e") {
			t.Errorf("missing items, found: %v", found)
		}
		if len(found) != 3 {
			t.Errorf("extra items")
		}
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
		if !found.HasAll("foo", "bar") {
			t.Errorf("missing items")
		}
		if len(found) != 2 {
			t.Errorf("extra items")
		}
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
			if err != nil {
				t.Errorf("Unexpected error %v", err)
			}
			for _, item := range indexResults {
				found.Insert(item.(testStoreObject).id)
			}
			items := v.List()
			if !found.HasAll(items...) {
				t.Errorf("missing items, index %s, expected %v but found %v", k, items, found.List())
			}
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
		Added:   4,
		Updated: 1,
		Deleted: 1,
	}
	changes := map[ChangeType]int{
		Added:   0,
		Updated: 0,
		Deleted: 0,
	}
	onChange := func(changeType ChangeType, obj interface{}) {
		changes[changeType] += 1
	}
	doTestStore(t, NewEventStore(testStoreKeyFunc, onChange))
	if !reflect.DeepEqual(expected, changes) {
		t.Errorf("expected changes %v, but got %v", expected, changes)
	}
}
func TestIndex(t *testing.T) {
	doTestIndex(t, cache.NewIndexer(testStoreKeyFunc, testStoreIndexers()))
}
