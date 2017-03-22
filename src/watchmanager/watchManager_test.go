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
	"reflect"
	"testing"

	log "f5/vlogger"
	"test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/client-go/pkg/api/v1"
)

// mockEventHandler used to pass into add calls, this will not be called
type mockEventHandler struct{}

func (eh *mockEventHandler) OnAdd(obj interface{}) {}

func (eh *mockEventHandler) OnUpdate(oldObj, newObj interface{}) {}

func (eh *mockEventHandler) OnDelete(obj interface{}) {}

// Verify the store and namespace size match what is expected after operations
func verifySizeofMap(t *testing.T, rm Manager, storeLength, nsLength int) {
	rms := rm.(*watchManager)
	assert.Equal(t, storeLength, len(rms.stores), "Store length does not match")
	assert.Equal(t, nsLength, len(rms.namespaces), "Namespace length does not match")
}

func TestNewWatchManager(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")
}

func TestAddEmptyResource(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")
	eh := mockEventHandler{}
	// a resource is required
	_, err := rm.Add("default", "", "label", &v1.ConfigMap{}, &eh)
	assert.Error(t, err)
	verifySizeofMap(t, rm, 0, 0)
}

func TestAddInvalidLabel(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	verifySizeofMap(t, rm, 0, 0)

	eh := mockEventHandler{}
	// 'label,' is an invalid label (note the comma) and will cause an error in the label parse
	_, err := rm.Add("default", "configmaps", "label,", &v1.ConfigMap{}, &eh)
	assert.Error(t, err)
	verifySizeofMap(t, rm, 0, 0)
}

func TestAddNewWatch(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	verifySizeofMap(t, rm, 0, 0)

	eh := mockEventHandler{}
	_, err := rm.Add("", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	verifySizeofMap(t, rm, 1, 1)
	assert.NotNil(t, rm.(*watchManager).stores["*_configmaps"])
}

func TestAddMultipleWatchesDifferentNamespaces(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	verifySizeofMap(t, rm, 0, 0)
	// Adding 4 namespaces and 4 stores
	eh := mockEventHandler{}
	_, err := rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace1", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace2", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace3", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)

	verifySizeofMap(t, rm, 4, 4)
}

func TestAddMultipleWatchesSameNamespace(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	verifySizeofMap(t, rm, 0, 0)
	// Adding three stores under the same namespace
	eh := mockEventHandler{}
	_, err := rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace0", "services", "", &v1.Service{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace0", "endpoints", "", &v1.Endpoints{}, &eh)
	assert.NoError(t, err)

	verifySizeofMap(t, rm, 3, 1)
}

func TestAddMultipleSameWatch(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	verifySizeofMap(t, rm, 0, 0)
	// Adding 1 namespace and 1 store, will not duplicate watches
	eh := mockEventHandler{}
	_, err := rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)

	verifySizeofMap(t, rm, 1, 1)
}

func TestAddRemoveWatches(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	verifySizeofMap(t, rm, 0, 0)
	// Adding 4 namespaces and 4 stores
	eh := mockEventHandler{}
	_, err := rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace1", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace2", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	_, err = rm.Add("namespace3", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)

	verifySizeofMap(t, rm, 4, 4)
	// 4 stores, 3 valid namespaces
	rm.Remove("namespace0", "configmaps")
	verifySizeofMap(t, rm, 4, 3)
	// 4 stores, 2 valid namespaces
	rm.Remove("namespace1", "configmaps")
	verifySizeofMap(t, rm, 4, 2)
	// 4 stores, 2 valid namespaces with duplicate delete
	rm.Remove("namespace1", "configmaps")
	verifySizeofMap(t, rm, 4, 2)
}

func TestGetStoreItem(t *testing.T) {
	var err error
	var exists bool
	var item interface{}

	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	// Store does not exists yet
	verifySizeofMap(t, rm, 0, 0)
	_, _, err = rm.GetStoreItem("namespace0", "configmaps", "test")
	assert.Error(t, err)

	eh := mockEventHandler{}
	_, err = rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	verifySizeofMap(t, rm, 1, 1)

	//Store exists but is empty
	_, exists, err = rm.GetStoreItem("namespace0", "configmaps", "test")
	assert.NoError(t, err)
	assert.Equal(t, false, exists)

	// Add the service to the store manually
	newFoo := test.NewService("test", "1", "namespace0", "NodePort",
		[]v1.ServicePort{{Port: 80, NodePort: 30001}})
	n := "namespace0_configmaps"
	rm.(*watchManager).stores[n].Add(newFoo)

	item, exists, err = rm.GetStoreItem("namespace0", "configmaps", "test")
	assert.NoError(t, err)
	assert.Equal(t, true, exists)
	assert.NotNil(t, item)
	assert.Equal(t, reflect.TypeOf(newFoo), reflect.TypeOf(item), "Return object should be of same type")
}

func TestNamespaceExists(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	// Store does not exists yet
	verifySizeofMap(t, rm, 0, 0)

	exists := rm.NamespaceExists("namespace0", &v1.ConfigMap{})
	assert.Equal(t, false, exists, "Namespace should not exists")
	// Add the namespace
	eh := mockEventHandler{}
	_, err := rm.Add("namespace0", "configmaps", "", &v1.ConfigMap{}, &eh)
	assert.NoError(t, err)
	verifySizeofMap(t, rm, 1, 1)

	exists = rm.NamespaceExists("namespace0", &v1.ConfigMap{})
	assert.Equal(t, true, exists, "Namespace should exists")

	// Will not match if the resource type is wrong
	exists = rm.NamespaceExists("namespace0", &v1.Service{})
	assert.Equal(t, false, exists, "Namespace should not exists")

	// Remove the namespace
	rm.Remove("namespace0", "configmaps")
	verifySizeofMap(t, rm, 1, 0)
	exists = rm.NamespaceExists("namespace0", &v1.ConfigMap{})
	assert.Equal(t, false, exists, "Namespace should not exists")
}

func TestDebugMode(t *testing.T) {
	fake := test.CreateFakeHTTPClient()
	require.NotNil(t, fake, "Mock HTTP client cannot be nil")
	rm := NewWatchManager(fake)
	require.NotNil(t, rm, "Mock resouce manager cannot be nil")

	// verify the current log level is debug and watchmanager is in debug mode
	ll := log.NewLogLevel("debug")
	assert.Equal(t, *ll, log.GetLogLevel())
	assert.True(t, rm.(*watchManager).debugMode)

	// set the log level to info and verify the watchmanager is not in debug mode
	ll = log.NewLogLevel("info")
	log.SetLogLevel(*ll)
	assert.Equal(t, *ll, log.GetLogLevel())
	rm = NewWatchManager(fake)
	assert.False(t, rm.(*watchManager).debugMode)
}
