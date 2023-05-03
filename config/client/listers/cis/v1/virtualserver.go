/*
Copyright The Kubernetes Authors.

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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// VirtualServerLister helps list VirtualServers.
// All objects returned here must be treated as read-only.
type VirtualServerLister interface {
	// List lists all VirtualServers in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.VirtualServer, err error)
	// VirtualServers returns an object that can list and get VirtualServers.
	VirtualServers(namespace string) VirtualServerNamespaceLister
	VirtualServerListerExpansion
}

// virtualServerLister implements the VirtualServerLister interface.
type virtualServerLister struct {
	indexer cache.Indexer
}

// NewVirtualServerLister returns a new VirtualServerLister.
func NewVirtualServerLister(indexer cache.Indexer) VirtualServerLister {
	return &virtualServerLister{indexer: indexer}
}

// List lists all VirtualServers in the indexer.
func (s *virtualServerLister) List(selector labels.Selector) (ret []*v1.VirtualServer, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.VirtualServer))
	})
	return ret, err
}

// VirtualServers returns an object that can list and get VirtualServers.
func (s *virtualServerLister) VirtualServers(namespace string) VirtualServerNamespaceLister {
	return virtualServerNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// VirtualServerNamespaceLister helps list and get VirtualServers.
// All objects returned here must be treated as read-only.
type VirtualServerNamespaceLister interface {
	// List lists all VirtualServers in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.VirtualServer, err error)
	// Get retrieves the VirtualServer from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.VirtualServer, error)
	VirtualServerNamespaceListerExpansion
}

// virtualServerNamespaceLister implements the VirtualServerNamespaceLister
// interface.
type virtualServerNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all VirtualServers in the indexer for a given namespace.
func (s virtualServerNamespaceLister) List(selector labels.Selector) (ret []*v1.VirtualServer, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.VirtualServer))
	})
	return ret, err
}

// Get retrieves the VirtualServer from the indexer for a given namespace and name.
func (s virtualServerNamespaceLister) Get(name string) (*v1.VirtualServer, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("virtualserver"), name)
	}
	return obj.(*v1.VirtualServer), nil
}
