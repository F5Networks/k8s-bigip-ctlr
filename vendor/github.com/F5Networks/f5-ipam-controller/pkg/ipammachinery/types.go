/*-
 * Copyright (c) 2021, F5 Networks, Inc.
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

package ipammachinery

import (
	"github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type (
	// CRManager defines the structure of Custom Resource Manager
	IPAMClient struct {
		kubeCRClient  versioned.Interface
		kubeClient    kubernetes.Interface
		restClient    rest.Interface
		ipamInformers map[string]*IPAMInformer
		namespaces    map[string]bool
		stopCh        chan interface{}
	}
	// Params defines parameters
	Params struct {
		Config        *rest.Config
		EventHandlers *cache.ResourceEventHandlerFuncs
		Namespaces    []string
	}
	// CRInformer defines the structure of Custom Resource Informer
	IPAMInformer struct {
		namespace    string
		stopCh       chan struct{}
		ipamInformer cache.SharedIndexInformer
	}
)
