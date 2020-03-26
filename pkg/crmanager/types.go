/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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

package crmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned"
	apm "github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type (
	CRManager struct {
		kubeClient       versioned.Interface
		crInformers      map[string]*CRInformer
		resourceSelector labels.Selector
		namespaces       []string
		resources        apm.Resources
	}

	Params struct {
		Config     *rest.Config
		Namespaces []string
	}

	CRInformer struct {
		namespace  string
		stopCh     chan struct{}
		vsInformer cache.SharedIndexInformer
	}
)
