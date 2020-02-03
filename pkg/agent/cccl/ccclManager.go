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

package cccl

import (
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"
	//routeapi "github.com/openshift/api/route/v1"
)

// AS3AS3Manager holds all the AS3 orchestration specific Data
type CCCLManager struct {
	configWriter writer.Writer
	eventChan    chan interface{}
	ResourceRequest
}

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	ConfigWriter writer.Writer
	EventChan    chan interface{}
}

// Create and return a new app manager that meets the Manager interface
func NewCCCLManager(params *Params) *CCCLManager {
	ccclManager := CCCLManager{
		configWriter: params.ConfigWriter,
		eventChan:    params.EventChan,
	}
	return &ccclManager
}

func (c *CCCLManager) ConfigWriter() writer.Writer {
	return c.configWriter
}
