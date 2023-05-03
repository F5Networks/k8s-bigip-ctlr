/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
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

package as3

import (
	"time"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
)

type L2L3Agent struct {
	configWriter writer.Writer
	eventChan    chan interface{}
}

func (am *AS3Manager) SendARPEntries() {

	if am.l2l3Agent.eventChan == nil {
		return
	}
	// Get all pool members and write them to VxlanMgr to configure ARP entries
	var allPoolMembers []Member

	// Filter the configs to only those that have active services
	for _, cfg := range am.Resources.RsMap {
		if cfg.MetaData.Active == true {
			for _, pool := range cfg.Pools {
				allPoolMembers = append(allPoolMembers, pool.Members...)
			}
		}
	}
	for _, cfgMap := range am.as3ActiveConfig.configmaps {
		allPoolMembers = append(allPoolMembers, cfgMap.endPoints...)
	}
	select {
	case am.l2l3Agent.eventChan <- allPoolMembers:
		log.Debugf("[AS3] AppManager wrote endpoints to VxlanMgr")
	case <-time.After(3 * time.Second):
	}
}
