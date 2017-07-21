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

package appmanager

import (
	"encoding/json"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

// Dump out the Virtual Server configs to a file
func (appMgr *Manager) outputConfig() {
	appMgr.resources.Lock()
	appMgr.outputConfigLocked()
	appMgr.resources.Unlock()
}

// Dump out the Virtual Server configs to a file
// This function MUST be called with the virtualServers
// lock held.
func (appMgr *Manager) outputConfigLocked() {

	// Initialize the Resources array as empty; json.Marshal() writes
	// an uninitialized array as 'null', but we want an empty array
	// written as '[]' instead
	resources := BigIPConfig{}

	// Filter the configs to only those that have active services
	appMgr.resources.ForEach(func(key serviceKey, cfg *ResourceConfig) {
		if cfg.MetaData.Active == true {
			resources.Virtuals = appendVirtual(resources.Virtuals, cfg.Virtual)
			for _, p := range cfg.Pools {
				resources.Pools = appendPool(resources.Pools, p)
			}
			for _, m := range cfg.Monitors {
				resources.Monitors = appendMonitor(resources.Monitors, m)
			}
			for _, p := range cfg.Policies {
				resources.Policies = appendPolicy(resources.Policies, p)
			}
		}
	})
	for _, profile := range appMgr.customProfiles.profs {
		resources.CustomProfiles = append(resources.CustomProfiles, profile)
	}
	if appMgr.vsQueue.Len() == 0 && appMgr.nsQueue.Len() == 0 ||
		appMgr.initialState == true {
		doneCh, errCh, err := appMgr.ConfigWriter().SendSection("resources", resources)
		if nil != err {
			log.Warningf("Failed to write Big-IP config data: %v", err)
		} else {
			select {
			case <-doneCh:
				log.Infof("Wrote %v Virtual Server configs", len(resources.Virtuals))
				if log.LL_DEBUG == log.GetLogLevel() {
					// Remove customProfiles from output
					resources.CustomProfiles = []CustomProfile{}
					output, err := json.Marshal(resources)
					if nil != err {
						log.Warningf("Failed creating output debug log: %v", err)
					} else {
						log.Debugf("Resources: %s", output)
					}
				}
			case e := <-errCh:
				log.Warningf("Failed to write Big-IP config data: %v", e)
			case <-time.After(time.Second):
				log.Warning("Did not receive config write response in 1s")
			}
		}
		appMgr.initialState = true
	}
}

// Only append to the list if it isn't already in the list
func appendVirtual(rsVirtuals []Virtual, v Virtual) []Virtual {
	for _, rv := range rsVirtuals {
		if rv.VirtualServerName == v.VirtualServerName &&
			rv.Partition == v.Partition {
			return rsVirtuals
		}
	}
	return append(rsVirtuals, v)
}

// Only append to the list if it isn't already in the list
func appendPool(rsPools []Pool, p Pool) []Pool {
	for i, rp := range rsPools {
		if rp.Name == p.Name &&
			rp.Partition == p.Partition {
			if len(p.PoolMemberAddrs) > 0 {
				rsPools[i].PoolMemberAddrs = p.PoolMemberAddrs
			}
			return rsPools
		}
	}
	return append(rsPools, p)
}

// Only append to the list if it isn't already in the list
func appendMonitor(rsMons []Monitor, m Monitor) []Monitor {
	for _, rm := range rsMons {
		if rm.Name == m.Name &&
			rm.Partition == m.Partition {
			return rsMons
		}
	}
	return append(rsMons, m)
}

// Only append to the list if it isn't already in the list
func appendPolicy(rsPolicies []Policy, p Policy) []Policy {
	for _, rp := range rsPolicies {
		if rp.Name == p.Name &&
			rp.Partition == p.Partition {
			return rsPolicies
		}
	}
	return append(rsPolicies, p)
}
