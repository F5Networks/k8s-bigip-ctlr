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

package appmanager

import (
	"encoding/json"
	"strings"
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
	// Initialize the Resources struct as empty

	// Organize the data as a map of arrays of resources (per partition)
	resources := PartitionMap{}

	// Filter the configs to only those that have active services
	for _, cfg := range appMgr.resources.GetAllResources() {
		if cfg.MetaData.Active == true {
			initPartitionData(resources, cfg.GetPartition())

			// Each cfg identifies either a Virtual Server or an IApp.
			if cfg.MetaData.ResourceType == "iapp" {
				for _, p := range cfg.Pools {
					if cfg.IApp.Name == p.Name {
						cfg.IApp.IAppPoolMemberTable.Members = p.Members
					}
				}
				resources[cfg.GetPartition()].IApps =
					append(resources[cfg.GetPartition()].IApps, cfg.IApp)
			} else {
				// If it's not an IApp, then it's a Virtual Server
				if "" != cfg.Virtual.Destination {
					resources[cfg.GetPartition()].Virtuals =
						append(resources[cfg.GetPartition()].Virtuals, cfg.Virtual)
				}
			}

			for _, p := range cfg.Pools {
				found := false
				initPartitionData(resources, p.Partition)
				// Differentiate pools that belong to IApps, don't create the pool
				// independently from the iApp that owns it
				for _, i := range resources[cfg.GetPartition()].IApps {
					if p.Name == i.Name {
						found = true
					}
				}
				if !found {
					resources[p.Partition].Pools = appendPool(resources[p.Partition].Pools, p)
				}
			}
			for _, m := range cfg.Monitors {
				initPartitionData(resources, m.Partition)
				resources[m.Partition].Monitors = appendMonitor(resources[m.Partition].Monitors, m)
			}
			for _, p := range cfg.Policies {
				initPartitionData(resources, p.Partition)
				resources[p.Partition].Policies = appendPolicy(resources[p.Partition].Policies, p)
			}
		}
	}

	for _, profile := range appMgr.customProfiles.profs {
		initPartitionData(resources, profile.Partition)
		resources[profile.Partition].CustomProfiles = append(resources[profile.Partition].CustomProfiles, profile)
	}
	for _, irule := range appMgr.irulesMap {
		initPartitionData(resources, irule.Partition)
		resources[irule.Partition].IRules = append(resources[irule.Partition].IRules, *irule)
	}
	for intDgKey, intDgMap := range appMgr.intDgMap {
		initPartitionData(resources, intDgKey.Partition)
		// Join all namespace DG's into one DG before adding.
		flatDg := intDgMap.FlattenNamespaces()
		if nil != flatDg {
			resources[intDgKey.Partition].InternalDataGroups = append(resources[intDgKey.Partition].InternalDataGroups, *flatDg)
		} else {
			// The data group is required, but we have no information.
			resources[intDgKey.Partition].InternalDataGroups = append(resources[intDgKey.Partition].InternalDataGroups, *NewInternalDataGroup(intDgKey.Name, intDgKey.Partition))
		}
	}

	if appMgr.eventChan != nil {
		// Get all pool members and write them to VxlanMgr to configure ARP entries
		var allPoolMembers []Member
		for _, cfg := range resources {
			for _, pool := range cfg.Pools {
				allPoolMembers = append(allPoolMembers, pool.Members...)
			}
			for _, iapp := range cfg.IApps {
				allPoolMembers = append(allPoolMembers, iapp.IAppPoolMemberTable.Members...)
			}
		}

		for member := range appMgr.as3Members {
			allPoolMembers = append(allPoolMembers, member)
		}

		select {
		case appMgr.eventChan <- allPoolMembers:
			log.Debugf("AppManager wrote endpoints to VxlanMgr.")
		case <-time.After(3 * time.Second):
		}
	}

	// To allow the ssl passthrough iRule to be associated with a virtual,
	// it must have at least one client or server SSL profile associated with
	// it. If the virtual doesn't have any of either type, we force it to take
	// the BIG-IP's base client SSL profile in the output config.
	for partition, partitionConfig := range resources {
		for vKey, virtual := range partitionConfig.Virtuals {
			for _, irule := range virtual.IRules {
				if strings.Contains(irule, sslPassthroughIRuleName) {
					clientProfCt := virtual.GetProfileCountByContext(customProfileClient)
					serverProfCt := virtual.GetProfileCountByContext(customProfileServer)
					if 0 == clientProfCt && 0 == serverProfCt {
						sslProf := ProfileRef{
							Partition: "Common",
							Name:      "clientssl",
							Context:   customProfileClient,
						}
						resources[partition].Virtuals[vKey].AddOrUpdateProfile(sslProf)
					}
				}
			}
		}
	}

	if appMgr.processedItems >= appMgr.queueLen || appMgr.initialState {
		doneCh, errCh, err := appMgr.ConfigWriter().SendSection("resources", resources)
		if nil != err {
			log.Warningf("Failed to write Big-IP config data: %v", err)
		} else {
			select {
			case <-doneCh:
				virtualCount := 0
				iappCount := 0
				for _, partitionConfig := range resources {
					virtualCount += len(partitionConfig.Virtuals)
					iappCount += len(partitionConfig.IApps)
				}
				log.Infof("Wrote %v Virtual Server and %v IApp configs",
					virtualCount, iappCount)
				if log.LL_DEBUG == log.GetLogLevel() {
					// Copy everything from resources except CustomProfiles
					// to be used for debug logging
					resourceLog := copyResourceData(resources)
					output, err := json.Marshal(resourceLog)
					if nil != err {
						log.Warningf("Failed creating output debug log: %v", err)
					} else {
						log.Debugf("LTM Resources: %s", output)
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

// Parse the SSL Profile and append it to the list
func appendSslProfile(profs []ProfileRef, profile string, context string) []ProfileRef {
	p := strings.Split(profile, "/")
	if len(p) != 2 {
		log.Errorf("Could not parse partition and name from SSL profile: %s", profile)
		return profs
	} else {
		return append(profs, ProfileRef{Partition: p[0], Name: p[1], Context: context})
	}
}

// Create a partition entry in the map if it doesn't exist
func initPartitionData(resources PartitionMap, partition string) {
	if _, ok := resources[partition]; !ok {
		resources[partition] = &BigIPConfig{}
	}
}

// Only append to the list if it isn't already in the list
func appendPool(rsPools []Pool, p Pool) []Pool {
	for i, rp := range rsPools {
		if rp.Name == p.Name &&
			rp.Partition == p.Partition {
			if len(p.Members) > 0 {
				rsPools[i].Members = p.Members
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

func copyResourceData(resources PartitionMap) PartitionMap {
	resourceLog := PartitionMap{}
	for partition, cfg := range resources {
		initPartitionData(resourceLog, partition)

		resourceLog[partition].Virtuals = make([]Virtual, len(cfg.Virtuals))
		copy(resourceLog[partition].Virtuals, cfg.Virtuals)

		resourceLog[partition].Pools = make(Pools, len(cfg.Pools))
		copy(resourceLog[partition].Pools, cfg.Pools)

		resourceLog[partition].Monitors = make(Monitors, len(cfg.Monitors))
		copy(resourceLog[partition].Monitors, cfg.Monitors)

		resourceLog[partition].Policies = make([]Policy, len(cfg.Policies))
		copy(resourceLog[partition].Policies, cfg.Policies)

		resourceLog[partition].IRules = make([]IRule, len(cfg.IRules))
		copy(resourceLog[partition].IRules, cfg.IRules)

		resourceLog[partition].InternalDataGroups = make([]InternalDataGroup, len(cfg.InternalDataGroups))
		copy(resourceLog[partition].InternalDataGroups, cfg.InternalDataGroups)
	}
	return resourceLog
}
