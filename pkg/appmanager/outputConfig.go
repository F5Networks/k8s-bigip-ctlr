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
	"fmt"
	"net"
	"strings"
	"sync"
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
	appMgr.resources.ForEach(func(key serviceKey, cfg *ResourceConfig) {
		if cfg.MetaData.Active == true {
			initPartitionData(resources, cfg.Virtual.Partition)

			// The data for Virtual Servers and IApps are commingled,
			// separate them here
			if cfg.Virtual.IApp != "" {
				// Create the IApp from the data in the Virtual Server
				iapp := IApp{
					Name:                cfg.Virtual.VirtualServerName,
					Partition:           cfg.Virtual.Partition,
					IApp:                cfg.Virtual.IApp,
					IAppPoolMemberTable: cfg.Virtual.IAppPoolMemberTable,
					IAppOptions:         cfg.Virtual.IAppOptions,
					IAppTables:          cfg.Virtual.IAppTables,
					IAppVariables:       cfg.Virtual.IAppVariables,
				}
				for _, p := range cfg.Pools {
					if iapp.Name == p.Name {
						iapp.IAppPoolMemberTable.Members = p.Members
					}
				}
				resources[cfg.Virtual.Partition].IApps =
					appendIApp(resources[cfg.Virtual.Partition].IApps, iapp)
			} else {
				// If it's not an IApp, then it's a Virtual Server
				if nil != cfg.Virtual.VirtualAddress {
					// Validate the IP address, and create the destination
					addr := net.ParseIP(cfg.Virtual.VirtualAddress.BindAddr)
					if nil != addr {
						var format string
						if nil != addr.To4() {
							format = "/%s/%s:%d"
						} else {
							format = "/%s/%s.%d"
						}
						cfg.Virtual.Destination = fmt.Sprintf(
							format,
							cfg.Virtual.Partition,
							cfg.Virtual.VirtualAddress.BindAddr,
							cfg.Virtual.VirtualAddress.Port)
						resources[cfg.Virtual.Partition].Virtuals =
							appendVirtual(resources[cfg.Virtual.Partition].Virtuals, cfg.Virtual)
					}
				}
			}

			for _, p := range cfg.Pools {
				found := false
				initPartitionData(resources, p.Partition)
				// Differentiate pools that belong to IApps, don't create the pool
				// independently from the iApp that owns it
				for _, i := range resources[cfg.Virtual.Partition].IApps {
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
	})

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
						sslProf := "Common/clientssl"
						resources[partition].Virtuals[vKey].AddFrontendSslProfileName(sslProf)
					}
				}
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
	for _, intDg := range appMgr.intDgMap {
		initPartitionData(resources, intDg.Partition)
		resources[intDg.Partition].InternalDataGroups = append(resources[intDg.Partition].InternalDataGroups, *intDg)
	}

	// Update resources to conform to the CCCL schema and empty out unneeded fields
	// so they will be stripped out by the JSON marshaller.
	// Since these are independent chunks of data, the reformating can be parallelized
	var wg sync.WaitGroup
	wg.Add(len(resources))
	for partition, _ := range resources {
		go reformatPartitionResources(resources, partition, &wg)
	}
	wg.Wait()

	if appMgr.vsQueue.Len() == 0 && appMgr.nsQueue.Len() == 0 ||
		appMgr.initialState == true {
		doneCh, errCh, err := appMgr.ConfigWriter().SendSection("resources", resources)
		if nil != err {
			log.Warningf("Failed to write Big-IP config data: %v", err)
		} else {
			select {
			case <-doneCh:
				virtualCount := 0
				for _, partitionConfig := range resources {
					virtualCount += len(partitionConfig.Virtuals)
				}
				log.Infof("Wrote %v Virtual Server configs", virtualCount)
				if log.LL_DEBUG == log.GetLogLevel() {
					// Remove customProfiles from output
					// FIXME (sberman): Issue #365
					for partition, _ := range resources {
						resources[partition].CustomProfiles = []CustomProfile{}
					}
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
func appendIApp(rsIApps []IApp, i IApp) []IApp {
	for _, ri := range rsIApps {
		if ri.Name == i.Name &&
			ri.Partition == i.Partition {
			return rsIApps
		}
	}
	return append(rsIApps, i)
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

// Reformat the resources for a partition to be CCCL-schema compliant
func reformatPartitionResources(resources PartitionMap, partition string, wgp *sync.WaitGroup) {
	defer wgp.Done()

	var wg sync.WaitGroup
	wg.Add(8)
	go reformatVirtuals(resources, partition, &wg)
	go reformatIApps(resources, partition, &wg)
	go reformatMonitors(resources, partition, &wg)
	go reformatPolicies(resources, partition, &wg)
	go reformatCustomProfiles(resources, partition, &wg)
	go reformatIRules(resources, partition, &wg)
	go reformatInternalDataGroups(resources, partition, &wg)
	go reformatPools(resources, partition, &wg)
	wg.Wait()
}

// Reformat the IApps for a partition to be CCCL-schema compliant
func reformatIApps(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].IApps {
		resources[partition].IApps[i].Partition = ""
	}
}

// Reformat the Monitors for a partition to be CCCL-schema compliant
func reformatMonitors(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].Monitors {
		resources[partition].Monitors[i].Partition = ""
		resources[partition].Monitors[i].Type = resources[partition].Monitors[i].Protocol
		resources[partition].Monitors[i].Protocol = ""
	}
}

// Reformat the Policies for a partition to be CCCL-schema compliant
func reformatPolicies(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].Policies {
		resources[partition].Policies[i].Partition = ""
	}
}

// Reformat the Custom Profiles for a partition to be CCCL-schema compliant
func reformatCustomProfiles(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].CustomProfiles {
		resources[partition].CustomProfiles[i].Partition = ""
	}
}

// Reformat the IRules for a partition to be CCCL-schema compliant
func reformatIRules(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].IRules {
		resources[partition].IRules[i].Partition = ""
	}
}

// Reformat the Internal Data Groups for a partition to be CCCL-schema compliant
func reformatInternalDataGroups(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].InternalDataGroups {
		resources[partition].InternalDataGroups[i].Partition = ""
	}
}

// Reformat the Pools for a partition to be CCCL-schema compliant
func reformatPools(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].Pools {
		resources[partition].Pools[i].Partition = ""
		resources[partition].Pools[i].ServicePort = 0
		resources[partition].Pools[i].ServiceName = ""
	}
}

// Reformat the Virtuals for a partition to be CCCL-schema compliant
func reformatVirtuals(resources PartitionMap, partition string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i, _ := range resources[partition].Virtuals {
		resources[partition].Virtuals[i].Enabled = true

		// Add the profiles to the Virtual Server
		mode := strings.ToLower(resources[partition].Virtuals[i].Mode)
		if mode == "http" {
			resources[partition].Virtuals[i].IpProtocol = "tcp"
			profile := ProfileRef{Partition: "Common", Name: "http", Context: "all"}
			resources[partition].Virtuals[i].Profiles =
				append(resources[partition].Virtuals[i].Profiles, profile)
		} else if mode == "tcp" {
			resources[partition].Virtuals[i].IpProtocol = "tcp"
			profile := ProfileRef{Partition: "Common", Name: "tcp", Context: "all"}
			resources[partition].Virtuals[i].Profiles =
				append(resources[partition].Virtuals[i].Profiles, profile)
		} else if mode == "udp" {
			resources[partition].Virtuals[i].IpProtocol = "udp"
		}

		// Parse the SSL profile into partition and name
		for _, p := range resources[partition].Virtuals[i].GetFrontendSslProfileNames() {
			resources[partition].Virtuals[i].Profiles =
				appendSslProfile(resources[partition].Virtuals[i].Profiles, p, customProfileClient)
		}

		resources[partition].Virtuals[i].SourceAddrTranslation.Type = "automap"

		resources[partition].Virtuals[i].Partition = ""
		resources[partition].Virtuals[i].VirtualAddress = nil
		resources[partition].Virtuals[i].Balance = ""
		resources[partition].Virtuals[i].Mode = ""
		resources[partition].Virtuals[i].SslProfile = nil
		resources[partition].Virtuals[i].IAppPoolMemberTable = nil
	}
}
