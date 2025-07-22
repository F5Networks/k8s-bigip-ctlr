/*
Copyright © 2022 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/

package bigip

type VcmpGuest struct {
	Name              string   `json:"name,omitempty"`
	FullPath          string   `json:"fullPath,omitempty"`
	AllowedSlots      []int    `json:"allowedSlots,omitempty"`
	AssignedSlots     []int    `json:"assignedSlots,omitempty"`
	CoresPerSlot      int      `json:"coresPerSlot,omitempty"`
	Hostname          string   `json:"hostname,omitempty"`
	InitialImage      string   `json:"initialImage,omitempty"`
	InitialHotfix     string   `json:"initialHotfix,omitempty"`
	Slots             int      `json:"slots,omitempty"`
	MinSlots          int      `json:"minSlots,omitempty"`
	ManagementNetwork string   `json:"managementNetwork,omitempty"`
	ManagementIp      string   `json:"managementIp,omitempty"`
	ManagementGw      string   `json:"managementGw,omitempty"`
	VirtualDisk       string   `json:"virtualDisk,omitempty"`
	Vlans             []string `json:"vlans,omitempty"`
	State             string   `json:"state,omitempty"`
	SslMode           string   `json:"sslMode,omitempty"`
}

type VcmpDisks struct {
	Disks []VcmpDisk `json:"items,omitempty"`
}
type VcmpDisk struct {
	Name     string `json:"name,omitempty"`
	FullPath string `json:"fullPath,omitempty"`
}

type VcmpGuestStat struct {
	NestedStats struct {
		Entries struct {
			RequestedState struct {
				Descrption string `json:"description,omitempty"`
			} `json:"requestedState,omitempty"`
			VmStatus struct {
				Descrption string `json:"description,omitempty"`
			} `json:"vmStatus,omitempty"`
		} `json:"entries,omitempty"`
	} `json:"nestedStats,omitempty"`
}
type VcmpGuestStats struct {
	Kind     string  `json:"kind,omitempty"`
	SelfLink string  `json:"selfLink,omitempty"`
	Entries  DynStat `json:"entries,omitempty"`
}

type DynStat map[string]VcmpGuestStat

const (
	uriVcmp  = "vcmp"
	uriGuest = "guest"
	uriDisk  = "virtual-disk"
	uriStats = "stats"
)

func (b *BigIP) GetVcmpGuestStats(name string) (*VcmpGuestStats, error) {
	var stats VcmpGuestStats
	err, ok := b.getForEntity(&stats, uriVcmp, uriGuest, name, uriStats)

	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &stats, nil
}

func (b *BigIP) GetVcmpGuest(name string) (*VcmpGuest, error) {
	var guest VcmpGuest
	err, _ := b.getForEntity(&guest, uriVcmp, uriGuest, name)

	if err != nil {
		return nil, err
	}
	return &guest, nil
}

func (b *BigIP) GetVcmpDisks() (*VcmpDisks, error) {
	var disks VcmpDisks
	err, ok := b.getForEntity(&disks, uriVcmp, uriDisk)

	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &disks, nil
}

func (b *BigIP) DeleteVcmpDisk(name string) error {
	return b.delete(uriVcmp, uriDisk, name)
}

func (b *BigIP) CreateVcmpGuest(config *VcmpGuest) error {
	return b.post(config, uriVcmp, uriGuest)
}

func (b *BigIP) UpdateVcmpGuest(name string, config *VcmpGuest) error {
	return b.patch(config, uriVcmp, uriGuest, name)
}

func (b *BigIP) DeleteVcmpGuest(name string) error {
	return b.delete(uriVcmp, uriGuest, name)
}
