/*
Original work Copyright © 2015 Scott Ware
Modifications Copyright 2019 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/
package bigip

import "encoding/json"

// LIC contains device license for BIG-IP system.
type ULICs struct {
	LIC []LIC `json:"items"`
}

// This is BIG-IP which needs to be licensed.
type ULIC struct {
	DeviceAddress string
	Username      string
	Password      string
	UnitOfMeasure string
}

type UtilityPools struct {
	UtilityPool []UtilityPool `json:"items"`
}

type UtilityPool struct {
	Items []struct {
		RegKey string `json:"RegKey,omitempty"`
	}
}

type ULICDTO struct {
	DeviceAddress string `json:"deviceAddress,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	UnitOfMeasure string `json:"unitOfMeasure,omitempty"`
}

/*GET https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses

To view a particular utility license (exclude brackets)
GET https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses/{ reg key for license}
So for your license currently on box
GET https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses/FDKOC-UVGUE-FDURD-AYYDH-IXDSOYV

To view the list of offerings for a utility license
GET https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses/FDKOC-UVGUE-FDURD-AYYDH-IXDSOYV/offerings

To view the members of an offering
GET https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses/{RegKey}/offerings/{offering id}/members
So for your license currently on box
GET https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses/FDKOC-UVGUE-FDURD-AYYDH-IXDSOYV/offerings/fb7b7c65-5551-4ab2-a35a-659d47533e6b/members

To assign a license a device the license from an offering you would POST to the members collection like you would for purchased pool licenses for managed devices.
POST https://10.192.74.92/mgmt/cm/device/licensing/pool/utility/licenses/FDKOC-UVGUE-FDURD-AYYDH-IXDSOYV/offerings/fb7b7c65-5551-4ab2-a35a-659d47533e6b/members
{

                “unitOfMeasure”: “yearly”
}
UnitOfMeasure can be “hourly”,”daily”, “monthly”, “yearly”.

*/

func (p *ULIC) MarshalJSON() ([]byte, error) {
	var dto ULICDTO
	marshal(&dto, p)
	return json.Marshal(dto)
}

func (p *ULIC) UnmarshalJSON(b []byte) error {
	var dto ULICDTO
	err := json.Unmarshal(b, &dto)
	if err != nil {
		return err
	}
	return marshal(p, &dto)
}

// Get the RegKey which is used to know what Bulk license is available on BIG-IQ
func (b *BigIP) getUtilityPool() (*UtilityPool, error) {
	var utilityPool UtilityPool
	err, _ := b.getForEntity(&utilityPool, uriMgmt, uriCm, uriDiv, uriLins, uriPoo, uriUtility, uriLicn)
	if err != nil {
		return nil, err
	}
	// for loop over all returned license pools to check which one has available licenses
	// getAvailablePool(member[index_of_array].Uuid)
	// At the end change return statement to return only the UUID string of the one where license
	// is available
	return &utilityPool, nil
}

// Function to get the RegKey
func (b *BigIP) ULIC() (*ULIC, error) {
	var va ULIC
	utilityPool, utilityPoolErr := b.getUtilityPool()
	if utilityPoolErr != nil {
		return nil, utilityPoolErr
	}
	err, _ := b.getForEntity(&va, uriMgmt, uriCm, uriDiv, uriLins, uriPoo, uriUtility, uriLicn, utilityPool.Items[0].RegKey)
	if err != nil {
		return nil, err
	}
	return &va, nil
}

func (b *BigIP) CreateULIC(deviceAddress string, username string, password string, unitOfMeasure string) error {
	config := &ULIC{
		DeviceAddress: deviceAddress,
		Username:      username,
		Password:      password,
		UnitOfMeasure: unitOfMeasure,
	}

	utilityPool, utilityPoolErr := b.getUtilityPool()
	if utilityPoolErr != nil {
		return utilityPoolErr
	}

	return b.post(config, uriMgmt, uriCm, uriDiv, uriLins, uriPoo, uriUtility, uriLicn, utilityPool.Items[0].RegKey, uriOfferings, uriF5BIGMSPBT10G, uriMemb)
}

func (b *BigIP) ModifyULIC(config *ULIC) error {
	utilityPool, utilityPoolErr := b.getUtilityPool()
	if utilityPoolErr != nil {
		return utilityPoolErr
	}
	return b.patch(config, uriMgmt, uriCm, uriDiv, uriLins, uriPoo, uriUtility, uriLicn, utilityPool.Items[0].RegKey, uriMemb)
}

func (b *BigIP) ULICs() (*ULIC, error) {
	var members ULIC
	utilityPool, utilityPoolErr := b.getUtilityPool()
	if utilityPoolErr != nil {
		return nil, utilityPoolErr
	}
	err, _ := b.getForEntity(&members, uriMgmt, uriCm, uriDiv, uriLins, uriPoo, uriUtility, uriLicn, utilityPool.Items[0].RegKey, uriMemb)

	if err != nil {
		return nil, err
	}

	return &members, nil
}

func (b *BigIP) DeleteULIC(config *ULIC) error {

	utilityPool, utilityPoolErr := b.getUtilityPool()
	if utilityPoolErr != nil {
		return utilityPoolErr
	}

	return b.delete(uriMgmt, uriCm, uriDiv, uriLins, uriPoo, uriUtility, uriLicn, utilityPool.Items[0].RegKey, uriOfferings, uriF5BIGMSPBT10G, uriMemb)
}
