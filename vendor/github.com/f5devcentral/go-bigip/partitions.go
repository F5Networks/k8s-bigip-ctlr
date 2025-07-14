/*
Copyright © 2019 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/
package bigip

// TMPartitions contains a list of all partitions on the BIG-IP system.
type TMPartitions struct {
	TMPartitions []*TMPartition `json:"items"`
}

type TMPartition struct {
	Name               string `json:"name,omitempty"`
	Kind               string `json:"kind,omitempty"`
	DefaultRouteDomain int    `json:"defaultRouteDomain,omitempty"`
	FullPath           string `json:"fullPath,omitempty"`
	SelfLink           string `json:"selfLink,omitempty"`
}

// TMPartitions returns a list of partitions.
func (b *BigIP) TMPartitions() (*TMPartitions, error) {
	var pList TMPartitions
	if err, _ := b.getForEntity(&pList, "auth", "tmPartition"); err != nil {
		return nil, err
	}
	return &pList, nil
}
