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

import (
	//"encoding/json"
	"fmt"
	"log"
	"strings"
)

//  LIC contains device license for BIG-IP system.

type Iapps struct {
	Iapps []Iapp `json:"items"`
}

type Iapp struct {
	Name                       string `json:"name,omitempty"`
	Partition                  string `json:"partition,omitempty"`
	Description                string `json:"description,omitempty"`
	DeviceGroup                string `json:"deviceGroup,omitempty"`
	ExecuteAction              string `json:"execute-action,omitempty"`
	InheritedDevicegroup       string `json:"inheritedDevicegroup,omitempty"`
	InheritedTrafficGroup      string `json:"inheritedTrafficGroup,omitempty"`
	StrictUpdates              string `json:"strictUpdates,omitempty"`
	Template                   string `json:"template,omitempty"`
	TemplateModified           string `json:"templateModified,omitempty"`
	TemplatePrerequisiteErrors string `json:"templatePrerequisiteErrors,omitempty"`
	TrafficGroup               string `json:"trafficGroup,omitempty"`
	Jsonfile                   string `json:"apiAnonymous,omitempty"`
	Tables                     []struct {
		ColumnNames []string `json:"columnNames"`
		Name        string   `json:"name"`
		Rows        []struct {
			Row []string `json:"row"`
		} `json:"rows"`
	} `json:"tables,omitempty"`

	Lists []struct {
		Name      string   `json:"name"`
		Encrypted string   `json:"encrypted"`
		Value     []string `json:"value"`
	} `json:"lists,omitempty"`

	Variables []struct {
		Encrypted string `json:"encrypted"`
		Name      string `json:"name"`
		Value     string `json:"value"`
	} `json:"variables,omitempty"`

	Metadata []struct {
		Persist string `json:"persist"`
		Value   string `json:"value"`
	} `json:"metadata,omitempty"`
}

const (
	uriApp     = "application"
	uriService = "service"
	uriSysa    = "sys"
)

func (b *BigIP) CreateIapp(p *Iapp) error {
	return b.post(p, uriSysa, uriApp, uriService)
}

func (b *BigIP) UpdateIapp(name string, p *Iapp) error {

	values := []string{}
	values = append(values, fmt.Sprintf("~%s~", p.Partition))
	values = append(values, name)
	values = append(values, ".app~")
	values = append(values, name)
	// Join three strings into one.
	result := strings.Join(values, "")
	fmt.Println(result)
	return b.patch(p, uriSysa, uriApp, uriService, result)
}

func (b *BigIP) Iapp(name, partition string) (*Iapp, error) {
	var iapp Iapp
	log.Println(" Value of iapp before read  ", &iapp)
	values := []string{}
	values = append(values, fmt.Sprintf("~%s~", partition))
	values = append(values, name)
	values = append(values, ".app~")
	values = append(values, name)
	// Join three strings into one.
	result := strings.Join(values, "")
	err, _ := b.getForEntity(&iapp, uriSysa, uriApp, uriService, result)
	log.Println(" I am here in sdk with  ", err)
	if err != nil {
		return nil, err
	}
	log.Println(" Value of iapp after reading  ", &iapp)
	return &iapp, nil
}

func (b *BigIP) DeleteIapp(name, partition string) error {
	values := []string{}
	values = append(values, fmt.Sprintf("~%s~", partition))
	values = append(values, name)
	values = append(values, ".app~")
	values = append(values, name)
	// Join three strings into one.
	result := strings.Join(values, "")
	return b.delete(uriSys, uriApp, uriService, result)
}
