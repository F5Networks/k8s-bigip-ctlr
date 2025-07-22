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

import (
	"encoding/json"
	"log"
)

//ooo

type Datacenters struct {
	Datacenters []Datacenter `json:"items"`
}

type Datacenter struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Contact     string `json:"contact,omitempty"`
	App_service string `json:"appService,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	Prober_pool string `json:"proberPool,omitempty"`
}

type Gtmmonitors struct {
	Gtmmonitors []Gtmmonitor `json:"items"`
}

type Gtmmonitor struct {
	Name          string `json:"name,omitempty"`
	Defaults_from string `json:"defaultsFrom,omitempty"`
	Interval      int    `json:"interval,omitempty"`
	Probe_timeout int    `json:"probeTimeout,omitempty"`
	Recv          string `json:"recv,omitempty"`
	Send          string `json:"send,omitempty"`
}

type Servers struct {
	Servers []Server `json:"items"`
}

type Server struct {
	Name                     string
	Datacenter               string
	Monitor                  string
	Virtual_server_discovery bool
	Product                  string
	Addresses                []ServerAddresses
	GTMVirtual_Server        []VSrecord
}

type serverDTO struct {
	Name                     string `json:"name"`
	Datacenter               string `json:"datacenter,omitempty"`
	Monitor                  string `json:"monitor,omitempty"`
	Virtual_server_discovery bool   `json:"virtual_server_discovery"`
	Product                  string `json:"product,omitempty"`
	Addresses                struct {
		Items []ServerAddresses `json:"items,omitempty"`
	} `json:"addressesReference,omitempty"`
	GTMVirtual_Server struct {
		Items []VSrecord `json:"items,omitempty"`
	} `json:"virtualServersReference,omitempty"`
}

func (p *Server) MarshalJSON() ([]byte, error) {
	return json.Marshal(serverDTO{
		Name:                     p.Name,
		Datacenter:               p.Datacenter,
		Monitor:                  p.Monitor,
		Virtual_server_discovery: p.Virtual_server_discovery,
		Product:                  p.Product,
		Addresses: struct {
			Items []ServerAddresses `json:"items,omitempty"`
		}{Items: p.Addresses},
		GTMVirtual_Server: struct {
			Items []VSrecord `json:"items,omitempty"`
		}{Items: p.GTMVirtual_Server},
	})
}

func (p *Server) UnmarshalJSON(b []byte) error {
	var dto serverDTO
	err := json.Unmarshal(b, &dto)
	if err != nil {
		return err
	}

	p.Name = dto.Name
	p.Datacenter = dto.Datacenter
	p.Monitor = dto.Monitor
	p.Virtual_server_discovery = dto.Virtual_server_discovery
	p.Product = dto.Product
	p.Addresses = dto.Addresses.Items
	p.GTMVirtual_Server = dto.GTMVirtual_Server.Items
	return nil
}

type ServerAddressess struct {
	Items []ServerAddresses `json:"items,omitempty"`
}

type ServerAddresses struct {
	Name        string `json:"name"`
	Device_name string `json:"deviceName,omitempty"`
	Translation string `json:"translation,omitempty"`
}

type VSrecords struct {
	Items []VSrecord `json:"items,omitempty"`
}

type VSrecord struct {
	Name        string `json:"name"`
	Destination string `json:"destination,omitempty"`
}

type Pool_as struct {
	Pool_as []Pool_a `json:"items"`
}

type Pool_a struct {
	Name                 string   `json:"name,omitempty"`
	Monitor              string   `json:"monitor,omitempty"`
	Load_balancing_mode  string   `json:"load_balancing_mode,omitempty"`
	Max_answers_returned int      `json:"max_answers_returned,omitempty"`
	Alternate_mode       string   `json:"alternate_mode,omitempty"`
	Fallback_ip          string   `json:"fallback_ip,omitempty"`
	Fallback_mode        string   `json:"fallback_mode,omitempty"`
	Members              []string `json:"members,omitempty"`
}

const (
	uriGtm        = "gtm"
	uriServer     = "server"
	uriDatacenter = "datacenter"
	uriGtmmonitor = "monitor"
	uriPool_a     = "pool/a"
)

func (b *BigIP) Datacenters() (*Datacenter, error) {
	var datacenter Datacenter
	err, _ := b.getForEntity(&datacenter, uriGtm, uriDatacenter)

	if err != nil {
		return nil, err
	}

	return &datacenter, nil
}

func (b *BigIP) CreateDatacenter(name, description, contact, app_service string, enabled, disabled bool, prober_pool string) error {
	config := &Datacenter{
		Name:        name,
		Description: description,
		Contact:     contact,
		App_service: app_service,
		Enabled:     enabled,
		Disabled:    disabled,
		Prober_pool: prober_pool,
	}
	return b.post(config, uriGtm, uriDatacenter)
}

func (b *BigIP) ModifyDatacenter(*Datacenter) error {
	return b.patch(uriGtm, uriDatacenter)
}

func (b *BigIP) DeleteDatacenter(name string) error {
	return b.delete(uriGtm, uriDatacenter, name)
}

func (b *BigIP) Gtmmonitors() (*Gtmmonitor, error) {
	var gtmmonitor Gtmmonitor
	err, _ := b.getForEntity(&gtmmonitor, uriGtm, uriGtmmonitor, uriHttp)

	if err != nil {
		return nil, err
	}

	return &gtmmonitor, nil
}
func (b *BigIP) CreateGtmmonitor(name, defaults_from string, interval, probeTimeout int, recv, send string) error {
	config := &Gtmmonitor{
		Name:          name,
		Defaults_from: defaults_from,
		Interval:      interval,
		Probe_timeout: probeTimeout,
		Recv:          recv,
		Send:          send,
	}
	return b.post(config, uriGtm, uriGtmmonitor, uriHttp)
}

func (b *BigIP) ModifyGtmmonitor(*Gtmmonitor) error {
	return b.patch(uriGtm, uriGtmmonitor, uriHttp)
}

func (b *BigIP) DeleteGtmmonitor(name string) error {
	return b.delete(uriGtm, uriGtmmonitor, uriHttp, name)
}

func (b *BigIP) CreateGtmserver(p *Server) error {
	log.Println(" what is the complete payload    ", p)
	return b.post(p, uriGtm, uriServer)
}

// Update an existing policy.
func (b *BigIP) UpdateGtmserver(name string, p *Server) error {
	return b.put(p, uriGtm, uriServer, name)
}

// Delete a policy by name.
func (b *BigIP) DeleteGtmserver(name string) error {
	return b.delete(uriGtm, uriServer, name)
}

func (b *BigIP) GetGtmserver(name string) (*Server, error) {
	var p Server
	err, ok := b.getForEntity(&p, uriGtm, uriServer, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &p, nil
}

func (b *BigIP) CreatePool_a(name, monitor, load_balancing_mode string, max_answers_returned int, alternate_mode, fallback_ip, fallback_mode string, members []string) error {
	config := &Pool_a{
		Name:                 name,
		Monitor:              monitor,
		Load_balancing_mode:  load_balancing_mode,
		Max_answers_returned: max_answers_returned,
		Alternate_mode:       alternate_mode,
		Fallback_ip:          fallback_ip,
		Fallback_mode:        fallback_mode,
		Members:              members,
	}
	log.Println("in poola now", config)
	return b.patch(config, uriGtm, uriPool_a)
}

func (b *BigIP) ModifyPool_a(config *Pool_a) error {
	return b.put(config, uriGtm, uriPool_a)
}

func (b *BigIP) Pool_as() (*Pool_a, error) {
	var pool_a Pool_a
	err, _ := b.getForEntity(&pool_a, uriGtm, uriPool_a)

	if err != nil {
		return nil, err
	}

	return &pool_a, nil
}
