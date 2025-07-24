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

/*
AS3 uses a declarative model, meaning you provide a JSON declaration rather than a set of imperative commands. The declaration represents the configuration which AS3 is responsible for creating on a BIG-IP system. AS3 is well-defined according to the rules of JSON Schema, and declarations validate according to JSON Schema. AS3 accepts declaration updates via REST (push), reference (pull), or CLI (flat file editing).
To read more about As3 check https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/
*/
package bigip

import (
	"log"
)

type Appsvcs struct {
	Appsvcs []Appsvc01 `json:"items"`
}
type Appsvc01 struct {
	Class       string `json:"class"`
	Action      string `json:"action"`
	Persist     bool   `json:"persist"`
	Declaration struct {
		Class         string `json:"class"`
		SchemaVersion string `json:"schemaVersion"`
		ID            string `json:"id"`
		Label         string `json:"label"`
		Remark        string `json:"remark"`
		Sample01      struct {
			Class              string `json:"class"`
			DefaultRouteDomain int    `json:"defaultRouteDomain"`
			Application1       struct {
				Class       string `json:"class"`
				Template    string `json:"template"`
				ServiceMain struct {
					Class            string   `json:"class"`
					VirtualAddresses []string `json:"virtualAddresses"`
					Pool             string   `json:"pool"`
				} `json:"serviceMain"`
				WebPool struct {
					Class    string   `json:"class"`
					Monitors []string `json:"monitors"`
					Members  []struct {
						ServicePort     int      `json:"servicePort"`
						ServerAddresses []string `json:"serverAddresses"`
					} `json:"members"`
				} `json:"web_pool"`
			} `json:"Application_1"`
		} `json:"Sample_01,omitempty"`
	} `json:"declaration,omitempty"`
}

type Appsvc02 struct {
	Class       string `json:"class"`
	Action      string `json:"action"`
	Persist     bool   `json:"persist"`
	Declaration struct {
		Class         string `json:"class"`
		SchemaVersion string `json:"schemaVersion"`
		ID            string `json:"id"`
		Label         string `json:"label"`
		Remark        string `json:"remark"`
		Sample02      struct {
			Class string `json:"class"`
			A1    struct {
				Class       string `json:"class"`
				Template    string `json:"template"`
				ServiceMain struct {
					Class            string   `json:"class"`
					VirtualAddresses []string `json:"virtualAddresses"`
					Pool             string   `json:"pool"`
					ServerTLS        string   `json:"serverTLS"`
				} `json:"serviceMain"`
				WebPool struct {
					Class             string   `json:"class"`
					LoadBalancingMode string   `json:"loadBalancingMode"`
					Monitors          []string `json:"monitors"`
					Members           []struct {
						ServicePort     int      `json:"servicePort"`
						ServerAddresses []string `json:"serverAddresses"`
					} `json:"members"`
				} `json:"web_pool"`
				Webtls struct {
					Class        string `json:"class"`
					Certificates []struct {
						Certificate string `json:"certificate"`
					} `json:"certificates"`
				} `json:"webtls"`
				Webcert struct {
					Class       string `json:"class"`
					Remark      string `json:"remark"`
					Certificate string `json:"certificate"`
					PrivateKey  string `json:"privateKey"`
					Passphrase  struct {
						Ciphertext string `json:"ciphertext"`
						Protected  string `json:"protected"`
					} `json:"passphrase"`
				} `json:"webcert"`
			} `json:"A1"`
		} `json:"Sample_02"`
	} `json:"declaration"`
}

const (
	uriSam01 = "Sample_01"
	uriSam02 = "Sample_02"
)

// Appsvcss returns a list of appsvcs
func (b *BigIP) Appsvc01() (*Appsvc01, error) {
	var appsvc01 Appsvc01
	err, _ := b.getForEntity(uriSam01, uriSha, uriAppsvcs, uriDecl)
	log.Printf("i am here in sdk %+v  ", appsvc01)
	if err != nil {
		return nil, err
	}

	return &appsvc01, nil
}
func (b *BigIP) Appsvc02() (*Appsvc02, error) {
	var appsvc02 Appsvc02
	err, _ := b.getForEntity(uriSam02, uriSha, uriAppsvcs, uriDecl)
	log.Printf("i am here in sdk %+v  ", appsvc02)
	if err != nil {
		return nil, err
	}

	return &appsvc02, nil
}

// CreateAppsvcs creates a new iAppsvcs on the system.
func (b *BigIP) CreateAppsvc01(p *Appsvc01) error {
	log.Printf("++++++ Here is what terraform is sending to bigip ................ : %+v ", p)
	err := b.post(p, uriMgmt, uriSha, uriAppsvcs, uriDecl)
	if err != nil {
		log.Println(" API call not successfull  ", err)
	}
	return nil
}
func (b *BigIP) CreateAppsvc02(p *Appsvc02) error {
	log.Printf("++++++ Here is what terraform is sending to bigip ................ : %+v ", p)
	err := b.post(p, uriMgmt, uriSha, uriAppsvcs, uriDecl)
	if err != nil {
		log.Println(" API call not successfull  ", err)
	}
	return nil
}
func (b *BigIP) DeleteAppsvc01() error {
	return b.delete(uriMgmt, uriSha, uriAppsvcs, uriDecl, uriSam01)
}
func (b *BigIP) DeleteAppsvc02() error {
	return b.delete(uriMgmt, uriSha, uriAppsvcs, uriDecl, uriSam02)
}

func (b *BigIP) ModifyAppsvc01(p *Appsvc01) error {
	log.Printf("++++++ Here is what terraform is sending to bigip ................ : %+v ", p)
	err := b.patch(p, uriMgmt, uriSha, uriAppsvcs, uriDecl)
	log.Println("value of p in modify +++++++++++++++", p)
	if err != nil {
		log.Println(" API call not successfull  ", err)
	}
	return nil
}
func (b *BigIP) ModifyAppsvc02(p *Appsvc02) error {
	log.Printf("++++++ Here is what terraform is sending to bigip ................ : %+v ", p)
	err := b.patch(p, uriMgmt, uriSha, uriAppsvcs, uriDecl)
	if err != nil {
		log.Println(" API call not successfull  ", err)
	}
	return nil
}
