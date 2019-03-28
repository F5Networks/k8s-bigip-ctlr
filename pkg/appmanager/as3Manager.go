/*-
 * Copyright (c) 2016-2018, F5 Networks, Inc.
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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"
)

type as3Template string
type as3Declaration string

type serviceName string
type appName string
type tenantName string

type pool []Member
type tenant map[appName][]serviceName
type as3Object map[tenantName]tenant

//Rest client creation for big ip
type As3RestClient struct {
	client  *http.Client
	baseURL string
}

var BigIPUsername string
var BigIPPassword string
var BigIPURL string

// Takes an AS3 Template and perform service discovery with Kubernetes to generate AS3 Declaration
func (appMgr *Manager) processUserDefinedAS3(template string) bool {
	templateObj := as3Template(template)
	obj, ok := appMgr.getAS3ObjectFromTemplate(templateObj)

	if !ok {
		log.Errorf("Error processing template\n")
		return false
	}
	declaration := appMgr.buildAS3Declaration(obj, templateObj)
	log.Debugf("Generated AS3 Declaration: \n%v", declaration)

	appMgr.postAS3Declaration(declaration)
	return true
}

// getAS3ObjectFromTemplate gets an AS3 template as a input parameter.
// It parses AS3 template, constructs an as3Object and returns it.
func (appMgr *Manager) getAS3ObjectFromTemplate(
	template as3Template,
) (as3Object, bool) {
	var tmpl interface{}
	err := json.Unmarshal([]byte(template), &tmpl)
	if err != nil {
		log.Errorf("JSON unmarshal failed: %v\n", err)
		return nil, false
	}

	as3 := make(as3Object)
	// extract as3 declaration from template
	dclr := (tmpl.(map[string]interface{}))["declaration"]
	if dclr == nil {
		log.Error("No ADC class declaration found.")
		return nil, false
	}

	// Loop over all the tenants
	for tn, t := range dclr.(map[string]interface{}) {
		// Filter out non-json values
		if _, ok := t.(map[string]interface{}); !ok {
			continue
		}

		as3[tenantName(tn)] = make(tenant, 0)
		// Loop over all the services in a tenant
		for an, a := range t.(map[string]interface{}) {
			// Filter out non-json values
			if _, ok := a.(map[string]interface{}); !ok {
				continue
			}

			as3[tenantName(tn)][appName(an)] = []serviceName{}
			// Loop over all the json objects in an application
			for sn, v := range a.(map[string]interface{}) {
				// Filter out non-json values
				if _, ok := v.(map[string]interface{}); !ok {
					continue
				}

				// filter out empty json objects and pool objects
				if cl := getClass(v); cl == "" || cl == "Pool" {
					continue
				}
				//Update the list of services under corresponding application
				as3[tenantName(tn)][appName(an)] = append(
					as3[tenantName(tn)][appName(an)],
					serviceName(sn),
				)
			}
			if len(as3[tenantName(tn)][appName(an)]) == 0 {
				log.Debugf("No services declared for application: %s,"+
					" tenant: %s\n", an, tn)
			}
		}
		if len(as3[tenantName(tn)]) == 0 {
			log.Debugf("No applications declared for tenant: %s\n", tn)
		}
	}
	if len(as3) == 0 {
		log.Error("No tenants declared in AS3 template")
		return as3, false
	}
	return as3, true
}

func getClass(obj interface{}) string {
	cfg := obj.(map[string]interface{})
	cl, ok := cfg["class"].(string)
	if !ok {
		log.Debugf("No class attribute found")
		return ""
	}
	return cl
}

// Performs Service discovery for the given AS3 Service and returns a pool.
// Service discovery is loosely coupled with Kubernetes Service labels. A Kubernetes Service is treated as a match for
// an AS3 service, if the Kubernetes Service have the following labels and their values matches corresponding AS3
// Object.
// cis.f5.com/as3-tenant=<Tenant Name>
// cis.f5.com/as3-app=<Application Name>
// cis.f5.com/as3-service=<AS3 Service Name>
// When a match is found, returns Node's Address and Service NodePort as pool members, if Controller is running in
// NodePort mode, else by default ClusterIP Address and Port are returned.
func (appMgr *Manager) getEndpointsForAS3Service(tenant tenantName, app appName, as3Svc serviceName) pool {
	tenantKey := "cis.f5.com/as3-tenant="
	appKey := "cis.f5.com/as3-app="
	serviceKey := "cis.f5.com/as3-service="

	selector := tenantKey + string(tenant) + "," +
		appKey + string(app) + "," +
		serviceKey + string(as3Svc)

	svcListOptions := metaV1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matched the given label
	services, err := appMgr.kubeClient.CoreV1().Services(v1.NamespaceAll).List(svcListOptions)

	if err != nil {
		log.Errorf("[as3] Error getting service list. %v", err)
		return nil
	}

	var members []Member

	for _, service := range services.Items {
		if appMgr.isNodePort == false { // Controller is in ClusterIP Mode
			endpointsList, err := appMgr.kubeClient.CoreV1().Endpoints(service.Namespace).List(
				metaV1.ListOptions{
					FieldSelector: "metadata.name=" + service.Name,
				},
			)
			if err != nil {
				log.Debugf("[as3] Error getting endpoints for service %v", service.Name)
				continue
			}

			for _, endpoints := range endpointsList.Items {
				for _, subset := range endpoints.Subsets {
					for _, address := range subset.Addresses {
						member := Member{
							Address: address.IP,
							Port:    subset.Ports[0].Port,
						}
						members = append(members, member)
					}
				}
			}
		} else { // Controller is in NodePort mode.
			if service.Spec.Type == v1.ServiceTypeNodePort {
				members = appMgr.getEndpointsForNodePort(service.Spec.Ports[0].NodePort)
			} else {
				msg := fmt.Sprintf("Requested service backend '%+v' not of NodePort type", service.Name)
				log.Debug(msg)
			}
		}

		log.Debugf("[as3] Discovered members for service %v is %v", service, members)
	}

	return members
}

// Returns a pool of IP address.
func (appMgr *Manager) getFakeEndpointsForAS3Service(tenant tenantName, app appName, as3Svc serviceName) pool {
	return []Member{
		{"1.1.1.1", 80, ""},
		{"2.2.2.2", 80, ""},
		{"3.3.3.3", 80, ""},
	}
}

// Traverses through the AS3 JSON using the information passed from buildAS3Declaration,
// parses the AS3 JSON and populates it with pool members
func updatePoolMembers(tnt tenantName, app appName, svc serviceName, ips []string, port int32, templateJSON map[string]interface{}) map[string]interface{} {

	// Get the declaration object from AS3 Json
	dec := (templateJSON["declaration"]).(map[string]interface{})
	// Get the tenant object from AS3 Json
	tet := (dec[string(tnt)]).(map[string]interface{})

	// Get the poolname for the serviceName svc
	apps := (tet[string(app)].(map[string]interface{}))
	servicemain := (apps[string(svc)].(map[string]interface{}))
	poolname := (servicemain["pool"].(string))

	// Continue with the poolName and replace the as3 template with poolMembers
	toName := (tet[string(app)].(map[string]interface{}))
	pool := (toName[string(poolname)].(map[string]interface{}))
	poolmem := (((pool["members"]).([]interface{}))[0]).(map[string]interface{})

	// Replace pool member IP addresses
	poolmem["serverAddresses"] = ips
	// Replace port number
	poolmem["servicePort"] = port
	return templateJSON
}

// Takes AS3 template and AS3 Object and produce AS3 Declaration
func (appMgr *Manager) buildAS3Declaration(obj as3Object, template as3Template) as3Declaration {

	var tmp interface{}
	// unmarshall the template of type string to interface
	err := json.Unmarshal([]byte(template), &tmp)
	if nil != err {
		return ""
	}

	// convert tmp to map[string]interface{}, This conversion will help in traversing the as3 object
	templateJSON := tmp.(map[string]interface{})

	// traverse through the as3 object to fetch the list of services and get endpopints using the servicename
	log.Debugf("[as3_log] Started Parsing the AS3 Object")
	for tnt, apps := range obj {
		for app, svcs := range apps {
			for svc := range svcs {
				eps := appMgr.getEndpointsForAS3Service(tnt, app, svcs[svc])
				// Handle an empty value
				if len(eps) == 0 {
					continue
				}
				ips := make([]string, 0)
				for _, v := range eps {
					ips = append(ips, v.Address)
				}
				port := eps[0].Port
				log.Debugf("Updating AS3 Template for tenant '%s' app '%s' service '%s', ", tnt, app, svcs[svc])
				updatePoolMembers(tnt, app, svcs[svc], ips, port, templateJSON)
			}
		}
	}

	declaration, err := json.Marshal(templateJSON)
	if err != nil {
		log.Errorf("[as3_log] Issue marshalling AS3 Json")
	}
	log.Debugf("[as3_log] AS3 Template is populated with the pool members")
	log.Debugf("[as3_log] Printing AS3 Template ...")
	log.Debugf("%s", declaration)

	return as3Declaration(declaration)

}

// Takes AS3 Declaration and post it to BigIP
func (appMgr *Manager) postAS3Declaration(declaration as3Declaration) {
	log.Debugf("[as3_log] Processing AS3 POST call with AS3 Manager")
	var as3RC As3RestClient
	as3RC.baseURL = BigIPURL
	response, _ := as3RC.restCallToBigIP("POST", "/mgmt/shared/appsvcs/declare", declaration)
	log.Debugf("[as3_log] AS3 declaration POST call response %s", response)

}

// Takes AS3 Declaration, method, API route and post it to BigIP
func (as3RestClient *As3RestClient) restCallToBigIP(method string, route string, declaration as3Declaration) (string, bool) {
	log.Debugf("[as3_log] REST call with AS3 Manager")
	timeout := time.Duration(15 * time.Second)
	var body []byte
	//FIXME: tr flag is set true to disable SSL validation
	//Please remove SSL disable settings at RTW
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	as3RestClient.client = &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
	var data io.Reader
	if method == "POST" || method == "PUT" {
		var s = []byte(declaration)
		data = bytes.NewBuffer(s)
	}
	req, err := http.NewRequest(method, as3RestClient.baseURL+route, data)
	if err != nil {
		log.Errorf("[as3_log] Creating new HTTP request error: %v ", err)
		return string(body), false
	}
	req.SetBasicAuth(BigIPUsername, BigIPPassword)
	resp, err := as3RestClient.client.Do(req)
	if err != nil {
		log.Errorf("[as3_log] REST call error: %v ", err)
		return string(body), false
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("[as3_log] REST call error: %v ", err)
		return string(body), false
	}
	return string(body), true

}
