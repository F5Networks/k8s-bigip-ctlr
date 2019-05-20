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
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"github.com/xeipuuv/gojsonschema"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultAS3ConfigMapLabel = "f5type in (virtual-server), as3 in (true)"
)

type as3Template string
type as3Declaration string

type poolName string
type appName string
type tenantName string

type pool []Member
type tenant map[appName][]poolName
type as3Object map[tenantName]tenant

//Rest client creation for big ip
type As3RestClient struct {
	client      *http.Client
	baseURL     string
	oldChecksum string
	newChecksum string
}

var BigIPUsername string
var BigIPPassword string
var BigIPURL string
var as3RC As3RestClient
var certificates string

var buffer map[Member]struct{}

// Takes an AS3 Template and perform service discovery with Kubernetes to generate AS3 Declaration
func (appMgr *Manager) processUserDefinedAS3(template string) bool {

	// Validate AS3 Template
	if appMgr.as3Validation == true {
		log.Debugf("[as3] Start validating template")

		if ok := appMgr.validateAS3Template(template); !ok {
			log.Errorf("[as3] Error validating template \n")
			return false
		}
	}

	templateObj := as3Template(template)
	obj, ok := appMgr.getAS3ObjectFromTemplate(templateObj)

	if !ok {
		log.Errorf("[as3] Error processing template\n")
		return false
	}

	buffer = make(map[Member]struct{}, 0)

	declaration := appMgr.buildAS3Declaration(obj, templateObj)
	log.Debugf("Generated AS3 Declaration: \n%v", declaration)

	appMgr.as3Members = buffer
	appMgr.postAS3Declaration(declaration)

	return true
}

// Validates the AS3 Template
func (appMgr *Manager) validateAS3Template(template string) bool {

	var schema = appMgr.schemaLocal + "as3-schema-3.10-cis.json"

	// Load Both the AS3 Schema and AS3 Template
	schemaLoader := gojsonschema.NewReferenceLoader(schema)
	documentLoader := gojsonschema.NewStringLoader(template)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		log.Errorf("%s", err)
		return false
	}

	if !result.Valid() {
		log.Errorf("AS3 Template is not valid. see errors :\n")
		for _, desc := range result.Errors() {
			log.Errorf("- %s\n", desc)
		}
		return false
	}

	log.Debugf("AS3 Template is Validated Successfully \n")
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

			as3[tenantName(tn)][appName(an)] = []poolName{}
			// Loop over all the json objects in an application
			for pn, v := range a.(map[string]interface{}) {
				// Filter out non-json values
				if _, ok := v.(map[string]interface{}); !ok {
					continue
				}

				// filter out non-pool objects
				if cl := getClass(v); cl != "Pool" {
					continue
				}

				// Skip if list of serverAddress is not empty
				mems := (v.(map[string]interface{}))["members"]
				srvAddrs := ((mems.([]interface{}))[0].(map[string]interface{}))["serverAddresses"]
				if len(srvAddrs.([]interface{})) != 0 {
					continue
				}

				//Update the list of pools under corresponding application
				as3[tenantName(tn)][appName(an)] = append(
					as3[tenantName(tn)][appName(an)],
					poolName(pn),
				)
			}
			if len(as3[tenantName(tn)][appName(an)]) == 0 {
				log.Debugf("No pools declared for application: %s,"+
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

// Performs Service discovery for the given AS3 Pool and returns a pool.
// Service discovery is loosely coupled with Kubernetes Service labels. A Kubernetes Service is treated as a match for
// an AS3 Pool, if the Kubernetes Service have the following labels and their values matches corresponding AS3
// Object.
// cis.f5.com/as3-tenant=<Tenant Name>
// cis.f5.com/as3-app=<Application Name>
// cis.f5.com/as3-pool=<Pool Name>
// When controller is in NodePort mode, returns a pool of Node IP Address and NodePort.
// When controller is in ClusterIP mode, returns a pool of Cluster IP Address and Service Port. Also, it accumulates
// members for static ARP entry population.
func (appMgr *Manager) getEndpointsForPool(tenant tenantName, app appName, pool poolName) pool {
	log.Debugf("[as3_log] Discovering endpoints for pool: [%v -> %v -> %v]", tenant, app, pool)

	tenantKey := "cis.f5.com/as3-tenant="
	appKey := "cis.f5.com/as3-app="
	poolKey := "cis.f5.com/as3-pool="

	selector := tenantKey + string(tenant) + "," +
		appKey + string(app) + "," +
		poolKey + string(pool)

	svcListOptions := metaV1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matches the given label
	services, err := appMgr.kubeClient.CoreV1().Services(v1.NamespaceAll).List(svcListOptions)

	if err != nil {
		log.Errorf("[as3] Error getting service list. %v", err)
		return nil
	}

	var members []Member

	if len(services.Items) > 1 {
		svcNames := ""

		for _, service := range services.Items {
			svcNames += fmt.Sprintf("Service: %v, Namespace: %v \n", service.Name, service.Namespace)
		}

		log.Errorf("[as3] Multiple Services are tagged for this pool. Ignoring all endpoints.\n%v", svcNames)
		return members
	}

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

						// Update master AS3 Member list
						buffer[member] = struct{}{}
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
func (appMgr *Manager) getFakeEndpointsForPool(tenant tenantName, app appName, pool poolName) pool {
	return []Member{
		{"1.1.1.1", 80, ""},
		{"2.2.2.2", 80, ""},
		{"3.3.3.3", 80, ""},
	}
}

// Traverses through the AS3 JSON using the information passed from buildAS3Declaration,
// parses the AS3 JSON and populates it with pool members
func updatePoolMembers(tnt tenantName, app appName, pn poolName, ips []string, port int32, templateJSON map[string]interface{}) map[string]interface{} {

	// Get the declaration object from AS3 Json
	dec := (templateJSON["declaration"]).(map[string]interface{})
	// Get the tenant object from AS3 Json
	tet := (dec[string(tnt)]).(map[string]interface{})

	// Continue with the poolName and replace the as3 template with poolMembers
	toName := (tet[string(app)].(map[string]interface{}))
	pool := (toName[string(pn)].(map[string]interface{}))
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
		for app, pools := range apps {
			for _, pn := range pools {
				eps := appMgr.getEndpointsForPool(tnt, app, pn)
				// Handle an empty value
				if len(eps) == 0 {
					continue
				}
				ips := make([]string, 0)
				for _, v := range eps {
					ips = append(ips, v.Address)
				}
				port := eps[0].Port
				log.Debugf("Updating AS3 Template for tenant '%s' app '%s' pool '%s', ", tnt, app, pn)
				updatePoolMembers(tnt, app, pn, ips, port, templateJSON)
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
	as3RC.baseURL = BigIPURL
	as3RC.restCallToBigIP("POST", "/mgmt/shared/appsvcs/declare", declaration, appMgr.sslInsecure)

}

// Takes AS3 Declaration, method, API route and post it to BigIP
func (as3RestClient *As3RestClient) restCallToBigIP(method string, route string, declaration as3Declaration, sslInsecure bool) (string, bool) {
	log.Debugf("[as3_log] REST call with AS3 Manager")
	hash := md5.New()
	io.WriteString(hash, string(declaration))
	as3RestClient.newChecksum = string(hash.Sum(nil))
	timeout := time.Duration(60 * time.Second)
	var body []byte
	if as3RestClient.oldChecksum == as3RestClient.newChecksum {
		log.Debugf("[as3_log] No change in declaration.")
		return string(body), true
	}

	//Certificate setting
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Get the cert
	certs := []byte(certificates)

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debug("[as3_log] No certs appended, using system certs only")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: sslInsecure,
			RootCAs:            rootCAs,
		},
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
	if resp.StatusCode == 200 {
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("[as3_log] REST call response error: %v ", err)
			return string(body), false
		}
		var response map[string]interface{}
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Errorf("[as3_log] Response body unmarshal failed: %v\n", err)
			return string(body), false
		}
		//traverse all response results
		results := (response["results"]).([]interface{})
		for _, value := range results {
			v := value.(map[string]interface{})
			//log result with code, tenant and message
			log.Debugf("[as3_log] Response from Big-IP")
			log.Debugf("[as3_log] code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
		}
		as3RestClient.oldChecksum = as3RestClient.newChecksum
		return string(body), true
	} else {
		//Other then 200 status code
		log.Errorf("[as3_log] Big-IP Response error %v", resp)
		return string(body), false
	}

}

// Read certificate from configmap
func (appMgr *Manager) getCertFromConfigMap(cfgmap string) {

	certificates = ""
	namespaceCfgmapSlice := strings.Split(cfgmap, "/")
	if len(namespaceCfgmapSlice) < 2 {
		log.Debugf("[as3_log] Invalid trusted-certs-cfgmap option provided.")
	} else {
		certs := ""
		namespace := namespaceCfgmapSlice[0]
		cfgmapName := namespaceCfgmapSlice[1]
		cm, err := appMgr.kubeClient.CoreV1().ConfigMaps(namespace).Get(cfgmapName, metaV1.GetOptions{})
		if err != nil {
			log.Debugf("[as3_log] Reading certificate from configmap error: %v", err)
		} else {
			//Fetching all certificates from configmap
			for _, v := range cm.Data {
				certs = certs + v + "\n"
			}
			certificates = certs
		}
	}
}

// SetupAS3Informers returns an appInformer that includes the following set of informers.
// CfgMapInformer and SvcInformer are label based and endptInformer is not label based.
// These informers are event based informer and do not poll on the resources.
func (appMgr *Manager) SetupAS3Informers() error {
	// resyncPeriod is zero to avoid repolling
	var resyncPeriod time.Duration
	// namespace is Empty to create watchers for all namespaces
	namespace := v1.NamespaceAll

	log.Debug("[as3] Stated creating AS3 Informers")
	cfgMapSelector, err := labels.Parse(defaultAS3ConfigMapLabel)
	if err != nil {
		return fmt.Errorf("Failed to parse AS3 ConfigMap Label Selector string: %v", err)
	}

	appMgr.as3Informer = &appInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
		cfgMapInformer: cache.NewSharedIndexInformer(
			newListWatchWithLabelSelector(
				appMgr.restClientv1,
				"configmaps",
				namespace,
				cfgMapSelector,
			),
			&v1.ConfigMap{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}

	appMgr.as3Informer.cfgMapInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueConfigMap(obj) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueConfigMap(cur) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueConfigMap(obj) },
		},
		resyncPeriod,
	)

	return nil
}
