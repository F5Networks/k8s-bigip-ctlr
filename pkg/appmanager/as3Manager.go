package appmanager

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
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
	Client  *http.Client
	baseURL string
}

// Takes an AS3 Template and perform service discovery with Kubernetes to generate AS3 Declaration
func (appMgr *Manager) processUserDefinedAS3(template as3Template) {
	// TODO: Implement Me

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
	// extract as3 decleration from template
	dclr := (tmpl.(map[string]interface{}))["decleration"]

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

// Story 3
// Discover Endpoints for an application. Returns a pool
func (appMgr *Manager) getEndpointsForAS3Service(tenant tenantName, app appName, as3Svc serviceName) pool {
	return pool{}
}

// Returns a pool of IP address.
func (appMgr *Manager) getFakeEndpointsForAS3Service(tenant tenantName, app appName, as3Svc serviceName) pool {
	return []Member{
		{"1.1.1.1", 80, ""},
		{"2.2.2.2", 80, ""},
		{"3.3.3.3", 80, ""},
	}
}

// Story 4
// Takes AS3 template and AS3 Object and produce AS3 Declaration
func buildAS3Declaration(obj as3Object, template as3Template) as3Declaration {
	decalaration := ""
	return as3Declaration(decalaration)
}

//Story 5
// Takes AS3 Declaration and posting it to BigIP
func (appMgr *Manager) postAS3Declaration(declaration as3Declaration) {
	log.Debugf("[as3_log] Processing AS3 POST call with AS3 Manager")
	var as3RC As3RestClient
	as3RC.baseURL = "https://10.145.67.90"
	_, status := as3RC.restCallToBigIP("POST", "/mgmt/shared/appsvcs/declare", declaration)
	if status {
		log.Infof("[as3_log] AS3 declaration POST to BIG-IP success")
	}

}

// Takes AS3 Declaration and REST method and post it to BigIP
func (as3RestClient *As3RestClient) restCallToBigIP(method string, route string, declaration as3Declaration) (string, bool) {
	log.Debugf("[as3_log] REST call with AS3 Manager")
	timeout := time.Duration(5 * time.Second)
	var body []byte
	//tr flag is set true to disable SSL validation
	//Please remove SSL disable settings at RTW
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	as3RestClient.Client = &http.Client{
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
		log.Errorf("[as3_log] Creating new HTTP request error: %s ", err)
		return string(body), false
	}
	req.SetBasicAuth("admin", "admin")
	resp, err := as3RestClient.Client.Do(req)
	if err != nil {
		log.Errorf("[as3_log] REST call error: %s ", err)
		return string(body), false
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("[as3_log] REST call error: %s ", err)
		return string(body), false
	}
	log.Infof("[as3_log] AS3 REST call response: %s ", string(body))
	defer resp.Body.Close()
	return string(body), true

}
