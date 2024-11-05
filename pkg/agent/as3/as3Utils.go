/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
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
package as3

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

func ValidateJSONStringAndFetchObject(jsonData string, jsonObj *map[string]interface{}) error {

	if jsonData == "" {
		log.Errorf("[AS3] Empty JSON string passed as an input !!!")
		return fmt.Errorf("Empty Input JSON String")
	}

	if err := json.Unmarshal([]byte(jsonData), jsonObj); err != nil {
		log.Errorf("[AS3] Failed in JSON Un-Marshal test !!!: %v", err)
		return err
	}

	if data, err := json.Marshal(*jsonObj); err != nil && string(data) != "" {
		log.Errorf("[AS3] Failed in JSON Marshal test  !!!: %v", err)
		return err
	}

	return nil
}

func ValidateAndOverrideAS3JsonData(srcJsonData string, dstJsonData string) string {

	var srcJsonObj map[string]interface{}
	if err := ValidateJSONStringAndFetchObject(srcJsonData, &srcJsonObj); err != nil {
		log.Errorf("[AS3] JSON Validation error on source JSON string !!!")
		return ""
	}

	var dstJsonObj map[string]interface{}
	if err := ValidateJSONStringAndFetchObject(dstJsonData, &dstJsonObj); err != nil {
		log.Errorf("[AS3] JSON Validation error on destination JSON string !!!")
		return ""
	}

	// Fetch AS3 declarations Objects to filter
	// out tenants in srcJsonObj from dstJsonObj
	dstDeclr := dstJsonObj["declaration"]
	srcDeclr := srcJsonObj["declaration"]
	if srcDeclr == nil {
		log.Errorf("[AS3] Source JSON is not a valid AS3 declaration !!!")
		return ""
	}

	// Discard all tenants from source AS3 declaration that are not available in CIS.
	// For Example: Tenants that are not available in unified AS3 declaration.
	for tenantKey, _ := range srcDeclr.(map[string]interface{}) {
		// If a tenant in source json declaration not available in
		// destination, then simply delete that tenant from srcJsonObj
		if dstDeclr.(map[string]interface{})[tenantKey] == nil {
			delete(srcDeclr.(map[string]interface{}), tenantKey)
		}
	}

	// Return empty string if the Merged JSON config fails the Marshall test
	mergedJsonData, err := json.Marshal(mergeRecursive(srcJsonObj, dstJsonObj))
	if err != nil {
		log.Errorf("[AS3] CIS failed to merge JSON config !!!: %v", err)
		return ""
	}
	return string(mergedJsonData)
}

func mergeRecursive(srcJsonObj, dstJsonObj interface{}) interface{} {
	//In this algorithm, preferring srcJsonObj overriding on dstJsonObj
	switch srcJsonObj := srcJsonObj.(type) {
	case map[string]interface{}:
		// If any member for corresponding dstJsonObj not present
		// then simply consider member of the src object
		dstJsonObj, ok := dstJsonObj.(map[string]interface{})
		if !ok {
			return srcJsonObj
		}

		// If corresponding member of dstJsonObj present, then
		// in this case the keys from both objects are included and
		// only their values are merged recursively
		for dstKey, dstVal := range dstJsonObj {
			if srcKey, ok := srcJsonObj[dstKey]; ok {
				srcJsonObj[dstKey] = mergeRecursive(srcKey, dstVal)
			} else {
				srcJsonObj[dstKey] = dstVal
			}
		}
	case nil:
		// If a member of srcJsonObj is not present and its corresponding dstJsonObj
		// present, then simply consider member of the dstJsonObj, in which case
		// this below code will just merge "nil" and "map[string]interface{...}" to
		// "map[string]interface{...}"
		dstJsonObj, ok := dstJsonObj.(map[string]interface{})
		if ok {
			return dstJsonObj
		}
	}
	return srcJsonObj
}

func DeepEqualJSON(decl1, decl2 as3Declaration) bool {
	if decl1 == "" && decl2 == "" {
		return true
	}
	var o1, o2 interface{}

	err := json.Unmarshal([]byte(decl1), &o1)
	if err != nil {
		return false
	}

	err = json.Unmarshal([]byte(decl2), &o2)
	if err != nil {
		return false
	}

	return reflect.DeepEqual(o1, o2)
}

func ExtractVirtualAddressAndPort(str string) (string, int) {
	destination := strings.Split(str, "/")
	// Handle CIDR if specified
	if len(destination) >= 2 {
		matched, _ := regexp.MatchString(`(^\d+[:.]\d+$)|(^\d+%\d+[:.]\d+$)`, destination[len(destination)-1])
		if matched {
			destination[len(destination)-1] = destination[len(destination)-2] + "/" + destination[len(destination)-1]
		}
	}
	// split separator is in accordance with SetVirtualAddress function - ipv4/6 format
	ipPort := strings.Split(destination[len(destination)-1], ":")
	if len(ipPort) != 2 {
		ipPort = strings.Split(destination[len(destination)-1], ".")
	}
	// verify that ip address and port exists else log error.
	if len(ipPort) == 2 {
		port, _ := strconv.Atoi(ipPort[1])
		return ipPort[0], port
	} else {
		log.Error("[AS3] Invalid Virtual Server Destination IP address/Port.")
		return "", 0
	}

}

func getTenants(decl as3Declaration, includeEmptyTenant bool) []string {

	var tmpl interface{}
	if decl != "" {
		err := json.Unmarshal([]byte(decl), &tmpl)
		if err != nil {
			log.Errorf("[AS3] JSON unmarshal failed: %v  %v", err, decl)
			return nil
		}
	} else {
		return nil
	}
	// extract as3 declaration from template
	dclr := (tmpl.(map[string]interface{}))["declaration"]
	if dclr == nil {
		log.Error("[AS3] No ADC class declaration found.")
		return nil
	}

	tenants := []string{}
	// Loop over all the tenants
	for tn, t := range dclr.(map[string]interface{}) {
		// Filter out non-json values
		if _, ok := t.(map[string]interface{}); !ok {
			continue
		}

		// Skip Maps that are not tenants
		tnt := t.(map[string]interface{})
		if tnt["class"] != "Tenant" {
			continue
		}
		//To delete a parttion we should not consider previously deleted partitions
		if !includeEmptyTenant && len(tnt) < 2 {
			continue
		}
		tenants = append(tenants, tn)
	}

	return tenants
}

// getAS3ObjectFromTemplate gets an AS3 template as a input parameter.
// It parses AS3 template, constructs an as3Object and returns it.
func getAS3ObjectFromTemplate(
	template as3Template,
) (as3Object, bool) {
	var tmpl map[string]interface{}
	err := json.Unmarshal([]byte(template), &tmpl)
	if err != nil {
		log.Errorf("[AS3] JSON unmarshal failed: %v  %v", err, template)
		return nil, false
	}

	as3 := make(as3Object)

	// extract as3 declaration from template
	dclr := tmpl["declaration"]
	if dclr == nil || !assertToBe("map", dclr) {
		log.Error("[AS3] No ADC class declaration found or with wrong content.")
		return nil, false
	}

	// Loop over all the tenants
	for tn, t := range dclr.(map[string]interface{}) {
		// Filter out non-json values
		if !assertToBe("map", t) {
			continue
		}

		// Skip Maps that are not tenants
		tnt := t.(map[string]interface{})
		if tnt["class"] != "Tenant" {
			continue
		}

		as3[tenantName(tn)] = make(tenant, 0)
		// Loop over all the services in a tenant
		for an, a := range t.(map[string]interface{}) {
			// Filter out non-json values
			if !assertToBe("map", a) {
				continue
			}

			as3[tenantName(tn)][appName(an)] = []poolName{}
			// Loop over all the json objects in an application
			for pn, v := range a.(map[string]interface{}) {
				// Filter out non-json values
				if !assertToBe("map", v) {
					continue
				}

				// filter out non-pool objects
				if cl := getClass(v); cl != "Pool" {
					continue
				}

				// Skip if list of serverAddress is not empty
				mems := (v.(map[string]interface{}))["members"]
				if mems == nil {
					continue
				}

				if !assertToBe("slice", mems) || len(mems.([]interface{})) == 0 {
					continue
				}

				if !assertToBe("map", (mems.([]interface{}))[0]) {
					continue
				}
				mem0 := (mems.([]interface{}))[0].(map[string]interface{})
				srvAddrs := mem0["serverAddresses"]
				if srvAddrs == nil || len(srvAddrs.([]interface{})) != 0 {
					continue
				}

				//Update the list of pools under corresponding application
				as3[tenantName(tn)][appName(an)] = append(
					as3[tenantName(tn)][appName(an)],
					poolName(pn),
				)
			}
			if len(as3[tenantName(tn)][appName(an)]) == 0 {
				log.Debugf("[AS3] No pools declared for application: %s,"+
					" tenant: %s\n", an, tn)
			}
		}
		//TODO: Fix this post 2.1
		// if len(as3[tenantName(tn)]) == 0 {
		// 	log.Debugf("[AS3] No applications declared for tenant: %s\n", tn)
		// }
	}
	if len(as3) == 0 {
		log.Error("[AS3] No tenants declared in AS3 template")
		return as3, false
	}
	return as3, true
}

func getClass(obj interface{}) string {
	cfg, ok := obj.(map[string]interface{})
	if !ok {
		// If not a json object it doesn't have class attribute
		return ""
	}
	cl, ok := cfg["class"]
	if !ok {
		log.Debugf("No class attribute found")
		return ""
	}
	return cl.(string)
}

func assertToBe(kind string, obj interface{}) bool {
	if obj == nil {
		return false
	}
	return (reflect.TypeOf(obj).Kind().String() == kind)
}

// Build Control class with userAgent info
func (c as3Control) initDefault(userAgent string) {
	c["class"] = "Controls"
	c["userAgent"] = userAgent
}

func (adc as3ADC) initTenant(partition string, defaultRouteDomain int) {
	tnt := as3Tenant{}
	tnt.initDefault(defaultRouteDomain)
	adc[partition] = tnt
}

func (adc as3ADC) getAS3Partition(partition string) as3Tenant {
	if adc[partition] == nil {
		return nil
	}
	return adc[partition].(as3Tenant)
}

func (adc as3ADC) getAS3SharedApp(partition string) as3Application {
	if tnt := adc.getAS3Partition(partition); tnt != nil {
		if app := tnt.getAS3SharedApp(); app != nil {
			return app
		}
	}
	return nil
}

func (t as3Tenant) initDefault(defaultRouteDomain int) {
	app := as3Application{}
	app.initDefault()
	t[as3class] = as3tenant
	t[as3SharedApplication] = app
	t[as3defaultRouteDomain] = defaultRouteDomain
}

func (t as3Tenant) getAS3SharedApp() as3Application {
	if t[as3SharedApplication] != nil {
		return t[as3SharedApplication].(as3Application)
	}
	return nil
}

func (a as3Application) initDefault() {
	a[as3class] = as3application
	a[as3template] = as3shared
}

// Replacing "-" with "_" for given string
// also handling the IP addr to string as per AS3 for Ingress Resource.
func as3FormattedString(str string, resourceType string) string {
	var formattedString string
	switch resourceType {
	case ResourceTypeIngress:
		formattedString = strings.Replace(str, ".", "_", -1)
		formattedString = strings.Replace(formattedString, "+", "_", -1)
		formattedString = strings.Replace(formattedString, "-", "_", -1)
	default:
		formattedString = strings.Replace(str, "-", "_", -1)
		formattedString = strings.ReplaceAll(formattedString, "openshift_route", "osr")
	}
	//Reducing object name length by giving a shortened form of a word.
	formattedString = strings.ReplaceAll(formattedString, "client_ssl", "cssl")
	formattedString = strings.ReplaceAll(formattedString, "server_ssl", "sssl")
	return formattedString
}
