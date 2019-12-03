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
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
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

	// Return empty string if the Merged JSON Data fails the Marshall test
	mergedJsonData, err := json.Marshal(mergeRecursive(srcJsonObj, dstJsonObj))
	if err != nil {
		log.Errorf("[AS3] CIS failed to merge JSON Data !!!: %v", err)
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
