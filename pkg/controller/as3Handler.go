package controller

import (
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net/http"
	"strconv"
	"strings"
)

// write a function for NewAS3Handler, rewrite

type ApiTypeHandlerInterface interface {
	getAPIURL(params []string) string
	getTaskIdURL(taskId string) string
	UpdateApiVersion(version string, build string, schemaVersion string)
	getVersionURL() string
	getVersionsFromResponse(httpResp *http.Response, responseMap map[string]interface{}) (string, string, string, error)
	removeDeletedTenantsForBigIP(Config map[string]interface{}, rsConfig *ResourceConfigRequest, cisLabel, partition string)
	handleResponseStatusOK(responseMap map[string]interface{}) bool
	handleMultiStatus(responseMap map[string]interface{}, id int) bool
	handleResponseAccepted(responseMap map[string]interface{}) bool
	handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, id int) bool
	handleResponseStatusNotFound(responseMap map[string]interface{}, id int) bool
	handleResponseStatusUnAuthorized(responseMap map[string]interface{}, id int) bool
	handleResponseOthers(responseMap map[string]interface{}, id int) bool
	getRegKeyFromResponse(httpResp *http.Response, responseMap map[string]interface{}) (string, error)
	getVersionsFromBigIPResponse(httpResp *http.Response, responseMap map[string]interface{}) error
	getTenantConfigStatus(id string, httpResp *http.Response, responseMap map[string]interface{})
	getDeclarationFromBigIPResponse(httpResp *http.Response, responseMap map[string]interface{}) (map[string]interface{}, error)
	getBigipRegKeyURL() string
	logResponse(responseMap map[string]interface{})
	logRequest(cfg string)
	createAPIDeclaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration
	getApiHandler() *AS3Handler
	getResourceConfigRequest(config agentPostConfig) (*ResourceConfigRequest, error)
	//createLTMConfigADC(config ResourceConfigRequest) as3ADC
	//createGTMConfigADC(config ResourceConfigRequest, adc as3ADC) as3ADC
}

func NewAS3Handler(params AgentParams, postManager *PostManager) *AS3Handler {
	handler := &AS3Handler{
		AS3Config:   make(map[string]interface{}),
		AS3Parser:   NewAS3Parser(params),
		PostManager: postManager,
		LogResponse: params.PostParams.LogResponse,
		LogRequest:  params.PostParams.LogRequest,
	}

	return handler
}

func (am *AS3Handler) getVersionURL() string {
	apiURL := am.BIGIPURL + "/mgmt/shared/appsvcs/info"
	return apiURL
}

func (am *AS3Handler) getAPIURL(tenants []string) string {
	apiURL := am.BIGIPURL + "/mgmt/shared/appsvcs/declare/" + strings.Join(tenants, ",")
	return apiURL
}

func (am *AS3Handler) getTaskIdURL(taskId string) string {
	apiURL := am.BIGIPURL + "/mgmt/shared/appsvcs/task/" + taskId
	return apiURL
}

func (am *AS3Handler) getApiHandler() *AS3Handler {
	return am
}

func (am *AS3Handler) logRequest(cfg string) {
	var as3Config map[string]interface{}
	err := json.Unmarshal([]byte(cfg), &as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Request body unmarshal failed: %v\n", am.postManagerPrefix, err)
	}
	adc := as3Config["declaration"].(map[string]interface{})
	for _, value := range adc {
		if tenantMap, ok := value.(map[string]interface{}); ok {
			for _, value2 := range tenantMap {
				if appMap, ok := value2.(map[string]interface{}); ok {
					for _, obj := range appMap {
						if crt, ok := obj.(map[string]interface{}); ok {
							if crt["class"] == "Certificate" {
								crt["certificate"] = ""
								crt["privateKey"] = ""
								crt["chainCA"] = ""
							}
						}
					}
				}
			}
		}
	}
	decl, err := json.Marshal(as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Unified declaration error: %v\n", am.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v Unified declaration: %v\n", am.postManagerPrefix, as3Declaration(decl))
}

func (am *AS3Handler) logResponse(responseMap map[string]interface{}) {
	// removing the certificates/privateKey from response log
	if declaration, ok := (responseMap["declaration"]).([]interface{}); ok {
		for _, value := range declaration {
			if tenantMap, ok := value.(map[string]interface{}); ok {
				for _, value2 := range tenantMap {
					if appMap, ok := value2.(map[string]interface{}); ok {
						for _, obj := range appMap {
							if crt, ok := obj.(map[string]interface{}); ok {
								if crt["class"] == "Certificate" {
									crt["certificate"] = ""
									crt["privateKey"] = ""
									crt["chainCA"] = ""
								}
							}
						}
					}
				}
			}
		}
		decl, err := json.Marshal(declaration)
		if err != nil {
			log.Errorf("[AS3]%v error while reading declaration from AS3 response: %v\n", am.postManagerPrefix, err)
			return
		}
		responseMap["declaration"] = as3Declaration(decl)
	}
	log.Debugf("[AS3]%v Raw response from Big-IP: %v ", am.postManagerPrefix, responseMap)
}

func (am *AS3Handler) createAPIDeclaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration {
	var as3Config map[string]interface{}

	baseAS3ConfigTemplate := fmt.Sprintf(baseAS3Config, am.AS3VersionInfo.as3Version, am.AS3VersionInfo.as3Release, am.AS3VersionInfo.as3SchemaVersion)
	_ = json.Unmarshal([]byte(baseAS3ConfigTemplate), &as3Config)

	adc := as3Config["declaration"].(map[string]interface{})

	controlObj := make(map[string]interface{})
	controlObj["class"] = "Controls"
	controlObj["userAgent"] = userAgent
	adc["controls"] = controlObj

	for tenant, decl := range tenantDeclMap {
		adc[tenant] = decl
	}
	decl, err := json.Marshal(as3Config)
	if err != nil {
		log.Debugf("[AS3] Unified declaration: %v\n", err)
	}

	return as3Declaration(decl)
}

func (am *AS3Handler) getVersionsFromResponse(httpResp *http.Response, responseMap map[string]interface{}) (string, string, string, error) {
	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["version"] != nil {
			if version, ok1 := responseMap["version"].(string); ok1 {
				release, ok2 := responseMap["release"].(string)
				schemaVersion, ok3 := responseMap["schemaCurrent"].(string)
				if ok1 && ok2 && ok3 {
					return version, release, schemaVersion, nil
				}
			}
			return "", "", "", fmt.Errorf("Invalid response format from version check")
		}
		return "", "", "", fmt.Errorf("Version information not found in response")

	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return "", "", "", fmt.Errorf("RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		}
		return "", "", "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)

	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if msg, ok := responseMap["message"].(string); ok {
					return "", "", "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, msg)
				}
				return "", "", "", fmt.Errorf("authentication failed,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		}
		return "", "", "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)

	default:
		return "", "", "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
	}
}

func (am *AS3Handler) getDeclarationFromBigIPResponse(httpResp *http.Response, responseMap map[string]interface{}) (map[string]interface{}, error) {
	// Check response status code
	switch httpResp.StatusCode {
	case http.StatusOK:
		return responseMap, nil
	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return nil, fmt.Errorf("%s RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", am.apiType, httpResp.StatusCode)
			}
		} else {
			am.logResponse(responseMap)
		}
	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if _, ok := responseMap["message"].(string); ok {
					return nil, fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, responseMap["message"])
				} else {
					return nil, fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v", httpResp.StatusCode)
				}
			}
		} else {
			am.logResponse(responseMap)
		}
	}
	return nil, fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

func (am *AS3Handler) getVersionsFromBigIPResponse(httpResp *http.Response, responseMap map[string]interface{}) error {
	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["version"] != nil {
			return nil
		}
		return fmt.Errorf("Invalid response format from AS3 version check")

	case http.StatusNotFound:
		return fmt.Errorf("AS3 RPM is not installed on BIGIP")

	case http.StatusUnauthorized:
		return fmt.Errorf("Authentication failed for AS3 version check")

	default:
		return fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
	}
}

func (am *AS3Handler) getTenantConfigStatus(id string, httpResp *http.Response, responseMap map[string]interface{}) {
	var unknownResponse bool
	if httpResp.StatusCode == http.StatusOK {
		results, ok1 := (responseMap["results"]).([]interface{})
		declaration, ok2 := (responseMap["declaration"]).(interface{}).(map[string]interface{})
		if ok1 && ok2 {
			for _, value := range results {
				if v, ok := value.(map[string]interface{}); ok {
					code, ok1 := v["code"].(float64)
					tenant, ok2 := v["tenant"].(string)
					msg, ok3 := v["message"]
					if ok1 && ok2 && ok3 {
						if message, ok := msg.(string); ok && message == "in progress" {
							return
						}
						// reset task id, so that any unknownResponse failed will go to post call in the next retry
						am.PostManager.updateTenantResponseCode(int(code), "", tenant, updateTenantDeletion(tenant, declaration), "")
						if _, ok := v["response"]; ok {
							log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", am.postManagerPrefix, v["code"], v["tenant"], v["message"], v["response"])
						} else {
							log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", am.postManagerPrefix, v["code"], v["tenant"], v["message"])
						}
						intId, err := strconv.Atoi(id)
						if err == nil {
							log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(intId), am.postManagerPrefix)
						}
					} else {
						unknownResponse = true
					}
				} else {
					unknownResponse = true
				}
			}
		} else {
			unknownResponse = true
		}
	} else if httpResp.StatusCode != http.StatusServiceUnavailable {
		// reset task id, so that any failed tenants will go to post call in the next retry
		am.PostManager.updateTenantResponseCode(httpResp.StatusCode, "", "", false, "")
	}
	if !am.LogResponse && unknownResponse {
		am.logResponse(responseMap)
	}
}

func (am *AS3Handler) getRegKeyFromResponse(httpResp *http.Response, responseMap map[string]interface{}) (string, error) {
	switch httpResp.StatusCode {
	case http.StatusOK:
		if regKey, ok := responseMap["registrationKey"]; ok {
			if registrationKey, ok := regKey.(string); ok {
				return registrationKey, nil
			}
			return "", fmt.Errorf("Invalid registration key format")
		}
		return "", fmt.Errorf("Registration key not found in response")

	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return "", fmt.Errorf("RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		}
		return "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)

	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if msg, ok := responseMap["message"].(string); ok {
					return "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, msg)
				}
				return "", fmt.Errorf("authentication failed,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		}
		return "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)

	default:
		return "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
	}
}

func (am *AS3Handler) getBigipRegKeyURL() string {
	apiURL := am.BIGIPURL + "/mgmt/tm/shared/licensing/registration"
	return apiURL
}

func (am *AS3Handler) UpdateApiVersion(version string, build string, schemaVersion string) {
	floatValue, err := strconv.ParseFloat(version, 64) // Use 64 for double precision
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	aInfo := as3VersionInfo{
		as3Version:       floatValue,
		as3SchemaVersion: schemaVersion,
		as3Release:       version + "-" + build,
	}
	am.AS3VersionInfo = aInfo
	versionstr := version[:strings.LastIndex(version, ".")]
	am.bigIPAS3Version, err = strconv.ParseFloat(versionstr, 64)
}

func (am *AS3Handler) handleResponseStatusOK(responseMap map[string]interface{}) bool {
	var unknownResponse bool
	// traverse all response results
	results, ok1 := (responseMap["results"]).([]interface{})
	declaration, ok2 := (responseMap["declaration"]).(interface{}).(map[string]interface{})
	if ok1 && ok2 {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", am.postManagerPrefix, v["code"], v["tenant"], v["message"])
					am.PostManager.updateTenantResponseCode(int(code), "", tenant, updateTenantDeletion(tenant, declaration), "")
				} else {
					unknownResponse = true
				}
			} else {
				unknownResponse = true
			}
		}
	} else {
		unknownResponse = true
	}
	return unknownResponse
}

func (am *AS3Handler) handleMultiStatus(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	results, ok1 := (responseMap["results"]).([]interface{})
	declaration, ok2 := (responseMap["declaration"]).(interface{}).(map[string]interface{})
	if ok1 && ok2 {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					if code != 200 {
						am.PostManager.updateTenantResponseCode(int(code), "", tenant, false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", v["code"]))
						log.Errorf("%v[AS3]%v Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), am.postManagerPrefix, v["code"], v["tenant"], v["message"])
					} else {
						am.PostManager.updateTenantResponseCode(int(code), "", tenant, updateTenantDeletion(tenant, declaration), "")
						log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", am.postManagerPrefix, v["code"], v["tenant"], v["message"])
					}
				} else {
					unknownResponse = true
				}
			} else {
				unknownResponse = true
			}
		}
	} else {
		unknownResponse = true
	}
	return unknownResponse
}

func (am *AS3Handler) handleResponseAccepted(responseMap map[string]interface{}) bool {
	// traverse all response results
	var unknownResponse bool
	if respId, ok := (responseMap["id"]).(string); ok {
		am.PostManager.updateTenantResponseCode(http.StatusAccepted, respId, "", false, "")
		log.Debugf("[AS3]%v Response from BIG-IP: code 201 id %v, waiting %v seconds to poll response", am.postManagerPrefix, respId, timeoutMedium)
		unknownResponse = true
	}
	return unknownResponse
}

func (am *AS3Handler) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, id int) bool {
	var message string
	var unknownResponse bool
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), am.postManagerPrefix, err["code"])
		message = fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"])
		unknownResponse = true
	}
	log.Debugf("[AS3]%v Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", am.postManagerPrefix, timeoutMedium)
	am.PostManager.updateTenantResponseCode(http.StatusServiceUnavailable, "", "", false, message)
	return unknownResponse
}

func (am *AS3Handler) handleResponseStatusNotFound(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	var message string
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), am.postManagerPrefix, err["code"])
		message = fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"])
	} else {
		unknownResponse = true
		message = "Big-IP Responded with error -- verify the logs for detailed error"
	}
	am.PostManager.updateTenantResponseCode(http.StatusNotFound, "", "", false, message)
	return unknownResponse
}

func (am *AS3Handler) handleResponseStatusUnAuthorized(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	var message string
	if _, ok := responseMap["code"].(float64); ok {
		if _, ok := responseMap["message"].(string); ok {
			log.Errorf("%v[AS3]%v authentication failed,"+
				" Error response from BIGIP with status code: 401 Message: %v", getRequestPrefix(id), am.postManagerPrefix, responseMap["message"])
		} else {
			log.Errorf("%v[AS3]%v authentication failed,"+
				" Error response from BIGIP with status code: 401", getRequestPrefix(id), am.postManagerPrefix)
		}
		message = "authentication failed, Error response from BIGIP with status code: 401 -- verify the logs for detailed error"
	} else {
		unknownResponse = true
		message = "Big-IP Responded with error -- verify the logs for detailed error"
	}

	am.PostManager.updateTenantResponseCode(http.StatusUnauthorized, "", "", false, message)
	return unknownResponse
}

func (am *AS3Handler) handleResponseOthers(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					log.Errorf("%v[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), am.postManagerPrefix, v["code"], v["tenant"], v["message"])
					am.PostManager.updateTenantResponseCode(int(code), "", tenant, false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", code))
				} else {
					unknownResponse = true
				}
			} else {
				unknownResponse = true
			}
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), am.postManagerPrefix, err["code"])
		if code, ok := err["code"].(float64); ok {
			am.PostManager.updateTenantResponseCode(int(code), "", "", false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"]))
		} else {
			unknownResponse = true
		}
	} else {
		unknownResponse = true
		if code, ok := responseMap["code"].(float64); ok {
			am.PostManager.updateTenantResponseCode(int(code), "", "", false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", code))
		}
	}
	return unknownResponse
}

func (am *AS3Handler) removeDeletedTenantsForBigIP(as3Config map[string]interface{}, rsConfig *ResourceConfigRequest, cisLabel, partition string) {
	for k, v := range as3Config {
		if decl, ok := v.(map[string]interface{}); ok {
			if label, found := decl["label"]; found && label == cisLabel && k != partition+"_gtm" {
				if _, ok := rsConfig.ltmConfig[k]; !ok {
					// adding an empty tenant to delete the tenant from BIGIP
					priority := 1
					rsConfig.ltmConfig[k] = &PartitionConfig{Priority: &priority}
				}
			}
		}
	}
}

func (am *AS3Handler) getResourceConfigRequest(cfg agentPostConfig) (*ResourceConfigRequest, error) {
	// fix this entire function below in terms of parsing and return the error
	var rcr ResourceConfigRequest
	var as3Config map[string]interface{}

	err := json.Unmarshal([]byte(cfg.data), &as3Config)
	if err != nil {
		return nil, fmt.Errorf("[AS3] Error unmarshaling AS3 declaration: %v", err)
	}

	// Extract declaration from AS3 config
	//declaration, ok := as3Config["declaration"].(map[string]interface{})
	//if !ok {
	//	return nil, fmt.Errorf("[AS3] Error extracting declaration from AS3 config")
	//}

	rcr.reqId = cfg.id
	rcr.ltmConfig = make(LTMConfig)

	//// Process each tenant in declaration
	//for tenant, config := range declaration {
	//	// Skip class and schemaVersion fields
	//	if tenant == "class" || tenant == "schemaVersion" {
	//		continue
	//	}
	//
	//	tenantCfg, ok := config.(map[string]interface{})
	//	if !ok {
	//		return nil, fmt.Errorf("[AS3] Error parsing tenant config for %s", tenant)
	//	}
	//
	//	rcr.ltmConfig[tenant] = &PartitionConfig{ResourceMap: make(ResourceMap), Priority: config.Priority}
	//
	//	// Process each resource in tenant
	//	for resource, rConfig := range tenantCfg {
	//		if resource == "class" {
	//			continue
	//		}
	//
	//		resourceCfg, ok := rConfig.(map[string]interface{})
	//		if !ok {
	//			return nil, fmt.Errorf("[AS3] Error parsing resource config for %s/%s", tenant, resource)
	//		}
	//
	//		rcr.ltmConfig[tenant].ResourceMap[resource] = &ResourceConfig{
	//			MetaData: metaData{
	//				ResourceType: "ltm",
	//				Name:         resource,
	//			},
	//			Raw: resourceCfg,
	//		}
	//	}
	//}

	return &rcr, nil

}
