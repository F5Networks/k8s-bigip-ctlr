package controller

import (
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// write a function for NewAS3Handler, rewrite

type ApiTypeHandlerInterface interface {
	getAPIURL(params []string) string
	getTaskIdURL(taskId string) string
	UpdateApiVersion(version string, build string, schemaVersion string)
	getVersionURL() string
	getVersionsFromResponse(httpResp *http.Response, responseMap map[string]interface{}) (string, string, string, error)
	removeDeletedTenantsForBigIP(Config map[string]interface{}, rsConfig *ResourceConfigRequest, cisLabel, partition string)
	handleResponseStatusOK(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	handleMultiStatus(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	handleResponseAccepted(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	handleResponseStatusNotFound(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	handleResponseStatusUnAuthorized(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	handleResponseOthers(responseMap map[string]interface{}, cfg *agentPostConfig) bool
	getRegKeyFromResponse(httpResp *http.Response, responseMap map[string]interface{}) (string, error)
	getVersionsFromBigIPResponse(httpResp *http.Response, responseMap map[string]interface{}) error
	getDeclarationFromBigIPResponse(httpResp *http.Response, responseMap map[string]interface{}) (map[string]interface{}, error)
	updateTenantConfigStatus(id string, httpResp *http.Response, responseMap map[string]interface{}, cfg *agentPostConfig)
	pollTenantStatus(cfg *agentPostConfig)
	verifyTenantConfigStatus(id string, agentCfg *agentPostConfig)
	getBigipRegKeyURL() string
	logResponse(responseMap map[string]interface{})
	logRequest(cfg string)
	createAPIDeclaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration
	getApiHandler() *AS3Handler
	createAPIConfig(rsConfig ResourceConfigRequest) agentPostConfig
	//createLTMConfigADC(config ResourceConfigRequest) as3ADC
	//createGTMConfigADC(config ResourceConfigRequest, adc as3ADC) as3ADC
}

func NewAS3Handler(postManager *PostManager) *AS3Handler {
	handler := &AS3Handler{
		cachedTenantDeclMap: make(map[string]as3Tenant),
		AS3Parser:           &AS3Parser{},
		PostManager:         postManager,
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
				if ok2 && ok3 {
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

func (am *AS3Handler) updateTenantConfigStatus(id string, httpResp *http.Response, responseMap map[string]interface{}, cfg *agentPostConfig) {
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
						am.updateTenantResponseCode(int(code), "", cfg, tenant, updateTenantDeletion(tenant, declaration), "")
						if _, ok := v["response"]; ok {
							log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", am.postManagerPrefix, v["code"], v["tenant"], v["message"], v["response"])
						} else {
							log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", am.postManagerPrefix, v["code"], v["tenant"], v["message"])
						}
						intId, err := strconv.Atoi(id)
						if err == nil {
							log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(int64(intId)), am.postManagerPrefix)
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
		am.updateTenantResponseCode(httpResp.StatusCode, "", cfg, "", false, "")
	}
	if !am.PostManager.LogResponse && unknownResponse {
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
	if version == "" {
		return
	}
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

func (am *AS3Handler) handleResponseStatusOK(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
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
					am.updateTenantResponseCode(int(code), "", cfg, tenant, updateTenantDeletion(tenant, declaration), "")
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

func (am *AS3Handler) handleMultiStatus(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
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
						am.updateTenantResponseCode(int(code), "", cfg, tenant, false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", v["code"]))
						log.Errorf("%v[AS3]%v Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix, v["code"], v["tenant"], v["message"])
					} else {
						am.updateTenantResponseCode(int(code), "", cfg, tenant, updateTenantDeletion(tenant, declaration), "")
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

func (am *AS3Handler) handleResponseAccepted(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
	// traverse all response results
	var unknownResponse bool
	if respId, ok := (responseMap["id"]).(string); ok {
		cfg.acceptedTaskId = respId
		log.Debugf("[AS3]%v Response from BIG-IP: code 201/202 id %v, waiting %v seconds to poll response", am.postManagerPrefix, respId, timeoutMedium)
		unknownResponse = true
	}
	return unknownResponse
}

func (am *AS3Handler) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
	var message string
	var unknownResponse bool
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix, err["code"])
		message = fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"])
		unknownResponse = true
	}
	log.Debugf("[AS3]%v Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", am.postManagerPrefix, timeoutMedium)
	am.updateTenantResponseCode(http.StatusServiceUnavailable, "", cfg, "", false, message)
	return unknownResponse
}

func (am *AS3Handler) handleResponseStatusNotFound(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
	var unknownResponse bool
	var message string
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix, err["code"])
		message = fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"])
	} else {
		unknownResponse = true
		message = "Big-IP Responded with error -- verify the logs for detailed error"
	}
	am.updateTenantResponseCode(http.StatusNotFound, "", cfg, "", false, message)
	return unknownResponse
}

func (am *AS3Handler) handleResponseStatusUnAuthorized(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
	var unknownResponse bool
	var message string
	if _, ok := responseMap["code"].(float64); ok {
		if _, ok := responseMap["message"].(string); ok {
			log.Errorf("%v[AS3]%v authentication failed,"+
				" Error response from BIGIP with status code: 401 Message: %v", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix, responseMap["message"])
		} else {
			log.Errorf("%v[AS3]%v authentication failed,"+
				" Error response from BIGIP with status code: 401", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix)
		}
		message = "authentication failed, Error response from BIGIP with status code: 401 -- verify the logs for detailed error"
	} else {
		unknownResponse = true
		message = "Big-IP Responded with error -- verify the logs for detailed error"
	}

	am.updateTenantResponseCode(http.StatusUnauthorized, "", cfg, "", false, message)
	return unknownResponse
}

func (am *AS3Handler) handleResponseOthers(responseMap map[string]interface{}, cfg *agentPostConfig) bool {
	var unknownResponse bool
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					log.Errorf("%v[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix, v["code"], v["tenant"], v["message"])
					am.updateTenantResponseCode(int(code), "", cfg, tenant, false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", code))
				} else {
					unknownResponse = true
				}
			} else {
				unknownResponse = true
			}
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(cfg.reqMeta.id), am.postManagerPrefix, err["code"])
		if code, ok := err["code"].(float64); ok {
			am.updateTenantResponseCode(int(code), "", cfg, "", false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"]))
		} else {
			unknownResponse = true
		}
	} else {
		unknownResponse = true
		if code, ok := responseMap["code"].(float64); ok {
			am.updateTenantResponseCode(int(code), "", cfg, "", false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", code))
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

// Creates AS3 adc only for tenants with updated configuration
func (am *AS3Handler) createAPIConfig(rsConfig ResourceConfigRequest) agentPostConfig {
	as3cfg := agentPostConfig{
		reqMeta:               rsConfig.reqMeta,
		tenantResponseMap:     make(map[string]tenantResponse),
		failedTenants:         make(map[string]tenantResponse),
		incomingTenantDeclMap: make(map[string]as3Tenant),
	}
	for tenant, cfg := range am.createLTMAndGTMConfigADC(rsConfig) {
		// this section is for gtm agent
		if !reflect.DeepEqual(cfg, am.cachedTenantDeclMap[tenant]) {
			as3cfg.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
			as3cfg.tenantResponseMap[tenant] = tenantResponse{}
		}
	}
	as3cfg.data = string(am.createAS3Declaration(as3cfg.incomingTenantDeclMap, am.userAgent))
	return as3cfg
}

func (am *AS3Handler) createAS3Declaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration {
	var as3Config map[string]interface{}
	var adc map[string]interface{}
	var baseAS3ConfigTemplate string
	// if !postMgr.AS3Config.DocumentAPI {
	baseAS3ConfigTemplate = fmt.Sprintf(baseAS3Config, am.AS3VersionInfo.as3Version,
		am.AS3VersionInfo.as3Release)
	_ = json.Unmarshal([]byte(baseAS3ConfigTemplate), &as3Config)
	adc = as3Config["declaration"].(map[string]interface{})
	// } else {
	// 	baseAS3ConfigTemplate = baseAS3Config2
	// 	_ = json.Unmarshal([]byte(baseAS3ConfigTemplate), &as3Config)
	// 	adc = as3Config
	// }

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

func (am *AS3Handler) createLTMConfigADC(config ResourceConfigRequest) as3ADC {
	adc := as3ADC{}
	cisLabel := am.AS3Parser.defaultPartition

	for tenant := range am.cachedTenantDeclMap {
		if _, ok := config.ltmConfig[tenant]; !ok {
			// Remove partition
			adc[tenant] = am.AS3Parser.getDeletedTenantDeclaration(tenant, cisLabel)
		}
	}
	for tenantName, partitionConfig := range config.ltmConfig {
		if len(partitionConfig.ResourceMap) == 0 {
			// Remove partition
			adc[tenantName] = am.AS3Parser.getDeletedTenantDeclaration(tenantName, cisLabel)
			continue
		}
		// Create AS3 Tenant
		tenantDecl := as3Tenant{
			"class": "Tenant",
			"label": cisLabel,
		}
		for _, resourceConfig := range partitionConfig.ResourceMap {
			// Create Shared as3Application object
			app := as3Application{}
			app["class"] = "Application"
			app["template"] = "shared"

			// Process rscfg to create AS3 Resources
			am.AS3Parser.processResourcesForAS3(resourceConfig, app, config.shareNodes, tenantName, config.poolMemberType)

			// Process CustomProfiles
			am.AS3Parser.processCustomProfilesForAS3(resourceConfig, app)

			// Process Profiles
			am.AS3Parser.processProfilesForAS3(resourceConfig, app)

			am.AS3Parser.processIRulesForAS3(resourceConfig, app)

			am.AS3Parser.processDataGroupForAS3(resourceConfig, app)
			tenantDecl[resourceConfig.Virtual.Name] = app
		}
		adc[tenantName] = tenantDecl
	}
	return adc
}

func (am *AS3Handler) createGTMConfigADC(config ResourceConfigRequest, adc as3ADC) as3ADC {
	if len(config.gtmConfig) == 0 {
		sharedApp := as3Application{}
		sharedApp["class"] = "Application"
		sharedApp["template"] = "shared"
		cisLabel := am.AS3Parser.defaultPartition
		tenantDecl := as3Tenant{
			"class":              "Tenant",
			as3SharedApplication: sharedApp,
			"label":              cisLabel,
		}
		adc[DEFAULT_GTM_PARTITION] = tenantDecl

		return adc
	}

	for pn, gtmPartitionConfig := range config.gtmConfig {
		var tenantDecl as3Tenant
		var sharedApp as3Application

		if obj, ok := adc[pn]; ok {
			tenantDecl = obj.(as3Tenant)
			sharedApp = tenantDecl[as3SharedApplication].(as3Application)
		} else {
			sharedApp = as3Application{}
			sharedApp["class"] = "Application"
			sharedApp["template"] = "shared"

			tenantDecl = as3Tenant{
				"class":              "Tenant",
				as3SharedApplication: sharedApp,
			}
		}

		for domainName, wideIP := range gtmPartitionConfig.WideIPs {

			gslbDomain := as3GLSBDomain{
				Class:              "GSLB_Domain",
				DomainName:         wideIP.DomainName,
				RecordType:         wideIP.RecordType,
				LBMode:             wideIP.LBMethod,
				PersistenceEnabled: wideIP.PersistenceEnabled,
				PersistCidrIPv4:    wideIP.PersistCidrIPv4,
				PersistCidrIPv6:    wideIP.PersistCidrIPv6,
				TTLPersistence:     wideIP.TTLPersistence,
				Pools:              make([]as3GSLBDomainPool, 0, len(wideIP.Pools)),
			}
			if wideIP.ClientSubnetPreferred != nil {
				gslbDomain.ClientSubnetPreferred = wideIP.ClientSubnetPreferred
			}
			for _, pool := range wideIP.Pools {
				gslbPool := as3GSLBPool{
					Class:          "GSLB_Pool",
					RecordType:     pool.RecordType,
					LBMode:         pool.LBMethod,
					LBModeFallback: pool.LBModeFallBack,
					Members:        make([]as3GSLBPoolMemberA, 0, len(pool.Members)),
					Monitors:       make([]as3ResourcePointer, 0, len(pool.Monitors)),
				}

				for _, mem := range pool.Members {
					gslbPool.Members = append(gslbPool.Members, as3GSLBPoolMemberA{
						Enabled: true,
						Server: as3ResourcePointer{
							BigIP: pool.DataServer,
						},
						VirtualServer: mem,
					})
				}

				for _, mon := range pool.Monitors {
					gslbMon := as3GSLBMonitor{
						Class:    "GSLB_Monitor",
						Interval: mon.Interval,
						Type:     mon.Type,
						Send:     mon.Send,
						Receive:  mon.Recv,
						Timeout:  mon.Timeout,
					}

					gslbPool.Monitors = append(gslbPool.Monitors, as3ResourcePointer{
						Use: mon.Name,
					})

					sharedApp[mon.Name] = gslbMon
				}
				gslbDomain.Pools = append(gslbDomain.Pools, as3GSLBDomainPool{Use: pool.Name, Ratio: pool.Ratio})
				sharedApp[pool.Name] = gslbPool
			}

			sharedApp[strings.Replace(domainName, "*", "wildcard", -1)] = gslbDomain
		}
		adc[pn] = tenantDecl
	}

	return adc
}

func (am *AS3Handler) createLTMAndGTMConfigADC(config ResourceConfigRequest) as3ADC {
	adc := as3ADC{}
	if am.postManagerPrefix == gtmPostmanagerPrefix {
		// this section is for gtm agent
		adc = am.createGTMConfigADC(config, adc)
	} else {
		// this section is for primary/secondary agent
		adc = am.createLTMConfigADC(config)
		adc = am.createGTMConfigADC(config, adc)
	}
	return adc
}

func (am *AS3Handler) updateTenantResponseCode(code int, id string, cfg *agentPostConfig, tenant string, isDeleted bool, message string) {
	// Update status for a specific tenant if mentioned, else update the response for all tenants
	if tenant != "" {
		cfg.tenantResponseMap[tenant] = tenantResponse{code, id, isDeleted, message}
	} else {
		for tenant := range cfg.tenantResponseMap {
			cfg.tenantResponseMap[tenant] = tenantResponse{code, id, false, message}
		}
	}
}

func (am *AS3Handler) updateTenantResponseMap(agentCfg *agentPostConfig) {
	for tenant, resp := range agentCfg.tenantResponseMap {
		if resp.agentResponseCode == 200 {
			if resp.isDeleted {
				// Update the cache tenant map if tenant is deleted.
				delete(am.cachedTenantDeclMap, tenant)
			}
		}
	}
}

func (am *AS3Handler) updateTenantCache(cfg *agentPostConfig) {
	/*
	 Non 200 ok tenants will be added to retryTenantDeclMap map
	 Locks to update the map will be acquired in the calling method
	*/
	// re-initialize the failed tenants map
	cfg.failedTenants = make(map[string]tenantResponse)
	for tenant, resp := range cfg.tenantResponseMap {
		if resp.agentResponseCode == 200 {
			// update the post manager's tenant cache
			if resp.isDeleted {
				// Update the cache tenant map if tenant is deleted.
				delete(am.cachedTenantDeclMap, tenant)
			} else {
				am.cachedTenantDeclMap[tenant] = cfg.incomingTenantDeclMap[tenant]
			}
		} else {
			// update the failed tenants list
			cfg.failedTenants[tenant] = resp
		}
	}
}

func (am *AS3Handler) pollTenantStatus(cfg *agentPostConfig) {
	// Keep retrying until accepted tenant statuses are updated
	// This prevents agent from unlocking and thus any incoming post requests (config changes) also need to hold on
	for cfg.acceptedTaskId != "" {
		//if !postMgr.AS3Config.DocumentAPI {
		<-time.After(timeoutMedium)
		//} else {
		//	<-time.After(timeoutSmall)
		//}
		cfg.tenantResponseMap = make(map[string]tenantResponse)
		am.verifyTenantConfigStatus(cfg.acceptedTaskId, cfg)
		am.updateTenantCache(cfg)
	}
}

func (am *AS3Handler) verifyTenantConfigStatus(id string, agentCfg *agentPostConfig) {
	taskURI := am.getTaskIdURL(id)
	req, err := http.NewRequest("GET", taskURI, nil)
	if err != nil {
		log.Errorf("[%s]%v Creating new HTTP request error: %v ", am.apiType, am.postManagerPrefix, err)
		return
	}
	log.Debugf("[%s]%v posting request with taskId to %v", am.apiType, am.postManagerPrefix, taskURI)
	req.SetBasicAuth(am.BIGIPUsername, am.BIGIPPassword)

	httpResp, responseMap := am.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if am.PostManager.LogResponse {
		am.logResponse(responseMap)
	}
	am.updateTenantConfigStatus(id, httpResp, responseMap, agentCfg)
}
