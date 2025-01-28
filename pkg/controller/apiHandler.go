package controller

import (
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const gtmPostmanagerPrefix = "[GTM]"

type PostManagerInterface interface {
	setupBIGIPRESTClient()
}

type APIHandlerInterface interface {
	getAPIURL(params []string) string
	getTaskIdURL(taskId string) string
	getVersionURL() string
	getBigipRegKeyURL() string
	logResponse(responseMap map[string]interface{})
	logRequest(cfg string)
	createAS3Declaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration
	getApiHandler() *AS3Handler
}

func NewGTMAPIHandler(params AgentParams) *GTMAPIHandler {
	gtm := &GTMAPIHandler{
		BaseAPIHandler: NewBaseAPIHandler(params, true),
		Partition:      DEFAULT_GTM_PARTITION,
	}
	// Initialize appropriate API handler based on type
	switch params.ApiType {
	case "as3":
		gtm.APIHandler = NewAS3Handler(params)
		if as3Handler, ok := gtm.APIHandler.(*AS3Handler); ok {
			as3Handler.PostParams = &gtm.PostManager.PostParams
			as3Handler.postManagerPrefix = gtmPostmanagerPrefix
			gtm.PopulateAS3Version()
		}
	/*
		case "otherapi":
			am.apiHandler = NewOtherAPIHandler(params)
	*/
	default:
		log.Errorf("Unsupported API type: %v", params.ApiType)
		return nil
	}

	return gtm
}

func NewBaseAPIHandler(params AgentParams, isGtm bool) *BaseAPIHandler {
	return &BaseAPIHandler{
		apiType:     params.ApiType,
		PostManager: NewPostManager(params, isGtm),
	}
}

func NewLTMAPIHandler(params AgentParams) *LTMAPIHandler {
	ltm := &LTMAPIHandler{
		BaseAPIHandler: NewBaseAPIHandler(params, false),
	}
	// Initialize appropriate API handler based on type
	switch params.ApiType {
	case "as3":
		ltm.APIHandler = NewAS3Handler(params)
		if as3Handler, ok := ltm.APIHandler.(*AS3Handler); ok {
			as3Handler.PostParams = &ltm.PostManager.PostParams
			ltm.PopulateAS3Version()
		}
	/*
		case "otherapi":
			am.apiHandler = NewOtherAPIHandler(params)
	*/
	default:
		log.Errorf("Unsupported API type: %v", params.ApiType)
		return nil
	}

	return ltm
}

// Function to create new API Manager based on API type
func NewAPIHandler(params AgentParams) *APIHandler {
	//func NewAPIHandler(apiType string) *APIHandler {
	am := &APIHandler{
		LTM: NewLTMAPIHandler(params),
	}

	if isGTMOnSeparateServer(params) {
		am.GTM = NewGTMAPIHandler(params)
	}

	return am
}

//func GetPostManager(apiHandler *APIHandler) *PostManager {
//	var postManager *PostManager
//	if handler, ok := apiHandler.apiHandler.(*AS3Handler); ok {
//		postManager = handler.PostManager
//	}
//	return postManager
//}

func (api *BaseAPIHandler) PopulateAS3Version() {
	version, build, schemaVersion, err := api.GetBigIPAPIVersion(api.postManagerPrefix)
	if err != nil {
		log.Errorf("[AS3]%v %v ", api.postManagerPrefix, err)
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
	if as3Handler, ok := api.APIHandler.(*AS3Handler); ok {
		as3Handler.AS3VersionInfo = aInfo
		versionstr := version[:strings.LastIndex(version, ".")]
		as3Handler.bigIPAS3Version, err = strconv.ParseFloat(versionstr, 64)
	}
	if err != nil {
		log.Errorf("[AS3]%v Error while converting AS3 version to float", api.postManagerPrefix)
		return
	}

}

// publishConfig posts incoming configuration to BIG-IP
func (api *BaseAPIHandler) postConfig(cfg *agentConfig) {
	// log as3 request if it's set
	if api.LogRequest {
		api.APIHandler.logRequest(cfg.data)
	}

	httpResp, responseMap := api.PostManager.postConfig(cfg)
	if httpResp == nil || responseMap == nil {
		return
	}

	var unknownResponse = false
	switch httpResp.StatusCode {
	case http.StatusOK:
		log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleResponseStatusOK(responseMap)
	case http.StatusCreated, http.StatusAccepted:
		log.Infof("%v[AS3]%v post resulted in ACCEPTED", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleResponseAccepted(responseMap)
	case http.StatusMultiStatus:
		log.Infof("%v[AS3]%v post resulted in MULTI-STATUS", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleMultiStatus(responseMap, cfg.id)
	case http.StatusServiceUnavailable:
		log.Infof("%v[AS3]%v post resulted in RETRY", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleResponseStatusServiceUnavailable(responseMap, cfg.id)
	case http.StatusNotFound:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleResponseStatusNotFound(responseMap, cfg.id)
	case http.StatusUnauthorized:
		log.Infof("%v[AS3]%v post resulted in UNAUTHORIZED FAILURE", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleResponseStatusUnAuthorized(responseMap, cfg.id)
	default:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), api.postManagerPrefix)
		unknownResponse = api.handleResponseOthers(responseMap, cfg.id)
	}
	if api.LogResponse || unknownResponse {
		api.APIHandler.logResponse(responseMap)
	}
}

func (api *BaseAPIHandler) IsBigIPAppServicesAvailable() error {
	// Get the API URL for AS3 version check
	url := api.APIHandler.getVersionURL()

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v", err)
		return err
	}

	// Set basic auth credentials
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	// Make HTTP request
	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return fmt.Errorf("Internal Error")
	}

	// Check response status code
	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["version"] != nil {
			// Successfully verified AS3 is available
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

func (api *BaseAPIHandler) GetAS3DeclarationFromBigIP() (map[string]interface{}, error) {
	// Get the API URL for AS3 declaration
	url := api.APIHandler.getAPIURL([]string{})

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", api.postManagerPrefix, err)
		return nil, err
	}

	// Set basic auth credentials
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	// Make HTTP request
	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return nil, fmt.Errorf("Internal Error")
	}

	// Check response status code
	switch httpResp.StatusCode {
	case http.StatusOK:
		return responseMap, err
	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return nil, fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		} else {
			api.APIHandler.logResponse(responseMap)
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
			api.APIHandler.logResponse(responseMap)
		}
	}
	return nil, fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)

}

func (gtmApi *GTMAPIHandler) GetAS3DeclarationFromBigIP(postManagerPrefix string) (map[string]interface{}, error) {
	// Get the API URL for AS3 declaration
	url := gtmApi.APIHandler.getAPIURL([]string{})

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postManagerPrefix, err)
		return nil, err
	}

	// Set basic auth credentials
	req.SetBasicAuth(gtmApi.BIGIPUsername, gtmApi.BIGIPPassword)

	// Make HTTP request
	httpResp, responseMap := gtmApi.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return nil, fmt.Errorf("Internal Error")
	}

	// Check response status code
	switch httpResp.StatusCode {
	case http.StatusOK:
		return responseMap, err
	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return nil, fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		} else {
			gtmApi.APIHandler.logResponse(responseMap)
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
			gtmApi.APIHandler.logResponse(responseMap)
		}
	}
	return nil, fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)

}

func (api *BaseAPIHandler) createHTTPRequest(url string, postManagerPrefix string) (*http.Request, error) {
	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postManagerPrefix, err)
		return nil, err
	}

	// Set basic auth credentials
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	return req, nil
}

func (api *BaseAPIHandler) publishConfig(cfg agentConfig) {
	log.Debugf("[AS3]%v PostManager Accepted the configuration", api.postManagerPrefix)
	// postConfig updates the tenantResponseMap with response codes
	api.postConfig(&cfg)
}

func (api *BaseAPIHandler) GetBigIPAPIVersion(postManagerPrefix string) (string, string, string, error) {
	// Get the API URL for AS3 version check
	url := api.APIHandler.getVersionURL()

	req, err := api.createHTTPRequest(url, postManagerPrefix)
	if err != nil {
		return "", "", "", fmt.Errorf("Internal Error")
	}

	// Make HTTP request
	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return "", "", "", fmt.Errorf("Internal Error")
	}

	var unknownResponse = false
	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["version"] != nil {
			as3VersionStr, ok1 := responseMap["version"].(string)
			as3versionreleaseStr, ok2 := responseMap["release"].(string)
			as3SchemaVersion, ok3 := responseMap["schemaCurrent"].(string)
			if ok1 && ok2 && ok3 {
				return as3VersionStr, as3versionreleaseStr, as3SchemaVersion, nil
			} else {
				unknownResponse = true
			}
		} else {
			unknownResponse = true
		}
	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return "", "", "", fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		} else {
			unknownResponse = true
		}
	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if msg, ok := responseMap["message"].(string); ok {
					return "", "", "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, msg)
				} else {
					return "", "", "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v", httpResp.StatusCode)
				}
			}
		} else {
			unknownResponse = true
		}
	}
	if api.LogResponse || unknownResponse {
		api.APIHandler.logResponse(responseMap)
	}
	return "", "", "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

func (api *BaseAPIHandler) GetBigipRegKey() (string, error) {
	url := api.APIHandler.getBigipRegKeyURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", api.postManagerPrefix, err)
		return "", err
	}

	log.Debugf("[AS3]%v Posting GET BIGIP Reg Key request on %v", api.postManagerPrefix, url)
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return "", fmt.Errorf("Internal Error")
	}
	var unknownResponse bool
	switch httpResp.StatusCode {
	case http.StatusOK:
		if regKey, ok := responseMap["registrationKey"]; ok {
			if registrationKey, ok := regKey.(string); ok {
				return registrationKey, nil
			} else {
				unknownResponse = true
			}
		} else {
			unknownResponse = true
		}
	case http.StatusNotFound:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusNotFound {
				return "", fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
					" Error response from BIGIP with status code %v", httpResp.StatusCode)
			}
		} else {
			unknownResponse = true
		}
	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if _, ok := responseMap["message"].(string); ok {
					return "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, responseMap["message"])
				} else {
					return "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v", httpResp.StatusCode)
				}
			}
		} else {
			unknownResponse = true
		}
	}
	if unknownResponse {
		api.APIHandler.logResponse(responseMap)
	}
	return "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

func (api *BaseAPIHandler) getTenantConfigStatus(id string) {
	req, err := http.NewRequest("GET", api.APIHandler.getTaskIdURL(id), nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", api.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request with taskId to %v", api.postManagerPrefix, api.APIHandler.getTaskIdURL(id))
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	httpResp, responseMap := api.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if api.LogResponse {
		api.APIHandler.logResponse(responseMap)
	}
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
						api.updateTenantResponseCode(int(code), "", tenant, updateTenantDeletion(tenant, declaration), "")
						if _, ok := v["response"]; ok {
							log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", api.postManagerPrefix, v["code"], v["tenant"], v["message"], v["response"])
						} else {
							log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", api.postManagerPrefix, v["code"], v["tenant"], v["message"])
						}
						intId, err := strconv.Atoi(id)
						if err == nil {
							log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(intId), api.postManagerPrefix)
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
		api.updateTenantResponseCode(httpResp.StatusCode, "", "", false, "")
	}
	if !api.LogResponse && unknownResponse {
		api.APIHandler.logResponse(responseMap)
	}
}

func (api *BaseAPIHandler) pollTenantStatus(agentWorkerUpdate bool) {

	var acceptedTenants []string
	// Create a set to hold unique polling ids
	acceptedTenantIds := map[string]struct{}{}

	api.tenantResponseMap = make(map[string]tenantResponse)

	for tenant, cfg := range api.retryTenantDeclMap {
		// So, when we call updateTenantResponseMap, we have to retain failed agentResponseCodes and taskId's correctly
		api.tenantResponseMap[tenant] = tenantResponse{agentResponseCode: cfg.agentResponseCode, taskId: cfg.taskId}
		if cfg.taskId != "" {
			if _, found := acceptedTenantIds[cfg.taskId]; !found {
				acceptedTenantIds[cfg.taskId] = struct{}{}
				acceptedTenants = append(acceptedTenants, tenant)
			}
		}
	}

	for len(acceptedTenantIds) > 0 {
		// Keep retrying until accepted tenant statuses are updated
		// This prevents agent from unlocking and thus any incoming post requests (config changes) also need to hold on
		for taskId := range acceptedTenantIds {
			<-time.After(timeoutMedium)
			api.getTenantConfigStatus(taskId)
		}
		for _, tenant := range acceptedTenants {
			acceptedTenantIds = map[string]struct{}{}
			// Even if there is any pending tenant which is not updated, keep retrying for that ID
			if api.tenantResponseMap[tenant].taskId != "" {
				acceptedTenantIds[api.tenantResponseMap[tenant].taskId] = struct{}{}
			}
		}
	}

	if len(acceptedTenants) > 0 {
		api.updateTenantResponseMap(agentWorkerUpdate)
	}
}

// removeDeletedTenantsForBigIP will check the tenant exists on bigip or not
// if tenant exists and rsConfig does not have tenant, update the tenant with empty PartitionConfig
func (api *BaseAPIHandler) removeDeletedTenantsForBigIP(rsConfig *ResourceConfigRequest, cisLabel string) {
	//Fetching the latest BIGIP Configuration and identify if any tenant needs to be deleted
	as3Config, err := api.GetAS3DeclarationFromBigIP()
	if err != nil {
		log.Errorf("[AS3] Could not fetch the latest AS3 declaration from BIG-IP")
	}
	for k, v := range as3Config {
		if decl, ok := v.(map[string]interface{}); ok {
			if label, found := decl["label"]; found && label == cisLabel && k != api.Partition+"_gtm" {
				if _, ok := rsConfig.ltmConfig[k]; !ok {
					// adding an empty tenant to delete the tenant from BIGIP
					priority := 1
					rsConfig.ltmConfig[k] = &PartitionConfig{Priority: &priority}
				}
			}
		}
	}
}
