package controller

import (
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net/http"
	"time"
)

const gtmPostmanagerPrefix = "[GTM]"

type PostManagerInterface interface {
	setupBIGIPRESTClient()
}

func NewGTMAPIHandler(params AgentParams) *GTMAPIHandler {
	gtm := &GTMAPIHandler{
		BaseAPIHandler: NewBaseAPIHandler(params, true),
		Partition:      DEFAULT_GTM_PARTITION,
	}
	// Initialize appropriate API handler based on type
	switch params.ApiType {
	case "as3":
		gtm.APIHandler = NewAS3Handler(params, gtm.PostManager)
		if as3Handler, ok := gtm.APIHandler.(*AS3Handler); ok {
			as3Handler.PostParams = &gtm.PostManager.PostParams
			as3Handler.postManagerPrefix = gtmPostmanagerPrefix
			gtm.PopulateAPIVersion()
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
		ltm.APIHandler = NewAS3Handler(params, ltm.PostManager)
		if as3Handler, ok := ltm.APIHandler.(*AS3Handler); ok {
			as3Handler.PostParams = &ltm.PostManager.PostParams
			ltm.PopulateAPIVersion()
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

// publishConfig posts incoming configuration to BIG-IP
func (api *BaseAPIHandler) postConfig(cfg *agentConfig) {
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
		log.Infof("%v[%s]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusOK(responseMap)
	case http.StatusCreated, http.StatusAccepted:
		log.Infof("%v[%s]%v post resulted in ACCEPTED", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseAccepted(responseMap)
	case http.StatusMultiStatus:
		log.Infof("%v[%s]%v post resulted in MULTI-STATUS", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleMultiStatus(responseMap, cfg.id)
	case http.StatusServiceUnavailable:
		log.Infof("%v[%s]%v post resulted in RETRY", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusServiceUnavailable(responseMap, cfg.id)
	case http.StatusNotFound:
		log.Infof("%v[%s]%v post resulted in FAILURE", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusNotFound(responseMap, cfg.id)
	case http.StatusUnauthorized:
		log.Infof("%v[%s]%v post resulted in UNAUTHORIZED FAILURE", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusUnAuthorized(responseMap, cfg.id)
	default:
		log.Infof("%v[%s]%v post resulted in FAILURE", getRequestPrefix(cfg.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseOthers(responseMap, cfg.id)
	}
	if api.LogResponse || unknownResponse {
		api.APIHandler.logResponse(responseMap)
	}
}

func (api *BaseAPIHandler) IsBigIPAppServicesAvailable() error {
	url := api.APIHandler.getVersionURL()
	var err error

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[%s] Creating new HTTP request error: %v", api.apiType, err)
		return err
	}

	// Set basic auth credentials
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	// Make HTTP request
	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return fmt.Errorf("Internal Error")
	}

	return api.APIHandler.getVersionsFromBigIPResponse(httpResp, responseMap)
}

func (api *BaseAPIHandler) GetDeclarationFromBigIP() (map[string]interface{}, error) {
	url := api.APIHandler.getAPIURL([]string{})

	req, err := api.createHTTPRequest(url, api.postManagerPrefix)
	if err != nil {
		return nil, fmt.Errorf("Internal Error")
	}
	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return nil, fmt.Errorf("Internal Error")
	}

	return api.APIHandler.getDeclarationFromBigIPResponse(httpResp, responseMap)

}

func (gtmApi *GTMAPIHandler) GetDeclarationFromBigIP(postManagerPrefix string) (map[string]interface{}, error) {
	url := gtmApi.APIHandler.getAPIURL([]string{})

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[%s]%v Creating new HTTP request error: %v ", gtmApi.apiType, postManagerPrefix, err)
		return nil, err
	}

	// Set basic auth credentials
	req.SetBasicAuth(gtmApi.BIGIPUsername, gtmApi.BIGIPPassword)

	// Make HTTP request
	httpResp, responseMap := gtmApi.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return nil, fmt.Errorf("Internal Error")
	}

	return gtmApi.APIHandler.getDeclarationFromBigIPResponse(httpResp, responseMap)
}

func (api *BaseAPIHandler) createHTTPRequest(url string, postManagerPrefix string) (*http.Request, error) {
	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[%s]%v Creating new HTTP request error: %v ", api.apiType, postManagerPrefix, err)
		return nil, err
	}

	// Set basic auth credentials
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	return req, nil
}

func (api *BaseAPIHandler) publishConfig(cfg agentConfig) {
	log.Debugf("[%s]%v PostManager Accepted the configuration", api.apiType, api.postManagerPrefix)
	// postConfig updates the tenantResponseMap with response codes
	api.postConfig(&cfg)
}

func (api *BaseAPIHandler) PopulateAPIVersion() error {
	version, build, schemaVersion, err := api.GetBigIPAPIVersion(api.postManagerPrefix)
	if err != nil {
		log.Errorf("[%s]%v %v ", api.apiType, api.postManagerPrefix, err)
		return err
	}
	api.APIHandler.UpdateApiVersion(version, build, schemaVersion)
	return nil

}

func (api *BaseAPIHandler) GetBigIPAPIVersion(postManagerPrefix string) (string, string, string, error) {
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

	return api.APIHandler.getVersionsFromResponse(httpResp, responseMap)

}

func (api *BaseAPIHandler) GetBigipRegKey() (string, error) {
	url := api.APIHandler.getBigipRegKeyURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[%s]%v Creating new HTTP request error: %v ", api.apiType, api.postManagerPrefix, err)
		return "", err
	}

	log.Debugf("[%s]%v Posting GET BIGIP Reg Key request on %v", api.apiType, api.postManagerPrefix, url)
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	httpResp, responseMap := api.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return "", fmt.Errorf("Internal Error")
	}

	// can you write a function to return the regKey in a seperate function using below code?
	return api.APIHandler.getRegKeyFromResponse(httpResp, responseMap)

}

func (api *BaseAPIHandler) getTenantConfigStatus(id string) {
	req, err := http.NewRequest("GET", api.APIHandler.getTaskIdURL(id), nil)
	if err != nil {
		log.Errorf("[%s]%v Creating new HTTP request error: %v ", api.apiType, api.postManagerPrefix, err)
		return
	}
	log.Debugf("[%s]%v posting request with taskId to %v", api.apiType, api.postManagerPrefix, api.APIHandler.getTaskIdURL(id))
	req.SetBasicAuth(api.BIGIPUsername, api.BIGIPPassword)

	httpResp, responseMap := api.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if api.LogResponse {
		api.APIHandler.logResponse(responseMap)
	}

	api.APIHandler.getTenantConfigStatus(id, httpResp, responseMap)

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
	Config, err := api.GetDeclarationFromBigIP()
	if err != nil {
		log.Errorf("[%s] Could not fetch the latest declaration template from BIG-IP", api.apiType)
	}
	api.APIHandler.removeDeletedTenantsForBigIP(Config, rsConfig, cisLabel, api.Partition)

}
