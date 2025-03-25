package controller

import (
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net/http"
)

const gtmPostmanagerPrefix = "[GTM BigIP]"
const secondaryPostmanagerPrefix = "[Secondary BigIP]"
const primaryPostmanagerPrefix = "[Primary BigIP]"
const defaultPostmanagerPrefix = "[BigIP]"

type PostManagerInterface interface {
	setupBIGIPRESTClient()
}

func NewGTMAPIHandler(params AgentParams, respChan chan *agentPostConfig) *GTMAPIHandler {
	gtm := &GTMAPIHandler{
		BaseAPIHandler: NewBaseAPIHandler(params, GTMBigIP, respChan),
		Partition:      DEFAULT_GTM_PARTITION,
	}
	switch params.ApiType {
	case AS3:
		gtm.APIHandler = NewAS3Handler(gtm.PostManager, params.Partition)
		if as3Handler, ok := gtm.APIHandler.(*AS3Handler); ok {
			as3Handler.PostParams = gtm.PostManager.PostParams
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

func NewBaseAPIHandler(params AgentParams, kind string, respChan chan *agentPostConfig) *BaseAPIHandler {
	return &BaseAPIHandler{
		apiType:     params.ApiType,
		PostManager: NewPostManager(params, kind, respChan),
	}
}

func NewLTMAPIHandler(params AgentParams, kind string, respChan chan *agentPostConfig) *LTMAPIHandler {
	ltm := &LTMAPIHandler{
		BaseAPIHandler: NewBaseAPIHandler(params, kind, respChan),
	}
	// Initialize appropriate API handler based on type
	switch params.ApiType {
	case AS3:
		ltm.APIHandler = NewAS3Handler(ltm.PostManager, params.Partition)
		if as3Handler, ok := ltm.APIHandler.(*AS3Handler); ok {
			as3Handler.PostParams = ltm.PostManager.PostParams
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

// publishConfig posts incoming configuration to BIG-IP
func (api *BaseAPIHandler) postConfig(cfg *agentPostConfig) {
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
		log.Infof("%v[%s]%v post resulted in SUCCESS", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusOK(responseMap, cfg)
	case http.StatusCreated, http.StatusAccepted:
		log.Infof("%v[%s]%v post resulted in ACCEPTED", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseAccepted(responseMap, cfg)
	case http.StatusMultiStatus:
		log.Infof("%v[%s]%v post resulted in MULTI-STATUS", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleMultiStatus(responseMap, cfg)
	case http.StatusServiceUnavailable:
		log.Infof("%v[%s]%v post resulted in RETRY", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusServiceUnavailable(responseMap, cfg)
	case http.StatusNotFound:
		log.Infof("%v[%s]%v post resulted in FAILURE", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusNotFound(responseMap, cfg)
	case http.StatusUnauthorized:
		log.Infof("%v[%s]%v post resulted in UNAUTHORIZED FAILURE", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseStatusUnAuthorized(responseMap, cfg)
	default:
		log.Infof("%v[%s]%v post resulted in FAILURE", getRequestPrefix(cfg.reqMeta.id), api.apiType, api.postManagerPrefix)
		unknownResponse = api.APIHandler.handleResponseOthers(responseMap, cfg)
	}
	if api.PostManager.LogResponse || unknownResponse {
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

func (api *BaseAPIHandler) publishConfig(cfg *agentPostConfig) {
	log.Debugf("[%s]%v PostManager Accepted the configuration", api.apiType, api.postManagerPrefix)
	// postConfig updates the tenantResponseMap with response codes
	api.postConfig(cfg)
}

func (api *BaseAPIHandler) PopulateAPIVersion() {
	version, build, schemaVersion, err := api.GetBigIPAPIVersion()
	if err != nil {
		log.Errorf("[%s]%v %v ", api.apiType, api.postManagerPrefix, err)
	}
	api.APIHandler.UpdateApiVersion(version, build, schemaVersion)
}

func (api *BaseAPIHandler) GetBigIPAPIVersion() (string, string, string, error) {
	url := api.APIHandler.getVersionURL()

	req, err := api.createHTTPRequest(url, api.postManagerPrefix)
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

func (apiHandler *APIHandler) getPostManager() *PostManager {
	if apiHandler.GTM != nil {
		return apiHandler.GTM.PostManager
	}
	return apiHandler.LTM.PostManager
}

func (apiHandler *APIHandler) getAPIType() string {
	if apiHandler.GTM != nil {
		return apiHandler.GTM.PostManager.apiType
	}
	return apiHandler.LTM.PostManager.apiType
}
