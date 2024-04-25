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

package controller

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func NewPostManager(params PostParams, partition string) *PostManager {

	var pm = &PostManager{
		AS3PostManager: &AS3PostManager{
			AS3Config: params.AS3Config,
		},
		tokenManager:           params.tokenManager,
		cachedTenantDeclMap:    make(map[string]as3Tenant),
		postChan:               make(chan agentConfig, 1),
		defaultPartition:       partition,
		tenantDeclarationIDMap: make(map[string]string),
	}
	// postManager runs as a separate go routine
	// blocks on postChan to get new/updated AS3/L3 declaration to be posted to BIG-IP
	go pm.postManager()
	pm.PostParams = params
	pm.setupBIGIPRESTClient()
	return pm
}

// blocks on post channel and handles posting of AS3,L3 declaration to BIGIP pairs.
func (postMgr *PostManager) postManager() {
	for config := range postMgr.postChan {
		// For the very first post after starting controller, need not wait to post
		if !postMgr.AS3PostManager.firstPost && postMgr.AS3PostManager.AS3Config.PostDelayAS3 != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds ", postMgr.AS3PostManager.AS3Config.PostDelayAS3)
			_ = <-time.After(time.Duration(postMgr.AS3PostManager.AS3Config.PostDelayAS3) * time.Second)
		}
		// Set the target address for the as3 request
		config.as3Config.targetAddress = config.BigIpKey.BigIpAddress

		//Handle AS3 post
		postMgr.publishConfig(&config.as3Config)
		//TODO: L3 post manger handling
		//TODO: after post check for failed state and update retry chan

		if !postMgr.AS3Config.DocumentAPI {
			postMgr.updateTenantCache(&config.as3Config)
		}

		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		if !postMgr.AS3Config.DocumentAPI {
			postMgr.pollTenantStatus(&config.as3Config)
		}
		// notify resourceStatusUpdate response handler on successful tenant update
		postMgr.respChan <- &config
	}
}

func (postMgr *PostManager) setupBIGIPRESTClient() {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// TODO: Make sure appMgr sets certificates in bigipInfo
	certs := []byte(postMgr.tokenManager.TrustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debugf("[AS3]%v No certs appended, using only system certs", postMgr.postManagerPrefix)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: postMgr.tokenManager.SslInsecure,
			RootCAs:            rootCAs,
		},
	}

	if postMgr.HTTPClientMetrics {
		log.Debug("[BIGIP] Http client instrumented with metrics!")
		instrumentedRoundTripper := promhttp.InstrumentRoundTripperInFlight(prometheus.ClientInFlightGauge,
			promhttp.InstrumentRoundTripperCounter(prometheus.ClientAPIRequestsCounter,
				promhttp.InstrumentRoundTripperTrace(prometheus.ClientTrace,
					promhttp.InstrumentRoundTripperDuration(prometheus.ClientHistVec, tr),
				),
			),
		)
		postMgr.PostParams.httpClient = &http.Client{
			Transport: instrumentedRoundTripper,
			Timeout:   timeoutLarge,
		}
	} else {
		postMgr.httpClient = &http.Client{
			Transport: tr,
			Timeout:   timeoutLarge,
		}
	}
}

func (postMgr *PostManager) getAS3APIURL(bigipAddress string) string {
	// TODO: Add tenant filtering when support is added in Central Manger AS3
	//apiURL := postMgr.tokenManager.ServerURL + CmDeclareApi + strings.Join(tenants, ",")
	var apiURL string
	if !postMgr.AS3Config.DocumentAPI {
		apiURL = postMgr.tokenManager.ServerURL + CmDeclareApi + "?target_address=" + bigipAddress
	} else {
		apiURL = postMgr.tokenManager.ServerURL + CmDocumentApi
	}
	return apiURL
}

func (postMgr *PostManager) getAS3TaskIdURL(taskId string) string {
	var apiURL string
	if !postMgr.AS3Config.DocumentAPI {
		apiURL = postMgr.tokenManager.ServerURL + CmDeclareTaskApi + taskId
	} else {
		ids := strings.Split(taskId, "/")
		if len(ids) != 2 {
			return ""
		}
		apiURL = postMgr.tokenManager.ServerURL + CmDocumentApi + ids[0] + "/deployments/" + ids[1]
	}
	return apiURL
}

// publishConfig posts incoming configuration to BIG-IP
func (postMgr *PostManager) publishConfig(cfg *as3Config) {
	log.Debugf("[AS3]%v PostManager Accepted the configuration", postMgr.postManagerPrefix)
	// postConfig updates the tenantResponseMap with response codes
	if !postMgr.AS3Config.DocumentAPI {
		postMgr.postConfig(cfg)
	} else {
		postMgr.postConfigUsingDocumentAPI(cfg)
	}
}

func (postMgr *PostManager) postConfig(cfg *as3Config) {
	// log as3 request if it's set
	if postMgr.AS3PostManager.AS3Config.DebugAS3 {
		postMgr.logAS3Request(cfg.data)
	}
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	var tenants []string
	if len(cfg.failedTenants) > 0 {
		for tenant := range cfg.failedTenants {
			tenants = append(tenants, tenant)
		}
	} else {
		for tenant := range cfg.incomingTenantDeclMap {
			// CIS with AS3 doesn't allow to write to Common partition.So objects in common partition
			// should not be updated or deleted by CIS. So removing from tenant map
			if tenant != "Common" {
				tenants = append(tenants, tenant)
			}
		}
	}
	cfg.as3APIURL = postMgr.getAS3APIURL(cfg.targetAddress)
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("%v[AS3]%v Creating new HTTP request error: %v ", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, err)
		return
	}
	log.Infof("%v[AS3]%v posting request to %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, cfg.as3APIURL)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+postMgr.tokenManager.GetToken())
	// add content type header to the req
	req.Header.Add("Content-Type", "application/json")
	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if postMgr.AS3PostManager.firstPost {
		postMgr.AS3PostManager.firstPost = false
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseStatusOK(responseMap, cfg)
	case http.StatusCreated, http.StatusAccepted:
		log.Infof("%v[AS3]%v post resulted in ACCEPTED", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseAccepted(responseMap, cfg)
	case http.StatusMultiStatus:
		log.Infof("%v[AS3]%v post resulted in MULTI-STATUS", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleMultiStatus(responseMap, cfg)
	case http.StatusServiceUnavailable:
		log.Infof("%v[AS3]%v post resulted in RETRY", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseStatusServiceUnavailable(responseMap, cfg)
	case http.StatusNotFound:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseStatusNotFound(responseMap, cfg)
	default:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseOthers(responseMap, cfg)
	}
}

func (postMgr *PostManager) postConfigUsingDocumentAPI(cfg *as3Config) {
	// log as3 request if it's set
	if postMgr.AS3PostManager.AS3Config.DebugAS3 {
		postMgr.logAS3Request(cfg.data)
	}
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	var tenants []string
	if len(cfg.failedTenants) > 0 {
		for tenant := range cfg.failedTenants {
			tenants = append(tenants, tenant)
		}
	} else {
		for tenant := range cfg.incomingTenantDeclMap {
			// CIS with AS3 doesn't allow to write to Common partition.So objects in common partition
			// should not be updated or deleted by CIS. So removing from tenant map
			if tenant != "Common" {
				tenants = append(tenants, tenant)
			}
		}
	}
	// TODO: support deletion case for custom tenant
	if len(tenants) == 0 {
		tenants = append(tenants, postMgr.defaultPartition)
	}
	cfg.as3APIURL = postMgr.getAS3APIURL(cfg.targetAddress)
	method := "POST"
	declarationID := postMgr.tenantDeclarationIDMap[tenants[0]]
	if declarationID != "" {
		if !cfg.deleted {
			method = "PUT"
		} else {
			method = "DELETE"
		}
	}
	if declarationID == "" && method == "DELETE" {
		log.Errorf("[AS3]%v Document ID is required for deletion of declaration", postMgr.postManagerPrefix)
		return
	}
	// add authorization header to the req
	if postMgr.tokenManager.GetToken() == "" {
		log.Debugf("[AS3] Waiting for max 5 seconds for token syncing..")
		t := 0
		for t < 5 {
			time.Sleep(1 * time.Second)
			if postMgr.tokenManager.GetToken() != "" {
				log.Debugf("[AS3] Token is now available")
				break
			}
		}
		if postMgr.tokenManager.GetToken() == "" {
			log.Errorf("[AS3]%v Creating new HTTP request error: access token missing ", postMgr.postManagerPrefix)
			return
		}
	}
	if method == "DELETE" {
		postMgr.deleteDocumentAPI(tenants[0], cfg, declarationID)
		return
	}
	if method == "PUT" {
		declarationID = postMgr.updateDocumentAPI(tenants[0], cfg, httpReqBody, declarationID)
		return
	}
	declarationID = postMgr.declareDocumentAPI(cfg, httpReqBody, tenants[0], method)
	if declarationID == "" {
		return
	}
	postMgr.deployDocumentAPI(cfg, declarationID, tenants[0])
}

func (postMgr *PostManager) deployDocumentAPI(cfg *as3Config, declarationID string, tenant string) {
	// Deploy request
	target := fmt.Sprintf(`{
		"target": "%s"
	}`, cfg.targetAddress)
	httpReqBody := bytes.NewBuffer([]byte(target))
	deployReq, err := http.NewRequest("POST", fmt.Sprintf(cfg.as3APIURL+declarationID+"/deployments"), httpReqBody)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request to %v", postMgr.postManagerPrefix, cfg.as3APIURL+"/deployments")
	// add authorization header to the req
	deployReq.Header.Add("Authorization", "Bearer "+postMgr.tokenManager.GetToken())
	deployReq.Header.Add("Content-Type", "application/json")

	httpDeployResp, deployResponseMap := postMgr.httpPOST(deployReq)
	if httpDeployResp == nil || deployResponseMap == nil {
		return
	}

	if postMgr.AS3PostManager.firstPost {
		postMgr.AS3PostManager.firstPost = false
	}
	switch httpDeployResp.StatusCode {
	case http.StatusOK:
		log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleDocumentAPIResponseStatusOK(deployResponseMap, cfg, tenant, httpDeployResp.StatusCode)
	case http.StatusAccepted:
		log.Infof("%v[AS3]%v post resulted in ACCEPTED", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleDocumentAPIResponseAccepted(deployResponseMap, declarationID, cfg)
	default:
		postMgr.handleDocumentAPIResponseFailureStatus(deployResponseMap, cfg, tenant, httpDeployResp.StatusCode)
		log.Errorf("[AS3]%v Failed to post declaration to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
	}
}

func (postMgr *PostManager) declareDocumentAPI(cfg *as3Config, httpReqBody io.Reader, tenant string, method string) string {
	declareReq, err := http.NewRequest(method, cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return ""
	}
	log.Debugf("[AS3]%v posting request to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
	// add authorization header to the req
	declareReq.Header.Add("Authorization", "Bearer "+postMgr.tokenManager.GetToken())

	httpDeclareResp, declareResponseMap := postMgr.httpPOST(declareReq)
	if httpDeclareResp == nil || declareResponseMap == nil {
		return ""
	}

	// Read the document ID
	var docID string
	switch httpDeclareResp.StatusCode {
	case http.StatusOK:
		if id, ok := declareResponseMap["id"].(string); ok {
			docID = id
			postMgr.tenantDeclarationIDMap[tenant] = docID // Since we are only supporting single tenant as of now
		}
		log.Debugf("[AS3]%v Successfully posted declare request to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
		if cfg.acceptedTaskId != "" {
			postMgr.handleDocumentAPIResponseStatusOK(declareResponseMap, cfg, tenant, httpDeclareResp.StatusCode)
			return ""
		}
	default:
		postMgr.handleDocumentAPIResponseFailureStatus(declareResponseMap, cfg, tenant, httpDeclareResp.StatusCode)
		log.Errorf("[AS3]%v Failed to post declaration to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
		return ""
	}
	return docID
}
func (postMgr *PostManager) updateDocumentAPI(tenant string, cfg *as3Config, httpReqBody io.Reader, docID string) string {
	updateReq, err := http.NewRequest("PUT", cfg.as3APIURL+docID, httpReqBody)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return ""
	}
	log.Debugf("[AS3]%v posting update request to %v", postMgr.postManagerPrefix, cfg.as3APIURL+docID)
	// add authorization header to the req
	updateReq.Header.Add("Authorization", "Bearer "+postMgr.tokenManager.GetToken())
	updateReq.Header.Add("Content-Type", "application/json")

	httpUpdateResp, updateResponseMap := postMgr.httpPOST(updateReq)
	if httpUpdateResp == nil || updateResponseMap == nil {
		return ""
	}

	// Read the document ID
	switch httpUpdateResp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		if id, ok := updateResponseMap["id"].(string); ok {
			docID = id
			postMgr.tenantDeclarationIDMap[tenant] = docID // Since we are only supporting single tenant as of now
		}
		postMgr.handleDocumentAPIResponseStatusOK(updateResponseMap, cfg, tenant, httpUpdateResp.StatusCode)
		log.Debugf("[AS3]%v Successfully posted update request to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
	default:
		postMgr.handleDocumentAPIResponseFailureStatus(updateResponseMap, cfg, tenant, httpUpdateResp.StatusCode)
		log.Errorf("[AS3]%v Failed to post update request to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
		return ""
	}
	return docID
}

func (postMgr *PostManager) deleteDocumentAPI(tenant string, cfg *as3Config, docID string) {
	deleteReq, err := http.NewRequest("DELETE", cfg.as3APIURL+docID, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request to %v", postMgr.postManagerPrefix, cfg.as3APIURL+docID)
	// add authorization header to the req
	deleteReq.Header.Add("Authorization", "Bearer "+postMgr.tokenManager.GetToken())

	httpDeclareResp, declareResponseMap := postMgr.httpPOST(deleteReq)
	if httpDeclareResp == nil || declareResponseMap == nil {
		return
	}
	// TODO: Handle delete response
	switch httpDeclareResp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		log.Debugf("[AS3]%v Successfully posted delete request to %v", postMgr.postManagerPrefix, cfg.as3APIURL+docID)
		delete(postMgr.tenantDeclarationIDMap, tenant)
		postMgr.updateTenantResponseCode(200, cfg, tenant, true)
	default:
		log.Errorf("[AS3]%v Failed to post delete request for tenant: %v to %v", postMgr.postManagerPrefix, tenant, cfg.as3APIURL+docID)
		postMgr.updateTenantResponseCode(200, cfg, tenant, true)
	}
}

func updateTenantDeletion(tenant string, declaration map[string]interface{}) bool {
	// We are finding the tenant is deleted based on the AS3 API response,
	// if results contain the partition with status code of 200 and declaration does not contain the partition we assume that partition is deleted.
	if _, ok := declaration[tenant]; !ok {
		return true
	}
	return false
}

func (postMgr *PostManager) httpPOST(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[AS3]%v REST call error: %v ", postMgr.postManagerPrefix, err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[AS3]%v REST call response error: %v ", postMgr.postManagerPrefix, err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[AS3]%v Response body unmarshal failed: %v\n", postMgr.postManagerPrefix, err)
		if postMgr.AS3PostManager.AS3Config.DebugAS3 {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) updateTenantResponseCode(code int, cfg *as3Config, tenant string, isDeleted bool) {
	// Update status for a specific tenant if mentioned, else update the response for all tenants
	if tenant != "" {
		cfg.tenantResponseMap[tenant] = tenantResponse{code, isDeleted}
	} else {
		for tenant := range cfg.tenantResponseMap {
			cfg.tenantResponseMap[tenant] = tenantResponse{code, false}
		}
	}
}

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}, cfg *as3Config) {
	// traverse all response results
	unknownResponse := false
	results, ok1 := (responseMap["results"]).([]interface{})
	declaration, ok2 := (responseMap["declaration"]).(interface{}).(map[string]interface{})
	if ok1 && ok2 {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
					postMgr.updateTenantResponseCode(int(code), cfg, tenant, updateTenantDeletion(tenant, declaration))
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
	if postMgr.AS3PostManager.AS3Config.DebugAS3 || unknownResponse {
		postMgr.logAS3Response(responseMap)
	}
}

func (postMgr *PostManager) handleDocumentAPIResponseStatusOK(responseMap map[string]interface{}, cfg *as3Config, tenant string, statusCode int) {
	// response is for single tenant as multiple tenant is single declaration isn't supported
	var status, msg interface{}
	var found bool
	status, _ = responseMap["status"]
	if msg, found = responseMap["Message"]; !found {
		msg, _ = responseMap["message"]
	}
	log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant --- message: %v", postMgr.postManagerPrefix, status, msg)
	postMgr.updateTenantResponseCode(statusCode, cfg, tenant, false)

}

func (postMgr *PostManager) handleDocumentAPIResponseFailureStatus(responseMap map[string]interface{}, cfg *as3Config, tenant string, statusCode int) {
	// response is for single tenant as multiple tenant in single declaration isn't supported
	var msg interface{}
	var found bool
	if msg, found = responseMap["Message"]; !found {
		msg, _ = responseMap["message"]
	}
	log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v, Error: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, statusCode, msg)
	postMgr.updateTenantResponseCode(statusCode, cfg, tenant, false)

}

func (postMgr *PostManager) getTenantConfigStatus(id string, cfg *as3Config) {
	var url string
	if !postMgr.AS3Config.DocumentAPI {
		url = postMgr.getAS3TaskIdURL(id)
	} else {
		url = postMgr.getAS3TaskIdURL(id)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request with taskId to %v", postMgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+postMgr.tokenManager.GetToken())

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	declarationKey := "declaration"
	if postMgr.AS3Config.DocumentAPI {
		declarationKey = "request"
	}
	if httpResp.StatusCode == http.StatusOK {
		var results []interface{}
		if !postMgr.AS3Config.DocumentAPI {
			results = (responseMap["results"]).([]interface{})
		} else {
			if responseMap["response"] != nil {
				response := (responseMap["response"]).(map[string]interface{})
				results = (response["results"]).([]interface{})
			} else {
				log.Debugf("[AS3]%v response is nil", postMgr.postManagerPrefix)
				return
			}
		}
		declaration := (responseMap[declarationKey]).(interface{}).(map[string]interface{})
		// reset the accepted task id
		cfg.acceptedTaskId = ""
		for _, value := range results {
			v := value.(map[string]interface{})
			if msg, ok := v["message"]; ok && msg.(string) == "in progress" {
				return
			} else {
				// reset task id, so that any failed tenants will go to post call in the next retry
				postMgr.updateTenantResponseCode(int(v["code"].(float64)), cfg, v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
				if _, ok := v["response"]; ok {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"], v["response"])
				} else {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
				}
				log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
			}
		}
	} else if httpResp.StatusCode != http.StatusServiceUnavailable {
		// reset task id, so that any failed tenants will go to post call in the next retry
		cfg.acceptedTaskId = ""
		postMgr.updateTenantResponseCode(httpResp.StatusCode, cfg, "", false)
	}
}

func (postMgr *PostManager) handleMultiStatus(responseMap map[string]interface{}, cfg *as3Config) {
	unknownResponse := false
	results, ok1 := (responseMap["results"]).([]interface{})
	declaration, ok2 := (responseMap["declaration"]).(interface{}).(map[string]interface{})
	if ok1 && ok2 {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					if code != 200 {
						postMgr.updateTenantResponseCode(int(code), cfg, tenant, false)
						log.Errorf("%v[AS3]%v Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
					} else {
						postMgr.updateTenantResponseCode(int(code), cfg, tenant, updateTenantDeletion(tenant, declaration))
						log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
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
	if postMgr.AS3PostManager.AS3Config.DebugAS3 || unknownResponse {
		postMgr.logAS3Response(responseMap)
	}
}

func (postMgr *PostManager) handleResponseAccepted(responseMap map[string]interface{}, cfg *as3Config) {
	// traverse all response results
	if respId, ok := (responseMap["id"]).(string); ok {
		cfg.acceptedTaskId = respId
		log.Debugf("[AS3]%v Response from BIG-IP: code 201/202 id %v, waiting %v seconds to poll response", postMgr.postManagerPrefix, respId, timeoutMedium)
	}
}

func (postMgr *PostManager) handleDocumentAPIResponseAccepted(responseMap map[string]interface{}, docID string, cfg *as3Config) {
	var deploymentID string
	deploymentID, _ = (responseMap["id"]).(string)
	cfg.acceptedTaskId = docID + "/" + deploymentID
	log.Debugf("[AS3]%v Response from BIG-IP: code 201/202 id %v, waiting %v seconds to poll response", postMgr.postManagerPrefix, docID, timeoutMedium)
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, cfg *as3Config) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, err["code"])
	}
	log.Debugf("[AS3]%v Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", postMgr.postManagerPrefix, timeoutMedium)
	postMgr.updateTenantResponseCode(http.StatusServiceUnavailable, cfg, "", false)
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}, cfg *as3Config) {
	unknownResponse := false
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, err["code"])
	} else {
		unknownResponse = true
	}
	if postMgr.AS3PostManager.AS3Config.DebugAS3 || unknownResponse {
		postMgr.logAS3Response(responseMap)
	}
	postMgr.updateTenantResponseCode(http.StatusNotFound, cfg, "", false)
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}, cfg *as3Config) {
	unknownResponse := false
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					log.Errorf("%v[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
					postMgr.updateTenantResponseCode(int(code), cfg, tenant, false)
				} else {
					unknownResponse = true
				}
			} else {
				unknownResponse = true
			}
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, err["code"])
		if code, ok := err["code"].(float64); ok {
			postMgr.updateTenantResponseCode(int(code), cfg, "", false)
		} else {
			unknownResponse = true
		}
	} else {
		unknownResponse = true
		log.Errorf("%v[AS3]%v Big-IP Responded with code: %v", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, responseMap["code"])
		if code, ok := responseMap["code"].(float64); ok {
			postMgr.updateTenantResponseCode(int(code), cfg, "", false)
		}
	}
	if postMgr.AS3PostManager.AS3Config.DebugAS3 || unknownResponse {
		postMgr.logAS3Response(responseMap)
	}
}

func (postMgr *PostManager) GetBigipAS3Version() (string, string, string, error) {
	url := postMgr.getAS3VersionURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return "", "", "", err
	}

	log.Debugf("[AS3]%v posting GET BIGIP AS3 Version request on %v", postMgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", postMgr.tokenManager.GetToken())

	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return "", "", "", fmt.Errorf("Internal Error")
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["version"] != nil {
			as3VersionStr := responseMap["version"].(string)
			as3versionreleaseStr := responseMap["release"].(string)
			as3SchemaVersion := responseMap["schemaCurrent"].(string)
			return as3VersionStr, as3versionreleaseStr, as3SchemaVersion, nil
		}
	case http.StatusNotFound:
		responseMap["code"] = int(responseMap["code"].(float64))
		if responseMap["code"] == http.StatusNotFound {
			return "", "", "", fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
				" Error response from BIGIP with status code %v", httpResp.StatusCode)
		}
		// In case of 503 status code : CIS will exit and auto restart of the
		// controller might fetch the BIGIP version once BIGIP is available.
	}
	return "", "", "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

// GetBigipRegKey ...
func (postMgr *PostManager) GetBigipRegKey() (string, error) {
	url := postMgr.getBigipRegKeyURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return "", err
	}

	log.Debugf("[AS3]%v Posting GET BIGIP Reg Key request on %v", postMgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", postMgr.tokenManager.GetToken())

	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return "", fmt.Errorf("Internal Error")
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["registrationKey"] != nil {
			registrationKey := responseMap["registrationKey"].(string)
			return registrationKey, nil
		}
	case http.StatusNotFound:
		if int(responseMap["code"].(float64)) == http.StatusNotFound {
			return "", fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
				" Error response from BIGIP with status code %v", httpResp.StatusCode)
		}
	}
	return "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

func (postMgr *PostManager) GetAS3DeclarationFromBigIP() (map[string]interface{}, error) {
	url := postMgr.getAS3APIURL("")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return nil, err
	}

	log.Debugf("[AS3]%v posting GET BIGIP AS3 declaration request on %v", postMgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", postMgr.tokenManager.GetToken())

	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return nil, fmt.Errorf("Internal Error")
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		return responseMap, err
	case http.StatusNotFound:
		responseMap["code"] = int(responseMap["code"].(float64))
		if responseMap["code"] == http.StatusNotFound {
			return nil, fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
				" Error response from BIGIP with status code %v", httpResp.StatusCode)
		}
	}
	return nil, fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

func (postMgr *PostManager) httpReq(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[AS3]%v REST call error: %v ", postMgr.postManagerPrefix, err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[AS3]%v REST call response error: %v ", postMgr.postManagerPrefix, err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[AS3]%v Response body unmarshal failed: %v\n", postMgr.postManagerPrefix, err)
		if postMgr.AS3PostManager.AS3Config.DebugAS3 {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) getAS3VersionURL() string {
	apiURL := postMgr.tokenManager.ServerURL + CmDeclareInfoApi
	return apiURL
}

func (postMgr *PostManager) getBigipRegKeyURL() string {
	apiURL := postMgr.tokenManager.ServerURL + "/mgmt/tm/shared/licensing/registration"
	return apiURL
}

func (postMgr *PostManager) logAS3Response(responseMap map[string]interface{}) {
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
			log.Errorf("[AS3]%v error while reading declaration from AS3 response: %v\n", postMgr.postManagerPrefix, err)
			return
		}
		responseMap["declaration"] = as3Declaration(decl)
	}
	log.Errorf("[AS3]%v Raw response from Big-IP: %v ", postMgr.postManagerPrefix, responseMap)
}

func (postMgr *PostManager) logAS3Request(cfg string) {
	var as3Config, adc map[string]interface{}
	err := json.Unmarshal([]byte(cfg), &as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Request body unmarshal failed: %v\n", postMgr.postManagerPrefix, err)
	}
	if !postMgr.AS3Config.DocumentAPI {
		adc = as3Config["declaration"].(map[string]interface{})
	} else {
		adc = as3Config
	}
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
		log.Errorf("[AS3]%v Unified declaration error: %v\n", postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v Unified declaration: %v\n", postMgr.postManagerPrefix, as3Declaration(decl))
}

func (postMgr *PostManager) updateTenantCache(cfg *as3Config) {
	/*
	 Non 200 ok tenants will be added to retryTenantDeclMap map
	 Locks to update the map will be acquired in the calling method
	*/
	// re-initialize the failed tenants map
	cfg.failedTenants = make(map[string]struct{})
	for tenant, resp := range cfg.tenantResponseMap {
		if resp.agentResponseCode == 200 {
			// update the post manager's tenant cache
			if resp.isDeleted {
				// Update the cache tenant map if tenant is deleted.
				delete(postMgr.cachedTenantDeclMap, tenant)
			} else {
				postMgr.cachedTenantDeclMap[tenant] = cfg.incomingTenantDeclMap[tenant]
			}
		} else {
			// update the failed tenants list
			cfg.failedTenants[tenant] = struct{}{}
		}
	}
}

func (postMgr *PostManager) pollTenantStatus(cfg *as3Config) {
	// Keep retrying until accepted tenant statuses are updated
	// This prevents agent from unlocking and thus any incoming post requests (config changes) also need to hold on
	for cfg.acceptedTaskId != "" {
		if !postMgr.AS3Config.DocumentAPI {
			<-time.After(timeoutMedium)
		} else {
			<-time.After(timeoutSmall)
		}
		cfg.tenantResponseMap = make(map[string]tenantResponse)
		postMgr.getTenantConfigStatus(cfg.acceptedTaskId, cfg)
		postMgr.updateTenantCache(cfg)
	}
}

// function for returning the prefix string for request id
func getRequestPrefix(id int) string {
	if id == 0 {
		return "[Retry]"
	}
	return fmt.Sprintf("[Request: %v]", id)
}
