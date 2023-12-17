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
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PostManagerInterface interface {
	GetBigIPRegKey() (string, error)
	getFirstPost() bool
	getPostDelay() int
	getPostChan() chan interface{}
	getCMURL() string
	closePostChan()
	getRetryChan() chan struct{}
	createTenantDeclaration(BigIpResourceConfig, string, PrimaryClusterHealthProbeParams) interface{}
	getHTTPClientMetrics() bool
	getRespChan() chan resourceStatusMeta
	setRespChan(resourceStatusMeta)
	GetDeclarationFromBigIP() (map[string]interface{}, error)
	setFirstPost(bool)
	setTenantPriorityMap(tenantName string, priority int)
	initTenantResponseMap()
	getIncomingTenantDeclTenants() []string
	pollTenantStatus()
	retryFailedTenant(string)
	notifyRscStatusHandler(int, bool)
	setTenantResponseMap(string, tenantResponse)
	tenantPriorityHasTenant(string) bool
	getRetryTenantDeclMap() map[string]*tenantParams
	initRetryTenantDeclMap()
	getConfigForPost(interface{}, ResourceConfigRequest, []string, string) interface{}
}

func NewPostManager(params AgentParams, respChan chan resourceStatusMeta,
	config v1.AS3Config) PostManagerInterface {

	var pm = AS3Manager{
		AS3PostManager:        &AS3PostManager{AS3Config: config},
		tokenManager:          params.PostParams.tokenManager,
		cachedTenantDeclMap:   make(map[string]as3Tenant),
		incomingTenantDeclMap: make(map[string]as3Tenant),
		retryTenantDeclMap:    make(map[string]*tenantParams),
		tenantPriorityMap:     make(map[string]int),
		postChan:              make(chan interface{}, 1),
		retryChan:             make(chan struct{}, 1),
		respChan:              respChan,
		userAgent:             params.UserAgent,
	}
	// postManager runs as a separate go routine
	// blocks on postChan to get new/updated AS3/L3 declaration to be posted to BIG-IP
	go pm.postManager()
	pm.PostParams = params.PostParams
	pm.setupBIGIPRESTClient()
	return &pm
}

// blocks on post channel and handles posting of AS3,L3 declaration to BIGIP pairs.
func (as3Mgr *AS3Manager) postManager() {
	for config := range as3Mgr.postChan {
		//Handle AS3 post
		as3Mgr.publishConfig(config.(agentConfig).as3Config)
		//TODO: L3 post manger handling
		//TODO: after post check for failed state and update retry chan

		as3Mgr.updateTenantResponseMap(true)

		if len(as3Mgr.retryTenantDeclMap) > 0 {
			// Activate retry
			select {
			case as3Mgr.retryChan <- struct{}{}:
			case <-as3Mgr.retryChan:
				as3Mgr.retryChan <- struct{}{}
			}
		}

		/*
			If there are any tenants with 201 response code,
			poll for its status continuously and block incoming requests
		*/
		as3Mgr.pollTenantStatus()

		// notify resourceStatusUpdate response handler on successful tenant update
		as3Mgr.notifyRscStatusHandler(config.(agentConfig).as3Config.id, true)
	}
}

func (as3Mgr *AS3Manager) setupBIGIPRESTClient() {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// TODO: Make sure appMgr sets certificates in bigipInfo
	certs := []byte(as3Mgr.TrustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debugf("[AS3]%v No certs appended, using only system certs", as3Mgr.postManagerPrefix)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: as3Mgr.SSLInsecure,
			RootCAs:            rootCAs,
		},
	}

	if as3Mgr.HTTPClientMetrics {
		log.Debug("[BIGIP] Http client instrumented with metrics!")
		instrumentedRoundTripper := promhttp.InstrumentRoundTripperInFlight(prometheus.ClientInFlightGauge,
			promhttp.InstrumentRoundTripperCounter(prometheus.ClientAPIRequestsCounter,
				promhttp.InstrumentRoundTripperTrace(prometheus.ClientTrace,
					promhttp.InstrumentRoundTripperDuration(prometheus.ClientHistVec, tr),
				),
			),
		)
		as3Mgr.PostParams.httpClient = &http.Client{
			Transport: instrumentedRoundTripper,
			Timeout:   timeoutLarge,
		}
	} else {
		as3Mgr.httpClient = &http.Client{
			Transport: tr,
			Timeout:   timeoutLarge,
		}
	}
}

func (as3Mgr *AS3Manager) getAS3APIURL(tenants []string) string {
	apiURL := as3Mgr.CMURL + "/mgmt/shared/appsvcs/declare/" + strings.Join(tenants, ",")
	return apiURL
}

func (as3Mgr *AS3Manager) getAS3TaskIdURL(taskId string) string {
	apiURL := as3Mgr.CMURL + "/mgmt/shared/appsvcs/task/" + taskId
	return apiURL
}

// publishConfig posts incoming configuration to BIG-IP
func (as3Mgr *AS3Manager) publishConfig(cfg as3Config) {
	log.Debugf("[AS3]%v AS3Manager Accepted the configuration", as3Mgr.postManagerPrefix)
	// postConfig updates the tenantResponseMap with response codes
	as3Mgr.postConfig(&cfg)
}

func (as3Mgr *AS3Manager) postConfig(cfg *as3Config) {
	// log as3 request if it's set
	if as3Mgr.AS3PostManager.AS3Config.DebugAS3 {
		as3Mgr.logAS3Request(cfg.data)
	}
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("%v[AS3]%v Creating new HTTP request error: %v ", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix, err)
		return
	}

	log.Infof("%v[AS3]%v posting request for %v tenants", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix, getTenantsFromUri(cfg.as3APIURL))
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+as3Mgr.tokenManager.GetToken())

	httpResp, responseMap := as3Mgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if as3Mgr.AS3PostManager.firstPost {
		as3Mgr.AS3PostManager.firstPost = false
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix)
		as3Mgr.handleResponseStatusOK(responseMap)
	case http.StatusCreated, http.StatusAccepted:
		log.Infof("%v[AS3]%v post resulted in ACCEPTED", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix)
		as3Mgr.handleResponseAccepted(responseMap)
	case http.StatusMultiStatus:
		log.Infof("%v[AS3]%v post resulted in MULTI-STATUS", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix)
		as3Mgr.handleMultiStatus(responseMap, cfg.id)
	case http.StatusServiceUnavailable:
		log.Infof("%v[AS3]%v post resulted in RETRY", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix)
		as3Mgr.handleResponseStatusServiceUnavailable(responseMap, cfg.id)
	case http.StatusNotFound:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix)
		as3Mgr.handleResponseStatusNotFound(responseMap, cfg.id)
	default:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), as3Mgr.postManagerPrefix)
		as3Mgr.handleResponseOthers(responseMap, cfg.id)
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

func (as3Mgr *AS3Manager) httpPOST(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := as3Mgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[AS3]%v REST call error: %v ", as3Mgr.postManagerPrefix, err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[AS3]%v REST call response error: %v ", as3Mgr.postManagerPrefix, err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[AS3]%v Response body unmarshal failed: %v\n", as3Mgr.postManagerPrefix, err)
		if as3Mgr.AS3PostManager.AS3Config.DebugAS3 {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", as3Mgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (as3Mgr *AS3Manager) updateTenantResponseCode(code int, id string, tenant string, isDeleted bool) {
	// Update status for a specific tenant if mentioned, else update the response for all tenants
	if tenant != "" {
		as3Mgr.tenantResponseMap[tenant] = tenantResponse{code, id, isDeleted}
	} else {
		for tenant := range as3Mgr.tenantResponseMap {
			as3Mgr.tenantResponseMap[tenant] = tenantResponse{code, id, false}
		}
	}
}

func (as3Mgr *AS3Manager) handleResponseStatusOK(responseMap map[string]interface{}) {
	// traverse all response results
	results := (responseMap["results"]).([]interface{})
	declaration := (responseMap["declaration"]).(interface{}).(map[string]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", as3Mgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
		as3Mgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
	}
}

func (as3Mgr *AS3Manager) getTenantConfigStatus(id string) {
	req, err := http.NewRequest("GET", as3Mgr.getAS3TaskIdURL(id), nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", as3Mgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request with taskId to %v", as3Mgr.postManagerPrefix, as3Mgr.getAS3TaskIdURL(id))
	// add authorization header to the req
	req.Header.Add("Authorization", as3Mgr.tokenManager.GetToken())

	httpResp, responseMap := as3Mgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if httpResp.StatusCode == http.StatusOK {
		results := (responseMap["results"]).([]interface{})
		declaration := (responseMap["declaration"]).(interface{}).(map[string]interface{})
		for _, value := range results {
			v := value.(map[string]interface{})
			if msg, ok := v["message"]; ok && msg.(string) == "in progress" {
				return
			} else {
				// reset task id, so that any failed tenants will go to post call in the next retry
				as3Mgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
				if _, ok := v["response"]; ok {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", as3Mgr.postManagerPrefix, v["code"], v["tenant"], v["message"], v["response"])
				} else {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", as3Mgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
				}
				intId, err := strconv.Atoi(id)
				if err == nil {
					log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(intId), as3Mgr.postManagerPrefix)
				}
			}
		}
	} else if httpResp.StatusCode != http.StatusServiceUnavailable {
		// reset task id, so that any failed tenants will go to post call in the next retry
		as3Mgr.updateTenantResponseCode(httpResp.StatusCode, "", "", false)
	}
}

func (as3Mgr *AS3Manager) handleMultiStatus(responseMap map[string]interface{}, id int) {
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		declaration := (responseMap["declaration"]).(interface{}).(map[string]interface{})
		for _, value := range results {
			v := value.(map[string]interface{})

			if v["code"].(float64) != 200 {
				as3Mgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), false)
				log.Errorf("%v[AS3]%v Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
			} else {
				as3Mgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
				log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", as3Mgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
			}
		}
	}
}

func (as3Mgr *AS3Manager) handleResponseAccepted(responseMap map[string]interface{}) {
	// traverse all response results
	if respId, ok := (responseMap["id"]).(string); ok {
		as3Mgr.updateTenantResponseCode(http.StatusAccepted, respId, "", false)
		log.Debugf("[AS3]%v Response from BIG-IP: code 201 id %v, waiting %v seconds to poll response", as3Mgr.postManagerPrefix, respId, timeoutMedium)
	}
}

func (as3Mgr *AS3Manager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, id int) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, err["code"])
	}
	log.Debugf("[AS3]%v Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", as3Mgr.postManagerPrefix, timeoutMedium)
	as3Mgr.updateTenantResponseCode(http.StatusServiceUnavailable, "", "", false)
}

func (as3Mgr *AS3Manager) handleResponseStatusNotFound(responseMap map[string]interface{}, id int) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, err["code"])
	} else {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, http.StatusNotFound)
	}
	if as3Mgr.AS3PostManager.AS3Config.DebugAS3 {
		as3Mgr.logAS3Response(responseMap)
	}
	as3Mgr.updateTenantResponseCode(http.StatusNotFound, "", "", false)
}

func (as3Mgr *AS3Manager) handleResponseOthers(responseMap map[string]interface{}, id int) {
	if as3Mgr.AS3PostManager.AS3Config.DebugAS3 {
		as3Mgr.logAS3Response(responseMap)
	}
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			log.Errorf("%v[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
			as3Mgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), false)
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, err["code"])
		as3Mgr.updateTenantResponseCode(int(err["code"].(float64)), "", "", false)
	} else {
		log.Errorf("%v[AS3]%v Big-IP Responded with code: %v", getRequestPrefix(id), as3Mgr.postManagerPrefix, responseMap["code"])
		as3Mgr.updateTenantResponseCode(int(responseMap["code"].(float64)), "", "", false)
	}
}

func (as3Mgr *AS3Manager) GetBigipAS3Version() (string, string, string, error) {
	url := as3Mgr.getAS3VersionURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", as3Mgr.postManagerPrefix, err)
		return "", "", "", err
	}

	log.Debugf("[AS3]%v posting GET BIGIP AS3 Version request on %v", as3Mgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", as3Mgr.tokenManager.GetToken())

	httpResp, responseMap := as3Mgr.httpReq(req)
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
func (as3Mgr *AS3Manager) GetBigIPRegKey() (string, error) {
	url := as3Mgr.getBigipRegKeyURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", as3Mgr.postManagerPrefix, err)
		return "", err
	}

	log.Debugf("[AS3]%v Posting GET BIGIP Reg Key request on %v", as3Mgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", as3Mgr.tokenManager.GetToken())

	httpResp, responseMap := as3Mgr.httpReq(req)
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

func (as3Mgr *AS3Manager) GetDeclarationFromBigIP() (map[string]interface{}, error) {
	url := as3Mgr.getAS3APIURL([]string{})
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", as3Mgr.postManagerPrefix, err)
		return nil, err
	}

	log.Debugf("[AS3]%v posting GET BIGIP AS3 declaration request on %v", as3Mgr.postManagerPrefix, url)
	// add authorization header to the req
	req.Header.Add("Authorization", as3Mgr.tokenManager.GetToken())

	httpResp, responseMap := as3Mgr.httpReq(req)
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

func (as3Mgr *AS3Manager) httpReq(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := as3Mgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[AS3]%v REST call error: %v ", as3Mgr.postManagerPrefix, err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[AS3]%v REST call response error: %v ", as3Mgr.postManagerPrefix, err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[AS3]%v Response body unmarshal failed: %v\n", as3Mgr.postManagerPrefix, err)
		if as3Mgr.AS3PostManager.AS3Config.DebugAS3 {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", as3Mgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (as3Mgr *AS3Manager) getAS3VersionURL() string {
	apiURL := as3Mgr.CMURL + "/mgmt/shared/appsvcs/info"
	return apiURL
}

func (as3Mgr *AS3Manager) getBigipRegKeyURL() string {
	apiURL := as3Mgr.CMURL + "/mgmt/tm/shared/licensing/registration"
	return apiURL
}

func (as3Mgr *AS3Manager) logAS3Response(responseMap map[string]interface{}) {
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
			log.Errorf("[AS3]%v error while reading declaration from AS3 response: %v\n", as3Mgr.postManagerPrefix, err)
			return
		}
		responseMap["declaration"] = as3Declaration(decl)
	}
	log.Errorf("[AS3]%v Raw response from Big-IP: %v ", as3Mgr.postManagerPrefix, responseMap)
}

func (as3Mgr *AS3Manager) logAS3Request(cfg string) {
	var as3Config map[string]interface{}
	err := json.Unmarshal([]byte(cfg), &as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Request body unmarshal failed: %v\n", as3Mgr.postManagerPrefix, err)
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
		log.Errorf("[AS3]%v Unified declaration error: %v\n", as3Mgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v Unified declaration: %v\n", as3Mgr.postManagerPrefix, as3Declaration(decl))
}

func (as3Mgr *AS3Manager) updateTenantResponseMap(agentWorkerUpdate bool) {
	/*
	 Non 200 ok tenants will be added to retryTenantDeclMap map
	 Locks to update the map will be acquired in the calling method
	*/
	for tenant, resp := range as3Mgr.tenantResponseMap {
		if resp.agentResponseCode == 200 {
			if resp.isDeleted {
				// Update the cache tenant map if tenant is deleted.
				delete(as3Mgr.cachedTenantDeclMap, tenant)
			} else {
				// update cachedTenantDeclMap with successfully posted declaration
				if agentWorkerUpdate {
					as3Mgr.cachedTenantDeclMap[tenant] = as3Mgr.incomingTenantDeclMap[tenant]
				} else {
					as3Mgr.cachedTenantDeclMap[tenant] = as3Mgr.retryTenantDeclMap[tenant].as3Decl.(as3Tenant)
				}
				// if received the 200 response remove the entry from tenantPriorityMap
				if _, ok := as3Mgr.tenantPriorityMap[tenant]; ok {
					delete(as3Mgr.tenantPriorityMap, tenant)
				}
			}
		}
		if agentWorkerUpdate {
			as3Mgr.updateRetryMap(tenant, resp, as3Mgr.incomingTenantDeclMap[tenant])
		} else {
			as3Mgr.updateRetryMap(tenant, resp, as3Mgr.retryTenantDeclMap[tenant].as3Decl)
		}
	}
}

func (as3Mgr *AS3Manager) updateRetryMap(tenant string, resp tenantResponse, tenDecl interface{}) {
	if resp.agentResponseCode == http.StatusOK {
		// delete the tenant entry from retry if any
		delete(as3Mgr.retryTenantDeclMap, tenant)
		// if received the 200 response remove the entry from tenantPriorityMap
		if _, ok := as3Mgr.tenantPriorityMap[tenant]; ok {
			delete(as3Mgr.tenantPriorityMap, tenant)
		}
	} else {
		as3Mgr.retryTenantDeclMap[tenant] = &tenantParams{
			tenDecl,
			tenantResponse{resp.agentResponseCode, resp.taskId, false},
		}
	}
}

func (as3Mgr *AS3Manager) pollTenantStatus() {

	var acceptedTenants []string
	// Create a set to hold unique polling ids
	acceptedTenantIds := map[string]struct{}{}

	as3Mgr.tenantResponseMap = make(map[string]tenantResponse)

	for tenant, cfg := range as3Mgr.retryTenantDeclMap {
		// So, when we call updateTenantResponseMap, we have to retain failed agentResponseCodes and taskId's correctly
		as3Mgr.tenantResponseMap[tenant] = tenantResponse{agentResponseCode: cfg.agentResponseCode, taskId: cfg.taskId}
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
			as3Mgr.getTenantConfigStatus(taskId)
		}
		for _, tenant := range acceptedTenants {
			acceptedTenantIds = map[string]struct{}{}
			// Even if there is any pending tenant which is not updated, keep retrying for that ID
			if as3Mgr.tenantResponseMap[tenant].taskId != "" {
				acceptedTenantIds[as3Mgr.tenantResponseMap[tenant].taskId] = struct{}{}
			}
		}
	}

	if len(acceptedTenants) > 0 {
		as3Mgr.updateTenantResponseMap(false)
	}
}

func (as3Mgr *AS3Manager) retryFailedTenant(userAgent string) {
	var retryTenants []string

	// this map is to collect all non-201 tenant configs
	retryDecl := make(map[string]as3Tenant)

	as3Mgr.tenantResponseMap = make(map[string]tenantResponse)

	for tenant, cfg := range as3Mgr.retryTenantDeclMap {
		// So, when we call updateTenantResponseMap, we have to retain failed agentResponseCodes and taskId's correctly
		as3Mgr.tenantResponseMap[tenant] = tenantResponse{agentResponseCode: cfg.agentResponseCode, taskId: cfg.taskId}
		if cfg.taskId == "" {
			retryTenants = append(retryTenants, tenant)
			retryDecl[tenant] = cfg.as3Decl.(as3Tenant)
		}
	}

	if len(retryTenants) > 0 {
		// Until all accepted tenants are not processed, we do not want to re-post failed tenants since we will anyways get a 503
		cfg := as3Config{
			data:      string(as3Mgr.AS3PostManager.createAS3Declaration(retryDecl, userAgent)),
			as3APIURL: as3Mgr.getAS3APIURL(retryTenants),
			id:        0,
		}
		// Ignoring timeouts for custom errors
		<-time.After(timeoutMedium)

		as3Mgr.postConfig(&cfg)

		as3Mgr.updateTenantResponseMap(false)
	}

}

func (as3Mgr *AS3Manager) notifyRscStatusHandler(id int, overwriteCfg bool) {

	rscUpdateMeta := resourceStatusMeta{
		id,
		make(map[string]struct{}),
	}
	for tenant := range as3Mgr.retryTenantDeclMap {
		rscUpdateMeta.failedTenants[tenant] = struct{}{}
	}
	// If triggerred from retry block, process the previous successful request completely
	if !overwriteCfg {
		as3Mgr.respChan <- rscUpdateMeta
	} else {
		// Always push latest id to channel
		// Case1: Put latest id into the channel
		// Case2: If channel is blocked because of earlier id, pop out earlier id and push latest id
		// Either Case1 or Case2 executes, which ensures the above
		select {
		case as3Mgr.respChan <- rscUpdateMeta:
		case <-as3Mgr.respChan:
			as3Mgr.respChan <- rscUpdateMeta
		}
	}
}

// function for returning the prefix string for request id
func getRequestPrefix(id int) string {
	if id == 0 {
		return "[Retry]"
	}
	return fmt.Sprintf("[Request: %v]", id)
}

// function for returning the tenants from URI
func getTenantsFromUri(uri string) string {
	res := strings.Split(uri, "declare/")
	if len(res[0]) == 0 {
		return "all"
	}
	return res[1]
}

func (as3Mgr *AS3Manager) getConfigForPost(decl interface{}, rsConfig ResourceConfigRequest, tenants []string, bigipTargetAddress string) interface{} {
	as3cfg := as3Config{
		data:               decl.(string),
		as3APIURL:          as3Mgr.getAS3APIURL(tenants),
		id:                 rsConfig.reqId,
		bigipTargetAddress: bigipTargetAddress,
	}
	//TODO: Implement as part of L3 Manager
	l3cfg := l3Config{}
	cfg := agentConfig{as3Config: as3cfg, l3Config: l3cfg}
	return cfg
}

// Creates AS3 adc only for tenants with updated configuration
func (as3Mgr *AS3Manager) createTenantDeclaration(config BigIpResourceConfig, partition string, primaryClusterHealthProbeParams PrimaryClusterHealthProbeParams) interface{} {
	// Re-initialise incomingTenantDeclMap map and tenantPriorityMap for each new config request
	as3Mgr.incomingTenantDeclMap = make(map[string]as3Tenant)
	as3Mgr.tenantPriorityMap = make(map[string]int)

	for tenant, cfg := range as3Mgr.AS3PostManager.createAS3BIGIPConfig(config, partition, as3Mgr.cachedTenantDeclMap) {
		if !reflect.DeepEqual(cfg, as3Mgr.cachedTenantDeclMap[tenant]) ||
			(primaryClusterHealthProbeParams.EndPoint != "" && primaryClusterHealthProbeParams.statusChanged) {
			as3Mgr.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
		} else {
			// cachedTenantDeclMap always holds the current configuration on BigIP(lets say A)
			// When an invalid configuration(B) is reverted (to initial A) (i.e., config state A -> B -> A),
			// delete entry from retryTenantDeclMap if any
			delete(as3Mgr.retryTenantDeclMap, tenant)
			// Log only when it's primary/standalone CIS or when it's secondary CIS and primary CIS is down
			if primaryClusterHealthProbeParams.EndPoint == "" || !primaryClusterHealthProbeParams.statusRunning {
				log.Debugf("[AS3] No change in %v tenant configuration", tenant)
			}
		}
	}

	return as3Mgr.AS3PostManager.createAS3Declaration(as3Mgr.incomingTenantDeclMap, as3Mgr.userAgent)
}

func (as3Mgr *AS3Manager) getFirstPost() bool {
	return as3Mgr.AS3PostManager.firstPost
}

func (as3Mgr *AS3Manager) getPostDelay() int {
	return as3Mgr.AS3PostManager.AS3Config.PostDelayAS3
}

func (as3Mgr *AS3Manager) getCMURL() string {
	return as3Mgr.CMURL
}

func (as3Mgr *AS3Manager) setFirstPost(firstPost bool) {
	as3Mgr.AS3PostManager.firstPost = firstPost
}

func (as3Mgr *AS3Manager) closePostChan() {
	if as3Mgr.postChan != nil {
		close(as3Mgr.postChan)
		close(as3Mgr.respChan)
	}
}

func (as3Mgr *AS3Manager) getPostChan() chan interface{} {
	return as3Mgr.postChan
}

func (as3Mgr *AS3Manager) getRetryChan() chan struct{} {
	return as3Mgr.retryChan
}

func (as3Mgr *AS3Manager) getHTTPClientMetrics() bool {
	return as3Mgr.HTTPClientMetrics
}

func (as3Mgr *AS3Manager) getRespChan() chan resourceStatusMeta {
	return as3Mgr.respChan
}

func (as3Mgr *AS3Manager) setRespChan(respChan resourceStatusMeta) {
	as3Mgr.respChan <- respChan
}

func (as3Mgr *AS3Manager) setTenantPriorityMap(tenantName string, priority int) {
	as3Mgr.tenantPriorityMap[tenantName] = priority
}

func (as3Mgr *AS3Manager) initTenantResponseMap() {
	as3Mgr.tenantResponseMap = make(map[string]tenantResponse)
}

func (as3Mgr *AS3Manager) getIncomingTenantDeclTenants() []string {
	var tenants []string
	for k := range as3Mgr.incomingTenantDeclMap {
		tenants = append(tenants, k)
	}
	return tenants
}

func (as3Mgr *AS3Manager) setTenantResponseMap(tenant string, response tenantResponse) {
	as3Mgr.tenantResponseMap[tenant] = response
}

func (as3Mgr *AS3Manager) tenantPriorityHasTenant(tenant string) bool {
	_, ok := as3Mgr.tenantPriorityMap[tenant]
	return ok
}

func (as3Mgr *AS3Manager) getRetryTenantDeclMap() map[string]*tenantParams {
	return as3Mgr.retryTenantDeclMap
}

func (as3Mgr *AS3Manager) initRetryTenantDeclMap() {
	as3Mgr.retryTenantDeclMap = make(map[string]*tenantParams)
}
