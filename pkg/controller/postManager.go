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

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	timeoutMedium = 30 * time.Second
	timeoutLarge  = 180 * time.Second
)

func NewPostManager(params AgentParams, gtmPostMgr bool) *PostManager {
	pm := &PostManager{
		firstPost:                       true,
		PrimaryClusterHealthProbeParams: params.PrimaryClusterHealthProbeParams,
		cachedTenantDeclMap:             make(map[string]as3Tenant),
		incomingTenantDeclMap:           make(map[string]as3Tenant),
		retryTenantDeclMap:              make(map[string]*tenantParams),
		tenantPriorityMap:               make(map[string]int),
		postChan:                        make(chan ResourceConfigRequest, 1),
	}
	if !gtmPostMgr {
		pm.PostParams = params.PostParams
	} else {
		pm.PostParams = params.GTMParams
		pm.postManagerPrefix = "[GTM]"
	}
	pm.setupBIGIPRESTClient()
	return pm
}

func (postMgr *PostManager) setupBIGIPRESTClient() {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// TODO: Make sure appMgr sets certificates in bigipInfo
	certs := []byte(postMgr.TrustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debugf("[AS3]%v No certs appended, using only system certs", postMgr.postManagerPrefix)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: postMgr.SSLInsecure,
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
		postMgr.httpClient = &http.Client{
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

func (postMgr *PostManager) postConfig(cfg *agentConfig) (*http.Response, map[string]interface{}) {
	// log as3 request if it's set
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("%v[AS3]%v Creating new HTTP request error: %v ", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, err)
		return nil, nil
	}
	log.Debugf("[AS3]%v posting request to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
	log.Infof("%v[AS3]%v posting request to %v for %v tenants", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, postMgr.BIGIPURL, getTenantsFromUri(cfg.as3APIURL))
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return nil, nil
	}

	if postMgr.firstPost {
		postMgr.firstPost = false
	}
	return httpResp, responseMap
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
		if httpResp.StatusCode == http.StatusUnauthorized {
			log.Errorf("[AS3]%v Unauthorized access to BIG-IP, please check the credentials, message: %v", postMgr.postManagerPrefix, string(body))
		}
		if postMgr.LogResponse {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) updateTenantResponseCode(code int, id string, tenant string, isDeleted bool, message string) {
	// Update status for a specific tenant if mentioned, else update the response for all tenants
	if tenant != "" {
		postMgr.tenantResponseMap[tenant] = tenantResponse{code, id, isDeleted, message}
	} else {
		for tenant := range postMgr.tenantResponseMap {
			postMgr.tenantResponseMap[tenant] = tenantResponse{code, id, false, message}
		}
	}
}

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}) bool {
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
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
					postMgr.updateTenantResponseCode(int(code), "", tenant, updateTenantDeletion(tenant, declaration), "")
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

func (postMgr *PostManager) handleMultiStatus(responseMap map[string]interface{}, id int) bool {
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
						postMgr.updateTenantResponseCode(int(code), "", tenant, false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", v["code"]))
						log.Errorf("%v[AS3]%v Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
					} else {
						postMgr.updateTenantResponseCode(int(code), "", tenant, updateTenantDeletion(tenant, declaration), "")
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
	return unknownResponse
}

func (postMgr *PostManager) handleResponseAccepted(responseMap map[string]interface{}) bool {
	// traverse all response results
	var unknownResponse bool
	if respId, ok := (responseMap["id"]).(string); ok {
		postMgr.updateTenantResponseCode(http.StatusAccepted, respId, "", false, "")
		log.Debugf("[AS3]%v Response from BIG-IP: code 201 id %v, waiting %v seconds to poll response", postMgr.postManagerPrefix, respId, timeoutMedium)
		unknownResponse = true
	}
	return unknownResponse
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, id int) bool {
	var message string
	var unknownResponse bool
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, err["code"])
		message = fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"])
		unknownResponse = true
	}
	log.Debugf("[AS3]%v Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", postMgr.postManagerPrefix, timeoutMedium)
	postMgr.updateTenantResponseCode(http.StatusServiceUnavailable, "", "", false, message)
	return unknownResponse
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	var message string
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, err["code"])
		message = fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"])
	} else {
		unknownResponse = true
		message = "Big-IP Responded with error -- verify the logs for detailed error"
	}
	postMgr.updateTenantResponseCode(http.StatusNotFound, "", "", false, message)
	return unknownResponse
}

func (postMgr *PostManager) handleResponseStatusUnAuthorized(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	var message string
	if _, ok := responseMap["code"].(float64); ok {
		if _, ok := responseMap["message"].(string); ok {
			log.Errorf("%v[AS3]%v authentication failed,"+
				" Error response from BIGIP with status code: 401 Message: %v", getRequestPrefix(id), postMgr.postManagerPrefix, responseMap["message"])
		} else {
			log.Errorf("%v[AS3]%v authentication failed,"+
				" Error response from BIGIP with status code: 401", getRequestPrefix(id), postMgr.postManagerPrefix)
		}
		message = "authentication failed, Error response from BIGIP with status code: 401 -- verify the logs for detailed error"
	} else {
		unknownResponse = true
		message = "Big-IP Responded with error -- verify the logs for detailed error"
	}

	postMgr.updateTenantResponseCode(http.StatusUnauthorized, "", "", false, message)
	return unknownResponse
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}, id int) bool {
	var unknownResponse bool
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			if v, ok := value.(map[string]interface{}); ok {
				code, ok1 := v["code"].(float64)
				tenant, ok2 := v["tenant"].(string)
				if ok1 && ok2 {
					log.Errorf("%v[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
					postMgr.updateTenantResponseCode(int(code), "", tenant, false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", code))
				} else {
					unknownResponse = true
				}
			} else {
				unknownResponse = true
			}
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, err["code"])
		if code, ok := err["code"].(float64); ok {
			postMgr.updateTenantResponseCode(int(code), "", "", false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", err["code"]))
		} else {
			unknownResponse = true
		}
	} else {
		unknownResponse = true
		if code, ok := responseMap["code"].(float64); ok {
			postMgr.updateTenantResponseCode(int(code), "", "", false, fmt.Sprintf("Big-IP Responded with error code: %v -- verify the logs for detailed error", code))
		}
	}
	return unknownResponse
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
		if httpResp.StatusCode == http.StatusUnauthorized {
			log.Errorf("[AS3]%v Unauthorized access to BIG-IP, please check the credentials, message: %v", postMgr.postManagerPrefix, string(body))
		}
		if postMgr.LogResponse {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}


//func (postMgr *PostManager) getBigipRegKeyURL() string {
//	apiURL := postMgr.BIGIPURL + "/mgmt/tm/shared/licensing/registration"
//	return apiURL
//}

// Method to verify if App Services are installed or CIS as3 version is
// compatible with BIG-IP, it will return with error if any one of the
// requirements are not met

func (postMgr *PostManager) updateTenantResponseMap(agentWorkerUpdate bool) {
	/*
		Non 200 ok tenants will be added to retryTenantDeclMap map
		Locks to update the map will be acquired in the calling method
	*/
	for tenant, resp := range postMgr.tenantResponseMap {
		if resp.agentResponseCode == 200 {
			if resp.isDeleted {
				// Update the cache tenant map if tenant is deleted.
				delete(postMgr.cachedTenantDeclMap, tenant)
			} else {
				// update cachedTenantDeclMap with successfully posted declaration
				if agentWorkerUpdate {
					postMgr.cachedTenantDeclMap[tenant] = postMgr.incomingTenantDeclMap[tenant]
				} else {
					postMgr.cachedTenantDeclMap[tenant] = postMgr.retryTenantDeclMap[tenant].as3Decl.(as3Tenant)
				}
				// if received the 200 response remove the entry from tenantPriorityMap
				if _, ok := postMgr.tenantPriorityMap[tenant]; ok {
					delete(postMgr.tenantPriorityMap, tenant)
				}
			}
		}
		if agentWorkerUpdate {
			postMgr.updateRetryMap(tenant, resp, postMgr.incomingTenantDeclMap[tenant])
		} else {
			postMgr.updateRetryMap(tenant, resp, postMgr.retryTenantDeclMap[tenant].as3Decl)
		}
	}
}

func (postMgr *PostManager) updateRetryMap(tenant string, resp tenantResponse, tenDecl interface{}) {
	if resp.agentResponseCode == http.StatusOK {
		// delete the tenant entry from retry if any
		delete(postMgr.retryTenantDeclMap, tenant)
		// if received the 200 response remove the entry from tenantPriorityMap
		if _, ok := postMgr.tenantPriorityMap[tenant]; ok {
			delete(postMgr.tenantPriorityMap, tenant)
		}
	} else {
		postMgr.retryTenantDeclMap[tenant] = &tenantParams{
			tenDecl,
			tenantResponse{resp.agentResponseCode, resp.taskId, false, resp.message},
		}
	}
}

//func (postMgr *PostManager) retryFailedTenant(userAgent string) {
//	var retryTenants []string
//
//	// this map is to collect all non-201 tenant configs
//	retryDecl := make(map[string]as3Tenant)
//
//	postMgr.tenantResponseMap = make(map[string]tenantResponse)
//
//	for tenant, cfg := range postMgr.retryTenantDeclMap {
//		// So, when we call updateTenantResponseMap, we have to retain failed agentResponseCodes and taskId's correctly
//		postMgr.tenantResponseMap[tenant] = tenantResponse{agentResponseCode: cfg.agentResponseCode, taskId: cfg.taskId}
//		if cfg.taskId == "" {
//			retryTenants = append(retryTenants, tenant)
//			retryDecl[tenant] = cfg.as3Decl.(as3Tenant)
//		}
//	}
//
//	if len(retryTenants) > 0 {
//		// Until all accepted tenants are not processed, we do not want to re-post failed tenants since we will anyways get a 503
//		cfg := agentConfig{
//			data:      string(postMgr.createAS3Declaration(retryDecl, userAgent)),
//			as3APIURL: postMgr.getAS3APIURL(retryTenants),
//			id:        0,
//		}
//
//		postMgr.postConfig(&cfg)
//
//		postMgr.updateTenantResponseMap(false)
//	}
//
//}

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
