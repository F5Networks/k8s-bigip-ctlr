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
		apiType:                         params.ApiType,
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
		log.Debugf("[%s]%v No certs appended, using only system certs", postMgr.apiType, postMgr.postManagerPrefix)
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
	req, err := http.NewRequest("POST", cfg.apiURL, httpReqBody)
	if err != nil {
		log.Errorf("%v[%s]%v Creating new HTTP request error: %v ", getRequestPrefix(cfg.id), postMgr.apiType, postMgr.postManagerPrefix, err)
		return nil, nil
	}
	log.Debugf("[%s]%v posting request to %v", postMgr.apiType, postMgr.postManagerPrefix, cfg.apiURL)
	log.Infof("%v[%s]%v posting request to %v for %v tenants", getRequestPrefix(cfg.id), postMgr.apiType, postMgr.postManagerPrefix, postMgr.BIGIPURL, getTenantsFromUri(cfg.apiURL))
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
	// We are finding the tenant is deleted based on the API response,
	// if results contain the partition with status code of 200 and declaration does not contain the partition we assume that partition is deleted.
	if _, ok := declaration[tenant]; !ok {
		return true
	}
	return false
}

func (postMgr *PostManager) httpPOST(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[%s]%v REST call error: %v ", postMgr.apiType, postMgr.postManagerPrefix, err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[%s]%v REST call response error: %v ", postMgr.apiType, postMgr.postManagerPrefix, err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[%s]%v Response body unmarshal failed: %v\n", postMgr.apiType, postMgr.postManagerPrefix, err)
		if httpResp.StatusCode == http.StatusUnauthorized {
			log.Errorf("[%s]%v Unauthorized access to BIG-IP, please check the credentials, message: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
		}
		if postMgr.LogResponse {
			log.Errorf("[%s]%v Raw response from Big-IP: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
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

func (postMgr *PostManager) httpReq(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[%s]%v REST call error: %v ", postMgr.apiType, postMgr.postManagerPrefix, err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[%s]%v REST call response error: %v ", postMgr.apiType, postMgr.postManagerPrefix, err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[%s]%v Response body unmarshal failed: %v\n", postMgr.apiType, postMgr.postManagerPrefix, err)
		if httpResp.StatusCode == http.StatusUnauthorized {
			log.Errorf("[%d]%v Unauthorized access to BIG-IP, please check the credentials, message: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
		}
		if postMgr.LogResponse {
			log.Errorf("[%s]%v Raw response from Big-IP: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

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
					postMgr.cachedTenantDeclMap[tenant] = postMgr.retryTenantDeclMap[tenant].decl.(as3Tenant)
				}
				// if received the 200 response remove the entry from tenantPriorityMap
				if _, ok := postMgr.tenantPriorityMap[tenant]; ok {
					delete(postMgr.tenantPriorityMap, tenant)
				}
			}
		}
		//if agentWorkerUpdate {
		//	postMgr.updateRetryMap(tenant, resp, postMgr.incomingTenantDeclMap[tenant])
		//} else {
		//	postMgr.updateRetryMap(tenant, resp, postMgr.retryTenantDeclMap[tenant].as3Decl)
		//}
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
