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
	"encoding/json"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/httpclient"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/tokenmanager"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

const (
	timeoutMedium     = 30 * time.Second
	timeoutLarge      = 180 * time.Second
	loginProviderName = "tmos"
	timeoutMax        = 240 * time.Second
)

func NewPostManager(params AgentParams, kind string, respChan chan *agentPostConfig) *PostManager {
	pm := &PostManager{
		firstPost:  true,
		respChan:   respChan,
		postChan:   make(chan *agentPostConfig, 1),
		apiType:    params.ApiType,
		declUpdate: sync.Mutex{},
	}
	switch kind {
	case GTMBigIP:
		pm.PostParams = params.GTMParams
		pm.postManagerPrefix = gtmPostmanagerPrefix
	case PrimaryBigIP:
		pm.PostParams = params.PrimaryParams
		if (params.SecondaryParams != PostParams{}) {
			pm.postManagerPrefix = primaryPostmanagerPrefix
		} else {
			pm.postManagerPrefix = defaultPostmanagerPrefix
		}
	case SecondaryBigIP:
		pm.PostParams = params.SecondaryParams
		pm.postManagerPrefix = secondaryPostmanagerPrefix
	}
	pm.setupBIGIPRESTClient()

	// Use shared token manager instead of creating a new instance
	sharedTM := tokenmanager.GetSharedTokenManager()
	pm.TokenManagerInterface = sharedTM.GetOrCreateTokenManager(
		extractHostFromURL(pm.BIGIPURL),
		pm.BIGIPUsername,
		pm.BIGIPPassword,
		pm.httpClient,
	)
	return pm
}

func (postMgr *PostManager) setupBIGIPRESTClient() {
	// Create HTTP client configuration
	clientConfig := httpclient.ClientConfig{
		TrustedCerts:  postMgr.TrustedCerts,
		SSLInsecure:   postMgr.SSLInsecure,
		Timeout:       timeoutLarge,
		EnableMetrics: postMgr.HTTPClientMetrics,
	}

	// Add metrics configuration if enabled
	if postMgr.HTTPClientMetrics {
		clientConfig.MetricsConfig = &httpclient.MetricsConfig{
			InFlightGauge:   prometheus.ClientInFlightGauge,
			RequestsCounter: prometheus.ClientAPIRequestsCounter,
			Trace:           prometheus.ClientTrace,
			HistogramVec:    prometheus.ClientHistVec,
		}
		log.Debug("[BIGIP] Http client instrumented with metrics!")
	}

	// Generate a unique key for this configuration including SSL settings
	clientKey := fmt.Sprintf("postmgr-%s-%s-ssl-%t-metrics-%t", postMgr.apiType, postMgr.postManagerPrefix, postMgr.SSLInsecure, postMgr.HTTPClientMetrics)

	// Get HTTP client from factory
	factory := httpclient.GetFactory()
	postMgr.httpClient = factory.GetOrCreateClient(clientKey, clientConfig)
}

func (postMgr *PostManager) postConfig(cfg *agentPostConfig) (*http.Response, map[string]interface{}) {
	// log as3 request if it's set
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("%v[%s]%v Creating new HTTP request error: %v ", getRequestPrefix(cfg.reqMeta.id), postMgr.apiType, postMgr.postManagerPrefix, err)
		return nil, nil
	}
	log.Debugf("[%s]%v posting request to %v", postMgr.apiType, postMgr.postManagerPrefix, cfg.as3APIURL)
	log.Infof("%v[%s]%v posting request to %v for %v tenants", getRequestPrefix(cfg.reqMeta.id), postMgr.apiType, postMgr.postManagerPrefix, postMgr.BIGIPURL, getTenantsFromUri(cfg.as3APIURL))

	// Use token authentication instead of basic auth
	var token string
	if postMgr.TokenManagerInterface != nil {
		token = postMgr.TokenManagerInterface.GetToken()
	}
	if token != "" {
		req.Header.Add("X-F5-Auth-Token", token)
	} else {
		// Fallback to basic auth if token is not available
		req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
		log.Warningf("%v[%s]%v Failed to get auth token, falling back to basic auth", getRequestPrefix(cfg.reqMeta.id), postMgr.apiType, postMgr.postManagerPrefix)
	}

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil && responseMap == nil {
		return nil, nil
	}

	if postMgr.firstPost {
		postMgr.firstPost = false
	}
	return httpResp, responseMap
}

func (postMgr *PostManager) httpPOST(request *http.Request) (*http.Response, map[string]interface{}) {
	// Ensure content type is set
	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

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
		if postMgr.LogResponse {
			log.Debugf("[%s]%v Raw response from Big-IP: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
		}
		return httpResp, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) httpReq(request *http.Request) (*http.Response, map[string]interface{}) {
	// Use token authentication instead of basic auth
	var token string
	if postMgr.TokenManagerInterface != nil {
		token = postMgr.TokenManagerInterface.GetToken()
	}
	if token != "" {
		request.Header.Set("X-F5-Auth-Token", token)
	} else {
		// Fallback to basic auth if token is not available
		request.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
		log.Warningf("[%s]%v Failed to get auth token, falling back to basic auth", postMgr.apiType, postMgr.postManagerPrefix)
	}

	// Ensure content type is set
	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

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
		return nil, nil
	}
	if httpResp.StatusCode == http.StatusUnauthorized {
		log.Errorf("[%s]%v Unauthorized access to BIG-IP, please check the credentials, message: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
		// Try to refresh the token on 401
		if postMgr.TokenManagerInterface != nil {
			log.Debugf("[%s]%v Attempting to refresh token after unauthorized response", postMgr.apiType, postMgr.postManagerPrefix)
			err = postMgr.TokenManagerInterface.RefreshToken()
			if err != nil {
				log.Errorf("[%s]%v Failed to refresh token after unauthorized response, error: %v", postMgr.apiType, postMgr.postManagerPrefix, err)
				// Return error
				return nil, nil
			}
		}
		return nil, nil
	}
	if postMgr.LogResponse {
		log.Debugf("[%s]%v Raw response from Big-IP: %v", postMgr.apiType, postMgr.postManagerPrefix, string(body))
	}
	return httpResp, response
}

// function for returning the prefix string for request id
func getRequestPrefix(id int64) string {
	if id == 0 {
		return "[Retry]"
	}
	return fmt.Sprintf("[Request: %v]", id)
}

// function for returning the tenants from URI
func getTenantsFromUri(uri string) string {
	res := strings.Split(uri, "declare/")
	if len(res) < 2 {
		return "all"
	}
	return res[1]
}

func updateTenantDeletion(tenant string, declaration map[string]interface{}) bool {
	// We are finding the tenant is deleted based on the AS3 API response,
	// if results contain the partition with status code of 200 and declaration does not contain the partition we assume that partition is deleted.
	if _, ok := declaration[tenant]; !ok {
		return true
	}
	return false
}

// extractHostFromURL extracts the hostname from a URL string
func extractHostFromURL(url string) string {
	// Remove protocol prefix if present
	if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	} else if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	}

	// Extract just the hostname (remove port and path)
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	return url
}
