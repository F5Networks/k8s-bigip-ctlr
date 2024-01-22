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
	"strconv"
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
		retryChan:                       make(chan struct{}, 1),
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

func (postMgr *PostManager) getAS3APIURL(tenants []string) string {
	apiURL := postMgr.BIGIPURL + "/mgmt/shared/appsvcs/declare/" + strings.Join(tenants, ",")
	return apiURL
}

func (postMgr *PostManager) getAS3TaskIdURL(taskId string) string {
	apiURL := postMgr.BIGIPURL + "/mgmt/shared/appsvcs/task/" + taskId
	return apiURL
}

// publishConfig posts incoming configuration to BIG-IP
func (postMgr *PostManager) publishConfig(cfg agentConfig) {
	log.Debugf("[AS3]%v PostManager Accepted the configuration", postMgr.postManagerPrefix)
	// postConfig updates the tenantResponseMap with response codes
	postMgr.postConfig(&cfg)
}

func (postMgr *PostManager) postConfig(cfg *agentConfig) {
	// log as3 request if it's set
	if postMgr.LogAS3Request {
		postMgr.logAS3Request(cfg.data)
	}
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("%v[AS3]%v Creating new HTTP request error: %v ", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request to %v", postMgr.postManagerPrefix, cfg.as3APIURL)
	log.Infof("%v[AS3]%v posting request to %v for %v tenants", getRequestPrefix(cfg.id), postMgr.postManagerPrefix, postMgr.BIGIPURL, getTenantsFromUri(cfg.as3APIURL))
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if postMgr.firstPost {
		postMgr.firstPost = false
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseStatusOK(responseMap)
	case http.StatusCreated, http.StatusAccepted:
		log.Infof("%v[AS3]%v post resulted in ACCEPTED", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseAccepted(responseMap)
	case http.StatusMultiStatus:
		log.Infof("%v[AS3]%v post resulted in MULTI-STATUS", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleMultiStatus(responseMap, cfg.id)
	case http.StatusServiceUnavailable:
		log.Infof("%v[AS3]%v post resulted in RETRY", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseStatusServiceUnavailable(responseMap, cfg.id)
	case http.StatusNotFound:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseStatusNotFound(responseMap, cfg.id)
	default:
		log.Infof("%v[AS3]%v post resulted in FAILURE", getRequestPrefix(cfg.id), postMgr.postManagerPrefix)
		postMgr.handleResponseOthers(responseMap, cfg.id)
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
		if postMgr.LogAS3Response {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) updateTenantResponseCode(code int, id string, tenant string, isDeleted bool) {
	// Update status for a specific tenant if mentioned, else update the response for all tenants
	if tenant != "" {
		postMgr.tenantResponseMap[tenant] = tenantResponse{code, id, isDeleted}
	} else {
		for tenant := range postMgr.tenantResponseMap {
			postMgr.tenantResponseMap[tenant] = tenantResponse{code, id, false}
		}
	}
}

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}) {
	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap, true)
	}
	// traverse all response results
	results := (responseMap["results"]).([]interface{})
	declaration := (responseMap["declaration"]).(interface{}).(map[string]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
		postMgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
	}
}

func (postMgr *PostManager) getTenantConfigStatus(id string) {
	req, err := http.NewRequest("GET", postMgr.getAS3TaskIdURL(id), nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v posting request with taskId to %v", postMgr.postManagerPrefix, postMgr.getAS3TaskIdURL(id))
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpPOST(req)
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
				postMgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
				if _, ok := v["response"]; ok {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"], v["response"])
				} else {
					log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
				}
				intId, err := strconv.Atoi(id)
				if err == nil {
					log.Infof("%v[AS3]%v post resulted in SUCCESS", getRequestPrefix(intId), postMgr.postManagerPrefix)
				}

			}
		}
	} else if httpResp.StatusCode != http.StatusServiceUnavailable {
		// reset task id, so that any failed tenants will go to post call in the next retry
		postMgr.updateTenantResponseCode(httpResp.StatusCode, "", "", false)
	}
}

func (postMgr *PostManager) handleMultiStatus(responseMap map[string]interface{}, id int) {
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		declaration := (responseMap["declaration"]).(interface{}).(map[string]interface{})
		debug := true
		for _, value := range results {
			v := value.(map[string]interface{})

			if v["code"].(float64) != 200 {
				debug = false
				postMgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), false)
				log.Errorf("%v[AS3]%v Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
			} else {
				postMgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), updateTenantDeletion(v["tenant"].(string), declaration))
				log.Debugf("[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
			}
		}
		if postMgr.LogAS3Response {
			postMgr.logAS3Response(responseMap, debug)
		}
	}
}

func (postMgr *PostManager) handleResponseAccepted(responseMap map[string]interface{}) {
	// traverse all response results
	if respId, ok := (responseMap["id"]).(string); ok {
		postMgr.updateTenantResponseCode(http.StatusAccepted, respId, "", false)
		log.Debugf("[AS3]%v Response from BIG-IP: code 201 id %v, waiting %v seconds to poll response", postMgr.postManagerPrefix, respId, timeoutMedium)
	}
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, id int) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, err["code"])
	}
	log.Debugf("[AS3]%v Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", postMgr.postManagerPrefix, timeoutMedium)
	postMgr.updateTenantResponseCode(http.StatusServiceUnavailable, "", "", false)
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}, id int) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, err["code"])
	} else {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, http.StatusNotFound)
	}
	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap, false)
	}
	postMgr.updateTenantResponseCode(http.StatusNotFound, "", "", false)
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}, id int) {
	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap, false)
	}
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			log.Errorf("%v[AS3]%v Response from BIG-IP: code: %v --- tenant:%v --- message: %v", getRequestPrefix(id), postMgr.postManagerPrefix, v["code"], v["tenant"], v["message"])
			postMgr.updateTenantResponseCode(int(v["code"].(float64)), "", v["tenant"].(string), false)
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("%v[AS3]%v Big-IP Responded with error code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, err["code"])
		postMgr.updateTenantResponseCode(int(err["code"].(float64)), "", "", false)
	} else {
		log.Errorf("%v[AS3]%v Big-IP Responded with code: %v", getRequestPrefix(id), postMgr.postManagerPrefix, responseMap["code"])
		postMgr.updateTenantResponseCode(int(responseMap["code"].(float64)), "", "", false)
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
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

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
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

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
	url := postMgr.getAS3APIURL([]string{})
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3]%v Creating new HTTP request error: %v ", postMgr.postManagerPrefix, err)
		return nil, err
	}

	log.Debugf("[AS3]%v posting GET BIGIP AS3 declaration request on %v", postMgr.postManagerPrefix, url)
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

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
		if postMgr.LogAS3Response {
			log.Errorf("[AS3]%v Raw response from Big-IP: %v", postMgr.postManagerPrefix, string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) getAS3VersionURL() string {
	apiURL := postMgr.BIGIPURL + "/mgmt/shared/appsvcs/info"
	return apiURL
}

func (postMgr *PostManager) getBigipRegKeyURL() string {
	apiURL := postMgr.BIGIPURL + "/mgmt/tm/shared/licensing/registration"
	return apiURL
}

func (postMgr *PostManager) logAS3Response(responseMap map[string]interface{}, debug bool) {
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
	rawResponse := fmt.Sprintf("[AS3]%v Raw response from Big-IP: %v ", postMgr.postManagerPrefix, responseMap)
	if debug {
		log.Debugf(rawResponse)
	} else {
		log.Errorf(rawResponse)
	}
}

func (postMgr *PostManager) logAS3Request(cfg string) {
	var as3Config map[string]interface{}
	err := json.Unmarshal([]byte(cfg), &as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Request body unmarshal failed: %v\n", postMgr.postManagerPrefix, err)
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
		log.Errorf("[AS3]%v Unified declaration error: %v\n", postMgr.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v Unified declaration: %v\n", postMgr.postManagerPrefix, as3Declaration(decl))
}

// Method to verify if App Services are installed or CIS as3 version is
// compatible with BIG-IP, it will return with error if any one of the
// requirements are not met
func (postMgr *PostManager) IsBigIPAppServicesAvailable() error {
	version, build, schemaVersion, err := postMgr.GetBigipAS3Version()
	if err != nil {
		log.Errorf("[AS3]%v %v ", postMgr.postManagerPrefix, err)
		return err
	}
	am := as3VersionInfo{
		as3Version:       version,
		as3SchemaVersion: schemaVersion,
		as3Release:       version + "-" + build,
	}
	postMgr.AS3VersionInfo = am
	versionstr := version[:strings.LastIndex(version, ".")]
	bigIPAS3Version, err := strconv.ParseFloat(versionstr, 64)
	if err != nil {
		log.Errorf("[AS3]%v Error while converting AS3 version to float", postMgr.postManagerPrefix)
		return err
	}
	postMgr.bigIPAS3Version = bigIPAS3Version
	if bigIPAS3Version >= as3SupportedVersion && bigIPAS3Version <= as3Version {
		log.Debugf("[AS3]%v BIGIP is serving with AS3 version: %v", postMgr.postManagerPrefix, version)
		return nil
	}

	if bigIPAS3Version > as3Version {
		am.as3Version = defaultAS3Version
		am.as3SchemaVersion = fmt.Sprintf("%.2f.0", as3Version)
		as3Build := defaultAS3Build
		am.as3Release = am.as3Version + "-" + as3Build
		log.Debugf("[AS3]%v BIGIP is serving with AS3 version: %v", postMgr.postManagerPrefix, bigIPAS3Version)
		postMgr.AS3VersionInfo = am
		return nil
	}

	return fmt.Errorf("CIS versions >= 2.0 are compatible with AS3 versions >=%v. "+
		"Upgrade AS3 version in BIGIP from %v to %v or above.", as3SupportedVersion,
		bigIPAS3Version, as3SupportedVersion)
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
			tenantResponse{resp.agentResponseCode, resp.taskId, false},
		}
	}
}

func (postMgr *PostManager) pollTenantStatus() {

	var acceptedTenants []string
	// Create a set to hold unique polling ids
	acceptedTenantIds := map[string]struct{}{}

	postMgr.tenantResponseMap = make(map[string]tenantResponse)

	for tenant, cfg := range postMgr.retryTenantDeclMap {
		// So, when we call updateTenantResponseMap, we have to retain failed agentResponseCodes and taskId's correctly
		postMgr.tenantResponseMap[tenant] = tenantResponse{agentResponseCode: cfg.agentResponseCode, taskId: cfg.taskId}
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
			postMgr.getTenantConfigStatus(taskId)
		}
		for _, tenant := range acceptedTenants {
			acceptedTenantIds = map[string]struct{}{}
			// Even if there is any pending tenant which is not updated, keep retrying for that ID
			if postMgr.tenantResponseMap[tenant].taskId != "" {
				acceptedTenantIds[postMgr.tenantResponseMap[tenant].taskId] = struct{}{}
			}
		}
	}

	if len(acceptedTenants) > 0 {
		postMgr.updateTenantResponseMap(false)
	}
}

func (postMgr *PostManager) createAS3Declaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration {
	var as3Config map[string]interface{}

	baseAS3ConfigTemplate := fmt.Sprintf(baseAS3Config, postMgr.AS3VersionInfo.as3Version, postMgr.AS3VersionInfo.as3Release, postMgr.AS3VersionInfo.as3SchemaVersion)
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

func (postMgr *PostManager) retryFailedTenant(userAgent string) {
	var retryTenants []string

	// this map is to collect all non-201 tenant configs
	retryDecl := make(map[string]as3Tenant)

	postMgr.tenantResponseMap = make(map[string]tenantResponse)

	for tenant, cfg := range postMgr.retryTenantDeclMap {
		// So, when we call updateTenantResponseMap, we have to retain failed agentResponseCodes and taskId's correctly
		postMgr.tenantResponseMap[tenant] = tenantResponse{agentResponseCode: cfg.agentResponseCode, taskId: cfg.taskId}
		if cfg.taskId == "" {
			retryTenants = append(retryTenants, tenant)
			retryDecl[tenant] = cfg.as3Decl.(as3Tenant)
		}
	}

	if len(retryTenants) > 0 {
		// Until all accepted tenants are not processed, we do not want to re-post failed tenants since we will anyways get a 503
		cfg := agentConfig{
			data:      string(postMgr.createAS3Declaration(retryDecl, userAgent)),
			as3APIURL: postMgr.getAS3APIURL(retryTenants),
			id:        0,
		}
		// Ignoring timeouts for custom errors
		<-time.After(timeoutMedium)

		postMgr.postConfig(&cfg)

		postMgr.updateTenantResponseMap(false)
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
