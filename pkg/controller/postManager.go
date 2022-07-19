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
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

const (
	timeoutSmall  = 3 * time.Second
	timeoutMedium = 30 * time.Second
	timeoutLarge  = 60 * time.Second
)

func NewPostManager(params PostParams) *PostManager {
	pm := &PostManager{
		PostParams: params,
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
		log.Debug("[AS3] No certs appended, using only system certs")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: postMgr.SSLInsecure,
			RootCAs:            rootCAs,
		},
	}

	postMgr.httpClient = &http.Client{
		Transport: tr,
		Timeout:   timeoutLarge,
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
func (postMgr *PostManager) publishConfig(cfg agentConfig, firstPost bool) {

	if !firstPost && postMgr.AS3PostDelay != 0 {
		// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
		log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds", postMgr.AS3PostDelay)
		_ = <-time.After(time.Duration(postMgr.AS3PostDelay) * time.Second)
	}

	log.Debug("[AS3] PostManager Accepted the configuration")

	// postConfig updates the tenantResponseMap with response codes
	postMgr.postConfig(&cfg)
}

func (postMgr *PostManager) postConfig(cfg *agentConfig) {
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return
	}
	log.Debugf("[AS3] posting request to %v", cfg.as3APIURL)
	//req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	token := postMgr.getBigipAuthToken(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+token)
	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		postMgr.handleResponseStatusOK(responseMap)
	case http.StatusCreated, http.StatusAccepted:
		postMgr.handleResponseAccepted(responseMap)
	case http.StatusMultiStatus:
		postMgr.handleMultiStatus(responseMap)
	case http.StatusServiceUnavailable:
		postMgr.handleResponseStatusServiceUnavailable(responseMap)
	case http.StatusNotFound:
		postMgr.handleResponseStatusNotFound(responseMap)
	default:
		postMgr.handleResponseOthers(responseMap, cfg)
	}

}

func (postMgr *PostManager) httpPOST(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("[AS3] REST call error: %v ", err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("[AS3] REST call response error: %v ", err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("[AS3] Response body unmarshal failed: %v\n", err)
		if postMgr.LogResponse {
			log.Errorf("[AS3] Raw response from Big-IP: %v", string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) updateTenantResponse(code int, id string, tenant string) {
	// Update status for a specific tenant if mentioned, else update the response for all tenants
	if tenant != "" {
		postMgr.tenantResponseMap[tenant] = tenantResponse{code, id}
	} else {
		for tenant := range postMgr.tenantResponseMap {
			postMgr.tenantResponseMap[tenant] = tenantResponse{code, id}
		}
	}
}

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}) {
	//traverse all response results
	results := (responseMap["results"]).([]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
		postMgr.updateTenantResponse(int(v["code"].(float64)), "", v["tenant"].(string))
	}
}

func (postMgr *PostManager) getTenantConfigStatus(id string) {

	req, err := http.NewRequest("GET", postMgr.getAS3TaskIdURL(id), nil)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return
	}
	log.Debugf("[AS3] posting request with taskId to %v", postMgr.getAS3TaskIdURL(id))
	//req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	token := postMgr.getBigipAuthToken(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+token)
	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return
	}

	if httpResp.StatusCode == http.StatusOK {
		results := (responseMap["results"]).([]interface{})
		for _, value := range results {
			v := value.(map[string]interface{})
			if msg, ok := v["message"]; ok && msg.(string) == "in progress" {
				return
			} else {
				// reset task id, so that any failed tenants will go to post call in the next retry
				postMgr.updateTenantResponse(int(v["code"].(float64)), "", v["tenant"].(string))
				if _, ok := v["response"]; ok {
					log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v %v", v["code"], v["tenant"], v["message"], v["response"])
				} else {
					log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
				}
			}
		}
	} else if httpResp.StatusCode != http.StatusServiceUnavailable {
		// reset task id, so that any failed tenants will go to post call in the next retry
		postMgr.updateTenantResponse(httpResp.StatusCode, "", "")
	}
}

func (postMgr *PostManager) handleMultiStatus(responseMap map[string]interface{}) {

	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			postMgr.updateTenantResponse(int(v["code"].(float64)), "", v["tenant"].(string))

			if v["code"].(float64) != 200 {
				log.Errorf("[AS3] Error response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
			} else {
				log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
			}
		}
	}
}

func (postMgr *PostManager) handleResponseAccepted(responseMap map[string]interface{}) {
	//traverse all response results
	if respId, ok := (responseMap["id"]).(string); ok {
		postMgr.updateTenantResponse(http.StatusAccepted, respId, "")
		log.Debugf("[AS3] Response from BIG-IP: code 201 id %v, waiting %v seconds to poll response", respId, timeoutMedium)
	}
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	}
	log.Debugf("[AS3] Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", timeoutMedium)
	postMgr.updateTenantResponse(http.StatusServiceUnavailable, "", "")
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", http.StatusNotFound)
	}
	if postMgr.LogResponse {
		log.Errorf("[AS3] Raw response from Big-IP: %v ", responseMap)
	}
	postMgr.updateTenantResponse(http.StatusNotFound, "", "")
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}, cfg *agentConfig) {
	if postMgr.LogResponse {
		log.Errorf("[AS3] Raw response from Big-IP: %v %v", responseMap, cfg.data)
	}
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			log.Errorf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
			postMgr.updateTenantResponse(int(v["code"].(float64)), "", v["tenant"].(string))
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
		postMgr.updateTenantResponse(int(err["code"].(float64)), "", "")
	} else {
		log.Errorf("[AS3] Big-IP Responded with code: %v", responseMap["code"])
		postMgr.updateTenantResponse(int(responseMap["code"].(float64)), "", "")
	}
}

// GetBigipAS3Version ...
func (postMgr *PostManager) GetBigipAS3Version() error {
	url := postMgr.getAS3VersionURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Creating new HTTP request error: %v ", err)
		return err
	}

	log.Infof("Posting GET BIGIP AS3 Version request on %v", url)
	//req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	token := postMgr.getBigipAuthToken(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	log.Infof("lavanya: token is %v", token)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+token)
	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return fmt.Errorf("Internal Error")
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["version"] != nil {
			as3VersionStr := responseMap["version"].(string)
			as3versionreleaseStr := responseMap["release"].(string)
			log.Infof("BIGIP is serving with AS3 version : %v ", as3VersionStr+"-"+as3versionreleaseStr)
			return nil
		}
	case http.StatusNotFound:
		if int(responseMap["code"].(float64)) == http.StatusNotFound {
			return fmt.Errorf("AS3 RPM is not installed on BIGIP,"+
				" Error response from BIGIP with status code %v", httpResp.StatusCode)
		}
	}
	return fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

// GetBigipRegKey ...
func (postMgr *PostManager) GetBigipRegKey() (string, error) {
	url := postMgr.getBigipRegKeyURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Creating new HTTP request error: %v ", err)
		return "", err
	}

	log.Debugf("Posting GET BIGIP Reg Key request on %v", url)
	//req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	token := postMgr.getBigipAuthToken(postMgr.BIGIPUsername, postMgr.BIGIPPassword)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+token)
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

func (postMgr *PostManager) httpReq(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.httpClient.Do(request)
	if err != nil {
		log.Errorf("REST call error: %v ", err)
		return nil, nil
	}
	defer httpResp.Body.Close()

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		log.Errorf("REST call response error: %v ", err)
		return nil, nil
	}
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Errorf("Response body unmarshal failed: %v\n", err)
		if postMgr.LogResponse {
			log.Errorf("Raw response from Big-IP: %v", string(body))
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

func (postMgr *PostManager) getBigipAuthToken(username string, password string) string {
	authPort := "5443"
	authURL := postMgr.BIGIPURL + ":" + authPort + "/api/v1/login"
	req, _ := http.NewRequest("GET", authURL, nil)
	req.SetBasicAuth(username, password)
	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil || responseMap == nil {
		log.Errorf("Internal Error")
		return ""
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		if responseMap["token"] != nil {
			token := responseMap["token"].(string)
			return token
		}
	case http.StatusNotFound:
		responseMap["code"] = int(responseMap["code"].(float64))
		if responseMap["code"] == http.StatusNotFound {
			log.Errorf("AS3 RPM is not installed on BIGIP,"+
				" Error response from BIGIP with status code %v", httpResp.StatusCode)
		}
		return ""
	}
	// In case of 503 status code : CIS will exit and auto restart of the
	// controller might fetch the BIGIP version once BIGIP is available.
	return ""
}
