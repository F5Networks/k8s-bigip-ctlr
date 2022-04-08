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
		postChan:   make(chan agentConfig, 1),
		PostParams: params,
	}
	pm.setupBIGIPRESTClient()

	// configWorker runs as a separate go routine
	// blocks on postChan to get new/updated configuration to be posted to BIG-IP
	go pm.configWorker()
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

// Write sets activeConfig with the latest config received, so that configWorker can use latest configuration
// Write enqueues postChan to unblock configWorker, which gets blocked on postChan
func (postMgr *PostManager) Write(
	activeConfig agentConfig,
) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above
	select {
	case postMgr.postChan <- activeConfig:
	case <-postMgr.postChan:
		postMgr.postChan <- activeConfig
	}
	log.Debug("[AS3] PostManager Accepted the configuration")

	return
}

// configWorker blocks on postChan
// whenever gets unblocked posts active configuration to BIG-IP
func (postMgr *PostManager) configWorker() {
	// For the very first post after starting controller, need not wait to post
	firstPost := true
	for cfg := range postMgr.postChan {
		if !firstPost && postMgr.AS3PostDelay != 0 {
			// Time (in seconds) that CIS waits to post the AS3 declaration to BIG-IP.
			log.Debugf("[AS3] Delaying post to BIG-IP for %v seconds", postMgr.AS3PostDelay)
			_ = <-time.After(time.Duration(postMgr.AS3PostDelay) * time.Second)
		}

		// After postDelay expires pick up latest declaration, if available
		select {
		case cfg = <-postMgr.postChan:
		case <-time.After(1 * time.Microsecond):
		}

		respCfg, posted := postMgr.postConfig(&cfg)
		// To handle general errors
		for !posted {
			respCfg, posted = postMgr.postOnEventOrTimeout(timeoutMedium, &cfg)
		}

		select {
		case postMgr.respChan <- respCfg.id:
		case <-postMgr.respChan:
			postMgr.respChan <- respCfg.id
		}
		firstPost = false
	}
}

func (postMgr *PostManager) postOnEventOrTimeout(timeout time.Duration, cfg *agentConfig) (*agentConfig, bool) {
	select {
	case newCfg := <-postMgr.postChan:
		return postMgr.postConfig(&newCfg)
	case <-time.After(timeout):
		return postMgr.postConfig(cfg)
	}
}

func (postMgr *PostManager) postConfig(cfg *agentConfig) (*agentConfig, bool) {
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))
	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return cfg, false
	}
	log.Debugf("[AS3] posting request to %v", cfg.as3APIURL)
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return cfg, false
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return postMgr.handleResponseStatusOK(responseMap, cfg)
	case http.StatusServiceUnavailable:
		return postMgr.handleResponseStatusServiceUnavailable(responseMap, cfg)
	case http.StatusNotFound:
		return postMgr.handleResponseStatusNotFound(responseMap, cfg)
	default:
		return postMgr.handleResponseOthers(responseMap, cfg)
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

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}, cfg *agentConfig) (*agentConfig, bool) {
	//traverse all response results
	results := (responseMap["results"]).([]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		//log result with code, tenant and message
		log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
	}

	return cfg, true
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, cfg *agentConfig) (*agentConfig, bool) {
	log.Errorf("[AS3] Big-IP Responded with error code: %v", responseMap["code"])
	log.Debugf("[AS3] Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", timeoutSmall)
	return postMgr.postOnEventOrTimeout(timeoutSmall, cfg)
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}, cfg *agentConfig) (*agentConfig, bool) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", http.StatusNotFound)
	}

	if postMgr.LogResponse {
		log.Errorf("[AS3] Raw response from Big-IP: %v ", responseMap)
	}
	return cfg, true
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}, cfg *agentConfig) (*agentConfig, bool) {
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			//log result with code, tenant and message
			log.Errorf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with code: %v", responseMap["code"])
	}

	if postMgr.LogResponse {
		log.Errorf("[AS3] Raw response from Big-IP: %v ", responseMap)
	}
	return postMgr.postOnEventOrTimeout(timeoutMedium, cfg)
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
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

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
