/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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

package crmanager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	F5RouterName  = "F5 BIG-IP"
)

type PostManager struct {
	postChan   chan config
	httpClient *http.Client
	PostParams
}

type PostParams struct {
	BIGIPUsername string
	BIGIPPassword string
	BIGIPURL      string
	TrustedCerts  string
	SSLInsecure   bool
	AS3PostDelay  int
	//Log the AS3 response body in Controller logs
	LogResponse bool
}

type config struct {
	data      string
	routesMap map[string][]string
	as3APIURL string
}

func NewPostManager(params PostParams) *PostManager {
	pm := &PostManager{
		postChan:   make(chan config, 1),
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
	data string,
	partitions []string,
) {
	activeConfig := config{
		data:      data,
		as3APIURL: postMgr.getAS3APIURL(partitions),
	}

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

		posted := postMgr.postConfig(cfg)
		// To handle general errors
		for !posted {
			posted = postMgr.postOnEventOrTimeout(timeoutMedium, cfg)
		}
		firstPost = false
	}
}

func (postMgr *PostManager) postOnEventOrTimeout(timeout time.Duration, cfg config) bool {
	select {
	case newCfg := <-postMgr.postChan:
		return postMgr.postConfig(newCfg)
	case <-time.After(timeout):
		return postMgr.postConfig(cfg)
	}
}

func (postMgr *PostManager) postConfig(cfg config) bool {
	httpReqBody := bytes.NewBuffer([]byte(cfg.data))

	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return false
	}
	log.Debugf("[AS3] posting request to %v", cfg.as3APIURL)
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return false
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return postMgr.handleResponseStatusOK(responseMap, cfg)
	case http.StatusServiceUnavailable:
		return postMgr.handleResponseStatusServiceUnavailable(responseMap, cfg)
	case http.StatusNotFound:
		return postMgr.handleResponseStatusNotFound(responseMap)
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

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}, cfg config) bool {
	//traverse all response results
	results := (responseMap["results"]).([]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		//log result with code, tenant and message
		log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
	}

	return true
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}, cfg config) bool {
	log.Errorf("[AS3] Big-IP Responded with error code: %v", responseMap["code"])
	log.Debugf("[AS3] Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", timeoutSmall)
	return postMgr.postOnEventOrTimeout(timeoutSmall, cfg)
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}) bool {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", http.StatusNotFound)
	}

	if postMgr.LogResponse {
		log.Errorf("[AS3] Raw response from Big-IP: %v ", responseMap)
	}
	return true
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}, cfg config) bool {
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
