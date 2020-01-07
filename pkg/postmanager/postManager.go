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

package postmanager

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
)

type PostManager struct {
	postChan     chan bool
	activeConfig string
	as3APIURL    string
	httpClient   *http.Client
	Params
}

type Params struct {
	BIGIPUsername string
	BIGIPPassword string
	BIGIPURL      string
	TrustedCerts  string
	SSLInsecure   bool
	//Log the AS3 response body in Controller logs
	LogResponse bool
}

func NewPostManager(params Params) *PostManager {
	pm := &PostManager{
		postChan:     make(chan bool),
		activeConfig: "",
		Params:       params,
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
func (postMgr *PostManager) Write(config string, partitions []string) {
	postMgr.activeConfig = config
	postMgr.as3APIURL = postMgr.getAS3APIURL(partitions)
	postMgr.postChan <- true
	log.Debug("[AS3] PostManager Accepted the configuration")

	return
}

// configWorker blocks on postChan
// whenever gets unblocked posts active configuration to BIG-IP
func (postMgr *PostManager) configWorker() {
	for _ = range postMgr.postChan {
		posted := postMgr.postConfig()
		// To handle general errors
		for !posted {
			posted = postMgr.postOnEventOrTimeout(timeoutMedium)
		}
	}
}

func (postMgr *PostManager) postOnEventOrTimeout(timeout time.Duration) bool {
	select {
	case <-postMgr.postChan:
		return postMgr.postConfig()
	case <-time.After(timeout):
		return postMgr.postConfig()
	}
}

func (postMgr *PostManager) postConfig() bool {
	httpReqBody := bytes.NewBuffer([]byte(postMgr.activeConfig))

	req, err := http.NewRequest("POST", postMgr.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return false
	}
	log.Debugf("[AS3] POSTing request to %v", postMgr.as3APIURL)
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpPOST(req)
	if httpResp == nil || responseMap == nil {
		return false
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return handleResponseStatusOK(responseMap)
	case http.StatusServiceUnavailable:
		return postMgr.handleResponseStatusServiceUnavailable()
	default:
		return postMgr.handleResponseOthers(responseMap)
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

func handleResponseStatusOK(responseMap map[string]interface{}) bool {
	//traverse all response results
	results := (responseMap["results"]).([]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		//log result with code, tenant and message
		log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
	}
	return true
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable() bool {
	log.Debugf("[AS3] Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", timeoutSmall)
	return postMgr.postOnEventOrTimeout(timeoutSmall)
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}) bool {
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			//log result with code, tenant and message
			log.Errorf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
		}
	} else {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", responseMap["code"])
	}

	if postMgr.LogResponse {
		log.Errorf("[AS3] Raw response from Big-IP: %v ", responseMap)
	}
	return postMgr.postOnEventOrTimeout(timeoutMedium)
}
