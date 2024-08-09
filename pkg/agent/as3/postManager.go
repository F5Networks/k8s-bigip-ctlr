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

package as3

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

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	timeoutNill   = 0 * time.Second
	timeoutSmall  = 3 * time.Second
	timeoutMedium = 30 * time.Second
	timeoutLarge  = 180 * time.Second
)

const (
	responseStatusOk                  = "statusOK"
	responseStatusCommon              = "statusCommonResponse"
	responseStatusNotFound            = "statusNotFound"
	responseStatusServiceUnavailable  = "statusServiceUnavailable"
	responseStatusUnprocessableEntity = "statusUnprocessableEntity"
	responseStatusUnAuthorized        = "statusUnAuthorized"
	responseStatusDummy               = "dummy"
)

type PostManager struct {
	postChan   chan config
	HttpClient *http.Client
	activeCfg  config
	PostParams
}

type PostParams struct {
	BIGIPUsername string
	BIGIPPassword string
	BIGIPURL      string
	TrustedCerts  string
	SSLInsecure   bool
	AS3PostDelay  int
	// Log the AS3 response body in Controller logs
	LogAS3Response    bool
	LogAS3Request     bool
	RouteClientV1     routeclient.RouteV1Interface
	HTTPClientMetrics bool
}

type config struct {
	data      string
	as3APIURL string
}

func NewPostManager(params PostParams) *PostManager {
	pm := &PostManager{
		postChan:   make(chan config, 1),
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

	if postMgr.HTTPClientMetrics {
		log.Debug("[BIGIP] Http client instrumented with metrics!")
		instrumentedRoundTripper := promhttp.InstrumentRoundTripperInFlight(prometheus.ClientInFlightGauge,
			promhttp.InstrumentRoundTripperCounter(prometheus.ClientAPIRequestsCounter,
				promhttp.InstrumentRoundTripperTrace(prometheus.ClientTrace,
					promhttp.InstrumentRoundTripperDuration(prometheus.ClientHistVec, tr),
				),
			),
		)
		postMgr.HttpClient = &http.Client{
			Transport: instrumentedRoundTripper,
			Timeout:   timeoutLarge,
		}
	} else {
		postMgr.HttpClient = &http.Client{
			Transport: tr,
			Timeout:   timeoutLarge,
		}
	}
}

func (postMgr *PostManager) getAS3APIURL(tenants []string) string {
	apiURL := postMgr.BIGIPURL + "/mgmt/shared/appsvcs/declare/" + strings.Join(tenants, ",")
	return apiURL
}

func (postMgr *PostManager) getAS3VersionURL() string {
	apiURL := postMgr.BIGIPURL + "/mgmt/shared/appsvcs/info"
	return apiURL
}

func getTimeDurationForErrorResponse(errRsp string) time.Duration {
	duration := timeoutNill
	switch errRsp {
	case responseStatusCommon, responseStatusUnprocessableEntity:
		duration = timeoutMedium
	case responseStatusServiceUnavailable:
		duration = timeoutSmall
	}
	return duration
}

func (postMgr *PostManager) postConfigRequests(data string, url string) (bool, string) {
	cfg := config{
		data:      data,
		as3APIURL: url,
	}

	// log as3 request
	if postMgr.LogAS3Request {
		postMgr.logAS3Request(data)
	}

	httpReqBody := bytes.NewBuffer([]byte(cfg.data))

	req, err := http.NewRequest("POST", cfg.as3APIURL, httpReqBody)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return false, responseStatusCommon
	}
	log.Debugf("[AS3] posting request to %v", cfg.as3APIURL)
	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil || responseMap == nil {
		return false, responseStatusCommon
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return postMgr.handleResponseStatusOK(responseMap)
	case http.StatusServiceUnavailable:
		return postMgr.handleResponseStatusServiceUnavailable(responseMap)
	case http.StatusNotFound:
		return postMgr.handleResponseStatusNotFound(responseMap)
	case http.StatusUnprocessableEntity:
		return postMgr.handleStatusUnprocessableEntity(responseMap)
	case http.StatusUnauthorized:
		return postMgr.handleResponseStatusUnAuthorized(responseMap)
	default:
		return postMgr.handleResponseOthers(responseMap)
	}
}

func (postMgr *PostManager) GetBigipAS3Version() (string, string, string, error) {
	url := postMgr.getAS3VersionURL()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("[AS3] Creating new HTTP request error: %v ", err)
		return "", "", "", err
	}

	log.Debugf("[AS3] posting GET BIGIP AS3 Version request on %v", url)
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
	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if _, ok := responseMap["message"].(string); ok {
					return "", "", "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, responseMap["message"])
				} else {
					return "", "", "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v", httpResp.StatusCode)
				}
			}
		}
	}
	return "", "", "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
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
	case http.StatusUnauthorized:
		if code, ok := responseMap["code"].(float64); ok {
			if int(code) == http.StatusUnauthorized {
				if _, ok := responseMap["message"].(string); ok {
					return "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v Message: %v", httpResp.StatusCode, responseMap["message"])
				} else {
					return "", fmt.Errorf("authentication failed,"+
						" Error response from BIGIP with status code %v", httpResp.StatusCode)
				}
			}
		}
	}
	return "", fmt.Errorf("Error response from BIGIP with status code %v", httpResp.StatusCode)
}

func (postMgr *PostManager) httpReq(request *http.Request) (*http.Response, map[string]interface{}) {
	httpResp, err := postMgr.HttpClient.Do(request)
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
		if httpResp.StatusCode == http.StatusUnauthorized {
			log.Errorf("[AS3] Unauthorized access to BIG-IP, please check the credentials, message: %v", string(body))
		}
		if postMgr.LogAS3Response {
			log.Errorf("[AS3] Raw response from Big-IP: %v", string(body))
		}
		return nil, nil
	}
	return httpResp, response
}

func (postMgr *PostManager) handleResponseStatusOK(responseMap map[string]interface{}) (bool, string) {
	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap)
	}
	// traverse all response results
	results := (responseMap["results"]).([]interface{})
	for _, value := range results {
		v := value.(map[string]interface{})
		// log result with code, tenant and message
		log.Debugf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
	}
	return true, responseStatusOk
}

func (postMgr *PostManager) handleResponseStatusServiceUnavailable(responseMap map[string]interface{}) (bool, string) {
	log.Errorf("[AS3] Big-IP Responded with error code: %v", responseMap["code"])
	log.Debugf("[AS3] Response from BIG-IP: BIG-IP is busy, waiting %v seconds and re-posting the declaration", timeoutSmall)
	// return postMgr.postOnEventOrTimeout(timeoutSmall, cfg)
	return false, responseStatusServiceUnavailable
}

func (postMgr *PostManager) handleResponseStatusNotFound(responseMap map[string]interface{}) (bool, string) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", http.StatusNotFound)
	}

	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap)
	}
	return true, responseStatusNotFound
}

func (postMgr *PostManager) handleResponseStatusUnAuthorized(responseMap map[string]interface{}) (bool, string) {
	if _, ok := responseMap["code"].(float64); ok {
		if _, ok := responseMap["message"].(string); ok {
			log.Errorf("[AS3] authentication failed,"+
				" Error response from BIGIP with status code: 401 Message: %v", responseMap["message"])
		} else {
			log.Errorf("[AS3] authentication failed," +
				" Error response from BIGIP with status code: 401")
		}
	}

	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap)
	}
	return true, responseStatusUnAuthorized
}

func (postMgr *PostManager) handleStatusUnprocessableEntity(responseMap map[string]interface{}) (bool, string) {
	if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", http.StatusUnprocessableEntity)
	}

	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap)
	}
	return false, responseStatusUnprocessableEntity
}

func (postMgr *PostManager) handleResponseOthers(responseMap map[string]interface{}) (bool, string) {
	if results, ok := (responseMap["results"]).([]interface{}); ok {
		for _, value := range results {
			v := value.(map[string]interface{})
			// log result with code, tenant and message
			log.Errorf("[AS3] Response from BIG-IP: code: %v --- tenant:%v --- message: %v", v["code"], v["tenant"], v["message"])
		}
	} else if err, ok := (responseMap["error"]).(map[string]interface{}); ok {
		log.Errorf("[AS3] Big-IP Responded with error code: %v", err["code"])
	} else {
		log.Errorf("[AS3] Big-IP Responded with code: %v", responseMap["code"])
	}

	if postMgr.LogAS3Response {
		postMgr.logAS3Response(responseMap)
	}
	// return postMgr.postOnEventOrTimeout(timeoutMedium, cfg)
	return false, responseStatusCommon
}

func (postMgr *PostManager) getBigipRegKeyURL() string {
	apiURL := postMgr.BIGIPURL + "/mgmt/tm/shared/licensing/registration"
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
			log.Errorf("[AS3] error while reading declaration from AS3 response: %v\n", err)
			return
		}
		responseMap["declaration"] = as3Declaration(decl)
	}
	log.Debugf("[AS3] Raw response from Big-IP: %v ", responseMap)
}

func (postMgr *PostManager) logAS3Request(cfg string) {
	var as3Config map[string]interface{}
	err := json.Unmarshal([]byte(cfg), &as3Config)
	if err != nil {
		log.Errorf("Request body unmarshal failed: %v\n", err)
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
		log.Errorf("[AS3] Unified declaration error: %v\n", err)
		return
	}
	log.Debugf("[AS3] Unified declaration: %v\n", as3Declaration(decl))
}
