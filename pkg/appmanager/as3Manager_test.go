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
package appmanager

import (
	"crypto/md5"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("AS3Manager Tests", func() {
	var mockMgr *mockAppManager
	var mw *test.MockWriter
	BeforeEach(func() {
		RegisterBigIPSchemaTypes()

		mw = &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		fakeClient := fake.NewSimpleClientset()
		Expect(fakeClient).ToNot(BeNil())

		mockMgr = newMockAppManager(&Params{
			KubeClient:       fakeClient,
			ConfigWriter:     mw,
			restClient:       test.CreateFakeHTTPClient(),
			RouteClientV1:    test.CreateFakeHTTPClient(),
			IsNodePort:       true,
			broadcasterFunc:  NewFakeEventBroadcaster,
			ManageConfigMaps: true,
		})
	})
	AfterEach(func() {
		mockMgr.shutdown()
	})

	Describe("Validating AS3 ConfigMap with AS3Manager", func() {
		It("AS3 declaration with Invalid JSON", func() {
			data := readConfigFile(configPath + "as3config_invalid_JSON.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template is not a valid JSON.")
		})
		It("AS3 declaration with all Tenants, Applications and Pools", func() {
			data := readConfigFile(configPath + "as3config_valid.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(true), "AS3 Template parsed succesfully.")
		})
		It("AS3 declaration without Pools", func() {
			data := readConfigFile(configPath + "as3config_without_pools.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(true), "AS3 Template parsed succesfully [No Pools].")
		})
		It("AS3 declaration without Applications", func() {
			data := readConfigFile(configPath + "as3config_without_apps.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(true), "AS3 Template parsed succesfully [No Applications].")
		})
		It("AS3 declaration without Tenants", func() {
			data := readConfigFile(configPath + "as3config_without_tenants.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template parsed succesfully, [No Tenants].")
		})
		It("AS3 template without ADC declaration", func() {
			data := readConfigFile(configPath + "as3config_without_adc.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template without ADC declaration should not be processed.")
		})
	})

	Describe("Create HTTP REST mock client and test POST call", func() {

		It("Test POST call request with 200 OK response", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":true,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				// Send response to be tested
				data := `{"results":[{"message":"Success","host":"localhost","tenant":"Sample_01","runTime":262,"code":200}]}`
				_, err := rw.Write([]byte(data))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			// Use Client & URL from our local test server
			api := AS3RESTClient{server.Client(), server.URL, "", ""}
			_, status := api.restCallToBigIP(method, route, template, false)
			Expect(status).To(BeTrue())
		})

		It("Test POST call request with 500 response", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":true,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				// Send response to be tested
				data := `{"results":[{"message":"no change","host":"localhost","tenant":"Sample_01","runTime":262,"code":200}]}`
				rw.WriteHeader(500)
				_, err := rw.Write([]byte(data))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			// Use Client & URL from our local test server
			api := AS3RESTClient{server.Client(), server.URL, "", ""}
			_, status := api.restCallToBigIP(method, route, template, false)
			Expect(status).To(BeFalse())
		})

		It("Test POST call response with invalid json string", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":true,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				// Send response to be tested
				//Invalid json string as response
				data := `Invalid json string`
				_, err := rw.Write([]byte(data))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			// Use Client & URL from our local test server
			api := AS3RESTClient{server.Client(), server.URL, "", ""}
			_, status := api.restCallToBigIP(method, route, template, false)
			Expect(status).To(BeFalse())
		})

		It("Test POST call when server is down/closed", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":true,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				data := `{"results":[{"message":"no change","host":"localhost","tenant":"Sample_01","runTime":262,"code":200}]}`
				_, err := rw.Write([]byte(data))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			// Use Client & URL from our local test server
			api := AS3RESTClient{server.Client(), server.URL, "", ""}
			//Close serve to test serve failure
			server.Close()
			_, status := api.restCallToBigIP(method, route, template, false)
			Expect(status).To(BeFalse())
		})

		It("Test for same declaration posting to bigip", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":true,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				// Send response to be tested
				data := `{"results":[{"message":"no change","host":"localhost","tenant":"Sample_01","runTime":262,"code":200}]}`
				_, err := rw.Write([]byte(data))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			h := md5.New()
			io.WriteString(h, string(template))
			oldChecksum := string(h.Sum(nil))
			// Use Client & URL from our local test server
			api := AS3RESTClient{server.Client(), server.URL, oldChecksum, ""}
			_, status := api.restCallToBigIP(method, route, template, false)
			Expect(status).To(BeTrue())
		})

		It("Test for new declaration posting to bigip", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":false,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				// Send response to be tested
				data := `{"results":[{"message":"no change","host":"localhost","tenant":"Sample_01","runTime":262,"code":200}]}`
				_, err := rw.Write([]byte(data))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			// Use Client & URL from our local test server
			api := AS3RESTClient{server.Client(), server.URL, "", ""}
			_, status := api.restCallToBigIP(method, route, template, false)
			Expect(status).To(BeTrue())
		})
	})
	Describe("Validate Generated Unified Declaration", func() {
		It("Unified Declaration only with User Defined ConfigMap", func() {
			var cfg, generatedCfg interface{}

			data := readConfigFile(configPath + "as3config_valid.json")
			err := json.Unmarshal([]byte(data), &cfg)
			Expect(err).To(BeNil(), "Config should be json")
			mockMgr.appMgr.activeCfgMap.Data = string(data)

			result, _ := mockMgr.appMgr.getUnifiedAS3Declaration(as3Declaration(mockMgr.appMgr.activeCfgMap.Data), nil)

			err = json.Unmarshal([]byte(result), &generatedCfg)
			Expect(err).To(BeNil(), "Failed to Create Valid JSON")

			Expect(reflect.DeepEqual(cfg, generatedCfg)).To(BeTrue(), "Failed to Create JSON with correct configuration")
		})
		It("Unified Declaration only with Openshift Route", func() {
			var origCfg, generatedCfg interface{}
			var cfg as3ADC

			data := readConfigFile(configPath + "as3_route_declaration.json")
			err := json.Unmarshal([]byte(data), &origCfg)
			Expect(err).To(BeNil(), "Original Config should be json")

			data = readConfigFile(configPath + "as3_route.json")
			err = json.Unmarshal([]byte(data), &cfg)
			Expect(err).To(BeNil(), "Route Config should be json")
			mockMgr.appMgr.as3RouteCfg.Data = cfg

			result, _ := mockMgr.appMgr.getUnifiedAS3Declaration("", mockMgr.appMgr.as3RouteCfg.Data)

			err = json.Unmarshal([]byte(result), &generatedCfg)
			Expect(err).To(BeNil(), "Failed to Create Valid JSON")

			Expect(reflect.DeepEqual(origCfg, generatedCfg)).To(BeTrue(), "Failed to Create JSON with correct configuration")
		})
		It("Unified Declaration with User Defined ConfigMap and Openshift Route", func() {
			var origCfg, userCfg, generatedCfg interface{}
			var cfg as3ADC

			data := readConfigFile(configPath + "as3_route_cfgmap_declaration.json")
			err := json.Unmarshal([]byte(data), &origCfg)
			Expect(err).To(BeNil(), "Original Config should be json")

			data = readConfigFile(configPath + "as3config_valid.json")
			err = json.Unmarshal([]byte(data), &userCfg)
			Expect(err).To(BeNil(), "Config should be json")
			mockMgr.appMgr.activeCfgMap.Data = string(data)

			data = readConfigFile(configPath + "as3_route.json")
			err = json.Unmarshal([]byte(data), &cfg)
			Expect(err).To(BeNil(), "Route Config should be json")
			mockMgr.appMgr.as3RouteCfg.Data = cfg

			result, _ := mockMgr.appMgr.getUnifiedAS3Declaration(as3Declaration(mockMgr.appMgr.activeCfgMap.Data), mockMgr.appMgr.as3RouteCfg.Data)

			err = json.Unmarshal([]byte(result), &generatedCfg)
			Expect(err).To(BeNil(), "Failed to Create Valid JSON")

			Expect(reflect.DeepEqual(origCfg, generatedCfg)).To(BeTrue(), "Failed to Create JSON with correct configuration")
		})
	})
})
