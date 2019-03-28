/*-
 * Copyright (c) 2016-2018, F5 Networks, Inc.
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
	"net/http"
	"net/http/httptest"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("As3Manager Unit Tests", func() {

	Describe("Validating AS3 ConfigMap with AS3Manager", func() {
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

		It("AS3 declaration without ADC Class", func() {
			data := readConfigFile(configPath + "as3config_without_adc.json")
			_, ok := mockMgr.appMgr.getAS3ObjectFromTemplate(as3Template(data))
			Expect(ok).To(Equal(false), "AS3 Template without ADC class should not be processed.")
		})
	})

	Describe("Create HTTP REST mock client and test POST call", func() {

		It("AS3 declaratyion POST call test with 200 OK response", func() {
			route := "/mgmt/shared/appsvcs/declare"
			method := "POST"
			var template as3Declaration = `{"class":"AS3","action":"deploy","persist":true,}`
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Test request parameters
				Expect(req.URL.String()).To(BeEquivalentTo("/mgmt/shared/appsvcs/declare"))
				// Send response to be tested
				_, err := rw.Write([]byte("OK"))
				Expect(err).To(BeNil(), "Response writer should be written.")
			}))
			// Close the server when test finishes
			defer server.Close()
			// Use Client & URL from our local test server
			api := As3RestClient{server.Client(), server.URL}
			body, status := api.restCallToBigIP(method, route, template)
			Expect(status).To(BeTrue())
			Expect(body).To(BeEquivalentTo("OK"), "Response should be captured.")
		})

	})
})
