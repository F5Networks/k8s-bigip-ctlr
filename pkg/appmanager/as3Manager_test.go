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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Create HTTP REST mock client and test POST call", func() {

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
