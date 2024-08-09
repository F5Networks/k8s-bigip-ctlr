/*-
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Route Domain", func() {
	It("TestBigIpv4FormatChecker", func() {
		var schemaValidator BigIPv4FormatChecker

		type testDataType struct {
			address string
			isValid bool
		}
		testData := []testDataType{
			{
				address: "",
				isValid: false,
			}, {
				address: "1.2.3.4",
				isValid: true,
			}, {
				address: "http://bad",
				isValid: false,
			}, {
				address: "bad%0",
				isValid: false,
			}, {
				address: "1.2.3.4%bad",
				isValid: false,
			}, {
				address: "1.2.3.4%4",
				isValid: true,
			}, {
				address: "::",
				isValid: false,
			}, {
				address: "ff80::%12",
				isValid: false,
			},
		}

		for _, td := range testData {
			isValid := schemaValidator.IsFormat(td.address)
			Expect(isValid).To(Equal(td.isValid))
		}
	})

	It("TestBigIpv6FormatChecker", func() {
		var schemaValidator BigIPv6FormatChecker

		// Note: IPv4 addresses are valid IPv6 addresses
		//       (so we should always check for IPv4 first
		//        if we need to distinguish between the two)
		type testDataType struct {
			address string
			isValid bool
		}
		testData := []testDataType{
			{
				address: "",
				isValid: false,
			}, {
				address: "1.2.3.4",
				isValid: true,
			}, {
				address: "http://bad",
				isValid: false,
			}, {
				address: "bad%0",
				isValid: false,
			}, {
				address: "1.2.3.4%bad",
				isValid: false,
			}, {
				address: "1.2.3.4%4",
				isValid: true,
			}, {
				address: "::",
				isValid: true,
			}, {
				address: "ff80::%12",
				isValid: true,
			},
		}

		for _, td := range testData {
			isValid := schemaValidator.IsFormat(td.address)
			Expect(isValid).To(Equal(td.isValid))
		}
	})
})
