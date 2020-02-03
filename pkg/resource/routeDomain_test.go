/*-
 * Copyright (c) 2017,2018, F5 Networks, Inc.
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

package resource

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Route Domain", func() {
	It("split_ip_with_route_domain", func() {
		type testDataType struct {
			address    string
			expectedIP string
			expectedRD string
		}
		testData := []testDataType{
			{
				address:    "",
				expectedIP: "",
				expectedRD: "",
			}, {
				address:    "1.2.3.4",
				expectedIP: "1.2.3.4",
				expectedRD: "",
			}, {
				address:    "fe80::",
				expectedIP: "fe80::",
				expectedRD: "",
			}, {
				address:    "1.2.3.4%56",
				expectedIP: "1.2.3.4",
				expectedRD: "56",
			}, {
				address:    "fe80::%0",
				expectedIP: "fe80::",
				expectedRD: "0",
			},
		}

		for _, td := range testData {
			ip, rd := Split_ip_with_route_domain(td.address)
			Expect(ip).To(Equal(td.expectedIP))
			Expect(rd).To(Equal(td.expectedRD))
		}
	})
})
