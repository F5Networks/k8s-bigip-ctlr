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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Route Domain", func() {
	It("split_ip_with_route_domain", func() {
		type testDataType struct {
			address      string
			expectedIP   string
			expectedRD   string
			expectedCIDR string
		}
		testData := []testDataType{
			{
				address:      "",
				expectedIP:   "",
				expectedRD:   "",
				expectedCIDR: "",
			}, {
				address:      "1.2.3.4",
				expectedIP:   "1.2.3.4",
				expectedRD:   "",
				expectedCIDR: "",
			}, {
				address:      "fe80::",
				expectedIP:   "fe80::",
				expectedRD:   "",
				expectedCIDR: "",
			}, {
				address:      "1.2.3.4%56",
				expectedIP:   "1.2.3.4",
				expectedRD:   "56",
				expectedCIDR: "",
			}, {
				address:      "fe80::%0",
				expectedIP:   "fe80::",
				expectedRD:   "0",
				expectedCIDR: "",
			}, {
				address:      "fe80::/40",
				expectedIP:   "fe80::",
				expectedRD:   "",
				expectedCIDR: "40",
			}, {
				address:      "1.2.3.4/31",
				expectedIP:   "1.2.3.4",
				expectedRD:   "",
				expectedCIDR: "31",
			}, {
				address:      "1.2.3.4/31%56",
				expectedIP:   "1.2.3.4",
				expectedRD:   "56",
				expectedCIDR: "31",
			}, {
				address:      "fe80::/35%5",
				expectedIP:   "fe80::",
				expectedRD:   "5",
				expectedCIDR: "35",
			}, {
				address:      "1.2.3.4%56/31",
				expectedIP:   "1.2.3.4%56/31",
				expectedRD:   "",
				expectedCIDR: "",
			}, {
				address:      "fe80::%5/35",
				expectedIP:   "fe80::%5/35",
				expectedRD:   "",
				expectedCIDR: "",
			}, {
				address:      "fe80::%ab",
				expectedIP:   "fe80::%ab",
				expectedRD:   "",
				expectedCIDR: "",
			},
		}

		for _, td := range testData {
			ip, rd, cidr := Split_ip_with_route_domain_cidr(td.address)
			Expect(ip).To(Equal(td.expectedIP))
			Expect(rd).To(Equal(td.expectedRD))
			Expect(cidr).To(Equal(td.expectedCIDR))
		}
	})
})
