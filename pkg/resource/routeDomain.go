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
 * WITHOUT WARRANTIES OR conditionS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package resource

import (
	"strconv"
	"strings"
)

func Split_ip_with_route_domain(address string) (ip string, rd string) {
	// Split the address into the ip and routeDomain (optional) parts
	//     address is of the form: <ipv4_or_ipv6>[%<routeDomainID>]
	match := strings.Split(address, "%")
	if len(match) == 2 {
		_, err := strconv.Atoi(match[1])
		//Matches only when RD contains number, Not allowing RD has 80f
		if err == nil {
			ip = match[0]
			rd = match[1]
		} else {
			ip = address
		}
	} else {
		ip = match[0]
	}
	return
}
