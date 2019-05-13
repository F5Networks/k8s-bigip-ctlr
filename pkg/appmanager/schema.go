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
 * WITHOUT WARRANTIES OR conditionS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"net"
	"strconv"

	"github.com/xeipuuv/gojsonschema"
)

// Big-IP ipv4/ipv6 checkers
type BigIPv4FormatChecker struct{}

func (f BigIPv4FormatChecker) IsFormat(input interface{}) bool {
	var strInput = input.(string)
	ip, rd := split_ip_with_route_domain(strInput)
	if rd != "" {
		if _, err := strconv.Atoi(rd); err != nil {
			return false
		}
	}

	address := net.ParseIP(ip)
	if nil == address.To4() {
		return false
	}
	return true
}

type BigIPv6FormatChecker struct{}

func (f BigIPv6FormatChecker) IsFormat(input interface{}) bool {
	var strInput = input.(string)
	ip, rd := split_ip_with_route_domain(strInput)
	if rd != "" {
		if _, err := strconv.Atoi(rd); err != nil {
			return false
		}
	}

	address := net.ParseIP(ip)
	if nil == address.To16() {
		return false
	}

	return true
}

// Add new data format to the library
func RegisterBigIPSchemaTypes() {
	gojsonschema.FormatCheckers.Add("bigipv4", BigIPv4FormatChecker{})
	gojsonschema.FormatCheckers.Add("bigipv6", BigIPv6FormatChecker{})
}
