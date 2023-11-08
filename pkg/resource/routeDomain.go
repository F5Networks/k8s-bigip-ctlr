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
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"net"
	"strconv"
	"strings"
)

func Split_ip_with_route_domain_cidr(address string) (ip string, rd string, cidr string) {
	// Split the address into the ip, CIDR (optional) and routeDomain (optional) parts
	//     address is of the form: <ipv4_or_ipv6>[/<CIDR>][%<routeDomainID>]
	match := strings.Split(address, "%")
	if len(match) == 2 && strings.Contains(match[1], "/") {
		// Address is in the format <ipv4_or_ipv6>[%<routeDomainID>][/<CIDR>], which is invalid
		log.Errorf("Error CIDR format is invalid for address: %s", address)
	}
	ipCIDR := strings.Split(match[0], "/")
	if len(match) == 2 {
		_, err := strconv.Atoi(match[1])
		//Matches only when RD contains number, Not allowing RD has 80f
		if err == nil {
			ip = ipCIDR[0]
			rd = match[1]
		} else {
			ip = address
		}
	} else {
		ip = ipCIDR[0]
	}
	if len(ipCIDR) == 2 {
		if !strings.Contains(ipCIDR[1], "%") {
			cidr = ipCIDR[1]
		} else {
			ipCIDR = strings.Split(ipCIDR[1], "%")
			cidr = ipCIDR[0]
		}
		if _, _, err := net.ParseCIDR(ip + "/" + cidr); err != nil {
			log.Errorf("Error CIDR for the address: %s is not valid", address)
		}
	}
	return
}
