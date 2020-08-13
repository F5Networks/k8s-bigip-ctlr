/*-
 * Copyright (c) 2016-2020, F5 Networks, Inc.
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
	"fmt"
	"sort"
	"strconv"
	"strings"

	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"github.com/xeipuuv/gojsonschema"
)

// Validates the AS3 Template
func (am *AS3Manager) validateAS3Template(template string) bool {
	var schemaLoader gojsonschema.JSONLoader
	// Load AS3 Schema
	schemaLoader = gojsonschema.NewReferenceLoader(am.As3SchemaLatest)
	// Load AS3 Template
	documentLoader := gojsonschema.NewStringLoader(template)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		log.Errorf("%s", err)
		return false
	}

	if !result.Valid() {
		log.Errorf("[AS3] Template is not valid. see errors")
		for _, desc := range result.Errors() {
			log.Errorf("- %s\n", desc)
		}
		return false
	}

	return true
}

func (am *AS3Manager) processResourcesForAS3(sharedApp as3Application) {
	for _, cfg := range am.Resources.RsCfgs {
		//Create policies
		createPoliciesDecl(cfg, sharedApp)

		//Create health monitor declaration
		createMonitorDecl(cfg, sharedApp)

		//Create pools
		createPoolDecl(cfg, sharedApp)

		//Create AS3 Service for virtual server
		createServiceDecl(cfg, sharedApp)
	}
}

// Returns a pool of IP address.
//func getFakeEndpointsForPool(tenant tenantName, app appName, pool poolName) pool {
//	return []Member{
//		{"1.1.1.1", 80, ""},
//		{"2.2.2.2", 80, ""},
//		{"3.3.3.3", 80, ""},
//	}
//}

func (am *AS3Manager) processIRulesForAS3(sharedApp as3Application) {
	// Create irule declaration
	for _, v := range am.IrulesMap {
		iRule := &as3IRules{}
		iRule.Class = "iRule"
		iRule.IRule = v.Code
		sharedApp[as3FormattedString(v.Name, deriveResourceTypeFromAS3Value(v.Name))] = iRule
	}
}

func (am *AS3Manager) processDataGroupForAS3(sharedApp as3Application) {
	for idk, idg := range am.IntDgMap {
		for _, dg := range idg {
			dataGroupRecord, found := sharedApp[as3FormattedString(dg.Name, "")]
			if !found {
				dgMap := &as3DataGroup{}
				dgMap.Class = "Data_Group"
				dgMap.KeyDataType = "string"
				for _, record := range dg.Records {
					var rec as3Record
					rec.Key = record.Name
					// To override default Value created for CCCL for certain DG types
					if val, ok := getDGRecordValueForAS3(idk.Name, sharedApp); ok {
						rec.Value = val
					} else {
						rec.Value = as3FormattedString(record.Data, deriveResourceTypeFromAS3Value(record.Data))
					}
					dgMap.Records = append(dgMap.Records, rec)
				}
				// sort above create dgMap records.
				sort.Slice(dgMap.Records, func(i, j int) bool { return (dgMap.Records[i].Key < dgMap.Records[j].Key) })
				sharedApp[as3FormattedString(dg.Name, "")] = dgMap
			} else {
				for _, record := range dg.Records {
					var rec as3Record
					rec.Key = record.Name
					// To override default Value created for CCCL for certain DG types
					if val, ok := getDGRecordValueForAS3(idk.Name, sharedApp); ok {
						rec.Value = val
					} else {
						rec.Value = as3FormattedString(record.Data, deriveResourceTypeFromAS3Value(record.Data))
					}
					sharedApp[as3FormattedString(dg.Name, "")].(*as3DataGroup).Records = append(dataGroupRecord.(*as3DataGroup).Records, rec)
				}
				// sort above created
				sort.Slice(sharedApp[as3FormattedString(dg.Name, "")].(*as3DataGroup).Records,
					func(i, j int) bool {
						return (sharedApp[as3FormattedString(dg.Name, "")].(*as3DataGroup).Records[i].Key <
							sharedApp[as3FormattedString(dg.Name, "")].(*as3DataGroup).Records[j].Key)
					})
			}
		}
	}
}

func getDGRecordValueForAS3(dgName string, sharedApp as3Application) (string, bool) {
	switch dgName {
	case ReencryptServerSslDgName:
		for _, v := range sharedApp {
			if svc, ok := v.(*as3Service); ok && svc.Class == "Service_HTTPS" {
				if val, ok := svc.ClientTLS.(*as3ResourcePointer); ok {
					return val.BigIP, true
				}
				if val, ok := svc.ClientTLS.(string); ok {
					return strings.Join([]string{"", DEFAULT_PARTITION, as3SharedApplication, val}, "/"), true
				}
				log.Errorf("Unable to find serverssl for Data Group: %v\n", dgName)
			}
		}
	}
	return "", false
}

func (am *AS3Manager) processCustomProfilesForAS3(sharedApp as3Application) {
	caBundleName := "serverssl_ca_bundle"
	var tlsClient *as3TLSClient
	// TLS Certificates are available in CustomProfiles
	for key, prof := range am.Profs {
		// Create TLSServer and Certificate for each profile
		svcName := as3FormattedString(key.ResourceName, deriveResourceTypeFromAS3Value(key.ResourceName))
		if svcName == "" {
			continue
		}
		if ok := am.createUpdateTLSServer(prof, svcName, sharedApp); ok {
			// Create Certificate only if the corresponding TLSServer is created
			createCertificateDecl(prof, sharedApp)
		} else {
			createUpdateCABundle(prof, caBundleName, sharedApp)
			if tlsClient == nil {
				tlsClient = createTLSClient(prof, svcName, caBundleName, sharedApp)
			}
			skey := SecretKey{
				Name: prof.Name + "-ca",
			}
			if _, ok := am.Profs[skey]; ok && tlsClient != nil {
				// If a profile exist in customProfiles with key as created above
				// then it indicates that secure-serverssl needs to be added
				tlsClient.ValidateCertificate = true
			}
		}
	}
}

// Identify rule with condition that matches with given host and path
// Add WAF policy action to that rule
func updatePolicyWithWAF(ep *as3EndpointPolicy, rec Record, res F5Resources) {
	action := &as3Action{
		Type:  "waf",
		Event: "request",
		Policy: &as3ResourcePointer{
			BigIP: res.WAFPolicy,
		},
	}

	recPath := strings.TrimRight(rec.Path, "/")
	recPathElems := strings.Split(recPath, "/")[1:]

	for _, rule := range ep.Rules {
		var hosts []string
		var paths [][]string
		for _, cond := range rule.Conditions {
			if cond.All != nil {
				hosts = cond.All.Values
			}
			if cond.PathSegment != nil {
				paths = append(paths, cond.PathSegment.Values)
			}
		}

		if Contains(hosts, rec.Host) && len(recPathElems) == len(paths) {
			pathMatch := true
			for i, v := range recPathElems {
				if !Contains(paths[i], v) {
					pathMatch = false
					break
				}
			}
			if pathMatch {
				rule.Actions = append(rule.Actions, action)
				break
			}
		}
	}
}

func createPoliciesDecl(cfg *ResourceConfig, sharedApp as3Application) {
	_, port := ExtractVirtualAddressAndPort(cfg.Virtual.Destination)
	for _, pl := range cfg.Policies {
		//Create EndpointPolicy
		ep := &as3EndpointPolicy{}
		for _, rl := range pl.Rules {

			ep.Class = "Endpoint_Policy"
			s := strings.Split(pl.Strategy, "/")
			ep.Strategy = s[len(s)-1]

			//Create rules
			rulesData := &as3Rule{Name: as3FormattedString(rl.Name, cfg.MetaData.ResourceType)}

			//Create condition object
			createAS3RuleCondition(rl, rulesData, port)

			//Creat action object
			createAS3RuleAction(rl, rulesData, cfg.MetaData.ResourceType)

			ep.Rules = append(ep.Rules, rulesData)
		}
		if cfg.MetaData.ResourceType == ResourceTypeIngress {
			pl.Name = strings.Title(pl.Name)
		}
		//Setting Endpoint_Policy Name
		sharedApp[as3FormattedString(pl.Name, cfg.MetaData.ResourceType)] = ep
	}
}

// Create AS3 Pools for Route
func createPoolDecl(cfg *ResourceConfig, sharedApp as3Application) {
	for _, v := range cfg.Pools {
		pool := &as3Pool{}
		pool.LoadBalancingMode = v.Balance
		pool.Class = "Pool"
		for _, val := range v.Members {
			var member as3PoolMember
			member.AddressDiscovery = "static"
			member.ServicePort = val.Port
			member.ServerAddresses = append(member.ServerAddresses, val.Address)
			pool.Members = append(pool.Members, member)
		}
		for _, val := range v.MonitorNames {
			var monitor as3ResourcePointer
			use := strings.Split(val, "/")
			monitor.Use = fmt.Sprintf("/%s/%s/%s",
				DEFAULT_PARTITION,
				as3SharedApplication,
				as3FormattedString(use[len(use)-1], cfg.MetaData.ResourceType),
			)
			pool.Monitors = append(pool.Monitors, monitor)
		}
		sharedApp[as3FormattedString(v.Name, cfg.MetaData.ResourceType)] = pool
	}
}

func updateVirtualToHTTPS(v *as3Service) {
	v.Class = "Service_HTTPS"
	redirect80 := false
	v.Redirect80 = &redirect80
}

// Create AS3 Service for Route
func createServiceDecl(cfg *ResourceConfig, sharedApp as3Application) {
	svc := &as3Service{}
	numPolicies := len(cfg.Virtual.Policies)
	switch {
	case numPolicies == 1:
		policyName := cfg.Virtual.Policies[0].Name
		if cfg.MetaData.ResourceType == ResourceTypeIngress {
			policyName = strings.Title(cfg.Virtual.Policies[0].Name)
		}
		svc.PolicyEndpoint = fmt.Sprintf("/%s/%s/%s",
			DEFAULT_PARTITION,
			as3SharedApplication,
			as3FormattedString(policyName, cfg.MetaData.ResourceType))
	case numPolicies > 1:
		var peps []as3ResourcePointer
		for _, pep := range cfg.Virtual.Policies {
			if cfg.MetaData.ResourceType == ResourceTypeIngress {
				pep.Name = strings.Title(pep.Name)
			}
			svc.PolicyEndpoint = append(
				peps,
				as3ResourcePointer{
					BigIP: fmt.Sprintf("/%s/%s/%s",
						DEFAULT_PARTITION,
						as3SharedApplication,
						pep.Name,
					),
				},
			)
		}
		svc.PolicyEndpoint = peps
	case numPolicies == 0:
		// No policies since we need to handle the pool name.
		ps := strings.Split(cfg.Virtual.PoolName, "/")
		if cfg.Virtual.PoolName != "" {
			svc.Pool = fmt.Sprintf("/%s/%s/%s",
				DEFAULT_PARTITION,
				as3SharedApplication,
				as3FormattedString(ps[len(ps)-1], cfg.MetaData.ResourceType))
		}
	}

	svc.Layer4 = cfg.Virtual.IpProtocol
	svc.Source = "0.0.0.0/0"
	svc.TranslateServerAddress = true
	svc.TranslateServerPort = true

	svc.Class = "Service_HTTP"
	virtualAddress, port := ExtractVirtualAddressAndPort(cfg.Virtual.Destination)
	// verify that ip address and port exists.
	if virtualAddress != "" && port != 0 {
		va := append(svc.VirtualAddresses, virtualAddress)
		svc.VirtualAddresses = va
		svc.VirtualPort = port
	} else {
		log.Error("Invalid Virtual Server Destination IP address/Port.")
	}

	svc.SNAT = "auto"
	for _, v := range cfg.Virtual.IRules {
		splits := strings.Split(v, "/")
		iRuleName := splits[len(splits)-1]
		if iRuleName == SslPassthroughIRuleName {
			svc.ServerTLS = &as3ResourcePointer{
				BigIP: "/Common/clientssl",
			}
			updateVirtualToHTTPS(svc)
		}
		svc.IRules = append(svc.IRules, as3FormattedString(iRuleName, cfg.MetaData.ResourceType))
	}

	sharedApp[as3FormattedString(cfg.Virtual.Name, cfg.MetaData.ResourceType)] = svc
}

// Create AS3 Rule Condition for Route
func createAS3RuleCondition(rl *Rule, rulesData *as3Rule, port int) {
	for _, c := range rl.Conditions {
		condition := &as3Condition{}
		if c.Host {
			condition.Name = "host"
			var values []string
			// For ports other then 80 and 443, attaching port number to host.
			// Ex. example.com:8080
			if port != 80 && port != 443 {
				for i := range c.Values {
					val := c.Values[i] + ":" + strconv.Itoa(port)
					values = append(values, val)
				}
				condition.All = &as3PolicyCompareString{
					Values: values,
				}
			} else {
				condition.All = &as3PolicyCompareString{
					Values: c.Values,
				}
			}
			if c.HTTPHost {
				condition.Type = "httpHeader"
			}
			if c.Equals {
				condition.All.Operand = "equals"
			}
		} else if c.PathSegment {
			condition.PathSegment = &as3PolicyCompareString{
				Values: c.Values,
			}
			if c.Name != "" {
				condition.Name = c.Name
			}
			condition.Index = c.Index
			if c.HTTPURI {
				condition.Type = "httpUri"
			}
			if c.Equals {
				condition.PathSegment.Operand = "equals"
			}
		} else if c.Path {
			condition.Path = &as3PolicyCompareString{
				Values: c.Values,
			}
			if c.Name != "" {
				condition.Name = c.Name
			}
			condition.Index = c.Index
			if c.HTTPURI {
				condition.Type = "httpUri"
			}
			if c.Equals {
				condition.Path.Operand = "equals"
			}
		} else if c.Tcp {
			condition.Type = "tcp"
			condition.Address = &as3PolicyCompareString{}
			condition.Address.Values = c.Values
		}
		if c.Request {
			condition.Event = "request"
		}

		rulesData.Conditions = append(rulesData.Conditions, condition)
	}
}

// Create AS3 Rule Action for Route
func createAS3RuleAction(rl *Rule, rulesData *as3Rule, resourceType string) {
	for _, v := range rl.Actions {
		action := &as3Action{}
		if v.Forward {
			action.Type = "forward"
		}
		if v.Reset {
			action.Type = "drop"
		}
		if v.Request {
			action.Event = "request"
		}
		if v.Redirect {
			action.Type = "httpRedirect"
		}
		if v.HTTPHost {
			action.Type = "httpHeader"
		}
		if v.HTTPURI {
			action.Type = "httpUri"
		}
		if v.Location != "" {
			action.Location = v.Location
		}
		// Handle hostname rewrite.
		if v.Replace && v.HTTPHost {
			action.Replace = &as3ActionReplaceMap{
				Value: v.Value,
				Name:  "host",
			}
		}
		// handle uri rewrite.
		if v.Replace && v.HTTPURI {
			action.Replace = &as3ActionReplaceMap{
				Value: v.Value,
			}
		}
		p := strings.Split(v.Pool, "/")
		if v.Pool != "" {
			action.Select = &as3ActionForwardSelect{
				Pool: &as3ResourcePointer{
					Use: as3FormattedString(p[len(p)-1], resourceType),
				},
			}
		}
		rulesData.Actions = append(rulesData.Actions, action)
	}
}

//Create health monitor declaration
func createMonitorDecl(cfg *ResourceConfig, sharedApp as3Application) {

	for _, v := range cfg.Monitors {
		monitor := &as3Monitor{}
		monitor.Class = "Monitor"
		monitor.Interval = v.Interval
		monitor.MonitorType = v.Type
		monitor.Timeout = v.Timeout
		val := 0
		monitor.TargetPort = &val
		targetAddressStr := ""
		monitor.TargetAddress = &targetAddressStr
		//Monitor type
		switch v.Type {
		case "http":
			adaptiveFalse := false
			monitor.Adaptive = &adaptiveFalse
			monitor.Dscp = &val
			monitor.Receive = "none"
			if v.Recv != "" {
				monitor.Receive = v.Recv
			}
			monitor.TimeUnitilUp = &val
			monitor.Send = v.Send
		case "https":
			//Todo: For https monitor type
			adaptiveFalse := false
			monitor.Adaptive = &adaptiveFalse
		}
		sharedApp[as3FormattedString(v.Name, cfg.MetaData.ResourceType)] = monitor
	}

}

func createUpdateCABundle(prof CustomProfile, caBundleName string, sharedApp as3Application) {
	// For TLSClient only Cert (DestinationCACertificate) is given and key is empty string
	if "" != prof.Cert && "" == prof.Key {
		caBundle, ok := sharedApp[caBundleName].(*as3CABundle)

		if !ok {
			caBundle = &as3CABundle{
				Class:  "CA_Bundle",
				Bundle: "",
			}
			sharedApp[caBundleName] = caBundle
		}
		caBundle.Bundle += "\n" + prof.Cert
	}
}

func createCertificateDecl(prof CustomProfile, sharedApp as3Application) {
	if "" != prof.Cert && "" != prof.Key {
		cert := &as3Certificate{
			Class:       "Certificate",
			Certificate: prof.Cert,
			PrivateKey:  prof.Key,
			ChainCA:     prof.CAFile,
		}

		sharedApp[as3FormattedString(prof.Name, deriveResourceTypeFromAS3Value(prof.Name))] = cert
	}
}

// createUpdateTLSServer creates a new TLSServer instance or updates if one exists already
func (am *AS3Manager) createUpdateTLSServer(prof CustomProfile, svcName string, sharedApp as3Application) bool {
	// A TLSServer profile needs to carry both Certificate and Key
	if "" != prof.Cert && "" != prof.Key {
		if svc, ok := sharedApp[svcName].(*as3Service); ok {
			tlsServerName := fmt.Sprintf("%s_tls_server", svcName)
			tlsServer, ok := sharedApp[tlsServerName].(*as3TLSServer)
			certName := as3FormattedString(prof.Name, deriveResourceTypeFromAS3Value(prof.Name))
			if !ok {
				tlsServer = &as3TLSServer{
					Class:        "TLS_Server",
					Certificates: []as3TLSServerCertificates{},
				}
				// RenegotiationEnabled MUST be disabled/false to handle CVE-2009-3555.
				boolFalse := false
				tlsServer.RenegotiationEnabled = &boolFalse

				sharedApp[tlsServerName] = tlsServer
				svc.ServerTLS = tlsServerName
				updateVirtualToHTTPS(svc)
			}
			tlsServer.Certificates = append(
				tlsServer.Certificates,
				as3TLSServerCertificates{
					Certificate: certName,
				},
			)
			if len(tlsServer.Certificates) != 0 {
				sort.Slice(tlsServer.Certificates,
					func(i, j int) bool {
						return (tlsServer.Certificates[i].Certificate < tlsServer.Certificates[j].Certificate)
					})
			}
			if am.enableTLS == "1.2" {
				tlsServer.Ciphers = am.ciphers
			} else if am.enableTLS == "1.3" {
				tlsServer.Tls1_3Enabled = true
				tlsServer.CipherGroup = &as3ResourcePointer{
					BigIP: am.tls13CipherGroupReference,
				}
			}

			return true

		}
	}
	return false
}

func createTLSClient(
	prof CustomProfile,
	svcName, caBundleName string,
	sharedApp as3Application,
) *as3TLSClient {
	// For TLSClient only Cert (DestinationCACertificate) is given and key is empty string
	if "" != prof.Cert && "" == prof.Key {
		svc := sharedApp[svcName].(*as3Service)
		tlsClientName := fmt.Sprintf("%s_tls_client", svcName)

		tlsClient := &as3TLSClient{
			Class: "TLS_Client",
			TrustCA: &as3ResourcePointer{
				Use: caBundleName,
			},
		}

		sharedApp[tlsClientName] = tlsClient
		svc.ClientTLS = tlsClientName
		updateVirtualToHTTPS(svc)

		return tlsClient
	}
	return nil
}

// Utils definition to handle openshift and ingress resource types.
func deriveResourceTypeFromAS3Value(val string) string {
	if strings.HasPrefix(val, "openshift_") {
		return ResourceTypeRoute
	}
	return ResourceTypeIngress
}
