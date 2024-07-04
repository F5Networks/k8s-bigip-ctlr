package controller

import (
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func (postMgr *AS3PostManager) createAS3Declaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration {
	var as3Config map[string]interface{}
	var adc map[string]interface{}
	var baseAS3ConfigTemplate string
	// if !postMgr.AS3Config.DocumentAPI {
	baseAS3ConfigTemplate = fmt.Sprintf(baseAS3Config, postMgr.AS3VersionInfo.as3Version,
	postMgr.AS3VersionInfo.as3Release)
	_ = json.Unmarshal([]byte(baseAS3ConfigTemplate), &as3Config)
	adc = as3Config["declaration"].(map[string]interface{})
	// } else {
	// 	baseAS3ConfigTemplate = baseAS3Config2
	// 	_ = json.Unmarshal([]byte(baseAS3ConfigTemplate), &as3Config)
	// 	adc = as3Config
	// }

	controlObj := make(map[string]interface{})
	controlObj["class"] = "Controls"
	controlObj["userAgent"] = userAgent
	adc["controls"] = controlObj

	for tenant, decl := range tenantDeclMap {
		adc[tenant] = decl
	}

	decl, err := json.Marshal(as3Config)
	if err != nil {
		log.Debugf("[AS3] Unified declaration: %v\n", err)
	}

	return as3Declaration(decl)
}

func getDeletedTenantDeclaration(cisLabel string) as3Tenant {
	return as3Tenant{
		"class": "Tenant",
		"label": cisLabel,
	}
}

func processIRulesForAS3(rsCfg *ResourceConfig, app as3Application) {
	// Skip processing IRules for "None" value
	for _, v := range rsCfg.Virtual.IRules {
		if v == "none" {
			continue
		}
	}
	// Create irule declaration
	for _, v := range rsCfg.IRulesMap {
		iRule := &as3IRules{}
		iRule.Class = "iRule"
		iRule.IRule = v.Code
		app[v.Name] = iRule
	}
}

func processDataGroupForAS3(rsCfg *ResourceConfig, app as3Application) {
	// Skip processing DataGroup for "None" iRule value
	for _, v := range rsCfg.Virtual.IRules {
		if v == "none" {
			continue
		}
	}
	for _, idg := range rsCfg.IntDgMap {
		for _, dg := range idg {
			dataGroupRecord, found := app[dg.Name]
			if !found {
				dgMap := &as3DataGroup{}
				dgMap.Class = "Data_Group"
				dgMap.KeyDataType = dg.Type
				for _, record := range dg.Records {
					dgMap.Records = append(dgMap.Records, as3Record{Key: record.Name, Value: record.Data})
				}
				// sort above create dgMap records.
				sort.Slice(dgMap.Records, func(i, j int) bool { return dgMap.Records[i].Key < dgMap.Records[j].Key })
				app[dg.Name] = dgMap
			} else {
				for _, record := range dg.Records {
					app[dg.Name].(*as3DataGroup).Records = append(dataGroupRecord.(*as3DataGroup).Records, as3Record{Key: record.Name, Value: record.Data})
				}
				// sort above created
				sort.Slice(app[dg.Name].(*as3DataGroup).Records,
					func(i, j int) bool {
						return (app[dg.Name].(*as3DataGroup).Records[i].Key <
							app[dg.Name].(*as3DataGroup).Records[j].Key)
					})
			}
		}
	}
}

// Process for AS3 Resource
func processResourcesForAS3(cfg *ResourceConfig, app as3Application, shareNodes bool, tenant string, documentAPI bool,
	poolMemberType string) {

	//Create policies
	createPoliciesDecl(cfg, app)

	//Create health monitor declaration
	createMonitorDecl(cfg, app)

	//Create pools
	createPoolDecl(cfg, app, shareNodes, tenant, poolMemberType)

	switch cfg.MetaData.ResourceType {
	case VirtualServer:
		//Create AS3 Service for virtual server
		createServiceDecl(cfg, app, tenant)
	case TransportServer:
		//Create AS3 Service for transport virtual server
		createTransportServiceDecl(cfg, app, tenant)
	}

}

// Create policy declaration
func createPoliciesDecl(cfg *ResourceConfig, app as3Application) {
	_, port := extractVirtualAddressAndPort(cfg.Virtual.Destination)
	for _, pl := range cfg.Policies {
		//Create EndpointPolicy
		ep := &as3EndpointPolicy{}
		for _, rl := range pl.Rules {

			ep.Class = "Endpoint_Policy"
			s := strings.Split(pl.Strategy, "/")
			ep.Strategy = s[len(s)-1]

			//Create rules
			rulesData := &as3Rule{Name: rl.Name}

			//Create condition object
			createRuleCondition(rl, rulesData, port)

			//Creat action object
			createRuleAction(rl, rulesData)

			ep.Rules = append(ep.Rules, rulesData)
		}
		//Setting Endpoint_Policy Name
		app[pl.Name] = ep
	}
}

// Create AS3 Pools for CRD
func createPoolDecl(cfg *ResourceConfig, app as3Application, shareNodes bool, tenant, poolMemberType string) {
	for _, v := range cfg.Pools {
		pool := &as3Pool{}
		if v.Balance == "fastest-app-response" || v.Balance == "least-connections-member" ||
			v.Balance == "predictive-member" || v.Balance == "ratio-least-connections-member" ||
			v.Balance == "ratio-session" || v.Balance == "round-robin" || v.Balance == "weighted-round-robin" {
			pool.LoadBalancingMode = v.Balance
		} else {
			log.Warningf("[AS3] virtualServer: %v, pool: %v, only following load-balancing types are supported with BIG-IP Next - fastest-app-response, "+
				"least-connections-member, predictive-member, ratio-least-connections-member, ratio-session, round-robin, weighted-round-robin", cfg.Virtual.Name, v.Name)
		}
		pool.Class = "Pool"
		if v.ReselectTries > 0 {
			log.Warningf("[AS3] virtualServer: %v, pool: %v, ReselectTries pool property is not supported with BIG-IP Next", cfg.Virtual.Name, v.Name)
		}
		if v.ServiceDownAction != "" {
			log.Warningf("[AS3] virtualServer: %v, pool: %v, ServiceDownAction pool property is not supported with BIG-IP Next", cfg.Virtual.Name, v.Name)
		}
		pool.SlowRampTime = v.SlowRampTime
		poolMemberSet := make(map[PoolMember]struct{})
		for _, val := range v.Members {
			// Skip duplicate pool members
			if _, ok := poolMemberSet[val]; ok {
				continue
			}
			poolMemberSet[val] = struct{}{}
			var member as3PoolMember
			member.AddressDiscovery = "static"
			member.ServicePort = val.Port
			member.ServerAddresses = append(member.ServerAddresses, val.Address)
			if shareNodes || (poolMemberType == Auto && val.MemberType == NodePort) {
				member.ShareNodes = shareNodes
			}
			if val.AdminState != "" {
				member.AdminState = val.AdminState
			}
			if val.ConnectionLimit != 0 {
				member.ConnectionLimit = val.ConnectionLimit
			}
			pool.Members = append(pool.Members, member)
		}
		for _, val := range v.MonitorNames {
			var monitor as3ResourcePointer
			//Reference existing health monitor from BIGIP
			if val.Reference == BIGIP {
				log.Warningf("[AS3] virtualServer: %v, pool: %v, monitor: %v, bigIp reference feature is not supported with BIG-IP Next", cfg.Virtual.Name, v.Name, val.Name)
			} else {
				use := strings.Split(val.Name, "/")
				// Full path is not supported with BIG-IP Next
				//monitor.Use = fmt.Sprintf("/%s/%s/%s",
				//	tenant,
				//	cfg.Virtual.Name,
				//	use[len(use)-1],
				//)
				monitor.Use = fmt.Sprintf("%s",
					use[len(use)-1],
				)
				pool.Monitors = append(pool.Monitors, monitor)
			}
		}
		if len(pool.Monitors) > 0 {
			if v.MinimumMonitors.StrVal != "" || v.MinimumMonitors.IntVal != 0 {
				log.Warningf("[AS3] virtualServer: %v, pool: %v, MinimumMonitors feature is not supported with BIG-IP Next", cfg.Virtual.Name, v.Name)
			}
		}
		app[v.Name] = pool
	}
}

func updateVirtualToHTTPS(v *as3Service) {
	v.Class = "Service_HTTPS"
	redirect80 := false
	v.Redirect80 = &redirect80
}

// Process Irules for CRD
func processIrulesForCRD(cfg *ResourceConfig, svc *as3Service) {
	var IRules []interface{}
	// Skip processing IRules for "None" value
	for _, v := range cfg.Virtual.IRules {
		if v == "none" {
			continue
		}
		splits := strings.Split(v, "/")
		iRuleName := splits[len(splits)-1]

		var iRuleNoPort string
		lastIndex := strings.LastIndex(iRuleName, "_")
		if lastIndex > 0 {
			iRuleNoPort = iRuleName[:lastIndex]
		} else {
			iRuleNoPort = iRuleName
		}
		if strings.HasSuffix(iRuleNoPort, HttpRedirectIRuleName) ||
			strings.HasSuffix(iRuleNoPort, HttpRedirectNoHostIRuleName) ||
			strings.HasSuffix(iRuleName, TLSIRuleName) ||
			strings.HasSuffix(iRuleName, ABPathIRuleName) {
			IRules = append(IRules, iRuleName)
		} else if len(strings.Split(v, ":")) == 2 {
			cmIRule := strings.Split(v, ":")
			iRule := &as3ResourcePointer{
				CM: fmt.Sprintf("%s::%s", cmIRule[0], cmIRule[1]),
			}
			IRules = append(IRules, iRule)
		} else {
			irule := &as3ResourcePointer{
				BigIP: v,
			}
			IRules = append(IRules, irule)
		}
		svc.IRules = IRules
	}
}

// Create AS3 Service for CRD
func createServiceDecl(cfg *ResourceConfig, app as3Application, tenant string) {
	svc := &as3Service{}
	numPolicies := len(cfg.Virtual.Policies)
	switch {
	case numPolicies == 1:
		policyName := cfg.Virtual.Policies[0].Name
		svc.PolicyEndpoint = fmt.Sprintf("/%s/%s/%s",
			tenant,
			cfg.Virtual.Name,
			policyName)
	case numPolicies > 1:
		var peps []as3ResourcePointer
		for _, pep := range cfg.Virtual.Policies {
			peps = append(
				peps,
				as3ResourcePointer{
					Use: fmt.Sprintf("/%s/%s/%s",
						tenant,
						cfg.Virtual.Name,
						pep.Name,
					),
				},
			)
		}
		svc.PolicyEndpoint = peps
	}
	// Attach the default pool if pool name is present for virtual.
	if cfg.Virtual.PoolName != "" {
		var poolPointer as3ResourcePointer
		if cfg.MetaData.defaultPoolType == BIGIP {
			poolPointer.BigIP = cfg.Virtual.PoolName
		} else {
			ps := strings.Split(cfg.Virtual.PoolName, "/")
			poolPointer.Use = fmt.Sprintf("/%s/%s/%s",
				tenant,
				cfg.Virtual.Name,
				ps[len(ps)-1],
			)
		}
		svc.Pool = &poolPointer
	}

	if cfg.Virtual.TLSTermination != TLSPassthrough {
		svc.Layer4 = cfg.Virtual.IpProtocol
		svc.Class = "Service_HTTP"
	} else {
		if len(cfg.Virtual.PersistenceProfile) == 0 {
			cfg.Virtual.PersistenceProfile = "tls-session-id"
		}
		svc.Class = "Service_TCP"
	}

	svc.addPersistenceMethod(cfg.Virtual.PersistenceProfile)

	if len(cfg.Virtual.ProfileDOS) > 0 {
		log.Warningf("[AS3] virtualServer: %v, ProfileDOS feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}
	if len(cfg.Virtual.ProfileBotDefense) > 0 {
		log.Warningf("[AS3] virtualServer: %v, ProfileBotDefense monitors feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	if cfg.MetaData.Protocol == "https" {
		if len(cfg.Virtual.HTTP2.Client) > 0 || len(cfg.Virtual.HTTP2.Server) > 0 {
			if cfg.Virtual.HTTP2.Client == "" {
				log.Errorf("[AS3] resetting ProfileHTTP2 as client profile doesnt co-exist with HTTP2 Server Profile, Please include client HTTP2 Profile ")
			}
			if cfg.Virtual.HTTP2.Server == "" {
				svc.ProfileHTTP2 = &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", cfg.Virtual.HTTP2.Client),
				}
			}
			if cfg.Virtual.HTTP2.Client == "" && cfg.Virtual.HTTP2.Server != "" {
				svc.ProfileHTTP2 = as3ProfileHTTP2{
					Egress: &as3ResourcePointer{
						BigIP: fmt.Sprintf("%v", cfg.Virtual.HTTP2.Server),
					},
				}
			}
			if cfg.Virtual.HTTP2.Client != "" && cfg.Virtual.HTTP2.Server != "" {
				svc.ProfileHTTP2 = as3ProfileHTTP2{
					Ingress: &as3ResourcePointer{
						BigIP: fmt.Sprintf("%v", cfg.Virtual.HTTP2.Client),
					},
					Egress: &as3ResourcePointer{
						BigIP: fmt.Sprintf("%v", cfg.Virtual.HTTP2.Server),
					},
				}
			}
		}
	}

	if len(cfg.Virtual.TCP.Client) > 0 || len(cfg.Virtual.TCP.Server) > 0 {
		if cfg.Virtual.TCP.Client == "" {
			log.Errorf("[AS3] resetting ProfileTCP as client profile doesnt co-exist with TCP Server Profile, Please include client TCP Profile ")
		}
		if cfg.Virtual.TCP.Server == "" {
			svc.ProfileTCP = &as3ResourcePointer{
				BigIP: fmt.Sprintf("%v", cfg.Virtual.TCP.Client),
			}
		}
		if cfg.Virtual.TCP.Client != "" && cfg.Virtual.TCP.Server != "" {
			svc.ProfileTCP = as3ProfileTCP{
				Ingress: &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", cfg.Virtual.TCP.Client),
				},
				Egress: &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", cfg.Virtual.TCP.Server),
				},
			}
		}
	}

	if len(cfg.Virtual.ProfileMultiplex) > 0 {
		svc.ProfileMultiplex = &as3ResourcePointer{
			BigIP: cfg.Virtual.ProfileMultiplex,
		}
	}
	// updating the virtual server to https if a passthrough datagroup is found
	name := getRSCfgResName(cfg.Virtual.Name, PassthroughHostsDgName)
	mapKey := NameRef{
		Name:      name,
		Partition: cfg.Virtual.Partition,
	}
	if _, ok := cfg.IntDgMap[mapKey]; ok {
		svc.ServerTLS = &as3ResourcePointer{
			BigIP: "/Common/clientssl",
		}
		updateVirtualToHTTPS(svc)
	}

	// Attaching Profiles from Policy CRD
	for _, profile := range cfg.Virtual.Profiles {
		_, name := getPartitionAndName(profile.Name)
		switch profile.Context {
		case "http":
			if !profile.BigIPProfile {
				svc.ProfileHTTP = name
			} else {
				svc.ProfileHTTP = &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", profile.Name),
				}
			}
		}
	}

	//Attaching WAF policy
	if cfg.Virtual.WAF != "" {
		svc.WAF = &as3ResourcePointer{
			BigIP: fmt.Sprintf("%v", cfg.Virtual.WAF),
		}
	}

	virtualAddress, port := extractVirtualAddressAndPort(cfg.Virtual.Destination)
	// verify that ip address and port exists.
	if virtualAddress != "" && port != 0 {
		if len(cfg.ServiceAddress) == 0 {
			va := append(svc.VirtualAddresses, virtualAddress)
			if len(cfg.Virtual.AdditionalVirtualAddresses) > 0 {
				for _, val := range cfg.Virtual.AdditionalVirtualAddresses {
					va = append(va, val)
				}
			}
			svc.VirtualAddresses = va
			svc.VirtualPort = port
		} else {
			//Attach Service Address
			serviceAddressName := createServiceAddressDecl(cfg, virtualAddress, app)
			sa := &as3ResourcePointer{
				Use: serviceAddressName,
			}
			svc.VirtualAddresses = append(svc.VirtualAddresses, sa)
			if len(cfg.Virtual.AdditionalVirtualAddresses) > 0 {
				for _, val := range cfg.Virtual.AdditionalVirtualAddresses {
					//Attach Service Address
					serviceAddressName := createServiceAddressDecl(cfg, val, app)
					//handle additional service addresses
					asa := &as3ResourcePointer{
						Use: serviceAddressName,
					}
					svc.VirtualAddresses = append(svc.VirtualAddresses, asa)
				}
			}
			svc.VirtualPort = port
		}
	}
	if cfg.Virtual.HttpMrfRoutingEnabled != nil {
		//set HttpMrfRoutingEnabled
		log.Warningf("[AS3] virtualServer: %v, HttpMrfRoutingEnabled feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	if cfg.Virtual.AutoLastHop != "" {
		log.Warningf("[AS3] virtualServer: %v, AutoLastHop feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	if cfg.Virtual.AnalyticsProfiles.HTTPAnalyticsProfile != "" {
		svc.HttpAnalyticsProfile = &as3ResourcePointer{
			BigIP: cfg.Virtual.AnalyticsProfiles.HTTPAnalyticsProfile,
		}
	}
	//set websocket profile
	if cfg.Virtual.ProfileWebSocket != "" {
		log.Warningf("[AS3] virtualServer: %v, ProfileWebSocket feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}
	processCommonDecl(cfg, svc)
	app[cfg.Virtual.Name] = svc
}

// Create AS3 Service Address for Virtual Server Address
func createServiceAddressDecl(cfg *ResourceConfig, virtualAddress string, app as3Application) string {
	var name string
	for _, sa := range cfg.ServiceAddress {
		serviceAddress := &as3ServiceAddress{}
		serviceAddress.Class = "Service_Address"
		serviceAddress.ArpEnabled = sa.ArpEnabled
		serviceAddress.ICMPEcho = sa.ICMPEcho
		serviceAddress.RouteAdvertisement = sa.RouteAdvertisement
		serviceAddress.SpanningEnabled = sa.SpanningEnabled
		serviceAddress.TrafficGroup = sa.TrafficGroup
		serviceAddress.VirtualAddress = virtualAddress
		name = "crd_service_address_" + AS3NameFormatter(virtualAddress)
		app[name] = serviceAddress
	}
	return name
}

// Create AS3 Rule Condition for CRD
func createRuleCondition(rl *Rule, rulesData *as3Rule, port int) {
	for _, c := range rl.Conditions {
		condition := &as3Condition{}

		if c.Host {
			condition.Name = "host"
			var values []string
			// For ports other than 80 and 443, attaching port number to host.
			// Ex. example.com:8080
			if port != 80 && port != 443 {
				for i := range c.Values {
					val := c.Values[i] + ":" + strconv.Itoa(port)
					values = append(values, val)
				}
			} else {
				//For ports 80 and 443, host header should match both
				// host and host:port match
				for i := range c.Values {
					val := c.Values[i] + ":" + strconv.Itoa(port)
					values = append(values, val, c.Values[i])
				}
			}
			condition.All = &as3PolicyCompareString{
				Values: values,
			}
			if c.HTTPHost {
				condition.Type = "httpHeader"
			}
			if c.Equals {
				condition.All.Operand = "equals"
			}
			if c.EndsWith {
				condition.All.Operand = "ends-with"
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
			if c.Address && len(c.Values) > 0 {
				condition.Type = "tcp"
				condition.Address = &as3PolicyAddressString{
					Values: c.Values,
				}
			}
		}
		if c.Request {
			condition.Event = "request"
		}

		rulesData.Conditions = append(rulesData.Conditions, condition)
	}
}

// Create AS3 Rule Action for CRD
func createRuleAction(rl *Rule, rulesData *as3Rule) {
	for _, v := range rl.Actions {
		action := &as3Action{}
		if v.Forward {
			action.Type = "forward"
		}
		if v.Log {
			action.Type = "log"
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
		if v.Log {
			action.Write = &as3LogMessage{
				Message: v.Message,
			}
		}
		// Handle vsHostname rewrite.
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
					Use: p[len(p)-1],
				},
			}
		}
		// WAF action
		if v.WAF {
			action.Type = "waf"
		}
		// Add policy reference
		if v.Policy != "" {
			action.Policy = &as3ResourcePointer{
				BigIP: v.Policy,
			}
		}
		if v.Enabled != nil {
			action.Enabled = v.Enabled
		}
		// Add drop action if specified
		if v.Drop {
			action.Type = "drop"
		}

		rulesData.Actions = append(rulesData.Actions, action)
	}
}

func DeepEqualJSON(decl1, decl2 as3Declaration) bool {
	if decl1 == "" && decl2 == "" {
		return true
	}
	var o1, o2 interface{}

	err := json.Unmarshal([]byte(decl1), &o1)
	if err != nil {
		return false
	}

	err = json.Unmarshal([]byte(decl2), &o2)
	if err != nil {
		return false
	}

	return reflect.DeepEqual(o1, o2)
}

func processProfilesForAS3(cfg *ResourceConfig, app as3Application) {
	if svc, ok := app[cfg.Virtual.Name].(*as3Service); ok {
		processTLSProfilesForAS3(&cfg.Virtual, svc, cfg.Virtual.Name)
	}
}

func processTLSProfilesForAS3(virtual *Virtual, svc *as3Service, profileName string) {
	// let's discard BIGIP profile creation when there exists a custom profile.
	as3ClientSuffix := "_tls_client"
	as3ServerSuffix := "_tls_server"
	var clientProfiles []as3MultiTypeParam
	var serverProfiles []as3MultiTypeParam
	for _, profile := range virtual.Profiles {
		switch profile.Context {
		case CustomProfileClient:
			// Profile is stored in a k8s secret
			if !profile.BigIPProfile {
				// Incoming traffic (clientssl) from a web client will be handled by ServerTLS in AS3
				svc.ServerTLS = fmt.Sprintf("/%v/%v/%v%v", virtual.Partition,
					virtual.Name, profileName, as3ServerSuffix)

			} else {
				// Profile is a BIG-IP reference
				// Incoming traffic (clientssl) from a web client will be handled by ServerTLS in AS3
				clientProfiles = append(clientProfiles, &as3ResourcePointer{
					BigIP: fmt.Sprintf("/%v/%v", profile.Partition, profile.Name),
				})
			}
			updateVirtualToHTTPS(svc)
		case CustomProfileServer:
			// Profile is stored in a k8s secret
			if !profile.BigIPProfile {
				// Outgoing traffic (serverssl) to BackEnd Servers from BigIP will be handled by ClientTLS in AS3
				svc.ClientTLS = fmt.Sprintf("/%v/%v/%v%v", virtual.Partition,
					virtual.Name, profileName, as3ClientSuffix)
			} else {
				// Profile is a BIG-IP reference
				// Outgoing traffic (serverssl) to BackEnd Servers from BigIP will be handled by ClientTLS in AS3
				serverProfiles = append(serverProfiles, &as3ResourcePointer{
					BigIP: fmt.Sprintf("/%v/%v", profile.Partition, profile.Name),
				})
			}
			updateVirtualToHTTPS(svc)
		}
	}
	if len(clientProfiles) > 0 {
		svc.ServerTLS = clientProfiles
	}
	if len(serverProfiles) > 0 {
		svc.ClientTLS = serverProfiles
	}
}

func processCustomProfilesForAS3(rsCfg *ResourceConfig, app as3Application, as3Version float64) {
	caBundleName := "serverssl_ca_bundle"
	var tlsClient *as3TLSClient
	svcNameMap := make(map[string]struct{})
	// TLS Certificates are available in CustomProfiles

	// Sort customProfiles so that they are processed in orderly manner
	keys := getSortedCustomProfileKeys(rsCfg.customProfiles)

	for _, key := range keys {
		prof := rsCfg.customProfiles[key]
		// Create TLSServer and Certificate for each profile
		svcName := key.ResourceName
		if svcName == "" {
			continue
		}
		if ok := createUpdateTLSServer(prof, svcName, app); ok {
			// Create Certificate only if the corresponding TLSServer is created
			createCertificateDecl(prof, app)
			svcNameMap[svcName] = struct{}{}
		} else {
			createUpdateCABundle(prof, caBundleName, app)
			tlsClient = createTLSClient(prof, svcName, caBundleName, app)

			skey := SecretKey{
				Name: prof.Name + "-ca",
			}
			if _, ok := rsCfg.customProfiles[skey]; ok && tlsClient != nil {
				// If a profile exist in customProfiles with key as created above
				// then it indicates that secure-serverssl needs to be added
				tlsClient.ValidateCertificate = true
			}
		}
	}

	// if AS3 version on bigIP is lower than 3.44 then don't enable sniDefault, as it's only supported from AS3 v3.44 onwards
	if as3Version < 3.44 {
		return
	}
	for svcName := range svcNameMap {
		if _, ok := app[svcName].(*as3Service); ok {
			tlsServerName := fmt.Sprintf("%s_tls_server", svcName)
			tlsServer, ok := app[tlsServerName].(*as3TLSServer)
			if !ok {
				continue
			}
			if len(tlsServer.Certificates) > 1 {
				tlsServer.Certificates[0].SNIDefault = true
			}
		}
	}
}

// createUpdateTLSServer creates a new TLSServer instance or updates if one exists already
func createUpdateTLSServer(prof CustomProfile, svcName string, app as3Application) bool {
	if len(prof.Certificates) > 0 {
		if app[svcName] == nil {
			return false
		}
		svc := app[svcName].(*as3Service)
		tlsServerName := fmt.Sprintf("%s_tls_server", svcName)
		tlsServer, ok := app[tlsServerName].(*as3TLSServer)
		if !ok {
			tlsServer = &as3TLSServer{
				Class:        "TLS_Server",
				Certificates: []as3TLSServerCertificates{},
			}
			if prof.CipherGroup != "" {
				tlsServer.CipherGroup = &as3ResourcePointer{BigIP: prof.CipherGroup}
				tlsServer.TLS1_3Enabled = true
			} else {
				tlsServer.Ciphers = prof.Ciphers
			}

			app[tlsServerName] = tlsServer
			svc.ServerTLS = tlsServerName
			updateVirtualToHTTPS(svc)
		}
		for index, certificate := range prof.Certificates {
			certName := fmt.Sprintf("%s_%d", prof.Name, index)
			// A TLSServer profile needs to carry both Certificate and Key
			if len(certificate.Cert) > 0 && len(certificate.Key) > 0 {
				tlsServer.Certificates = append(
					tlsServer.Certificates,
					as3TLSServerCertificates{
						Certificate: certName,
					},
				)
			} else {
				return false
			}
		}
		return true
	}
	return false
}

func createCertificateDecl(prof CustomProfile, app as3Application) {
	for index, certificate := range prof.Certificates {
		if len(certificate.Cert) > 0 && len(certificate.Key) > 0 {
			cert := &as3Certificate{
				Class:       "Certificate",
				Certificate: certificate.Cert,
				PrivateKey:  certificate.Key,
				ChainCA:     prof.CAFile,
			}
			app[fmt.Sprintf("%s_%d", prof.Name, index)] = cert
		}
	}
}

func createUpdateCABundle(prof CustomProfile, caBundleName string, app as3Application) {
	for _, cert := range prof.Certificates {
		// For TLSClient only Cert (DestinationCACertificate) is given and key is empty string
		if len(cert.Cert) > 0 && len(cert.Key) == 0 {
			caBundle, ok := app[caBundleName].(*as3CABundle)

			if !ok {
				caBundle = &as3CABundle{
					Class:  "CA_Bundle",
					Bundle: "",
				}
				app[caBundleName] = caBundle
			}
			caBundle.Bundle += "\n" + cert.Cert
		}
	}
}

// Create health monitor declaration
func createMonitorDecl(cfg *ResourceConfig, app as3Application) {

	for _, v := range cfg.Monitors {
		monitor := &as3Monitor{}
		monitor.Class = "Monitor"
		monitor.Interval = v.Interval
		monitor.MonitorType = v.Type
		monitor.Timeout = v.Timeout
		monitor.TimeUnitilUp = v.TimeUntilUp
		//Monitor type
		switch v.Type {
		case "http":
			monitor.Receive = "none"
			if v.Recv != "" {
				monitor.Receive = v.Recv
			}
			monitor.Send = v.Send
		case "https":
			//Todo: For https monitor type
			if v.Recv != "" {
				monitor.Receive = v.Recv
			}
			monitor.Send = v.Send
			monitor.TimeUnitilUp = v.TimeUntilUp
		case "tcp", "udp":
			monitor.Receive = v.Recv
			monitor.Send = v.Send
		}
		app[v.Name] = monitor
	}

}

// Create AS3 transport Service for CRD
func createTransportServiceDecl(cfg *ResourceConfig, app as3Application, tenant string) {
	svc := &as3Service{}
	if cfg.Virtual.Mode == "standard" {
		if cfg.Virtual.IpProtocol == "udp" {
			svc.Class = "Service_UDP"
		} else if cfg.Virtual.IpProtocol == "sctp" {
			svc.Class = "Service_SCTP"
		} else {
			svc.Class = "Service_TCP"
		}
	} else if cfg.Virtual.Mode == "performance" {
		svc.Class = "Service_L4"
		if cfg.Virtual.IpProtocol == "udp" {
			svc.Layer4 = "udp"
		} else if cfg.Virtual.IpProtocol == "sctp" {
			svc.Layer4 = "sctp"
		} else {
			svc.Layer4 = "tcp"
		}
	}

	if len(cfg.Virtual.ProfileL4) > 0 {
		svc.ProfileL4 = &as3ResourcePointer{
			BigIP: cfg.Virtual.ProfileL4,
		}
	}

	svc.addPersistenceMethod(cfg.Virtual.PersistenceProfile)

	if len(cfg.Virtual.ProfileDOS) > 0 {
		log.Warningf("[AS3] virtualServer: %v, ProfileDOS feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	if len(cfg.Virtual.ProfileBotDefense) > 0 {
		log.Warningf("[AS3] virtualServer: %v, ProfileBotDefense feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	if len(cfg.Virtual.TCP.Client) > 0 || len(cfg.Virtual.TCP.Server) > 0 {
		if cfg.Virtual.TCP.Client == "" {
			log.Errorf("[AS3] resetting ProfileTCP as client profile doesnt co-exist with TCP Server Profile, Please include client TCP Profile ")
		}
		if cfg.Virtual.TCP.Server == "" {
			svc.ProfileTCP = &as3ResourcePointer{
				BigIP: fmt.Sprintf("%v", cfg.Virtual.TCP.Client),
			}
		}
		if cfg.Virtual.TCP.Client != "" && cfg.Virtual.TCP.Server != "" {
			svc.ProfileTCP = as3ProfileTCP{
				Ingress: &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", cfg.Virtual.TCP.Client),
				},
				Egress: &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", cfg.Virtual.TCP.Server),
				},
			}
		}
	}

	// Attaching Profiles from Policy CRD
	for _, profile := range cfg.Virtual.Profiles {
		_, name := getPartitionAndName(profile.Name)
		switch profile.Context {
		case "udp":
			if !profile.BigIPProfile {
				svc.ProfileUDP = name
			} else {
				svc.ProfileUDP = &as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", profile.Name),
				}
			}
		}
	}

	if cfg.Virtual.TranslateServerAddress == true {
		log.Warningf("[AS3] virtualServer: %v, TranslateServerAddress feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}
	if cfg.Virtual.TranslateServerPort == true {
		log.Warningf("[AS3] virtualServer: %v, TranslateServerPort feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}
	if cfg.Virtual.Source != "" {
		log.Warningf("[AS3] virtualServer: %v, Source feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}
	virtualAddress, port := extractVirtualAddressAndPort(cfg.Virtual.Destination)
	// verify that ip address and port exists.
	if virtualAddress != "" && port != 0 {
		if len(cfg.ServiceAddress) > 0 {
			log.Warningf("[AS3] virtualServer: %v, ServiceAddress feature is not supported with BIG-IP Next", cfg.Virtual.Name)
		}
		va := append(svc.VirtualAddresses, virtualAddress)
		svc.VirtualAddresses = va
		svc.VirtualPort = port

	}

	svc.Pool = cfg.Virtual.PoolName

	processCommonDecl(cfg, svc)
	app[cfg.Virtual.Name] = svc
}

// Process common declaration for VS and TS
func processCommonDecl(cfg *ResourceConfig, svc *as3Service) {

	if cfg.Virtual.SNAT == "auto" || cfg.Virtual.SNAT == "none" {
		svc.SNAT = cfg.Virtual.SNAT
	} else {
		svc.SNAT = &as3ResourcePointer{
			BigIP: fmt.Sprintf("%v", cfg.Virtual.SNAT),
		}
	}
	// Enable connection mirroring
	if cfg.Virtual.ConnectionMirroring != "" {
		svc.Mirroring = cfg.Virtual.ConnectionMirroring
	}
	//Attach AllowVLANs
	if cfg.Virtual.AllowVLANs != nil {
		log.Warningf("[AS3] virtualServer: %v, AllowVLANs feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	//Attach Firewall policy
	if cfg.Virtual.Firewall != "" {
		svc.Firewall = &as3ResourcePointer{
			BigIP: fmt.Sprintf("%v", cfg.Virtual.Firewall),
		}
	}

	//Attach ipIntelligence policy
	if cfg.Virtual.IpIntelligencePolicy != "" {
		log.Warningf("[AS3] virtualServer: %v, IpIntelligencePolicy feature is not supported with BIG-IP Next", cfg.Virtual.Name)
	}

	//Attach logging profile
	if cfg.Virtual.LogProfiles != nil {
		for _, lp := range cfg.Virtual.LogProfiles {
			logProfile := as3ResourcePointer{BigIP: lp}
			svc.LogProfiles = append(svc.LogProfiles, logProfile)
		}
	}

	//Process iRules for crd
	processIrulesForCRD(cfg, svc)
}

// addPersistenceMethod adds persistence methods in the service declaration
func (svc *as3Service) addPersistenceMethod(persistenceProfile string) {
	if len(persistenceProfile) == 0 {
		return
	}
	switch persistenceProfile {
	case "none":
		svc.PersistenceMethods = &[]as3MultiTypeParam{}
	case "cookie", "destination-address", "hash", "msrdp", "sip-info", "source-address", "tls-session-id", "universal":
		svc.PersistenceMethods = &[]as3MultiTypeParam{as3MultiTypeParam(persistenceProfile)}
	default:
		svc.PersistenceMethods = &[]as3MultiTypeParam{
			as3MultiTypeParam(
				as3ResourcePointer{
					BigIP: fmt.Sprintf("%v", persistenceProfile),
				},
			),
		}
	}
}

// Creates AS3 adc only for tenants with updated configuration
func (req *RequestHandler) createAS3Config(rsConfig ResourceConfigRequest, pm *PostManager) as3Config {
	as3cfg := as3Config{
		id:                    rsConfig.reqMeta.id,
		tenantResponseMap:     make(map[string]tenantResponse),
		failedTenants:         make(map[string]struct{}),
		incomingTenantDeclMap: make(map[string]as3Tenant),
	}
	for tenant, cfg := range pm.AS3PostManager.createAS3BIGIPConfig(rsConfig.bigIpResourceConfig, pm.defaultPartition, pm.cachedTenantDeclMap,
		rsConfig.poolMemberType) {
		if !reflect.DeepEqual(cfg, pm.cachedTenantDeclMap[tenant]) ||
			(req.PrimaryClusterHealthProbeParams.EndPoint != "" && req.PrimaryClusterHealthProbeParams.statusChanged) {
			as3cfg.incomingTenantDeclMap[tenant] = cfg.(as3Tenant)
			as3cfg.tenantResponseMap[tenant] = tenantResponse{}
		} else {
			// Log only when it's primary/standalone CIS or when it's secondary CIS and primary CIS is down
			if req.PrimaryClusterHealthProbeParams.EndPoint == "" || !req.PrimaryClusterHealthProbeParams.statusRunning {
				log.Debugf("[AS3] No change in %v tenant configuration", tenant)
			}
		}
	}
	as3cfg.data = string(pm.AS3PostManager.createAS3Declaration(as3cfg.incomingTenantDeclMap, req.userAgent))
	return as3cfg
}

func (as3PM *AS3PostManager) createAS3BIGIPConfig(config BigIpResourceConfig, partition string, cachedTenantDeclMap map[string]as3Tenant,
	poolMemberType string) as3ADC {
	adc := as3PM.createAS3LTMConfigADC(config, partition, cachedTenantDeclMap, poolMemberType)
	return adc
}

func (postMgr *AS3PostManager) createAS3LTMConfigADC(config BigIpResourceConfig, partition string, cachedTenantDeclMap map[string]as3Tenant,
	poolMemberType string) as3ADC {
	adc := as3ADC{}
	cisLabel := partition

	for tenant := range cachedTenantDeclMap {
		if _, ok := config.ltmConfig[tenant]; !ok {
			// Remove partition
			adc[tenant] = getDeletedTenantDeclaration(cisLabel)
		}
	}
	for tenantName, partitionConfig := range config.ltmConfig {
		if len(partitionConfig.ResourceMap) == 0 {
			// Remove partition
			adc[tenantName] = getDeletedTenantDeclaration(cisLabel)
			continue
		}
		// Create AS3 Tenant
		tenantDecl := as3Tenant{
			"class": "Tenant",
			"label": cisLabel,
		}
		for _, resourceConfig := range partitionConfig.ResourceMap {
			// Create Shared as3Application object
			app := as3Application{}
			app["class"] = "Application"
			app["template"] = "shared"

			// Process rscfg to create AS3 Resources
			processResourcesForAS3(resourceConfig, app, config.shareNodes, tenantName,
				postMgr.AS3Config.DocumentAPI, poolMemberType)

			// Process CustomProfiles
			processCustomProfilesForAS3(resourceConfig, app, postMgr.bigIPAS3Version)

			// Process Profiles
			processProfilesForAS3(resourceConfig, app)

			processIRulesForAS3(resourceConfig, app)

			processDataGroupForAS3(resourceConfig, app)
			tenantDecl[resourceConfig.Virtual.Name] = app
		}
		adc[tenantName] = tenantDecl
	}
	return adc
}

// removeDeletedTenantsForBigIP will check the tenant exists on bigip or not
// if tenant exists and rsConfig does not have tenant, update the tenant with empty PartitionConfig
func removeDeletedTenantsForBigIP(rsConfig *BigIpResourceConfig, cisLabel string, as3Config map[string]interface{}, partition string) {
	for k, v := range as3Config {
		if decl, ok := v.(map[string]interface{}); ok {
			if label, found := decl["label"]; found && label == cisLabel && k != partition+"_gtm" {
				if _, ok := rsConfig.ltmConfig[k]; !ok {
					// adding an empty tenant to delete the tenant from BIGIP
					priority := 1
					rsConfig.ltmConfig[k] = &PartitionConfig{Priority: &priority}
				}
			}
		}
	}
}

// AS3NameFormatter formarts resources names according to AS3 convention
// TODO: Should we use this? Or this will be done in agent?
func AS3NameFormatter(name string) string {
	modifySpecialChars := map[string]string{
		".":  "_",
		":":  "_",
		"/":  "_",
		"%":  ".",
		"-":  "_",
		"[":  "",
		"]":  "",
		"=":  "_",
		"*_": ""}
	SpecialChars := [9]string{".", ":", "/", "%", "-", "[", "]", "=", "*_"}
	for _, key := range SpecialChars {
		name = strings.ReplaceAll(name, key, modifySpecialChars[key])
	}
	return name
}
