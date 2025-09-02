package as3

import (
	"encoding/json"

	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

// cfgMap States
const (
	F5TypeLabel                  = "f5type"
	VSLabel                      = "virtual-server"
	TrueLabel                    = "true"
	FalseLabel                   = "false"
	OverrideAS3Label             = "overrideAS3"
	AS3Label                     = "as3"
	IsTenantNameServiceNamespace = "isTenantNameServiceNamespace"
	StagingAS3Label              = "stagingAS3"
)

func (am *AS3Manager) prepareResourceAS3ConfigMaps() (
	[]*AS3ConfigMap,
	string,
	error,
) {
	var as3Cfgmaps []*AS3ConfigMap
	var overriderAS3CfgmapData string

	// Reset AS3 persist and logLevel values
	am.as3DeclarationPersistence = nil
	am.as3LogLevel = nil
	// Process rscCfgMap if present in Resource Request
	for _, rscCfgMap := range am.ResourceRequest.AgentCfgmaps {
		log.Debugf("[AS3] Processing AgentCfgMap: %+v", rscCfgMap)
		// Log detection of AS3 ConfigMap events at INFO level
		switch rscCfgMap.Operation {
		case OprTypeCreate:
			log.Infof("[AS3][ConfigMap] Detected new AS3 ConfigMap: %v in Namespace: %v", rscCfgMap.Name, rscCfgMap.Namespace)
		case OprTypeUpdate:
			log.Infof("[AS3][ConfigMap] Detected update to AS3 ConfigMap: %v in Namespace: %v", rscCfgMap.Name, rscCfgMap.Namespace)
		case OprTypeDelete:
			log.Infof("[AS3][ConfigMap] Detected delete of AS3 ConfigMap: %v in Namespace: %v", rscCfgMap.Name, rscCfgMap.Namespace)
		}
		cfgmapType, ok := am.isValidConfigmap(rscCfgMap)
		log.Debugf("[AS3] isValidConfigmap result: cfgmapType=%v, ok=%v", cfgmapType, ok)
		if !ok {
			log.Debugf("[AS3] Skipping invalid ConfigMap: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
			continue
		}

		switch cfgmapType {
		case AS3Label:
			// Configmaps with OprTypeDelete true will be skipped
			// So that the tenants will be configured with empty config
			// while preparing unified declaration so that these partitions will deleted
			if rscCfgMap.Operation == OprTypeDelete {
				log.Debugf("[AS3] Skipping deleted AS3 ConfigMap: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
				continue
			}
			cfgmap := &AS3ConfigMap{
				Name:      rscCfgMap.Name,
				Namespace: rscCfgMap.Namespace,
				Validated: true,
			}

			if am.as3Validation {
				if ok := am.validateAS3Template(rscCfgMap.Data); !ok {
					log.Errorf("[AS3][Configmap] Error validating AS3 template")
					log.Errorf("[AS3][Configmap] Error in processing the resource ConfigMap: %v in Namespace: %v",
						rscCfgMap.Name, rscCfgMap.Namespace)
					// Adding this condition as cfgmap.Validated flag is only used in filter-tenant case
					if am.FilterTenants {
						cfgmap.Validated = false
						log.Debugf("[AS3] Validation failed, marking ConfigMap as not validated: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
					} else {
						log.Debugf("[AS3] Validation failed, skipping ConfigMap: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
						continue
					}

				}
			}

			tenantMap, endPoints, err := am.processCfgMap(rscCfgMap)
			log.Debugf("[AS3] processCfgMap result: tenantMap=%+v, endPoints=%+v, err=%v", tenantMap, endPoints, err)
			// Skip processing further if error encountered while processing configMap
			if err != nil {
				log.Errorf("[AS3] Error processing ConfigMap: %v/%v: %v", rscCfgMap.Namespace, rscCfgMap.Name, err)
				return nil, "", err
			}
			if tenantMap == nil {
				log.Debugf("[AS3] No tenantMap found, skipping ConfigMap: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
				continue
			}

			cfgmap.config = tenantMap
			cfgmap.endPoints = endPoints
			as3Cfgmaps = append(as3Cfgmaps, cfgmap)
			log.Infof("[AS3][ConfigMap] Added AS3 ConfigMap: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)

		case OverrideAS3Label:
			if rscCfgMap.Operation == OprTypeDelete {
				// In the event of deletion config of overriderAS3Cfgmap stays empty
				// So that nothing gets overridden
				log.Debugf("Setting overriderAS3CfgmapData to Empty")
				overriderAS3CfgmapData = ""
			} else {
				overriderAS3CfgmapData = rscCfgMap.Data
				log.Debugf("[AS3] Set overriderAS3CfgmapData for: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
			}
		case StagingAS3Label:
			log.Debugf("[AS3] Processing StagingAS3Label for: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
			tenants := getTenants(as3Declaration(rscCfgMap.Data), true)
			cfgmap := &AS3ConfigMap{
				Name:      rscCfgMap.Name,
				Namespace: rscCfgMap.Namespace,
				Validated: true,
			}
			rscCfgMap.Data = am.getTenantObjects(tenants)
			tenantMap, endPoints, err := am.processCfgMap(rscCfgMap)
			log.Debugf("[AS3] processCfgMap (staging) result: tenantMap=%+v, endPoints=%+v, err=%v", tenantMap, endPoints, err)
			// Skip processing further if error encountered while processing configMap
			if err != nil {
				log.Errorf("[AS3] Error processing staging ConfigMap: %v/%v: %v", rscCfgMap.Namespace, rscCfgMap.Name, err)
				return nil, "", err
			}
			cfgmap.config = tenantMap
			cfgmap.endPoints = endPoints
			as3Cfgmaps = append(as3Cfgmaps, cfgmap)
			log.Infof("[AS3][ConfigMap] Added staging AS3 ConfigMap: %v/%v", rscCfgMap.Namespace, rscCfgMap.Name)
		}
	}
	log.Debugf("[AS3] Exiting prepareResourceAS3ConfigMaps")
	return as3Cfgmaps, overriderAS3CfgmapData, nil
}

func (am *AS3Manager) isValidConfigmap(cfgmap *AgentCfgMap) (string, bool) {
	if val, ok := cfgmap.Label[F5TypeLabel]; ok && val == VSLabel {
		if val, ok := cfgmap.Label[OverrideAS3Label]; ok && val == FalseLabel {
			log.Errorf("[AS3] Removing Override Configuration: %v", am.OverriderCfgMapName)
			cfgmap.Operation = OprTypeDelete
			return OverrideAS3Label, true
		}
		if val, ok := cfgmap.Label[OverrideAS3Label]; ok && val == TrueLabel {
			overriderName := cfgmap.Namespace + "/" + cfgmap.Name
			if len(am.OverriderCfgMapName) > 0 && (am.OverriderCfgMapName != overriderName) {
				log.Errorf("[AS3] Invalid overrider cfgMap: %v", am.OverriderCfgMapName)
				return "", false
			}
			return OverrideAS3Label, true
		} else if val, ok := cfgmap.Label[AS3Label]; ok && val == TrueLabel {
			return AS3Label, true
		} else if val, ok := cfgmap.Label[AS3Label]; ok && val == FalseLabel {
			return StagingAS3Label, true
		}
	}
	return "", false
}

// processCfgMap processes a configmap and feeds pool Members
// and return a map of tenants and all endpoints
func (am *AS3Manager) processCfgMap(rscCfgMap *AgentCfgMap) (
	map[string]interface{},
	[]Member,
	error,
) {
	as3Tmpl := as3Template(rscCfgMap.Data)
	obj, ok := getAS3ObjectFromTemplate(as3Tmpl)
	if !ok {
		log.Errorf("[AS3][Configmap] Error processing AS3 template")
		log.Errorf("[AS3]Error in processing the ConfigMap: %v/%v",
			rscCfgMap.Namespace, rscCfgMap.Name)
		return nil, nil, nil
	}

	if _, ok := obj[tenantName(DEFAULT_PARTITION)]; ok {
		log.Errorf("[AS3] Error in processing the ConfigMap: %v/%v",
			rscCfgMap.Namespace, rscCfgMap.Name)
		log.Errorf("[AS3] CIS managed partition <%s> should not be used in ConfigMaps as a Tenant",
			DEFAULT_PARTITION)
		return nil, nil, nil
	}

	var tmp interface{}

	// unmarshall the template of type string to interface
	err := json.Unmarshal([]byte(as3Tmpl), &tmp)
	if nil != err {
		return nil, nil, nil
	}

	// convert tmp to map[string]interface{}, This conversion will help in traversing the as3 object
	templateJSON := tmp.(map[string]interface{})

	if logLevel, ok := templateJSON["logLevel"]; ok {
		if val, ok := logLevel.(string); ok {
			am.as3LogLevel = &val
		} else {
			log.Errorf("Invalid AS3 logLevel: %v specified. Using default logLevel value.", logLevel)
		}
	}
	if persist, ok := templateJSON["persist"]; ok {
		if val, ok := persist.(bool); ok {
			am.as3DeclarationPersistence = &val
		} else {
			log.Errorf("Invalid AS3 persist: %v specified. Using default persist value.", persist)
		}
	}

	dec := (templateJSON["declaration"]).(map[string]interface{})
	tenantMap := make(map[string]interface{})
	var members []Member

	for tnt, apps := range obj {
		tenantObj := dec[string(tnt)].(map[string]interface{})
		tenantObj[as3defaultRouteDomain] = am.defaultRouteDomain
		for app, pools := range apps {
			appObj := tenantObj[string(app)].(map[string]interface{})
			for _, pn := range pools {
				poolObj := appObj[string(pn)].(map[string]interface{})
				var eps []Member
				var filteredPoolMemConfig []map[string]interface{}
				if val, ok := rscCfgMap.Label[IsTenantNameServiceNamespace]; ok && val == TrueLabel {
					eps, filteredPoolMemConfig, err = rscCfgMap.GetEndpoints(am.getSelector(tnt, app, pn), string(tnt), (poolObj["members"]).([]interface{}), true)
				} else {
					eps, filteredPoolMemConfig, err = rscCfgMap.GetEndpoints(am.getSelector(tnt, app, pn), rscCfgMap.Namespace, (poolObj["members"]).([]interface{}), false)
				}
				// If there is some error while fetching the endpoint from API server then skip processing further
				if nil != err {
					return nil, nil, err
				}
				// Handle an empty value
				if len(eps) == 0 {
					continue
				}

				var poolMembers []map[string]interface{}
				if len(filteredPoolMemConfig) == 0 {
					poolMem := (((poolObj["members"]).([]interface{}))[0]).(map[string]interface{})
					if am.poolMemberType == NodePortLocal {
						for _, ep := range eps {
							var ips []string
							if int(ep.SvcPort) == int(poolMem["servicePort"].(float64)) {
								members = append(members, ep)
								ips = append(ips, ep.Address)
								//copy poolMem to poolMember to preserve all other fields defined on the pool member
								poolMember := make(map[string]interface{})
								for key, value := range poolMem {
									poolMember[key] = value
								}
								poolMember["serverAddresses"] = ips
								poolMember["servicePort"] = float64(ep.Port)
								poolMember["shareNodes"] = poolMem["shareNodes"]
								poolMembers = append(poolMembers, poolMember)
							}
						}
					} else {
						var port int32
						for _, ep := range eps {
							var ips []string
							if int(ep.SvcPort) == int(poolMem["servicePort"].(float64)) {
								ips = append(ips, ep.Address)
								members = append(members, ep)
								port = ep.Port
								//copy poolMem to poolMember to preserve all other fields defined on the pool member
								poolMember := make(map[string]interface{})
								for key, value := range poolMem {
									poolMember[key] = value
								}
								poolMember["serverAddresses"] = ips
								poolMember["servicePort"] = float64(ep.Port)
								if ep.AdminState != "" {
									poolMember["adminState"] = ep.AdminState
								}
								poolMembers = append(poolMembers, poolMember)
							}
						}

						if port == 0 {
							ipMap := make(map[string]bool)
							members = append(members, eps...)
							for _, ep := range eps {
								var ips []string
								if _, ok := ipMap[ep.Address]; !ok {
									ipMap[ep.Address] = true
									ips = append(ips, ep.Address)
									//copy poolMem to poolMember to preserve all other fields defined on the pool member
									poolMember := make(map[string]interface{})
									for key, value := range poolMem {
										poolMember[key] = value
									}
									poolMember["serverAddresses"] = ips
									poolMember["servicePort"] = float64(eps[0].Port)
									if ep.AdminState != "" {
										poolMember["adminState"] = ep.AdminState
									}
									poolMembers = append(poolMembers, poolMember)
								}
							}
						}
					}
				} else {
					for _, ep := range eps {
						for _, mem := range filteredPoolMemConfig {
							var ips []string
							poolMemPriorityGroup, ok := mem["priorityGroup"]
							if !ok {
								poolMemPriorityGroup = float64(0)
							}
							if int(ep.SvcPort) == int(mem["servicePort"].(float64)) && ep.PriorityGroup == int(poolMemPriorityGroup.(float64)) {
								members = append(members, ep)
								ips = append(ips, ep.Address)
								//copy poolMem to poolMember to preserve all other fields defined on the pool member
								poolMember := make(map[string]interface{})
								for key, value := range mem {
									poolMember[key] = value
								}
								poolMember["serverAddresses"] = ips
								poolMember["servicePort"] = float64(ep.Port)
								poolMember["shareNodes"] = mem["shareNodes"]
								if ep.AdminState != "" {
									poolMember["adminState"] = ep.AdminState
								}
								if len(poolMembers) > 0 && poolMembers[0]["shareNodes"] != poolMember["shareNodes"] {
									log.Warningf("Share nodes value should be same for all the pool members. Defaulting to the first processed pool member share nodes value: %v.", poolMembers[0]["shareNodes"])
									poolMember["shareNodes"] = poolMembers[0]["shareNodes"]
								}
								poolMembers = append(poolMembers, poolMember)
								break
							}
						}
					}
				}
				// update the pool members
				poolObj["members"] = poolMembers
			}
		}
		tenantMap[string(tnt)] = tenantObj
	}
	return tenantMap, members, nil
}

// Method prepares and returns the label selector in string format
func (am *AS3Manager) getSelector(tenant tenantName, app appName, pool poolName) string {
	return svcTenantLabel + string(tenant) + "," +
		svcAppLabel + string(app) + "," +
		svcPoolLabel + string(pool)
}
