package as3

import (
	"encoding/json"
	"strings"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
)

// cfgMap State Transitions
const (
	cmInit = iota + 1
	cmActive
	cmError
)

var buffer map[Member]struct{}
var epbuffer map[string]struct{}

func (m *AS3Manager) prepareUserDefinedAS3Decleration(data string) (bool) {
	if m.as3ActiveConfig.configmap.inErrorState(data) ||
		m.as3ActiveConfig.configmap.alreadyProcessed(data) {
		return false
	}

	m.as3ActiveConfig.configmap.tmpData = data

	m.as3ActiveConfig.configmap.Data =
		m.generateUserDefinedAS3Decleration(data)
	if m.as3ActiveConfig.configmap.Data == "" {
		log.Error("[AS3] Error processing this User Defined AS3")
		m.as3ActiveConfig.configmap.errorState()
		return false
	}

	m.as3Members = buffer
	m.watchedAS3Endpoints = epbuffer
	m.as3ActiveConfig.configmap.activeState()

	return true
}

// Takes an AS3 Template and perform service discovery with Kubernetes to generate AS3 Declaration
func (m *AS3Manager) generateUserDefinedAS3Decleration(template string) as3Declaration {

	if m.as3Validation == true {
		if ok := m.validateAS3Template(template); !ok {
			log.Errorf("[AS3] Error validating AS3 template ")
			return ""
		}
	}
	templateObj := as3Template(template)
	obj, ok := getAS3ObjectFromTemplate(templateObj)

	if !ok {
		log.Errorf("[AS3] Error processing template\n")
		return ""
	}

	_, found := obj[tenantName(DEFAULT_PARTITION)]
	switch m.Agent { // TODO SNATRA Remove this
	case "as3":
		_, foundNetworkPartition := obj[tenantName(strings.TrimSuffix(DEFAULT_PARTITION, "_AS3"))]
		if found || foundNetworkPartition {
			log.Error("[AS3] Error in processing the template")
			log.Errorf("[AS3] CIS managed partitions <%s> and <%s> should not be used in ConfigMap as Tenants",
				DEFAULT_PARTITION, strings.TrimSuffix(DEFAULT_PARTITION, "_AS3"))
			return ""
		}
	default:
		if found {
			log.Error("[AS3] Error in processing the template")
			log.Errorf("[AS3] CIS managed partition <%s> should not be used in ConfigMap as Tenants",
				DEFAULT_PARTITION)
			return ""
		}
	}

	buffer = make(map[Member]struct{}, 0)
	epbuffer = make(map[string]struct{}, 0)

	return m.buildAS3Declaration(obj, templateObj)
}

func (cm AS3ConfigMap) isCfgMatched(namespace, name string) bool {
	if cm.cfg == "" {
		return false
	}
	// Extract namespace and name for the override AS3 configuration
	cfg := strings.Split(cm.cfg, "/")
	if namespace == cfg[0] && name == cfg[1] {
		return true
	}
	return false
}

func (c *AS3Config) prepareUserDefinedAS3CfgMap(data string) bool {

	if c.configmap.inErrorState(data)|| c.configmap.alreadyProcessed(data) {
		return false
	}

	c.configmap.tmpData = data
	// Validate AS3 Template

	return true
}

func (c *AS3Config) prepareAS3OverrideDecleration(data string) bool {
	if c.overrideConfigmap.inErrorState(data) || c.overrideConfigmap.alreadyProcessed(data) {
		return false
	}

	c.overrideConfigmap.tmpData = data

	if !DeepEqualJSON(c.overrideConfigmap.Data, as3Declaration(data)) {
		c.overrideConfigmap.Data = as3Declaration(data)
		if c.unifiedDeclaration != "" && !c.isDefaultAS3PartitionEmpty() {
			return true
		}
		log.Debugf("Saving AS3 override, no active configuration available in CIS")
	}

	return false
}

//func (m *AS3Manager) isAS3CfgMap(cfgMap *v1.ConfigMap) (string, bool) {
//	if m.Agent == "as3" {
//		if val, ok := cfgMap.ObjectMeta.Labels["f5type"]; ok && val == "virtual-server" {
//			if val, ok := cfgMap.ObjectMeta.Labels["overrideAS3"]; ok && val == "true" {
//				return "overrideAS3", true
//			} else if val, ok := cfgMap.ObjectMeta.Labels["as3"]; ok && val == "true" {
//				return "as3", true
//			}
//		}
//	}
//	return "", false
//}

func (cm AS3ConfigMap) prepareDeleteUserDefinedAS3() bool {
	if tntList := getTenants(cm.Data); tntList != nil {
		var tmpl interface{}
		err := json.Unmarshal([]byte(cm.Data), &tmpl)
		if err != nil {
			log.Errorf("[AS3] JSON unmarshal failed: %v\n", err)
			return false
		}

		// extract as3 declaration from template
		adc := (tmpl.(map[string]interface{}))["declaration"].(as3ADC)
		if adc == nil {
			log.Error("[AS3] No ADC class declaration found.")
			return false
		}

		for _, tnt := range tntList {
			tmpTnt := as3ADC{}
			tmpTnt.initDefault(tnt)
			adc[tnt] = tmpTnt
		}

		declaration, err := json.Marshal(tmpl.(map[string]interface{}))
		if err != nil {
			log.Errorf("[AS3] Issue marshalling AS3 Json")
		}

		cm.Data = as3Declaration(declaration)
	}
	return true
}

//func (m *AS3Manager) syncAS3ConfigMap(name, namespace, data string, stats *vsSyncStats) bool{
//	cfg := &m.as3ActiveConfig
//	switch name{
//	case cfg.overrideConfigmap.Name:
//		if m.as3ActiveConfig.prepareAS3OverrideDecleration(data) {
//			stats.vsUpdated += 1
//		}
//
//	case cfg.configmap.Name:
//		if m.prepareUserDefinedAS3Decleration(data){
//			stats.vsUpdated += 1
//		}
//	}
//	return true
//}

//func (m *AS3Manager) prepareAndPostAS3ConfigMapInServiceQueue(cm *v1.ConfigMap, cmType, oprType string) {
//	// Do not honour if CIS not watching this namespace
//	//var keyList []*serviceQueueKey
//	_, ok := m.getNamespaceInformer(cm.ObjectMeta.Namespace)
//	if !ok {
//		log.Debugf("[AS3] Found ConfigMap %s in unsupported namespace %s",
//			cm.Name, cm.ObjectMeta.Namespace)
//		return
//	}
//
//	key := serviceQueueKey{
//		Namespace:   cm.ObjectMeta.Namespace,
//		Name:        cm.ObjectMeta.Name,
//	}
//
//	m.as3ActiveConfig.cfgMapAssignOprType(cmType, oprType)
//
//	//keyList = append(keyList, key)
//	m.vsQueue.Add(key)
//
//	return
//}

// Takes AS3 template and AS3 Object and produce AS3 Declaration
func (m *AS3Manager) buildAS3Declaration(obj as3Object, template as3Template) as3Declaration {

	var tmp interface{}
	// unmarshall the template of type string to interface
	err := json.Unmarshal([]byte(template), &tmp)
	if nil != err {
		return ""
	}

	// convert tmp to map[string]interface{}, This conversion will help in traversing the as3 object
	templateJSON := tmp.(map[string]interface{})

	// traverse through the as3 object to fetch the list of services and get endpopints using the servicename
	log.Debugf("[AS3] Started Parsing the AS3 Object")
	for tnt, apps := range obj {
		for app, pools := range apps {
			for _, pn := range pools {
				eps := m.getEndpointsForPool(tnt, app, pn)
				// Handle an empty value
				if len(eps) == 0 {
					continue
				}
				ips := make([]string, 0)
				for _, v := range eps {
					ips = append(ips, v.Address)
				}
				port := eps[0].Port
				log.Debugf("Updating AS3 Template for tenant '%s' app '%s' pool '%s', ", tnt, app, pn)
				updatePoolMembers(tnt, app, pn, ips, port, templateJSON)
			}
		}
	}

	declaration, err := json.Marshal(templateJSON)
	if err != nil {
		log.Errorf("[AS3] Issue marshalling AS3 Json")
	}
	log.Debugf("[AS3] AS3 Template is populated with the pool members")

	return as3Declaration(declaration)

}


func (appMgr *AS3Manager) processAS3CfgMapDelete(name string) bool {
	switch name {
	case appMgr.as3ActiveConfig.overrideConfigmap.Name:
		appMgr.as3ActiveConfig.overrideConfigmap.Data = ""
		appMgr.as3ActiveConfig.overrideConfigmap.OprType = ""
		return true
	case appMgr.as3ActiveConfig.configmap.Name:
		if appMgr.as3ActiveConfig.configmap.prepareDeleteUserDefinedAS3() {
			appMgr.as3ActiveConfig.configmap.OprType = ""
			return true
		}
	}
	return false
}

// Performs Service discovery for the given AS3 Pool and returns a pool.
// Service discovery is loosely coupled with Kubernetes Service labels. A Kubernetes Service is treated as a match for
// an AS3 Pool, if the Kubernetes Service have the following labels and their values matches corresponding AS3
// Object.
// cis.f5.com/as3-tenant=<Tenant Name>
// cis.f5.com/as3-app=<Application Name>
// cis.f5.com/as3-pool=<Pool Name>
// When controller is in NodePort mode, returns a list of Node IP Address and NodePort.
// When controller is in ClusterIP mode, returns a list of Cluster IP Address and Service Port. Also, it accumulates
// members for static ARP entry population.
func (m *AS3Manager) getEndpointsForPool(tenant tenantName, app appName, pool poolName) pool {
	log.Debugf("[AS3] Discovering endpoints for pool: [%v -> %v -> %v]", tenant, app, pool)

	var members []Member
	//tenantKey := "cis.f5.com/as3-tenant="
	//appKey := "cis.f5.com/as3-app="
	//poolKey := "cis.f5.com/as3-pool="
	//
	//selector := tenantKey + string(tenant) + "," +
	//	appKey + string(app) + "," +
	//	poolKey + string(pool)
	//
	//svcListOptions := metaV1.ListOptions{
	//	LabelSelector: selector,
	//}
	//
	//// Identify services that matches the given label
	//services, err := m.kubeClient.CoreV1().Services(v1.NamespaceAll).List(svcListOptions)
	//
	//if err != nil {
	//	log.Errorf("[AS3] Error getting service list. %v", err)
	//	return nil
	//}
	//
	//
	//if len(services.Items) > 1 {
	//	svcNames := ""
	//
	//	for _, service := range services.Items {
	//		svcNames += fmt.Sprintf("Service: %v, Namespace: %v \n", service.Name, service.Namespace)
	//	}
	//
	//	log.Errorf("[AS3] Multiple Services are tagged for this pool. Ignoring all endpoints.\n%v", svcNames)
	//	return members
	//}
	//
	//for _, service := range services.Items {
	//	if m.isNodePort == false { // Controller is in ClusterIP Mode
	//		endpointsList, err := m.kubeClient.CoreV1().Endpoints(service.Namespace).List(
	//			metaV1.ListOptions{
	//				FieldSelector: "metadata.name=" + service.Name,
	//			},
	//		)
	//		if err != nil {
	//			log.Debugf("[AS3] Error getting endpoints for service %v", service.Name)
	//			continue
	//		}
	//
	//		for _, endpoints := range endpointsList.Items {
	//			for _, subset := range endpoints.Subsets {
	//				for _, address := range subset.Addresses {
	//					member := Member{
	//						Address: address.IP,
	//						Port:    subset.Ports[0].Port,
	//					}
	//					members = append(members, member)
	//
	//					// Update master AS3 Member list
	//					buffer[member] = struct{}{}
	//				}
	//			}
	//			// Populate endpoints to watchList
	//			epbuffer[endpoints.Name] = struct{}{}
	//		}
	//	} else { // Controller is in NodePort mode.
	//		if service.Spec.Type == v1.ServiceTypeNodePort {
	//			members = m.getEndpointsForNodePort(service.Spec.Ports[0].NodePort)
	//		} else {
	//			msg := fmt.Sprintf("Requested service backend '%+v' not of NodePort type", service.Name)
	//			log.Debug(msg)
	//		}
	//	}
	//
	//	log.Debugf("[AS3] Discovered members for service %v is %v", service.Name, members)
	//}

	return members
}

func (cm *AS3ConfigMap) isUniqueName(cmName string) bool {
	if cm.Name == cmName {
		return true
	}
	return false
}

func (cm *AS3ConfigMap) inErrorState(data string) bool {
	if cm.State == cmError {
		if DeepEqualJSON(as3Declaration(cm.tmpData), as3Declaration(data)) {
			log.Errorf("[AS3] Configuration in cfgMap %v is invalid, please correct", cm.Name)
			return true
		}
	}
	return false
}

func (cm *AS3ConfigMap) alreadyProcessed(data string) bool {
	if cm.State == cmActive {
		if DeepEqualJSON(as3Declaration(cm.tmpData), as3Declaration(data)) {
			return true
		}
	}
	return false
}

func (cm *AS3ConfigMap) errorState() {
	cm.State = cmError
}

func (cm *AS3ConfigMap) activeState() {
	cm.State = cmActive
}

func (cm *AS3ConfigMap) reset() {
	cm.Name = ""
	cm.Namespace = ""
	cm.OprType = ""
	cm.Data = ""
	cm.tmpData = ""
	cm.State = cmInit
}

func (c AS3Config) isUniqueConfigMap(cmType, cmName string) bool {
	switch cmType {
	case "as3":
		return c.configmap.isUniqueName(cmName)
	case "overrideAS3":
		return c.overrideConfigmap.isUniqueName(cmName)
	}
	return false
}


func (c AS3Config) isCfgMapAdmitted(cmType, namespace, name string) bool {
	switch cmType {
	case "as3":
		if ! c.configmap.isCfgMatched(namespace, name){
			log.Debugf("[AS3] user defined AS3 configMap with namespace %v" +
				" and name %v cannot be admitted, please check --override-as3-declaration option in CIS",
				namespace, name)
			return false
		}
	case "overrideAS3":
		if !c.overrideConfigmap.isCfgMatched(namespace, name){
			log.Debugf("[AS3] override AS3 configMap with namespace %v" +
				" and name %v cannot be admitted, please check --userdefined-as3-declaration option in CIS",
				namespace, name)
			return false
		}
	}
	return true
}

func (c *AS3Config) setCfgMap(cmType, name, namespace string) {
	switch cmType {
	case "as3":
		c.configmap.Name = name
		c.configmap.Namespace = namespace
	case "overrideAS3":
		c.overrideConfigmap.Name = name
		c.overrideConfigmap.Namespace = namespace
	}
	return
}

func (c *AS3Config) cfgMapAssignOprType(cmType, oprType string) {
	switch cmType {
	case "as3":
		c.configmap.OprType = oprType
	case "overrideAS3":
		c.overrideConfigmap.OprType = oprType
	}
	return
}
