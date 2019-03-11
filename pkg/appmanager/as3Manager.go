package appmanager

type as3Template string
type as3Declaration string

type serviceName string
type appName string
type tenantName string

type pool []Member
type tenant map[appName][]serviceName
type as3Object map[tenantName]tenant

// Takes an AS3 Template and perform service discovery with Kubernetes to generate AS3 Declaration
func (appMgr *Manager) processUserDefinedAS3(template as3Template) {
	// TODO: Implement Me

}

// Story 2
// Covert AS3 JSON in to Map for further processing
func (appMgr *Manager) getAS3ObjectsFromTemplate(template as3Template) (as3Object, bool) {
	return as3Object{}, true
}

// Story 3
// Discover Endpoints for an application. Returns a pool
func (appMgr *Manager) getEndpointsForAS3Service(tenant tenantName, app appName, as3Svc serviceName) pool {
	return pool{}
}

// Returns a pool of IP address.
func (appMgr *Manager) getFakeEndpointsForAS3Service(tenant tenantName, app appName, as3Svc serviceName) pool {
	return []Member{
		{"1.1.1.1", 80, ""},
		{"2.2.2.2", 80, ""},
		{"3.3.3.3", 80, ""},
	}
}

// Story 4
// Takes AS3 template and AS3 Object and produce AS3 Declaration
func buildAS3Declaration(obj as3Object, template as3Template) as3Declaration {
	decalaration := ""
	return as3Declaration(decalaration)
}

//Story 5
// Takes AS3 Declaration and posting it to BigIP
func (appMgr *Manager) postAS3Declaration(declaration as3Declaration) {
}
