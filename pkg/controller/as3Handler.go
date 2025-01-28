package controller

import (
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"strings"
)

// write a function for NewAS3Handler, rewrite

func NewAS3Handler(params AgentParams) *AS3Handler {
	handler := &AS3Handler{
		AS3Config: make(map[string]interface{}),
		AS3Parser: NewAS3Parser(params),
	}

	return handler
}

//func (am *AS3Handler) publishConfig(cfg agentConfig) {
//	am.postConfig(&cfg)
//	if am.LogRequest {
//		am.logRequest(cfg.data)
//	}
//}

func (am *AS3Handler) getVersionURL() string {
	apiURL := am.BIGIPURL + "/mgmt/shared/appsvcs/info"
	return apiURL
}

func (am *AS3Handler) getAPIURL(tenants []string) string {
	apiURL := am.BIGIPURL + "/mgmt/shared/appsvcs/declare/" + strings.Join(tenants, ",")
	return apiURL
}

func (am *AS3Handler) getTaskIdURL(taskId string) string {
	apiURL := am.BIGIPURL + "/mgmt/shared/appsvcs/task/" + taskId
	return apiURL
}

func (am *AS3Handler) getApiHandler() *AS3Handler {
	return am
}

func (am *AS3Handler) logRequest(cfg string) {
	var as3Config map[string]interface{}
	err := json.Unmarshal([]byte(cfg), &as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Request body unmarshal failed: %v\n", am.postManagerPrefix, err)
	}
	adc := as3Config["declaration"].(map[string]interface{})
	for _, value := range adc {
		if tenantMap, ok := value.(map[string]interface{}); ok {
			for _, value2 := range tenantMap {
				if appMap, ok := value2.(map[string]interface{}); ok {
					for _, obj := range appMap {
						if crt, ok := obj.(map[string]interface{}); ok {
							if crt["class"] == "Certificate" {
								crt["certificate"] = ""
								crt["privateKey"] = ""
								crt["chainCA"] = ""
							}
						}
					}
				}
			}
		}
	}
	decl, err := json.Marshal(as3Config)
	if err != nil {
		log.Errorf("[AS3]%v Unified declaration error: %v\n", am.postManagerPrefix, err)
		return
	}
	log.Debugf("[AS3]%v Unified declaration: %v\n", am.postManagerPrefix, as3Declaration(decl))
}

func (am *AS3Handler) logResponse(responseMap map[string]interface{}) {
	// removing the certificates/privateKey from response log
	if declaration, ok := (responseMap["declaration"]).([]interface{}); ok {
		for _, value := range declaration {
			if tenantMap, ok := value.(map[string]interface{}); ok {
				for _, value2 := range tenantMap {
					if appMap, ok := value2.(map[string]interface{}); ok {
						for _, obj := range appMap {
							if crt, ok := obj.(map[string]interface{}); ok {
								if crt["class"] == "Certificate" {
									crt["certificate"] = ""
									crt["privateKey"] = ""
									crt["chainCA"] = ""
								}
							}
						}
					}
				}
			}
		}
		decl, err := json.Marshal(declaration)
		if err != nil {
			log.Errorf("[AS3]%v error while reading declaration from AS3 response: %v\n", am.postManagerPrefix, err)
			return
		}
		responseMap["declaration"] = as3Declaration(decl)
	}
	log.Debugf("[AS3]%v Raw response from Big-IP: %v ", am.postManagerPrefix, responseMap)
}

func (am *AS3Handler) createAS3Declaration(tenantDeclMap map[string]as3Tenant, userAgent string) as3Declaration {
	var as3Config map[string]interface{}

	baseAS3ConfigTemplate := fmt.Sprintf(baseAS3Config, am.AS3VersionInfo.as3Version, am.AS3VersionInfo.as3Release, am.AS3VersionInfo.as3SchemaVersion)
	_ = json.Unmarshal([]byte(baseAS3ConfigTemplate), &as3Config)

	adc := as3Config["declaration"].(map[string]interface{})

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

func (am *AS3Handler) getBigipRegKeyURL() string {
	apiURL := am.BIGIPURL + "/mgmt/tm/shared/licensing/registration"
	return apiURL
}
