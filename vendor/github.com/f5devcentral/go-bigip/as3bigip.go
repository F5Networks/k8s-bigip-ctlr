package bigip

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const doSchemaLatestURL = "https://raw.githubusercontent.com/F5Networks/terraform-provider-bigip/master/schemas/doschema.json"

const (
	uriSha          = "shared"
	uriAppsvcs      = "appsvcs"
	uriDecl         = "declare"
	uriInfo         = "info"
	uriTask         = "task"
	uriDeclare      = "declare"
	uriAsyncDeclare = "declare?async=true"
	uriSetting      = "settings"
	uriApplications = "applications"
)

type doValidate struct {
	doSchemaURL    string
	doSchemaLatest string
}

type as3Version struct {
	Version       string `json:"version"`
	Release       string `json:"release"`
	SchemaCurrent string `json:"schemaCurrent"`
	SchemaMinimum string `json:"schemaMinimum"`
}

type As3AllTaskType struct {
	Items []As3TaskType `json:"items,omitempty"`
}
type As3TaskType struct {
	ID string `json:"id,omitempty"`
	//Declaration struct{} `json:"declaration,omitempty"`
	Results []Results1 `json:"results,omitempty"`
}
type Results1 struct {
	Code      int64  `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	LineCount int64  `json:"lineCount,omitempty"`
	Host      string `json:"host,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	RunTime   int64  `json:"runTime,omitempty"`
}

// PostPerAppBigIp - used for posting Per-Application Declarations
func (b *BigIP) PostPerAppBigIp(as3NewJson, tenantFilter, queryParam string) (error, string) {
	// resp, err := PostPerApp()
	async := "?async=true" + queryParam
	resp, err := b.postAS3Req(as3NewJson, uriMgmt, uriShared, uriAppsvcs, uriDeclare, tenantFilter, uriApplications, async)
	if err != nil {
		return err, ""
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["id"].(string)
	taskStatus, err := b.getas3TaskStatus(respID)
	respCode := taskStatus["results"].([]interface{})[0].(map[string]interface{})["code"].(float64)
	log.Printf("[DEBUG]Per-App Deployment Code = %+v,ID = %+v", respCode, respID)

	for respCode != 200 || taskStatus["results"].([]interface{})[0].(map[string]interface{})["message"].(string) != "success" {
		log.Printf("[DEBUG]Per-App Deployment task status = %+v", taskStatus)
		if taskStatus["results"].([]interface{})[0].(map[string]interface{})["message"].(string) == "no change" {
			log.Printf("[DEBUG]Per-App Deployment task status = %+v", taskStatus)
			break
		}
		taskStatus, _ = b.getas3TaskStatus(respID)
		respCode = taskStatus["results"].([]interface{})[0].(map[string]interface{})["code"].(float64)
		log.Printf("respCode: %v", respCode)
		log.Printf("message: %v", taskStatus["results"].([]interface{})[0].(map[string]interface{})["message"].(string))
		if err != nil {
			return err, respID
		}
		if respCode == 503 || respCode >= 400 {
			j, _ := json.MarshalIndent(taskStatus["results"].([]interface{}), "", "\t")
			return fmt.Errorf("tenant Creation failed. Response: %+v", string(j)), respID
		}
		time.Sleep(3 * time.Second)
	}
	return nil, respID
}

/*
PostAs3Bigip used for posting as3 json file to BIGIP
*/
func (b *BigIP) PostAs3Bigip(as3NewJson, tenantFilter, queryParam string) (error, string, string) {
	tenant := tenantFilter + "?async=true" + queryParam

	successfulTenants := make([]string, 0)
	resp, err := b.postReq(as3NewJson, uriMgmt, uriShared, uriAppsvcs, uriDeclare, tenant)
	if err != nil {
		return err, "", ""
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["id"].(string)
	taskStatus, err := b.getas3TaskStatus(respID)
	respCode := taskStatus["results"].([]interface{})[0].(map[string]interface{})["code"].(float64)
	log.Printf("[DEBUG]Code = %+v,ID = %+v", respCode, respID)
	for respCode != 200 {
		fastTask, err := b.getas3TaskStatus(respID)
		if err != nil {
			return err, "", respID
		}
		respCode = fastTask["results"].([]interface{})[0].(map[string]interface{})["code"].(float64)
		if respCode != 0 && respCode != 503 {
			tenant_list, tenant_count, _ := b.GetTenantList(as3NewJson)
			if tenantCompare(tenant_list, tenantFilter) == 1 {
				if len(fastTask["results"].([]interface{})) == 1 && fastTask["results"].([]interface{})[0].(map[string]interface{})["message"].(string) == "declaration is invalid" {
					return fmt.Errorf("Error :%+v", fastTask["results"].([]interface{})[0].(map[string]interface{})["errors"]), "", respID
				}
				if len(fastTask["results"].([]interface{})) == 1 && fastTask["results"].([]interface{})[0].(map[string]interface{})["message"].(string) != "success" && fastTask["results"].([]interface{})[0].(map[string]interface{})["message"].(string) != "no change" {
					j, _ := json.MarshalIndent(fastTask["results"].([]interface{}), "", "\t")
					return fmt.Errorf("Tenant Creation failed with Response: %+v", string(j)), "", respID
				}
				i := tenant_count - 1
				success_count := 0
				for i >= 0 {
					if fastTask["results"].([]interface{})[i].(map[string]interface{})["code"].(float64) == 200 {
						successfulTenants = append(successfulTenants, fastTask["results"].([]interface{})[i].(map[string]interface{})["tenant"].(string))
						success_count++
					}
					if fastTask["results"].([]interface{})[i].(map[string]interface{})["code"].(float64) >= 400 {
						log.Printf("[ERROR] : HTTP %v :: %s for tenant %v", fastTask["results"].([]interface{})[i].(map[string]interface{})["code"].(float64), fastTask["results"].([]interface{})[i].(map[string]interface{})["message"].(string), fastTask["results"].([]interface{})[i].(map[string]interface{})["tenant"])
					}
					i = i - 1
				}
				if success_count == tenant_count {
					log.Printf("[DEBUG]Sucessfully Created Application with ID  = %v", respID)
					break // break here
				} else if success_count == 0 {
					j, _ := json.MarshalIndent(fastTask["results"].([]interface{}), "", "\t")
					return fmt.Errorf("Tenant Creation failed. Response: %+v", string(j)), "", respID
				} else {
					finallist := strings.Join(successfulTenants[:], ",")
					j, _ := json.MarshalIndent(fastTask["results"].([]interface{}), "", "\t")
					return fmt.Errorf("as3 config post error response %+v", string(j)), finallist, respID
				}
			}
			if respCode == 200 {
				log.Printf("[DEBUG]Sucessfully Created Application with ID  = %v", respID)
				break // break here
			}
			if respCode >= 400 {
				j, _ := json.MarshalIndent(fastTask["results"].([]interface{}), "", "\t")
				return fmt.Errorf("Tenant Creation failed. Response: %+v", string(j)), "", respID
			}
		}
		if respCode == 503 {
			taskIds, err := b.getas3Taskid()
			if err != nil {
				return err, "", respID
			}
			if len(taskIds) == 0 {
				time.Sleep(2 * time.Second)
				return b.PostAs3Bigip(as3NewJson, tenantFilter, queryParam)
			}
			for _, id := range taskIds {
				if b.pollingStatus(id, 5*time.Second) {
					return b.PostAs3Bigip(as3NewJson, tenantFilter, queryParam)
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	return nil, strings.Join(successfulTenants[:], ","), respID
}

func (b *BigIP) DeleteAs3Bigip(tenantName string) (error, string) {
	tenant := tenantName + "?async=true"
	failedTenants := make([]string, 0)
	resp, err := b.deleteReq(uriMgmt, uriShared, uriAppsvcs, uriDeclare, tenant)
	if err != nil {
		return err, ""
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["id"].(string)
	taskStatus, err := b.getas3Taskstatus(respID)
	respCode := taskStatus.Results[0].Code
	log.Printf("[DEBUG]Delete Code = %v,ID = %v", respCode, respID)
	for respCode != 200 {
		fastTask, err := b.getas3Taskstatus(respID)
		if err != nil {
			return err, ""
		}
		respCode = fastTask.Results[0].Code
		if respCode != 0 && respCode != 503 {
			tenant_count := len(strings.Split(tenantName, ","))
			if tenant_count != 1 {
				i := tenant_count - 1
				success_count := 0
				for i >= 0 {
					if fastTask.Results[i].Code == 200 {
						success_count++
					}
					if fastTask.Results[i].Code >= 400 {
						failedTenants = append(failedTenants, fastTask.Results[i].Tenant)
						log.Printf("[ERROR] : HTTP %d :: %s for tenant %v", fastTask.Results[i].Code, fastTask.Results[i].Message, fastTask.Results[i].Tenant)
					}
					i = i - 1
				}
				if success_count == tenant_count {
					log.Printf("[DEBUG]Sucessfully Deleted Application with ID  = %v", respID)
					break // break here
				} else if success_count == 0 {
					return errors.New(fmt.Sprintf("Tenant Deletion failed")), ""
				} else {
					finallist := strings.Join(failedTenants[:], ",")
					return errors.New(fmt.Sprintf("Partial Success")), finallist
				}
			}
			if respCode == 200 {
				log.Printf("[DEBUG]Sucessfully Deleted Application with ID  = %v", respID)
				break // break here
			}
			if respCode >= 400 {
				j, _ := json.MarshalIndent(fastTask, "", "\t")
				return fmt.Errorf("Tenant Deletion failed with Response: \n %+v", string(j)), ""
			}
		}
		if respCode == 503 {
			taskIds, err := b.getas3Taskid()
			if err != nil {
				return err, ""
			}
			if len(taskIds) == 0 {
				time.Sleep(2 * time.Second)
				return b.DeleteAs3Bigip(tenantName)
			}
			for _, id := range taskIds {
				if b.pollingStatus(id, 5*time.Second) {
					return b.DeleteAs3Bigip(tenantName)
				}
			}
		}
		time.Sleep(3 * time.Second)
	}

	return nil, ""

}
func (b *BigIP) ModifyAs3(tenantFilter string, as3_json string) error {
	tenant := tenantFilter + "?async=true"
	resp, err := b.fastPatch(as3_json, uriMgmt, uriShared, uriAppsvcs, uriDeclare, tenant)
	if err != nil {
		return err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["id"].(string)
	taskStatus, err := b.getas3Taskstatus(respID)
	respCode := taskStatus.Results[0].Code
	for respCode != 200 {
		fastTask, err := b.getas3Taskstatus(respID)
		if err != nil {
			return err
		}
		respCode = fastTask.Results[0].Code
		if respCode == 200 {
			log.Printf("[DEBUG]Sucessfully Modified Application with ID  = %v", respID)
			break // break here
		}
		if respCode == 503 {
			taskIds, err := b.getas3Taskid()
			if err != nil {
				return err
			}
			for _, id := range taskIds {
				if b.pollingStatus(id, 5*time.Second) {
					return b.ModifyAs3(tenantFilter, as3_json)
				}
			}
		}
	}

	return nil

}
func (b *BigIP) GetAs3(name, appList string, perAppMode bool) (string, error) {
	as3Json := make(map[string]interface{})
	adcJson := make(map[string]interface{})
	var err error
	var ok bool

	log.Printf("[DEBUG] (GetAs3) Per App Mode :%+v", perAppMode)

	if perAppMode {
		err, ok = b.getForEntity(&adcJson, uriMgmt, uriShared, uriAppsvcs, uriDeclare, name, uriApplications)
	} else {
		as3Json["class"] = "AS3"
		as3Json["action"] = "deploy"
		as3Json["persist"] = true
		err, ok = b.getForEntity(&adcJson, uriMgmt, uriShared, uriAppsvcs, uriDeclare, name)
	}
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	delete(adcJson, "updateMode")
	delete(adcJson, "controls")

	if perAppMode {
		as3Json = adcJson
	} else {
		as3Json["declaration"] = adcJson
	}
	out, _ := json.Marshal(as3Json)
	as3String := string(out)
	tenantList := strings.Split(appList, ",")
	found := 0
	for _, item := range tenantList {
		if item == "Shared" && name == "Common" {
			found = 1
		}
	}
	if found == 0 {
		sharedTenant := ""
		resp := []byte(as3String)
		jsonRef := make(map[string]interface{})
		json.Unmarshal(resp, &jsonRef)
		for key, value := range jsonRef {
			if rec, ok := value.(map[string]interface{}); ok && key == "declaration" {
				for k, v := range rec {
					if rec2, ok := v.(map[string]interface{}); ok {
						for k1, v1 := range rec2 {
							if _, ok := v1.(map[string]interface{}); ok {
								if k1 == "Shared" {
									sharedTenant = k
								}
							}
						}
					}
					if sharedTenant == "Common" && sharedTenant != name {
						// Removing delete call for shared tenant to address Issue #869
						// delete(rec, sharedTenant)
						log.Printf("[DEBUG]Shared Tenant:%+v", sharedTenant)
					}
				}
			}
		}
		out, _ = json.Marshal(jsonRef)
		as3String = string(out)
	}
	return as3String, nil
}
func (b *BigIP) getAs3version() (*as3Version, error) {
	var as3Ver as3Version
	err, _ := b.getForEntity(&as3Ver, uriMgmt, uriShared, uriAppsvcs, uriInfo)
	if err != nil {
		return nil, err
	}
	return &as3Ver, nil
}
func (b *BigIP) getas3Taskstatus(id string) (*As3TaskType, error) {
	var taskList As3TaskType
	err, _ := b.getForEntity(&taskList, uriMgmt, uriShared, uriAppsvcs, uriTask, id)
	if err != nil {
		return nil, err
	}
	return &taskList, nil
}
func (b *BigIP) getas3TaskStatus(id string) (map[string]interface{}, error) {
	var taskList map[string]interface{}
	err, _ := b.getForEntity(&taskList, uriMgmt, uriShared, uriAppsvcs, uriTask, id)
	if err != nil {
		return nil, err
	}
	return taskList, nil
}

func (b *BigIP) Getas3TaskResponse(id string) (interface{}, error) {
	as3Json := make(map[string]interface{})
	as3Json["class"] = "AS3"
	as3Json["action"] = "deploy"
	as3Json["persist"] = true
	var taskResponse map[string]interface{}
	err, ok := b.getForEntity(&taskResponse, uriMgmt, uriShared, uriAppsvcs, uriTask, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	delete(taskResponse["declaration"].(map[string]interface{}), "updateMode")
	delete(taskResponse["declaration"].(map[string]interface{}), "controls")
	delete(taskResponse["declaration"].(map[string]interface{}), "id")
	as3Json["declaration"] = taskResponse["declaration"]
	out, _ := json.Marshal(as3Json)
	as3String := string(out)
	return as3String, nil
}

func (b *BigIP) getas3Taskid() ([]string, error) {
	var taskList As3AllTaskType
	var taskIDs []string
	err, _ := b.getForEntity(&taskList, uriMgmt, uriShared, uriAppsvcs, uriTask)
	if err != nil {
		return taskIDs, err
	}
	for l := range taskList.Items {
		if taskList.Items[l].Results[0].Message == "in progress" {
			taskIDs = append(taskIDs, taskList.Items[l].ID)
		}
	}
	return taskIDs, nil
}

func (b *BigIP) pollingStatus(id string, backoff time.Duration) bool {
	log.Printf("[INFO]pollingStatus DELAY -- %d ", int(backoff.Seconds()))
	var taskList As3TaskType
	err, _ := b.getForEntity(&taskList, uriMgmt, uriShared, uriAppsvcs, uriTask, id)
	if err != nil {
		return false
	}
	if taskList.Results[0].Code != 200 {
		if backoff > 30*time.Second {
			backoff = 30 * time.Second // cap at 30 seconds
		}
		time.Sleep(backoff)
		return b.pollingStatus(id, backoff*2) // recursive call with doubled delay
	}

	return true
}

func (b *BigIP) GetTenantList(body interface{}) (string, int, string) {
	tenantList := make([]string, 0)
	applicationList := make([]string, 0)
	as3json := body.(string)
	resp := []byte(as3json)
	jsonRef := make(map[string]interface{})
	json.Unmarshal(resp, &jsonRef)
	for key, value := range jsonRef {
		if rec, ok := value.(map[string]interface{}); ok && key == "declaration" {
			for k, v := range rec {
				if rec2, ok := v.(map[string]interface{}); ok {
					found := 0
					for k1, v1 := range rec2 {
						if k1 == "class" && v1 == "Tenant" {
							found = 1
						}
						if rec3, ok := v1.(map[string]interface{}); ok {
							found1 := 0
							for k2, v2 := range rec3 {
								if k2 == "class" && v2 == "Application" {
									found1 = 1
								}
							}
							if found1 == 1 {
								applicationList = append(applicationList, k1)
							}

						}
					}
					if found == 1 {
						tenantList = append(tenantList, k)
					}
				}
			}
		}
	}
	finalTenantlist := strings.Join(tenantList[:], ",")
	finalApplicationList := strings.Join(applicationList[:], ",")
	return finalTenantlist, len(tenantList), finalApplicationList
}

func (b *BigIP) GetAppsList(body interface{}) string {
	//tenantList := make([]string, 0)
	appList := make([]string, 0)
	as3json := body.(string)
	resp := []byte(as3json)
	jsonRef := make(map[string]interface{})
	json.Unmarshal(resp, &jsonRef)
	for key, value := range jsonRef {
		//check value is of interface type
		if _, ok := value.(map[string]interface{}); ok {
			//check for class matches to Application
			//range over the map and check if key is class and value is Application
			for k1, v1 := range value.(map[string]interface{}) {
				//check for class matches to Application
				if k1 == "class" && v1 == "Application" {
					appList = append(appList, key)
				}
			}
		}
	}
	finalApplicationList := strings.Join(appList[:], ",")
	return finalApplicationList
}
func (b *BigIP) GetTarget(body interface{}) string {
	as3json := body.(string)
	resp := []byte(as3json)
	jsonRef := make(map[string]interface{})
	json.Unmarshal(resp, &jsonRef)
	for key, value := range jsonRef {
		if _, ok := value.(map[string]interface{}); ok && key == "declaration" {
			if val, ok := value.(map[string]interface{})["target"]; ok {
				//log.Printf("[DEBUG]: target:%+v", val.(map[string]interface{})["address"])
				return val.(map[string]interface{})["address"].(string)
			}
		}
	}
	return ""
}

func (b *BigIP) AddTeemAgent(body interface{}) (string, error) {
	var s string
	as3json := body.(string)
	resp := []byte(as3json)
	jsonRef := make(map[string]interface{})
	json.Unmarshal(resp, &jsonRef)
	//jsonRef["controls"] = map[string]interface{}{"class": "Controls", "userAgent": "Terraform Configured AS3"}
	as3ver, err := b.getAs3version()
	if err != nil {
		return "", fmt.Errorf("Getting AS3 Version failed with %v", err)
	}
	if as3ver.Version == "" {
		return "", fmt.Errorf("Getting AS3 Version failed,please check AS3 installed?")
	}
	log.Printf("[DEBUG] AS3 Version:%+v", as3ver.Version)
	log.Printf("[DEBUG] Terraform Version:%+v", b.UserAgent)
	//userAgent, err := getVersion("/usr/local/bin/terraform")
	//log.Printf("[DEBUG] Terraform version:%+v", userAgent)
	res1 := strings.Split(as3ver.Version, ".")
	for key, value := range jsonRef {
		if key == "declaration" {
			if rec, ok := value.(map[string]interface{}); ok {
				if intConvert(res1[0]) > 3 || intConvert(res1[1]) >= 18 {
					rec["controls"] = map[string]interface{}{"class": "Controls", "userAgent": b.UserAgent}
				}
			}
		}
	}
	jsonData, err := json.Marshal(jsonRef)
	if err != nil {
		//log.Println(err)
		return "", fmt.Errorf("Getting AS3 Version failed with %v", err)
	}
	s = string(jsonData)
	return s, nil
}

func (b *BigIP) CheckSetting() (bool, error) {
	err, resp := b.getSetting(uriMgmt, uriShared, uriAppsvcs, uriSetting)
	if err != nil {
		return false, err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	perAppDeploymentAllowed := false
	if value, ok := respRef["betaOptions"].(map[string]interface{}); ok { //for AS3 version < 3.5
		perAppDeploymentAllowed = value["perAppDeploymentAllowed"].(bool)
	} else if value, ok := respRef["perAppDeploymentAllowed"]; ok { // for As3 version 3.5
		perAppDeploymentAllowed = value.(bool)
	}
	log.Printf("[INFO] BigIP Setting perAppDeploymentAllowed:%+v", perAppDeploymentAllowed)
	return perAppDeploymentAllowed, nil

	// err, setting := b.getSetting(uriMgmt, uriShared, uriAppsvcs, uriSetting)
	// if err != nil {
	// 	return false, err
	// }
	// log.Printf("[INFO] BigIP Setting:%+v", setting)
	// perAppDeploymentAllowed := setting.BetaOptions.PerAppDeploymentAllowed

	// return perAppDeploymentAllowed, nil
}

func (b *BigIP) DeletePerApplicationAs3Bigip(tenantName string, applicationName string) error {

	_, err := b.deleteReq(uriMgmt, uriShared, uriAppsvcs, uriDeclare, tenantName, uriApplications, applicationName)
	if err != nil {
		return err
	}
	return nil
}

func (b *BigIP) AddServiceDiscoveryNodes(taskid string, config []interface{}) error {
	resp, err := b.postReq(config, uriMgmt, uriShared, "service-discovery", "task", taskid, "nodes")
	if err != nil {
		return err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	//respID := respRef["id"].(string)
	log.Printf("[INFO] Response:%+v", respRef)
	return nil
}

func (b *BigIP) GetServiceDiscoveryNodes(taskid string) (interface{}, error) {
	var nodesList interface{}
	err, ok := b.getForEntity(&nodesList, uriMgmt, uriShared, "service-discovery", "task", taskid, "nodes")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return nodesList, nil
}

func intConvert(v interface{}) int {
	if s, err := strconv.Atoi(v.(string)); err == nil {
		return s
	}
	return 0
}
func getVersion(tfBinary string) (string, error) {
	var versionRegex = regexp.MustCompile("Terraform v(.*?)(\\s.*)?\n")
	out, err := exec.Command(tfBinary, "version").Output()
	if err != nil {
		return "", err
	}
	versionOutput := string(out)
	match := versionRegex.FindStringSubmatch(versionOutput)
	ua := fmt.Sprintf("Terraform/%s", match[1])
	return ua, nil
}
func (b *BigIP) TenantDifference(slice1 []string, slice2 []string) string {
	var diff []string
	for _, s1 := range slice1 {
		found := false
		for _, s2 := range slice2 {
			if s1 == s2 {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, s1)
		}
	}
	diff_tenant_list := strings.Join(diff[:], ",")
	return diff_tenant_list
}
func tenantCompare(t1 string, t2 string) int {
	tenantList1 := strings.Split(t1, ",")
	tenantList2 := strings.Split(t2, ",")
	if len(tenantList1) == len(tenantList2) {
		return 1
	}
	return 0
}
