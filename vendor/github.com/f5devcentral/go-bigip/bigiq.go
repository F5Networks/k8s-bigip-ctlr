package bigip

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"
)

const (
	uriRegkey      = "regkey"
	uriLicenses    = "licenses"
	uriResolver    = "resolver"
	uriDevicegroup = "device-groups"
	uriCmBigip     = "cm-bigip-allBigIpDevices"
	uriDevice      = "device"
	uriMembers     = "members"
	uriTasks       = "tasks"
	uriManagement  = "member-management"
	uriPurchased   = "purchased-pool"
)

var tenantProperties []string = []string{"class", "constants", "controls", "defaultRouteDomain", "enable", "label", "optimisticLockKey", "remark"}

type BigiqDevice struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port,omitempty"`
}

type DeviceRef struct {
	Link string `json:"link"`
}
type ManagedDevice struct {
	DeviceReference DeviceRef `json:"deviceReference"`
}

type UnmanagedDevice struct {
	DeviceAddress string `json:"deviceAddress"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	HTTPSPort     int    `json:"httpsPort,omitempty"`
}

type regKeyPools struct {
	//Items      []struct {
	//      ID       string `json:"id"`
	//      Name     string `json:"name"`
	//      SortName string `json:"sortName"`
	//} `json:"items"`
	RegKeyPoollist []regKeyPool `json:"items"`
}

type regKeyPool struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	SortName string `json:"sortName"`
}

type devicesList struct {
	DevicesInfo []deviceInfo `json:"items"`
}
type deviceInfo struct {
	Address           string `json:"address"`
	DeviceURI         string `json:"deviceUri"`
	Hostname          string `json:"hostname"`
	HTTPSPort         int    `json:"httpsPort"`
	IsClustered       bool   `json:"isClustered"`
	MachineID         string `json:"machineId"`
	ManagementAddress string `json:"managementAddress"`
	McpDeviceName     string `json:"mcpDeviceName"`
	Product           string `json:"product"`
	SelfLink          string `json:"selfLink"`
	State             string `json:"state"`
	UUID              string `json:"uuid"`
	Version           string `json:"version"`
}

type MembersList struct {
	Members []memberDetail `json:"items"`
}

type memberDetail struct {
	AssignmentType  string `json:"assignmentType"`
	DeviceAddress   string `json:"deviceAddress"`
	DeviceMachineID string `json:"deviceMachineId"`
	DeviceName      string `json:"deviceName"`
	ID              string `json:"id"`
	Message         string `json:"message"`
	Status          string `json:"status"`
}

type regKeyAssignStatus struct {
	ID             string `json:"id"`
	DeviceAddress  string `json:"deviceAddress"`
	AssignmentType string `json:"assignmentType"`
	DeviceName     string `json:"deviceName"`
	Status         string `json:"status"`
}

type LicenseParam struct {
	Address         string `json:"address,omitempty"`
	Port            int    `json:"port,omitempty"`
	AssignmentType  string `json:"assignmentType,omitempty"`
	Command         string `json:"command,omitempty"`
	Hypervisor      string `json:"hypervisor,omitempty"`
	LicensePoolName string `json:"licensePoolName,omitempty"`
	MacAddress      string `json:"macAddress,omitempty"`
	Password        string `json:"password,omitempty"`
	SkuKeyword1     string `json:"skuKeyword1,omitempty"`
	SkuKeyword2     string `json:"skuKeyword2,omitempty"`
	Tenant          string `json:"tenant,omitempty"`
	UnitOfMeasure   string `json:"unitOfMeasure,omitempty"`
	User            string `json:"user,omitempty"`
}

type BigiqAs3AllTaskType struct {
	Items []BigiqAs3TaskType `json:"items,omitempty"`
}

type BigiqAs3TaskType struct {
	Code int64 `json:"code,omitempty"`
	//ID string `json:"id,omitempty"`
	//Declaration struct{} `json:"declaration,omitempty"`
	Results []BigiqResults `json:"results,omitempty"`
}
type BigiqResults struct {
	Code    int64  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	//      LineCount int64  `json:"lineCount,omitempty"`
	Host    string `json:"host,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	RunTime int64  `json:"runTime,omitempty"`
}

func (b *BigIP) PostLicense(config *LicenseParam) (string, error) {
	log.Printf("[INFO] %v license to BIGIP device:%v from BIGIQ", config.Command, config.Address)
	resp, err := b.postReq(config, uriMgmt, uriCm, uriDevice, uriTasks, uriLicensing, uriPool, uriManagement)
	if err != nil {
		return "", err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["id"].(string)
	time.Sleep(5 * time.Second)
	return respID, nil
}
func (b *BigIP) GetLicenseStatus(id string) (map[string]interface{}, error) {
	licRes := make(map[string]interface{})
	err, _ := b.getForEntity(&licRes, uriMgmt, uriCm, uriDevice, uriTasks, uriLicensing, uriPool, uriManagement, id)
	if err != nil {
		return nil, err
	}
	licStatus, ok := licRes["status"]
	if ok {
		licStatus = licStatus.(string)
	} else {
		return nil, fmt.Errorf("license status not available")
	}
	for licStatus != "FINISHED" {
		//log.Printf(" status response is :%s", licStatus)
		if licStatus == "FAILED" {
			log.Println("[ERROR]License assign/revoke status failed")
			return licRes, nil
		}
		return b.GetLicenseStatus(id)
	}
	log.Printf("License Assignment is :%s", licStatus)
	return licRes, nil
}

func (b *BigIP) GetDeviceLicenseStatus(path ...string) (string, error) {
	licRes := make(map[string]interface{})
	err, _ := b.getForEntity(&licRes, path...)
	if err != nil {
		return "", err
	}
	//log.Printf(" Initial status response is :%s", licRes["status"])
	return licRes["status"].(string), nil
}
func (b *BigIP) GetRegPools() (*regKeyPools, error) {
	var self regKeyPools
	err, _ := b.getForEntity(&self, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses)
	if err != nil {
		return nil, err
	}
	return &self, nil
}

func (b *BigIP) GetPoolType(poolName string) (*regKeyPool, error) {
	var self regKeyPools
	err, _ := b.getForEntity(&self, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses)
	if err != nil {
		return nil, err
	}
	for _, pool := range self.RegKeyPoollist {
		if pool.Name == poolName {
			return &pool, nil
		}
	}
	err, _ = b.getForEntity(&self, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriUtility, uriLicenses)
	if err != nil {
		return nil, err
	}
	for _, pool := range self.RegKeyPoollist {
		if pool.Name == poolName {
			return &pool, nil
		}
	}
	err, _ = b.getForEntity(&self, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriPurchased, uriLicenses)
	if err != nil {
		return nil, err
	}
	for _, pool := range self.RegKeyPoollist {
		if pool.Name == poolName {
			return &pool, nil
		}
	}
	return nil, nil
}

func (b *BigIP) GetManagedDevices() (*devicesList, error) {
	var self devicesList
	err, _ := b.getForEntity(&self, uriMgmt, uriShared, uriResolver, uriDevicegroup, uriCmBigip, uriDevices)
	if err != nil {
		return nil, err
	}
	return &self, nil
}

func (b *BigIP) GetDeviceId(deviceName string) (string, error) {
	var self devicesList
	err, _ := b.getForEntity(&self, uriMgmt, uriShared, uriResolver, uriDevicegroup, uriCmBigip, uriDevices)
	if err != nil {
		return "", err
	}
	for _, d := range self.DevicesInfo {
		log.Printf("Address=%v,Hostname=%v,UUID=%v", d.Address, d.Hostname, d.UUID)
		if d.Address == deviceName || d.Hostname == deviceName || d.UUID == deviceName {
			log.Printf("SelfLink Type=%T,SelfLink=%v", d.SelfLink, d.SelfLink)
			return d.SelfLink, nil
		}
	}
	return "", nil
}

func (b *BigIP) GetRegkeyPoolId(poolName string) (string, error) {
	var self regKeyPools
	err, _ := b.getForEntity(&self, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses)
	if err != nil {
		return "", err
	}
	for _, pool := range self.RegKeyPoollist {
		if pool.Name == poolName {
			return pool.ID, nil
		}
	}
	return "", nil
}

func (b *BigIP) RegkeylicenseAssign(config interface{}, poolId string, regKey string) (*memberDetail, error) {
	resp, err := b.postReq(config, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses, poolId, uriOfferings, regKey, uriMembers)
	if err != nil {
		return nil, err
	}
	var resp1 regKeyAssignStatus
	err = json.Unmarshal(resp, &resp1)
	if err != nil {
		return nil, err
	}
	return b.GetMemberStatus(poolId, regKey, resp1.ID)
}

func (b *BigIP) GetMemberStatus(poolId, regKey, memId string) (*memberDetail, error) {
	var self memberDetail
	err, _ := b.getForEntity(&self, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses, poolId, uriOfferings, regKey, uriMembers, memId)
	if err != nil {
		return nil, err
	}
	for self.Status != "LICENSED" {
		log.Printf("Member status:%+v", self.Status)
		if self.Status == "INSTALLATION_FAILED" {
			return &self, fmt.Errorf("INSTALLATION_FAILED with %s", self.Message)
		}
		return b.GetMemberStatus(poolId, regKey, memId)
	}
	return &self, nil
}
func (b *BigIP) RegkeylicenseRevoke(poolId, regKey, memId string) error {
	log.Printf("Deleting License for Member:%+v", memId)
	_, err := b.deleteReq(uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses, poolId, uriOfferings, regKey, uriMembers, memId)
	if err != nil {
		return err
	}
	r1 := make(map[string]interface{})
	err, _ = b.getForEntity(&r1, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses, poolId, uriOfferings, regKey, uriMembers, memId)
	if err != nil {
		return err
	}
	log.Printf("Response after delete:%+v", r1)
	return nil
}
func (b *BigIP) LicenseRevoke(config interface{}, poolId, regKey, memId string) error {
	log.Printf("Deleting License for Member:%+v from LicenseRevoke", memId)
	_, err := b.deleteReqBody(config, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses, poolId, uriOfferings, regKey, uriMembers, memId)
	if err != nil {
		return err
	}
	r1 := make(map[string]interface{})
	err, _ = b.getForEntity(&r1, uriMgmt, uriCm, uriDevice, uriLicensing, uriPool, uriRegkey, uriLicenses, poolId, uriOfferings, regKey, uriMembers, memId)
	if err != nil {
		return err
	}
	log.Printf("Response after delete:%+v", r1)
	return nil
}
func (b *BigIP) PostAs3Bigiq(as3NewJson string) (error, string) {
	resp, err := b.postReq(as3NewJson, uriMgmt, uriShared, uriAppsvcs, uriDeclare)
	if err != nil {
		return err, ""
	}
	var taskList BigiqAs3TaskType
	tenant_list, tenant_count, _ := b.GetTenantList(as3NewJson)
	json.Unmarshal(resp, &taskList)
	successfulTenants := make([]string, 0)
	if taskList.Code != 200 && taskList.Code != 0 {
		i := tenant_count - 1
		success_count := 0
		for i >= 0 {
			if taskList.Results[i].Code == 200 {
				successfulTenants = append(successfulTenants, taskList.Results[i].Tenant)
				success_count++
			}
			if taskList.Results[i].Code >= 400 {
				log.Printf("[ERROR] : HTTP %d :: %s for tenant %v", taskList.Results[i].Code, taskList.Results[i].Message, taskList.Results[i].Tenant)
			}
			i = i - 1
		}
		if success_count == tenant_count {
			log.Printf("[DEBUG]Sucessfully Created tenants  = %v", tenant_list)
		} else if success_count == 0 {
			return errors.New(fmt.Sprintf("Tenant Creation failed")), ""
		} else {
			finallist := strings.Join(successfulTenants[:], ",")
			return errors.New(fmt.Sprintf("Partial Success")), finallist
		}
	}
	return nil, tenant_list

}

func (b *BigIP) GetAs3Bigiq(targetRef, tenantRef string) (string, error) {
	as3Json := make(map[string]interface{})
	as3Json["class"] = "AS3"
	as3Json["action"] = "deploy"
	as3Json["persist"] = true
	//var adcJson
	//adcJson := make(map[string]interface{})
	//adcJson := []map[string]interface{}{}
	var adcJson interface{}
	tenantList := strings.Split(tenantRef, ",")
	//log.Printf("[DEBUG] tenantList:%+v",tenantList)
	err, ok := b.getForEntityNew(&adcJson, uriMgmt, uriShared, uriAppsvcs, uriDeclare, tenantRef)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	as3JsonNew := make(map[string]interface{})
	as3jsonType := reflect.TypeOf(adcJson).Kind()
	//log.Printf("[DEBUG] as3jsonType:%+v",as3jsonType)
	if as3jsonType == reflect.Map {
		adcJsonvalue := adcJson.(map[string]interface{})
		if adcJsonvalue["target"].(map[string]interface{})["address"].(string) == targetRef {
			for _, name := range tenantList {
				if adcJsonvalue[name] != nil {
					for k, v := range adcJsonvalue[name].(map[string]interface{}) {
						if !contains(tenantProperties, k) {
							delete(v.(map[string]interface{}), "schemaOverlay")
							for _, v1 := range v.(map[string]interface{}) {
								if reflect.TypeOf(v1).Kind() == reflect.Map && v1.(map[string]interface{})["class"] == "Service_HTTP" {
									if _, ok := v1.(map[string]interface{})["pool"]; ok {
										ss := v1.(map[string]interface{})["pool"].(string)
										ss1 := strings.Split(ss, "/")
										v1.(map[string]interface{})["pool"] = ss1[len(ss1)-1]
									}
								}
							}
						}
					}
					as3JsonNew[name] = adcJsonvalue[name]
					//delete(adcJsonvalue[name].(map[string]interface{}),"schemaOverlay")
					as3JsonNew["id"] = adcJsonvalue["id"]
					as3JsonNew["class"] = adcJsonvalue["class"]
					as3JsonNew["label"] = adcJsonvalue["label"]
					as3JsonNew["remark"] = adcJsonvalue["remark"]
					as3JsonNew["target"] = adcJsonvalue["target"]
					//as3JsonNew["updateMode"] = adcJsonvalue["updateMode"]
					as3JsonNew["schemaVersion"] = adcJsonvalue["schemaVersion"]
				}
			}
		}
	} else {
		for _, adcJsonvalue1 := range adcJson.([]interface{}) {
			adcJsonvalue := adcJsonvalue1.(map[string]interface{})
			if adcJsonvalue["target"].(map[string]interface{})["address"].(string) == targetRef {
				for _, name := range tenantList {
					if adcJsonvalue[name] != nil {
						for k, v := range adcJsonvalue[name].(map[string]interface{}) {
							if !contains(tenantProperties, k) {
								delete(v.(map[string]interface{}), "schemaOverlay")
								for _, v1 := range v.(map[string]interface{}) {
									if reflect.TypeOf(v1).Kind() == reflect.Map && v1.(map[string]interface{})["class"] == "Service_HTTP" {
										if _, ok := v1.(map[string]interface{})["pool"]; ok {
											ss := v1.(map[string]interface{})["pool"].(string)
											ss1 := strings.Split(ss, "/")
											v1.(map[string]interface{})["pool"] = ss1[len(ss1)-1]
										}
									}
								}
								//if val, ok := v.(map[string]interface{})["serviceMain"]; ok {
								//      ss := val.(map[string]interface{})["pool"].(string)
								//      ss1 := strings.Split(ss, "/")
								//      val.(map[string]interface{})["pool"] = ss1[len(ss1)-1]
								//}
							}
						}
						as3JsonNew[name] = adcJsonvalue[name]
						//delete(adcJsonvalue[name].(map[string]interface{}),"schemaOverlay")
						as3JsonNew["id"] = adcJsonvalue["id"]
						as3JsonNew["class"] = adcJsonvalue["class"]
						as3JsonNew["label"] = adcJsonvalue["label"]
						as3JsonNew["remark"] = adcJsonvalue["remark"]
						as3JsonNew["target"] = adcJsonvalue["target"]
						//as3JsonNew["updateMode"] = adcJsonvalue["updateMode"]
						as3JsonNew["schemaVersion"] = adcJsonvalue["schemaVersion"]
					}
				}
			}
		}
	}
	as3Json["declaration"] = as3JsonNew
	out, _ := json.Marshal(as3Json)
	as3String := string(out)
	return as3String, nil
}

func (b *BigIP) DeleteAs3Bigiq(as3NewJson string, tenantName string) (error, string) {
	as3Json, err := tenantTrimToDelete(as3NewJson)
	if err != nil {
		log.Println("[ERROR] Error in trimming the as3 json")
		return err, ""
	}
	return b.post(as3Json, uriMgmt, uriShared, uriAppsvcs, uriDeclare), ""
}

func tenantTrimToDelete(resp string) (string, error) {
	jsonRef := make(map[string]interface{})
	json.Unmarshal([]byte(resp), &jsonRef)

	if jsonRef["declaration"].(map[string]interface{})["remark"] == nil {
		delete(jsonRef["declaration"].(map[string]interface{}), "remark")
	}

	if jsonRef["declaration"].(map[string]interface{})["label"] == nil {
		delete(jsonRef["declaration"].(map[string]interface{}), "label")
	}

	for key, value := range jsonRef {
		if rec, ok := value.(map[string]interface{}); ok && key == "declaration" {
			for k, v := range rec {
				if k == "target" && reflect.ValueOf(v).Kind() == reflect.Map {
					continue
				}
				if rec2, ok := v.(map[string]interface{}); ok {
					for k1, v1 := range rec2 {
						if k1 != "class" && v1 != "Tenant" {
							delete(rec2, k1)
						}
					}

				}
			}
		}
	}

	b, err := json.Marshal(jsonRef)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	_, ok := set[item]
	return ok
}
