package bigip

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	uriFast     = "fast"
	uriFasttask = "tasks"
	uriTempl    = "templatesets"
	uriFastApp  = "applications"
)

type FastPayload struct {
	Name       string                 `json:"name,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

type FastTask struct {
	Id          string                 `json:"id,omitempty"`
	Code        int64                  `json:"code,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Tenant      string                 `json:"tenant,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Application string                 `json:"application,omitempty"`
	Operation   string                 `json:"operation,omitempty"`
}

type FastTemplateSet struct {
	Name            string        `json:"name,omitempty"`
	Hash            string        `json:"hash,omitempty"`
	Supported       bool          `json:"supported,omitempty"`
	Templates       []TmplArrType `json:"templates,omitempty"`
	Schemas         []TmplArrType `json:"schemas,omitempty"`
	Enabled         bool          `json:"enabled,omitempty"`
	UpdateAvailable bool          `json:"updateAvailable,omitempty"`
}

type TmplArrType struct {
	Name string `json:"name,omitempty"`
	Hash string `json:"hash,omitempty"`
}

type FastTCPJson struct {
	Tenant                        string         `json:"tenant_name,omitempty"`
	Application                   string         `json:"app_name,omitempty"`
	VirtualAddress                string         `json:"virtual_address,omitempty"`
	VirtualPort                   interface{}    `json:"virtual_port,omitempty"`
	SnatEnable                    bool           `json:"enable_snat,omitempty"`
	SnatAutomap                   bool           `json:"snat_automap"`
	MakeSnatPool                  bool           `json:"make_snatpool"`
	SnatPoolName                  string         `json:"snatpool_name,omitempty"`
	SnatAddresses                 []string       `json:"snat_addresses,omitempty"`
	PoolEnable                    bool           `json:"enable_pool"`
	MakePool                      bool           `json:"make_pool"`
	PoolName                      string         `json:"pool_name,omitempty"`
	PoolMembers                   []FastHttpPool `json:"pool_members,omitempty"`
	LoadBalancingMode             string         `json:"load_balancing_mode,omitempty"`
	SlowRampTime                  int            `json:"slow_ramp_time,omitempty"`
	MonitorEnable                 bool           `json:"enable_monitor,omitempty"`
	MakeMonitor                   bool           `json:"make_monitor"`
	TCPMonitor                    string         `json:"monitor_name,omitempty"`
	MonitorInterval               int            `json:"monitor_interval,omitempty"`
	EnablePersistence             bool           `json:"enable_persistence"`
	PersistenceProfile            string         `json:"persistence_profile,omitempty"`
	PersistenceType               string         `json:"persistence_type,omitempty"`
	UseExistingPersistenceProfile bool           `json:"use_existing_persistence_profile,omitempty"`
	EnableFallbackPersistence     bool           `json:"enable_fallback_persistence"`
	FallbackPersistenceType       string         `json:"fallback_persistence_type,omitempty"`
}

type FastUDPJson struct {
	Tenant                    string         `json:"tenant_name,omitempty"`
	Application               string         `json:"app_name,omitempty"`
	VirtualAddress            string         `json:"virtual_address,omitempty"`
	VirtualPort               interface{}    `json:"virtual_port,omitempty"`
	Fastl4Enable              bool           `json:"fastl4"`
	MakeFastl4Profile         bool           `json:"make_fastl4_profile,omitempty"`
	Fastl4ProfileName         string         `json:"fastl4_profile_name,omitempty"`
	UdpProfileName            string         `json:"udp_profile_name,omitempty"`
	SnatEnable                bool           `json:"enable_snat"`
	SnatAutomap               bool           `json:"snat_automap"`
	MakeSnatPool              bool           `json:"make_snatpool"`
	SnatPoolName              string         `json:"snatpool_name,omitempty"`
	SnatAddresses             []string       `json:"snat_addresses,omitempty"`
	EnablePersistence         bool           `json:"enable_persistence"`
	UseExistingPersistence    bool           `json:"use_existing_persistence_profile,omitempty"`
	Fastl4PersistenceProfile  string         `json:"fastl4_persistence_profile,omitempty"`
	Fastl4PersistenceType     string         `json:"fastl4_persistence_type,omitempty"`
	UdpPersistenceProfile     string         `json:"persistence_profile,omitempty"`
	UdpPersistenceType        string         `json:"persistence_type,omitempty"`
	EnableFallbackPersistence bool           `json:"enable_fallback_persistence"`
	FallbackPersistenceType   string         `json:"fallback_persistence_type,omitempty"`
	PoolEnable                bool           `json:"enable_pool"`
	MakePool                  bool           `json:"make_pool"`
	PoolName                  string         `json:"pool_name,omitempty"`
	PoolMembers               []FastHttpPool `json:"pool_members,omitempty"`
	LoadBalancingMode         string         `json:"load_balancing_mode,omitempty"`
	SlowRampTime              int            `json:"slow_ramp_time,omitempty"`
	MonitorEnable             bool           `json:"enable_monitor,omitempty"`
	MakeMonitor               bool           `json:"make_monitor"`
	MonitorInterval           int            `json:"monitor_interval,omitempty"`
	MonitorSendString         string         `json:"monitor_send_string,omitempty"`
	MonitorExpectedResponse   string         `json:"monitor_expected_response,omitempty"`
	UdpMonitor                string         `json:"monitor_name,omitempty"`
	IruleNames                []string       `json:"irule_names,omitempty"`
	VlansEnable               bool           `json:"vlans_enable"`
	VlansAllow                bool           `json:"vlans_allow"`
	Vlans                     []string       `json:"vlan_names,omitempty"`
	EnableAsmLogging          bool           `json:"enable_asm_logging"`
	LogProfileNames           []string       `json:"log_profile_names,omitempty"`
}

type FastHttpJson struct {
	Tenant                    string         `json:"tenant_name,omitempty"`
	Application               string         `json:"app_name,omitempty"`
	VirtualAddress            string         `json:"virtual_address,omitempty"`
	VirtualPort               interface{}    `json:"virtual_port,omitempty"`
	SnatEnable                bool           `json:"enable_snat,omitempty"`
	SnatAutomap               bool           `json:"snat_automap"`
	MakeSnatPool              bool           `json:"make_snatpool"`
	SnatPoolName              string         `json:"snatpool_name,omitempty"`
	SnatAddresses             []string       `json:"snat_addresses,omitempty"`
	PoolEnable                bool           `json:"enable_pool"`
	MakePool                  bool           `json:"make_pool"`
	TlsServerEnable           bool           `json:"enable_tls_server"`
	TlsClientEnable           bool           `json:"enable_tls_client"`
	TlsServerProfileCreate    bool           `json:"make_tls_server_profile"`
	TlsClientProfileCreate    bool           `json:"make_tls_client_profile"`
	TlsServerProfileName      string         `json:"tls_server_profile_name,omitempty"`
	TlsClientProfileName      string         `json:"tls_client_profile_name,omitempty"`
	TlsCertName               string         `json:"tls_cert_name,omitempty"`
	TlsKeyName                string         `json:"tls_key_name,omitempty"`
	PoolName                  string         `json:"pool_name,omitempty"`
	PoolMembers               []FastHttpPool `json:"pool_members,omitempty"`
	SdEnable                  bool           `json:"use_sd"`
	ServiceDiscovery          []interface{}  `json:"service_discovery,omitempty"`
	LoadBalancingMode         string         `json:"load_balancing_mode,omitempty"`
	SlowRampTime              int            `json:"slow_ramp_time,omitempty"`
	MonitorEnable             bool           `json:"enable_monitor,omitempty"`
	MakeMonitor               bool           `json:"make_monitor"`
	HTTPMonitor               string         `json:"monitor_name_http,omitempty"`
	HTTPSMonitor              string         `json:"monitor_name,omitempty"`
	MonitorAuth               bool           `json:"monitor_credentials"`
	MonitorUsername           string         `json:"monitor_username,omitempty"`
	MonitorPassword           string         `json:"monitor_passphrase,omitempty"`
	MonitorInterval           int            `json:"monitor_interval,omitempty"`
	MonitorSendString         string         `json:"monitor_send_string,omitempty"`
	MonitorResponse           string         `json:"monitor_expected_response,omitempty"`
	EnablePersistence         bool           `json:"enable_persistence"`
	UseExistingPersistence    bool           `json:"use_existing_persistence_profile,omitempty"`
	EnableFallbackPersistence bool           `json:"enable_fallback_persistence"`
	FallbackPersistenceType   string         `json:"fallback_persistence_type,omitempty"`
	PersistenceProfile        string         `json:"persistence_profile,omitempty"`
	PersistenceType           string         `json:"persistence_type,omitempty"`
	WafPolicyEnable           bool           `json:"enable_waf_policy"`
	MakeWafpolicy             bool           `json:"make_waf_policy"`
	WafPolicyName             string         `json:"asm_waf_policy,omitempty"`
	EndpointPolicyNames       []string       `json:"endpoint_policy_names,omitempty"`
	AsmLoggingEnable          bool           `json:"enable_asm_logging"`
	LogProfileNames           []string       `json:"log_profile_names,omitempty"`
}

type FastHttpPool struct {
	ServerAddresses []string `json:"serverAddresses,omitempty"`
	ServicePort     int      `json:"servicePort,omitempty"`
	ConnectionLimit int      `json:"connectionLimit,omitempty"`
	PriorityGroup   int      `json:"priorityGroup,omitempty"`
	ShareNodes      bool     `json:"shareNodes,omitempty"`
}

type SDConsulObject struct {
	SdType               string `json:"sd_type,omitempty"`
	SdPort               *int   `json:"sd_port,omitempty"`
	SdUri                string `json:"sd_uri,omitempty"`
	SdAddressRealm       string `json:"sd_addressRealm,omitempty"`
	SdCredentialUpdate   bool   `json:"sd_credentialUpdate,omitempty"`
	SdEncodedToken       string `json:"sd_encodedToken,omitempty"`
	SdJmesPathQuery      string `json:"sd_jmesPathQuery,omitempty"`
	SdMinimumMonitors    string `json:"sd_minimumMonitors,omitempty"`
	SdRejectUnauthorized bool   `json:"sd_rejectUnauthorized,omitempty"`
	SdTrustCA            string `json:"sd_trustCA,omitempty"`
	SdUndetectableAction string `json:"sd_undetectableAction,omitempty"`
	SdUpdateInterval     string `json:"sd_updateInterval,omitempty"`
}

type SdAwsObj struct {
	SdType               string `json:"sd_type,omitempty"`
	SdPort               *int   `json:"sd_port,omitempty"`
	SdTagKey             string `json:"sd_tag_key,omitempty"`
	SdTagVal             string `json:"sd_tag_val,omitempty"`
	SdAccessKeyId        string `json:"sd_accessKeyId,omitempty"`
	SdSecretAccessKey    string `json:"sd_secretAccessKey,omitempty"`
	SdAddressRealm       string `json:"sd_addressRealm,omitempty"`
	SdCredentialUpdate   bool   `json:"sd_credentialUpdate,omitempty"`
	SdExternalId         string `json:"sd_externalId,omitempty"`
	SdRoleARN            string `json:"sd_roleARN,omitempty"`
	SdMinimumMonitors    string `json:"sd_minimumMonitors,omitempty"`
	SdAwsRegion          string `json:"sd_aws_region,omitempty"`
	SdUndetectableAction string `json:"sd_undetectableAction,omitempty"`
	SdUpdateInterval     string `json:"sd_updateInterval,omitempty"`
}

type SDAzureObject struct {
	SdType               string `json:"sd_type,omitempty"`
	SdPort               *int   `json:"sd_port,omitempty"`
	SdRg                 string `json:"sd_rg,omitempty"`
	SdSid                string `json:"sd_sid,omitempty"`
	SdRid                string `json:"sd_rid,omitempty"`
	SdRtype              string `json:"sd_rtype,omitempty"`
	SdDirid              string `json:"sd_dirid,omitempty"`
	SdAppid              string `json:"sd_appid,omitempty"`
	SdApikey             string `json:"sd_apikey,omitempty"`
	SdAddressRealm       string `json:"sd_addressRealm,omitempty"`
	SdCredentialUpdate   bool   `json:"sd_credentialUpdate,omitempty"`
	SdEnvironment        string `json:"sd_environment,omitempty"`
	SdMinimumMonitors    string `json:"sd_minimumMonitors,omitempty"`
	SdAzureTagKey        string `json:"sd_azure_tag_key,omitempty"`
	SdAzureTagVal        string `json:"sd_azure_tag_val,omitempty"`
	SdUndetectableAction string `json:"sd_undetectableAction,omitempty"`
	SdUpdateInterval     string `json:"sd_updateInterval,omitempty"`
	SdUseManagedIdentity bool   `json:"sd_useManagedIdentity,omitempty"`
}

type SDGceObject struct {
	SdType               string `json:"sd_type,omitempty"`
	SdPort               *int   `json:"sd_port,omitempty"`
	SdTagKey             string `json:"sd_tag_key,omitempty"`
	SdTagVal             string `json:"sd_tag_val,omitempty"`
	SdRegion             string `json:"sd_region,omitempty"`
	SdAddressRealm       string `json:"sd_addressRealm,omitempty"`
	SdCredentialUpdate   bool   `json:"sd_credentialUpdate,omitempty"`
	SdEncodedCredentials string `json:"sd_encodedCredentials,omitempty"`
	SdMinimumMonitors    string `json:"sd_minimumMonitors,omitempty"`
	SdProjectId          string `json:"sd_projectId,omitempty"`
	SdUndetectableAction string `json:"sd_undetectableAction,omitempty"`
	SdUpdateInterval     string `json:"sd_updateInterval,omitempty"`
}

type ServiceDiscoverObj struct {
	SdType               string `json:"sd_type"`
	SdPort               int    `json:"sd_port"`
	SdTagKey             string `json:"sd_tag_key,omitempty"`
	SdTagVal             string `json:"sd_tag_val,omitempty"`
	SdAccessKeyId        string `json:"sd_accessKeyId,omitempty"`
	SdSecretAccessKey    string `json:"sd_secretAccessKey,omitempty"`
	SdAddressRealm       string `json:"sd_addressRealm,omitempty"`
	SdCredentialUpdate   bool   `json:"sd_credentialUpdate"`
	SdExternalId         string `json:"sd_externalId,omitempty"`
	SdRoleARN            string `json:"sd_roleARN,omitempty"`
	SdMinimumMonitors    string `json:"sd_minimumMonitors,omitempty"`
	SdAwsRegion          string `json:"sd_aws_region,omitempty"`
	SdUndetectableAction string `json:"sd_undetectableAction"`
	SdUpdateInterval     string `json:"sd_updateInterval,omitempty"`
	SdRg                 string `json:"sd_rg,omitempty"`
	SdSid                string `json:"sd_sid,omitempty"`
	SdRid                string `json:"sd_rid,omitempty"`
	SdRtype              string `json:"sd_rtype,omitempty"`
	SdDirid              string `json:"sd_dirid,omitempty"`
	SdAppid              string `json:"sd_appid,omitempty"`
	SdApikey             string `json:"sd_apikey,omitempty"`
	SdEnvironment        string `json:"sd_environment,omitempty"`
	SdAzureTagKey        string `json:"sd_azure_tag_key,omitempty"`
	SdAzureTagVal        string `json:"sd_azure_tag_val,omitempty"`
	SdUseManagedIdentity bool   `json:"sd_useManagedIdentity,omitempty"`
	SdRegion             string `json:"sd_region,omitempty"`
	SdEncodedCredentials string `json:"sd_encodedCredentials,omitempty"`
	SdProjectId          string `json:"sd_projectId,omitempty"`
	SdUri                string `json:"sd_uri,omitempty"`
	SdEncodedToken       string `json:"sd_encodedToken,omitempty"`
	SdJmesPathQuery      string `json:"sd_jmesPathQuery,omitempty"`
	SdRejectUnauthorized bool   `json:"sd_rejectUnauthorized,omitempty"`
	SdTrustCA            string `json:"sd_trustCA,omitempty"`
}

// UploadFastTemplate copies a template set from local disk to BIGIP
func (b *BigIP) UploadFastTemplate(tmplpath *os.File, tmplname string) error {
	_, err := b.UploadFastTemp(tmplpath, tmplname)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG]Template Path:%+v", tmplpath.Name())
	payload := FastTemplateSet{
		Name: tmplname,
	}
	err = b.AddTemplateSet(&payload)
	if err != nil {
		return err
	}
	return nil
}

// AddTemplateSet installs a template set.
func (b *BigIP) AddTemplateSet(tmpl *FastTemplateSet) error {
	return b.post(tmpl, uriMgmt, uriSha, uriFast, uriTempl)
}

// GetTemplateSet retrieves a Template set by name. Returns nil if the Template set does not exist
func (b *BigIP) GetTemplateSet(name string) (*FastTemplateSet, error) {
	var tmpl FastTemplateSet
	err, ok := b.getForEntity(&tmpl, uriMgmt, uriSha, uriFast, uriTempl, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &tmpl, nil
}

// DeleteTemplateSet removes a template set.
func (b *BigIP) DeleteTemplateSet(name string) error {
	return b.delete(uriMgmt, uriSha, uriFast, uriTempl, name)
}

// GetFastApp retrieves a Application set by tenant and app name. Returns nil if the application does not exist
func (b *BigIP) GetFastApp(tenant, app string) (string, error) {
	var out []byte
	fastJson := make(map[string]interface{})
	err, ok := b.getForEntity(&fastJson, uriMgmt, uriShared, uriFast, uriFastApp, tenant, app)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	for key, value := range fastJson {
		if rec, ok := value.(map[string]interface{}); ok && key == "constants" {
			for k, v := range rec {
				if rec2, ok := v.(map[string]interface{}); ok && k == "fast" {
					for k1, v1 := range rec2 {
						if rec3, ok := v1.(map[string]interface{}); ok {
							if k1 == "view" {
								out, _ = json.Marshal(rec3)
							}
						}
					}
				}

			}
		}
	}
	fastString := string(out)

	return fastString, nil
}

// PostFastAppBigip used for posting FAST json file to BIGIP
func (b *BigIP) PostFastAppBigip(body, fastTemplate, userAgent string) (tenant, app string, err error) {
	param := []byte(body)
	jsonRef := make(map[string]interface{})
	json.Unmarshal(param, &jsonRef)
	payload := &FastPayload{
		Name:       fastTemplate,
		Parameters: jsonRef,
	}
	log.Printf("[DEBUG]payload = %+v", payload)
	resp, err := b.postReq(payload, uriMgmt, uriShared, uriFast, uriFastApp, userAgent)
	if err != nil {
		return "", "", err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["message"].([]interface{})[0].(map[string]interface{})["id"].(string)
	taskStatus, err := b.getFastTaskStatus(respID)
	if err != nil {
		return "", "", err
	}
	respCode := taskStatus.Code
	log.Printf("[DEBUG]Initial response code = %+v,ID = %+v", respCode, respID)
	for respCode != 200 {
		fastTask, err := b.getFastTaskStatus(respID)
		if err != nil {
			return "", "", err
		}
		respCode = fastTask.Code
		log.Printf("[DEBUG]Response code = %+v,ID = %+v", respCode, respID)
		if respCode == 200 {
			log.Printf("[DEBUG]Sucessfully Created Application with ID  = %v", respID)
			break // break here
		}
		if respCode >= 400 {
			return "", "", fmt.Errorf("FAST Application creation failed with :%+v", fastTask.Message)
		}
		time.Sleep(3 * time.Second)
	}
	return taskStatus.Tenant, taskStatus.Application, err
}

// ModifyFastAppBigip used for updating FAST application on BIGIP
func (b *BigIP) ModifyFastAppBigip(body, fastTenant, fastApp string) error {
	param := []byte(body)
	jsonRef := make(map[string]interface{})
	json.Unmarshal(param, &jsonRef)
	payload := &FastPayload{
		Parameters: jsonRef,
	}
	resp, err := b.fastPatch(payload, uriMgmt, uriShared, uriFast, uriFastApp, fastTenant, fastApp)
	if err != nil {
		return err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["message"].([]interface{})[0].(map[string]interface{})["id"].(string)
	taskStatus, err := b.getFastTaskStatus(respID)
	if err != nil {
		return err
	}
	respCode := taskStatus.Code
	log.Printf("[DEBUG]Code = %+v,ID = %+v", respCode, respID)
	for respCode != 200 {
		fastTask, err := b.getFastTaskStatus(respID)
		if err != nil {
			return err
		}
		respCode = fastTask.Code
		if respCode == 200 {
			log.Printf("[DEBUG]Sucessfully Modified Application with ID  = %v", respID)
			break // break here
		}
		if respCode >= 400 {
			return fmt.Errorf("FAST Application update failed with :%+v", fastTask.Message)
			//return fmt.Errorf("FAST Application update failed")
		}
		time.Sleep(3 * time.Second)
	}
	return err
}

// DeleteFastAppBigip used for deleting FAST application on BIGIP
func (b *BigIP) DeleteFastAppBigip(fastTenant, fastApp string) error {
	resp, err := b.deleteReq(uriMgmt, uriShared, uriFast, uriFastApp, fastTenant, fastApp)
	if err != nil {
		return err
	}
	respRef := make(map[string]interface{})
	json.Unmarshal(resp, &respRef)
	respID := respRef["id"].(string)
	taskStatus, err := b.getFastTaskStatus(respID)
	if err != nil {
		return err
	}
	respCode := taskStatus.Code
	log.Printf("[DEBUG]Code = %+v,ID = %+v", respCode, respID)
	for respCode != 200 {
		fastTask, err := b.getFastTaskStatus(respID)
		if err != nil {
			return err
		}
		respCode = fastTask.Code
		if respCode == 200 {
			log.Printf("[DEBUG]Sucessfully Deleted Application with ID  = %v", respID)
			break // break here
		}
		if respCode >= 400 {
			return fmt.Errorf("FAST Application deletion failed")
		}
		time.Sleep(3 * time.Second)
	}
	return nil
}

// getFastTaskStatus used to obtain status of async task from BIGIP
func (b *BigIP) getFastTaskStatus(id string) (*FastTask, error) {
	var taskList FastTask
	err, _ := b.getForEntity(&taskList, uriMgmt, uriShared, uriFast, uriFasttask, id)
	if err != nil {
		return nil, err
	}
	return &taskList, nil
}

// Upload a file
func (b *BigIP) UploadFastTemp(f *os.File, tmpName string) (*Upload, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return b.Upload(f, info.Size(), uriShared, uriFileTransfer, uriUploads, fmt.Sprintf("%s.zip", tmpName))
}
