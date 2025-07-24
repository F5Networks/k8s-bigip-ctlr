package bigip

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	uriWafPol       = "policies"
	uriUrls         = "urls"
	uriParams       = "parameters"
	uriWafSign      = "signatures"
	uriImportpolicy = "import-policy"
	uriApplypolicy  = "apply-policy"
	uriExportpolicy = "export-policy"
	uriExpPb        = "export-suggestions"
)

type ApplywafPolicy struct {
	Filename string `json:"filename,omitempty"`
	FullPath string `json:"fullPath,omitempty"`
	Policy   struct {
		FullPath string `json:"fullPath,omitempty"`
	} `json:"policy,omitempty"`
	//PolicyReference struct {
	//	Link     string `json:"link,omitempty"`
	//	FullPath string `json:"fullPath,omitempty"`
	//} `json:"policyReference,omitempty"`
}

type PbExport struct {
	Status  string                 `json:"status,omitempty"`
	Task_id string                 `json:"id,omitempty"`
	Result  map[string]interface{} `json:"result,omitempty"`
}

type ExportPayload struct {
	Filename        string `json:"filename,omitempty"`
	Format          string `json:"format,omitempty"`
	Inline          bool   `json:"inline,omitempty"`
	Minimal         bool   `json:"minimal,omitempty"`
	PolicyReference struct {
		Link string `json:"link"`
	} `json:"policyReference"`
}

type WafQueriedPolicies struct {
	WafPolicyList []WafQueriedPolicy `json:"items"`
}

type WafQueriedPolicy struct {
	Name      string `json:"name,omitempty"`
	Partition string `json:"partition,omitempty"`
	Policy_id string `json:"id,omitempty"`
}

type Signatures struct {
	Signatures []Signature `json:"items"`
}

type WafSignature struct {
	Name                string      `json:"name,omitempty"`
	SignatureID         interface{} `json:"signatureId,omitempty"`
	IsPriorRuleEnforced bool        `json:"isPriorRuleEnforced,omitempty"`
	Alarm               bool        `json:"alarm,omitempty"`
	Block               bool        `json:"block,omitempty"`
	PerformStaging      bool        `json:"performStaging"`
	Learn               bool        `json:"learn,omitempty"`
	Enabled             bool        `json:"enabled,omitempty"`
}

type Signature struct {
	Name        string `json:"name,omitempty"`
	ResourceId  string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	SignatureId int    `json:"signatureId,omitempty"`
	Type        string `json:"signatureType,omitempty"`
	Accuracy    string `json:"accuracy,omitempty"`
	Risk        string `json:"risk,omitempty"`
}

type WafUrlJsons struct {
	WafUrlJsons []WafUrlJson `json:"items"`
}

type WafUrlAllowedOrigins struct {
	IncludeSubdomains bool   `json:"includeSubDomains,omitempty"`
	OriginPort        string `json:"originPort,omitempty"`
	OriginName        string `json:"originName,omitempty"`
	OriginProtocol    string `json:"originProtocol,omitempty"`
}

type WafUrlJson struct {
	Name                                string            `json:"name,omitempty"`
	Description                         string            `json:"description,omitempty"`
	Type                                string            `json:"type,omitempty"`
	Protocol                            string            `json:"protocol,omitempty"`
	Method                              string            `json:"method,omitempty"`
	PerformStaging                      bool              `json:"performStaging,omitempty"`
	SignatureOverrides                  []WafUrlSig       `json:"signatureOverrides,omitempty"`
	MethodOverrides                     []MethodOverrides `json:"methodOverrides,omitempty"`
	AttackSignaturesCheck               bool              `json:"attackSignaturesCheck,omitempty"`
	IsAllowed                           bool              `json:"isAllowed,omitempty"`
	MethodsOverrideOnUrlCheck           bool              `json:"methodsOverrideOnUrlCheck,omitempty"`
	ClickjackingProtection              bool              `json:"clickjackingProtection,omitempty"`
	DisallowFileUploadOfExecutables     bool              `json:"disallowFileUploadOfExecutables,omitempty"`
	HTML5CrossOriginRequestsEnforcement struct {
		EnforcementMode string                 `json:"enforcementMode,omitempty"`
		AllowerOrigins  []WafUrlAllowedOrigins `json:"crossDomainAllowedOrigin,omitempty"`
	} `json:"html5CrossOriginRequestsEnforcement,omitempty"`
	MandatoryBody      bool `json:"mandatoryBody,omitempty"`
	URLContentProfiles []struct {
		ContentProfile struct {
			Name string `json:"name,omitempty"`
		} `json:"contentProfile,omitempty"`
		HeaderName  string `json:"headerName,omitempty"`
		HeaderOrder string `json:"headerOrder,omitempty"`
		HeaderValue string `json:"headerValue,omitempty"`
		Type        string `json:"type,omitempty"`
	} `json:"urlContentProfiles,omitempty"`
}

type Filetype struct {
	Allowed                bool   `json:"allowed,omitempty"`
	CheckPostDataLength    bool   `json:"checkPostDataLength,omitempty"`
	CheckQueryStringLength bool   `json:"checkQueryStringLength,omitempty"`
	CheckRequestLength     bool   `json:"checkRequestLength,omitempty"`
	CheckURLLength         bool   `json:"checkUrlLength,omitempty"`
	Name                   string `json:"name,omitempty"`
	PerformStaging         bool   `json:"performStaging,omitempty"`
	PostDataLength         int    `json:"postDataLength,omitempty"`
	QueryStringLength      int    `json:"queryStringLength,omitempty"`
	RequestLength          int    `json:"requestLength,omitempty"`
	ResponseCheck          bool   `json:"responseCheck,omitempty"`
	Type                   string `json:"type,omitempty"`
	WildcardOrder          int    `json:"wildcardOrder,omitempty"`
	URLLength              int    `json:"urlLength,omitempty"`
}
type DefenseAttribute struct {
	AllowIntrospectionQueries bool        `json:"allowIntrospectionQueries"`
	MaximumBatchedQueries     interface{} `json:"maximumBatchedQueries,omitempty"`
	MaximumStructureDepth     interface{} `json:"maximumStructureDepth,omitempty"`
	MaximumTotalLength        interface{} `json:"maximumTotalLength,omitempty"`
	MaximumValueLength        interface{} `json:"maximumValueLength,omitempty"`
	TolerateParsingWarnings   bool        `json:"tolerateParsingWarnings"`
}
type GraphqlProfile struct {
	AttackSignaturesCheck bool             `json:"attackSignaturesCheck"`
	DefenseAttributes     DefenseAttribute `json:"defenseAttributes,omitempty"`
	Description           string           `json:"description,omitempty"`
	MetacharElementCheck  bool             `json:"metacharElementCheck"`
	Name                  string           `json:"name,omitempty"`
}

type SignatureType struct {
	Filter struct {
		AccuracyFilter    string `json:"accuracyFilter,omitempty"`
		AccuracyValue     string `json:"accuracyValue,omitempty"`
		HasCve            string `json:"hasCve,omitempty"`
		LastUpdatedFilter string `json:"lastUpdatedFilter,omitempty"`
		RiskFilter        string `json:"riskFilter,omitempty"`
		RiskValue         string `json:"riskValue,omitempty"`
		SignatureType     string `json:"signatureType,omitempty"`
		TagFilter         string `json:"tagFilter,omitempty"`
		UserDefinedFilter string `json:"userDefinedFilter,omitempty"`
	} `json:"filter,omitempty"`
	Systems []struct {
		Name string `json:"name,omitempty"`
	} `json:"systems,omitempty"`
	Type string `json:"type,omitempty"`
}

type HostName struct {
	IncludeSubdomains bool   `json:"includeSubdomains,omitempty"`
	Name              string `json:"name,omitempty"`
}

type WafSignaturesets struct {
	WafSignaturesets []SignatureSet `json:"items"`
}

type SignatureSet struct {
	Alarm        bool          `json:"alarm,omitempty"`
	Block        bool          `json:"block,omitempty"`
	Learn        bool          `json:"learn,omitempty"`
	Name         string        `json:"name,omitempty"`
	Signatureset SignatureType `json:"signatureSet,omitempty"`
}

type OpenApiLink struct {
	Link string `json:"link,omitempty"`
}
type MethodOverrides struct {
	Allowed bool   `json:"allowed"` // as we can supply true and false, omitempty would automatically remove allowed = false which we do not want
	Method  string `json:"method,omitempty"`
}

type WafUrlSig struct {
	Enabled bool `json:"enabled"` // as we can supply true and false, omitempty would automatically remove allowed = false which we do not want
	Id      int  `json:"signatureId,omitempty"`
}

type WafPolicies struct {
	WafPolicies []WafPolicy `json:"items,omitempty"`
}

type PolicyStruct struct {
	Policy        WafPolicy     `json:"policy,omitempty"`
	Modifications []interface{} `json:"modifications,omitempty"`
}
type PolicyStructobject struct {
	Policy        interface{}   `json:"policy,omitempty"`
	Modifications []interface{} `json:"modifications,omitempty"`
}
type ServerTech struct {
	ServerTechnologyName string `json:"serverTechnologyName,omitempty"`
}

type WhitelistIp struct {
	BlockRequests          string `json:"blockRequests,omitempty"`
	Description            string `json:"description,omitempty"`
	IgnoreAnomalies        bool   `json:"ignoreAnomalies,omitempty"`
	IgnoreIpReputation     bool   `json:"ignoreIpReputation,omitempty"`
	IpAddress              string `json:"ipAddress,omitempty"`
	IpMask                 string `json:"ipMask,omitempty"`
	NeverLearnRequests     bool   `json:"neverLearnRequests,omitempty"`
	NeverLogRequests       bool   `json:"neverLogRequests,omitempty"`
	TrustedByPolicyBuilder bool   `json:"trustedByPolicyBuilder,omitempty"`
}

type WafPolicy struct {
	Name        string `json:"name,omitempty"`
	Partition   string `json:"partition,omitempty"`
	Description string `json:"description,omitempty"`
	FullPath    string `json:"fullPath,omitempty"`
	ID          string `json:"id,omitempty"`
	Template    struct {
		Name string `json:"name,omitempty"`
		Link string `json:"link,omitempty"`
	} `json:"template,omitempty"`
	HasParent           bool         `json:"hasParent,omitempty"`
	ApplicationLanguage string       `json:"applicationLanguage,omitempty"`
	EnablePassiveMode   bool         `json:"enablePassiveMode,omitempty"`
	ProtocolIndependent bool         `json:"protocolIndependent,omitempty"`
	CaseInsensitive     bool         `json:"caseInsensitive,omitempty"`
	EnforcementMode     string       `json:"enforcementMode,omitempty"`
	Type                string       `json:"type,omitempty"`
	Parameters          []Parameter  `json:"parameters,omitempty"`
	ServerTechnologies  []ServerTech `json:"server-technologies,omitempty"`
	Urls                []WafUrlJson `json:"urls,omitempty"`
	PolicyBuilder       struct {
		LearningMode string `json:"learningMode,omitempty"`
	} `json:"policy-builder,omitempty"`
	SignatureSettings struct {
		SignatureStaging bool `json:"signatureStaging,omitempty"`
	} `json:"signature-settings,omitempty"`
	Signatures             []WafSignature   `json:"signatures,omitempty"`
	WhitelistIps           []WhitelistIp    `json:"whitelist-ips,omitempty"`
	GraphqlProfiles        []GraphqlProfile `json:"graphql-profiles,omitempty"`
	Filetypes              []Filetype       `json:"filetypes,omitempty"`
	DisallowedGeolocations []struct {
		CountryName string `json:"countryName,omitempty"`
	} `json:"disallowed-geolocations,omitempty"`
	OpenAPIFiles   []OpenApiLink  `json:"open-api-files,omitempty"`
	SignatureSets  []SignatureSet `json:"signature-sets,omitempty"`
	VirtualServers []interface{}  `json:"virtualServers,omitempty"`
	DataGuard      struct {
		Enabled         bool   `json:"enabled,omitempty"`
		EnforcementMode string `json:"enforcementMode,omitempty"`
	} `json:"data-guard,omitempty"`
	IpIntelligence struct {
		Enabled bool `json:"enabled,omitempty"`
	} `json:"ip-intelligence,omitempty"`
	HostNames []HostName `json:"host-names,omitempty"`
	General   struct {
		AllowedResponseCodes           []int  `json:"allowedResponseCodes,omitempty"`
		EnableEventCorrelation         bool   `json:"enableEventCorrelation,omitempty"`
		EnforcementReadinessPeriod     int    `json:"enforcementReadinessPeriod,omitempty"`
		MaskCreditCardNumbersInRequest bool   `json:"maskCreditCardNumbersInRequest,omitempty"`
		PathParameterHandling          string `json:"pathParameterHandling,omitempty"`
		TriggerAsmIruleEvent           string `json:"triggerAsmIruleEvent,omitempty"`
		TrustXff                       bool   `json:"trustXff,omitempty"`
		UseDynamicSessionIdInUrl       bool   `json:"useDynamicSessionIdInUrl,omitempty"`
	} `json:"general,omitempty"`
}

type ImportStatus struct {
	IsBase64                  bool   `json:"isBase64,omitempty"`
	Status                    string `json:"status"`
	GetPolicyAttributesOnly   bool   `json:"getPolicyAttributesOnly,omitempty"`
	Filename                  string `json:"filename"`
	ID                        string `json:"id"`
	RetainInheritanceSettings bool   `json:"retainInheritanceSettings"`
	Result                    struct {
		File    string `json:"file,omitempty"`
		Message string `json:"message"`
	} `json:"result,omitempty"`
}

type ApplyStatus struct {
	PolicyReference struct {
		Link     string `json:"link"`
		FullPath string `json:"fullPath"`
	} `json:"policyReference"`
	Status string `json:"status"`
	ID     string `json:"id"`
	Result struct {
		Message string `json:"message"`
	} `json:"result,omitempty"`
}

type Parameters struct {
	Parameters []Parameter `json:"items"`
}
type ParameterUrl struct {
	Method   string `json:"method,omitempty"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Type     string `json:"type,omitempty"`
}
type Parameter struct {
	Name                           string                   `json:"name,omitempty"`
	Description                    string                   `json:"description,omitempty"`
	Type                           string                   `json:"type,omitempty"`
	ValueType                      string                   `json:"valueType,omitempty"`
	AllowEmptyValue                bool                     `json:"allowEmptyValue,omitempty"`
	AllowRepeatedParameterName     bool                     `json:"allowRepeatedParameterName,omitempty"`
	AttackSignaturesCheck          bool                     `json:"attackSignaturesCheck,omitempty"`
	CheckMaxValueLength            bool                     `json:"checkMaxValueLength,omitempty"`
	CheckMinValueLength            bool                     `json:"checkMinValueLength,omitempty"`
	DataType                       string                   `json:"dataType,omitempty"`
	EnableRegularExpression        bool                     `json:"enableRegularExpression,omitempty"`
	IsBase64                       bool                     `json:"isBase64,omitempty"`
	IsCookie                       bool                     `json:"isCookie,omitempty"`
	IsHeader                       bool                     `json:"isHeader,omitempty"`
	Level                          string                   `json:"level,omitempty"`
	Mandatory                      bool                     `json:"mandatory,omitempty"`
	MetacharsOnParameterValueCheck bool                     `json:"metacharsOnParameterValueCheck,omitempty"`
	ParameterLocation              string                   `json:"parameterLocation,omitempty"`
	PerformStaging                 bool                     `json:"performStaging,omitempty"`
	SensitiveParameter             bool                     `json:"sensitiveParameter,omitempty"`
	SignatureOverrides             []map[string]interface{} `json:"signatureOverrides,omitempty"`
	URL                            interface{}              `json:"url,omitempty"`
	MaximumLength                  int                      `json:"maximumLength,omitempty"`
	MinimumLength                  int                      `json:"minimumLength,omitempty"`
}

func (b *BigIP) GetWafSignature(signatureid int) (*Signatures, error) {
	var signature Signatures
	var query = fmt.Sprintf("?$filter=signatureId+eq+%d", signatureid)
	err, _ := b.getForEntity(&signature, uriMgmt, uriTm, uriAsm, uriWafSign, query)
	if err != nil {
		return nil, err
	}
	return &signature, nil
}

func (b *BigIP) GetWafPolicyId(policyName, partition string) (string, error) {
	var self WafQueriedPolicies
	query := fmt.Sprintf("?$filter=contains(name,'%s')+and+contains(partition,'%s')&$select=name,partition,id", policyName, partition)
	err, _ := b.getForEntity(&self, uriMgmt, uriTm, uriAsm, uriWafPol, query)

	if err != nil {
		return "", err
	}

	for _, policy := range self.WafPolicyList {
		if policy.Name == policyName && policy.Partition == partition {
			return policy.Policy_id, nil
		}
	}

	return "", fmt.Errorf("could not get the policy ID")
}

func (b *BigIP) PostPbExport(payload interface{}) (*PbExport, error) {
	var export PbExport
	resp, err := b.postReq(payload, uriMgmt, uriTm, uriAsm, uriTasks, uriExpPb)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(resp, &export)
	return &export, nil
}
func (b *BigIP) GetWafPbExportResult(id string) (*PbExport, error) {
	var pbexport PbExport
	err, _ := b.getForEntity(&pbexport, uriMgmt, uriTm, uriAsm, uriTasks, uriExpPb, id)
	if err != nil {
		return nil, err
	}
	return &pbexport, nil
}

func (b *BigIP) GetWafPolicyQuery(wafPolicyName string, partition string) (*WafPolicy, error) {
	var wafPolicies WafPolicies
	query := fmt.Sprintf("?$filter=contains(name,'%s')+and+contains(partition,'%s')", wafPolicyName, partition)
	err, _ := b.getForEntity(&wafPolicies, uriMgmt, uriTm, uriAsm, uriWafPol, query)
	if err != nil {
		return nil, err
	}
	if len(wafPolicies.WafPolicies) == 0 {
		return nil, fmt.Errorf("[ERROR] WafPolicy: %s on partition %s not found", wafPolicyName, partition)
	}

	for _, policy := range wafPolicies.WafPolicies {
		if policy.Name == wafPolicyName && policy.Partition == partition {
			return &policy, nil
		}
	}
	return nil, fmt.Errorf("[ERROR] WafPolicy: %s on partition %s not found", wafPolicyName, partition)
}

func (b *BigIP) GetWafPolicy(policyID string) (*WafPolicy, error) {
	var wafPolicy WafPolicy
	log.Printf("[DEBUG] WAF policy get with ID:%+v", policyID)
	err, _ := b.getForEntity(&wafPolicy, uriMgmt, uriTm, uriAsm, uriWafPol, policyID)
	if err != nil {
		return nil, err
	}
	return &wafPolicy, nil
}

func (b *BigIP) ExportPolicy(policyID string) (*PolicyStruct, error) {
	//export JSON policy
	var exportPayload ExportPayload
	exportPayload.Format = "json"
	exportPayload.Inline = true
	exportPayload.Minimal = true
	exportPayload.PolicyReference.Link = fmt.Sprintf("https://localhost/mgmt/tm/asm/policies/%s", policyID)

	log.Printf("[INFO]payload:%+v", exportPayload)
	resp, err := b.postReq(exportPayload, uriMgmt, uriTm, uriAsm, uriTasks, uriExportpolicy)
	if err != nil {
		return nil, err
	}
	var taskStatus ImportStatus
	err = json.Unmarshal(resp, &taskStatus)
	if err != nil {
		return nil, err
	}
	//check export status
	exportStatus, err := b.GetExportStatus(taskStatus.ID)
	if err != nil {
		return nil, err
	}

	var exportData PolicyStruct
	err = json.Unmarshal([]byte(exportStatus.Result.File), &exportData)
	if err != nil {
		return nil, err
	}

	return &exportData, nil
}

func (b *BigIP) ExportPolicyFull(policyID string) (*string, error) {
	//export JSON policy
	var exportPayload ExportPayload
	exportPayload.Format = "json"
	exportPayload.Inline = true
	exportPayload.Minimal = true
	exportPayload.PolicyReference.Link = fmt.Sprintf("https://localhost/mgmt/tm/asm/policies/%s", policyID)

	log.Printf("[INFO] payload:%+v", exportPayload)
	resp, err := b.postReq(exportPayload, uriMgmt, uriTm, uriAsm, uriTasks, uriExportpolicy)
	if err != nil {
		return nil, err
	}
	var taskStatus ImportStatus
	err = json.Unmarshal(resp, &taskStatus)
	if err != nil {
		return nil, err
	}
	//check export status
	exportStatus, err := b.GetExportStatus(taskStatus.ID)
	if err != nil {
		return nil, err
	}
	return &exportStatus.Result.File, nil
}

func (b *BigIP) GetExportStatus(taskId string) (*ImportStatus, error) {
	var exportStatus ImportStatus
	err, _ := b.getForEntity(&exportStatus, uriMgmt, uriTm, uriAsm, uriTasks, uriExportpolicy, taskId)
	if err != nil {
		return nil, err
	}
	if exportStatus.Status != "COMPLETED" && exportStatus.Status != "FAILURE" {
		time.Sleep(5 * time.Second)
		return b.GetExportStatus(taskId)
		//return nil
	}
	if exportStatus.Status == "FAILURE" {
		return nil, fmt.Errorf("[ERROR] WafPolicy import failed with :%+v", exportStatus.Result)
	}
	if exportStatus.Status == "COMPLETED" {
		return &exportStatus, nil
	}
	return &exportStatus, nil
}

func (b *BigIP) GetWafPolicyUrls(policyID string) (*WafUrlJsons, error) {
	var wafUrls WafUrlJsons
	err, _ := b.getForEntity(&wafUrls, uriMgmt, uriTm, uriAsm, uriWafPol, policyID, uriUrls)
	if err != nil {
		return nil, err
	}
	return &wafUrls, nil
}

func (b *BigIP) GetWafPolicyParameters(policyID string) (*Parameters, error) {
	var wafParams Parameters
	err, _ := b.getForEntity(&wafParams, uriMgmt, uriTm, uriAsm, uriWafPol, policyID, uriParams)
	if err != nil {
		return nil, err
	}
	return &wafParams, nil
}

func (b *BigIP) GetImportStatus(taskId string) error {
	var importStatus ImportStatus
	err, _ := b.getForEntity(&importStatus, uriMgmt, uriTm, uriAsm, uriTasks, uriImportpolicy, taskId)
	if err != nil {
		return err
	}
	if importStatus.Status == "COMPLETED" {
		return nil
	}
	if importStatus.Status == "FAILURE" {
		return fmt.Errorf("[ERROR] WafPolicy import failed with :%+v", importStatus.Result)
	}
	if importStatus.Status == "STARTED" {
		time.Sleep(5 * time.Second)
		return b.GetImportStatus(taskId)
	}
	return nil
}

func (b *BigIP) GetApplyStatus(taskId string) error {
	var applyStatus ApplyStatus
	err, _ := b.getForEntity(&applyStatus, uriMgmt, uriTm, uriAsm, uriTasks, uriApplypolicy, taskId)
	if err != nil {
		return err
	}
	if applyStatus.Status == "COMPLETED" {
		return nil
	}
	if applyStatus.Status == "FAILURE" {
		return fmt.Errorf("[ERROR] WafPolicy Apply failed with :%+v", applyStatus.Result.Message)
	}
	if applyStatus.Status == "STARTED" {
		time.Sleep(5 * time.Second)
		return b.GetApplyStatus(taskId)
	}
	return nil
}

// DeleteWafPolicy removes waf Policy
func (b *BigIP) DeleteWafPolicy(policyId string) error {
	return b.delete(uriMgmt, uriTm, uriAsm, uriWafPol, policyId)
}

// ImportAwafJson import Awaf Json from local machine to BIGIP
func (b *BigIP) ImportAwafJson(awafPolicyName, awafJsonContent, policyID string) (string, error) {
	certbyte := []byte(awafJsonContent)
	policyName := awafPolicyName[strings.LastIndex(awafPolicyName, "/")+1:]
	_, err := b.UploadAsmBytes(certbyte, fmt.Sprintf("%s.json", policyName))
	if err != nil {
		return "", err
	}
	applywaf := ApplywafPolicy{
		Filename: fmt.Sprintf("%s.json", policyName),
		FullPath: awafPolicyName,
	}
	if policyID == "" {
		policyPath := struct {
			FullPath string `json:"fullPath,omitempty"`
		}{
			FullPath: awafPolicyName,
		}
		applywaf.Policy = policyPath
	} else {
		policyPath := struct {
			Link     string `json:"link,omitempty"`
			FullPath string `json:"fullPath,omitempty"`
		}{
			Link:     fmt.Sprintf("https://localhost/mgmt/tm/asm/policies/%s", policyID),
			FullPath: awafPolicyName,
		}
		policy := struct {
			FileName        string      `json:"filename"`
			PolicyReference interface{} `json:"policyReference"`
		}{
			FileName: fmt.Sprintf("%s.json", policyName),
			//FullPath: awafPolicyName,
			PolicyReference: policyPath,
		}
		log.Printf("[DEBUG] Import policy:%+v", policy)
		resp, err := b.postReq(policy, uriMgmt, uriTm, uriAsm, uriTasks, uriImportpolicy)
		if err != nil {
			return "", err
		}
		var taskStatus ImportStatus
		err = json.Unmarshal(resp, &taskStatus)
		if err != nil {
			return "", err
		}
		return taskStatus.ID, nil
	}
	log.Printf("[DEBUG] Import policy:%+v", applywaf)
	resp, err := b.postReq(applywaf, uriMgmt, uriTm, uriAsm, uriTasks, uriImportpolicy)
	if err != nil {
		return "", err
	}
	var taskStatus ImportStatus
	err = json.Unmarshal(resp, &taskStatus)
	if err != nil {
		return "", err
	}
	return taskStatus.ID, nil
}

// ApplyAwafJson apply Awaf Json policy
func (b *BigIP) ApplyAwafJson(awafPolicyName, policyID string) (string, error) {
	applywaf := ApplywafPolicy{}
	if policyID == "" {
		policyPath := struct {
			FullPath string `json:"fullPath,omitempty"`
		}{
			FullPath: awafPolicyName,
		}
		applywaf.Policy = policyPath
	} else {
		policyPath := struct {
			Link     string `json:"link,omitempty"`
			FullPath string `json:"fullPath,omitempty"`
		}{
			Link:     fmt.Sprintf("https://localhost/mgmt/tm/asm/policies/%s", policyID),
			FullPath: awafPolicyName,
		}
		policy := struct {
			PolicyReference interface{} `json:"policyReference,omitempty"`
		}{
			PolicyReference: policyPath,
		}
		log.Printf("import policy:%+v", policy)
		resp, err := b.postReq(policy, uriMgmt, uriTm, uriAsm, uriTasks, uriApplypolicy)
		if err != nil {
			return "", err
		}
		var taskStatus ApplyStatus
		err = json.Unmarshal(resp, &taskStatus)
		if err != nil {
			return "", err
		}
		return taskStatus.ID, nil
	}

	log.Printf("apply policy body:%+v", applywaf)
	resp, err := b.postReq(applywaf, uriMgmt, uriTm, uriAsm, uriTasks, uriApplypolicy)
	if err != nil {
		return "", err
	}
	var taskStatus ApplyStatus
	err = json.Unmarshal(resp, &taskStatus)
	if err != nil {
		return "", err
	}
	return taskStatus.ID, nil
}
