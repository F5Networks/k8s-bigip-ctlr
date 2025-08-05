package bigip

import (
	"context"
	"encoding/json"
)

type (
	WebtopType        string
	CustomizationType string
	InitialState      string
	LinkType          string
)

const (
	WebtopTypePortal  WebtopType = "portal-access"
	WebtopTypeFull               = "full"
	WebtopTypeNetwork            = "network-access"
)

const (
	CustomizationTypeModern   CustomizationType = "Modern"
	CustomizationTypeStandard                   = "Standard"
)

const (
	InitialStateCollapsed InitialState = "Collapsed"
	InitialStateExpanded               = "Expanded"
)

const (
	LinkTypeUri LinkType = "uri"
)

const (
	uriAccess       = "access"
	uriAccessPolicy = "access-policy"
)

// Some endpoints have a "booledString" a boolean value that is represented as a string in the json payload
type BooledString bool

func (b BooledString) MarshalJSON() ([]byte, error) {
	str := "false"
	if b {
		str = "true"
	}
	return json.Marshal(str)
}

func (b BooledString) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	b = str == "true"
	return nil
}

// Values in WebtopConfig are updateable
type WebtopConfig struct {
	Description        string            `json:"description,omitempty"`
	LinkType           LinkType          `json:"linkType,omitempty"`
	CustomizationGroup string            `json:"customizationGroup"`
	Type               WebtopType        `json:"webtopType,omitempty"`
	CustomizationType  CustomizationType `json:"customizationType,omitempty"`
	LocationSpecific   BooledString      `json:"locationSpecific"`
	MinimizeToTray     BooledString      `json:"minimizeToTray"`
	ShowSearch         BooledString      `json:"showSearch"`
	WarningOnClose     BooledString      `json:"warningOnClose"`
	UrlEntryField      BooledString      `json:"urlEntryField"`
	ResourceSearch     BooledString      `json:"resourceSearch"`
	InitialState       InitialState      `json:"initialState,omitempty"`
}

// Only the values within WebtopConfig can be updated. Any changes made to non-config values will be ignored when using UpdateWebtop.
type Webtop struct {
	Name        string `json:"name,omitempty"`
	Partition   string `json:"partition,omitempty"`
	TMPartition string `json:"tmPartition,omitempty"`
	WebtopConfig
}

type WebtopRead struct {
	Webtop
	FullPath                    string `json:"fullPath,omitempty"`
	Generation                  int    `json:"generation,omitempty"`
	SelfLink                    string `json:"selfLink,omitempty"`
	CustomizationGroupReference struct {
		Link string `json:"link,omitempty"`
	} `json:"customizationGroupReference,omitempty"`
}

func (b *BigIP) CreateWebtop(ctx context.Context, webtop Webtop) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return b.post(webtop, uriMgmt, uriTm, uriApm, uriResource, uriWebtop)
}

func (b *BigIP) DeleteWebtop(ctx context.Context, name string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return b.delete(uriMgmt, uriTm, uriApm, uriResource, uriWebtop, name)
}

func (b *BigIP) GetWebtop(ctx context.Context, name string) (*WebtopRead, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var webtop WebtopRead
	err, _ := b.getForEntity(&webtop, uriMgmt, uriTm, uriApm, uriResource, uriWebtop, name)
	return &webtop, err
}

func (b *BigIP) ModifyWebtop(ctx context.Context, name string, webtop WebtopConfig) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return b.patch(webtop, uriMgmt, uriTm, uriApm, uriResource, uriWebtop, name)
}

// AccessProfiles contains a list of all access profiles on the BIG-IP system.
type AccessProfiles struct {
	AccessProfiles []AccessProfile `json:"items"`
}

// AccessProfile contains information about each access profile.
type AccessProfile struct {
	Name                        string   `json:"name,omitempty"`
	Partition                   string   `json:"partition,omitempty"`
	FullPath                    string   `json:"fullPath,omitempty"`
	Generation                  int      `json:"generation,omitempty"`
	SelfLink                    string   `json:"selfLink,omitempty"`
	Kind                        string   `json:"kind,omitempty"`
	DefaultsFrom                string   `json:"defaultsFrom,omitempty"`
	Description                 string   `json:"description,omitempty"`
	AcceptLanguages             []string `json:"acceptLanguages,omitempty"`
	AccessPolicy                string   `json:"accessPolicy,omitempty"`
	AccessPolicyTimeout         int      `json:"accessPolicyTimeout,omitempty"`
	CertificateKey              string   `json:"certificateKey,omitempty"`
	CompressGzipLevel           int      `json:"compressGzipLevel,omitempty"`
	CookieNames                 string   `json:"cookieNames,omitempty"`
	CustomizationKey            string   `json:"customizationKey,omitempty"`
	DefaultLanguage             string   `json:"defaultLanguage,omitempty"`
	Domain                      string   `json:"domain,omitempty"`
	DomainCookie                string   `json:"domainCookie,omitempty"`
	DomainMode                  string   `json:"domainMode,omitempty"`
	EpsProfile                  string   `json:"epsProfile,omitempty"`
	ErrorMapItem                string   `json:"errorMapItem,omitempty"`
	EnforcePolicy               string   `json:"enforcePolicy,omitempty"`
	FrameworkInstallationID     string   `json:"frameworkInstallationId,omitempty"`
	GenerationAction            string   `json:"generationAction,omitempty"`
	GzipLevel                   int      `json:"gzipLevel,omitempty"`
	HTTPOnlyCookie              string   `json:"httponlyCookie,omitempty"`
	InactivityTimeout           int      `json:"inactivityTimeout,omitempty"`
	LogSettings                 []string `json:"logSettings,omitempty"`
	LogoutURIInclude            string   `json:"logoutUriInclude,omitempty"`
	LogoutURITimeout            int      `json:"logoutUriTimeout,omitempty"`
	MaxConcurrentSessions       int      `json:"maxConcurrentSessions,omitempty"`
	MaxConcurrentUsers          int      `json:"maxConcurrentUsers,omitempty"`
	MaxFailureDelay             int      `json:"maxFailureDelay,omitempty"`
	MaxInProgressSessions       int      `json:"maxInProgressSessions,omitempty"`
	MaxSessionTimeout           int      `json:"maxSessionTimeout,omitempty"`
	MinFailureDelay             int      `json:"minFailureDelay,omitempty"`
	ModifiedSinceLastPolicySync string   `json:"modifiedSinceLastPolicySync,omitempty"`
	NtlmConnPool                string   `json:"ntlmConnPool,omitempty"`
	PersistentCookie            string   `json:"persistentCookie,omitempty"`
	RestrictToSingleClientIP    string   `json:"restrictToSingleClientIp,omitempty"`
	SamesiteCookie              string   `json:"samesiteCookie,omitempty"`
	SamesiteCookieAttrValue     string   `json:"samesiteCookieAttrValue,omitempty"`
	Scope                       string   `json:"scope,omitempty"`
	ScopeFilteringProfile       string   `json:"scopeFilteringProfile,omitempty"`
	SecureCookie                string   `json:"secureCookie,omitempty"`
	Services                    []string `json:"services,omitempty"`
	SsoName                     string   `json:"ssoName,omitempty"`
	TmGeneration                int      `json:"tmGeneration,omitempty"`
	Type                        string   `json:"type,omitempty"`
	UserIdentityMethod          string   `json:"userIdentityMethod,omitempty"`
	UseHTTP503OnError           string   `json:"useHttp_503OnError,omitempty"`
	UsernameCookie              string   `json:"usernameCookie,omitempty"`
	WebtopRedirectOnRootURI     string   `json:"webtopRedirectOnRootUri,omitempty"`
	DomainGroupsReference       struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"domainGroupsReference,omitempty"`
}

// AccessPolicies contains a list of all access policies on the BIG-IP system.
type AccessPolicies struct {
	Kind     string         `json:"kind,omitempty"`
	SelfLink string         `json:"selfLink,omitempty"`
	Items    []AccessPolicy `json:"items"`
}

// PolicyItem represents an item within an access policy.
type PolicyItem struct {
	Name          string `json:"name,omitempty"`
	Partition     string `json:"partition,omitempty"`
	Priority      int    `json:"priority,omitempty"`
	NameReference struct {
		Link string `json:"link,omitempty"`
	} `json:"nameReference,omitempty"`
}

// PerReqPolicyProperty represents per-request policy properties.
type PerReqPolicyProperty struct {
	Name             string `json:"name,omitempty"`
	Partition        string `json:"partition,omitempty"`
	IncompleteAction string `json:"incompleteAction,omitempty"`
}

// AccessPolicy contains information about each access policy.
type AccessPolicy struct {
	Kind                   string `json:"kind,omitempty"`
	Name                   string `json:"name,omitempty"`
	Partition              string `json:"partition,omitempty"`
	FullPath               string `json:"fullPath,omitempty"`
	Generation             int    `json:"generation,omitempty"`
	SelfLink               string `json:"selfLink,omitempty"`
	DefaultEnding          string `json:"defaultEnding,omitempty"`
	DefaultEndingReference struct {
		Link string `json:"link,omitempty"`
	} `json:"defaultEndingReference,omitempty"`
	MaxMacroLoopCount  int    `json:"maxMacroLoopCount,omitempty"`
	OneshotMacro       string `json:"oneshotMacro,omitempty"`
	StartItem          string `json:"startItem,omitempty"`
	StartItemReference struct {
		Link string `json:"link,omitempty"`
	} `json:"startItemReference,omitempty"`
	Type                   string                 `json:"type,omitempty"`
	Items                  []PolicyItem           `json:"items,omitempty"`
	PerReqPolicyProperties []PerReqPolicyProperty `json:"perReqPolicyProperties,omitempty"`
}

// GetAccessProfile gets an access profile by name. Returns nil if the access profile does not exist
func (b *BigIP) GetAccessProfile(name string) (*AccessProfile, error) {
	var accessProfile AccessProfile
	err, ok := b.getForEntity(&accessProfile, uriMgmt, uriTm, uriApm, uriProfile, uriAccess, name)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &accessProfile, nil
}

// AccessProfiles returns a list of all access profiles
func (b *BigIP) AccessProfiles() (*AccessProfiles, error) {
	var accessProfiles AccessProfiles
	err, _ := b.getForEntity(&accessProfiles, uriMgmt, uriTm, uriApm, uriProfile, uriAccess)
	if err != nil {
		return nil, err
	}

	return &accessProfiles, nil
}

// CreateAccessProfile adds a new access profile to the BIG-IP system.
func (b *BigIP) CreateAccessProfile(config *AccessProfile) error {
	return b.post(config, uriMgmt, uriTm, uriApm, uriProfile, uriAccess)
}

// DeleteAccessProfile removes an access profile.
func (b *BigIP) DeleteAccessProfile(name string) error {
	return b.delete(uriMgmt, uriTm, uriApm, uriProfile, uriAccess, name)
}

// ModifyAccessProfile allows you to change any attribute of an access profile.
// Fields that can be modified are referenced in the AccessProfile struct.
func (b *BigIP) ModifyAccessProfile(name string, config *AccessProfile) error {
	return b.patch(config, uriMgmt, uriTm, uriApm, uriProfile, uriAccess, name)
}

// GetAccessPolicy gets an access policy by name. Returns nil if the access policy does not exist
func (b *BigIP) GetAccessPolicy(name string) (*AccessPolicy, error) {
	var accessPolicy AccessPolicy
	err, ok := b.getForEntity(&accessPolicy, uriMgmt, uriTm, uriApm, uriPolicy, uriAccessPolicy, name)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &accessPolicy, nil
}

// AccessPolicies returns a list of all access policies
func (b *BigIP) AccessPolicies() (*AccessPolicies, error) {
	var accessPolicies AccessPolicies
	err, _ := b.getForEntity(&accessPolicies, uriMgmt, uriTm, uriApm, uriPolicy, uriAccessPolicy)
	if err != nil {
		return nil, err
	}

	return &accessPolicies, nil
}

// CreateAccessPolicy adds a new access policy to the BIG-IP system.
func (b *BigIP) CreateAccessPolicy(config *AccessPolicy) error {
	return b.post(config, uriMgmt, uriTm, uriApm, uriPolicy, uriAccessPolicy)
}

// DeleteAccessPolicy removes an access policy.
func (b *BigIP) DeleteAccessPolicy(name string) error {
	return b.delete(uriMgmt, uriTm, uriApm, uriPolicy, uriAccessPolicy, name)
}

// ModifyAccessPolicy allows you to change any attribute of an access policy.
// Fields that can be modified are referenced in the AccessPolicy struct.
func (b *BigIP) ModifyAccessPolicy(name string, config *AccessPolicy) error {
	return b.patch(config, uriMgmt, uriTm, uriApm, uriPolicy, uriAccessPolicy, name)
}
