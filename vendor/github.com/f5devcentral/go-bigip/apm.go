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
