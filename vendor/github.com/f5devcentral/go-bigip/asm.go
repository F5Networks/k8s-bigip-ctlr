/*
Copyright © 2019 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/

/*
AS3 uses a declarative model, meaning you provide a JSON declaration rather than a set of imperative commands. The declaration represents the configuration which AS3 is responsible for creating on a BIG-IP system. AS3 is well-defined according to the rules of JSON Schema, and declarations validate according to JSON Schema. AS3 accepts declaration updates via REST (push), reference (pull), or CLI (flat file editing).
To read more about As3 check https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/
*/

package bigip

// ASM module for Application Security Manager functions

// URI constants for ASM operations
const (
	uriDos            = "dos"
	uriFirewall       = "firewall"
	uriIPIntelligence = "ip-intelligence"
	uriLog            = "log"
)

// DOSProfiles contains a list of every DOS profile on the BIG-IP system.
type DOSProfiles struct {
	DOSProfiles []DOSProfile `json:"items"`
}

// DOSProfile contains information about each DOS profile. You can use all
// of these fields when modifying a DOS profile.
type DOSProfile struct {
	Kind                 string `json:"kind,omitempty"`
	Name                 string `json:"name,omitempty"`
	Partition            string `json:"partition,omitempty"`
	FullPath             string `json:"fullPath,omitempty"`
	Generation           int    `json:"generation,omitempty"`
	SelfLink             string `json:"selfLink,omitempty"`
	CreationTime         string `json:"creationTime,omitempty"`
	CreationUser         string `json:"creationUser,omitempty"`
	LastModifiedTime     string `json:"lastModifiedTime,omitempty"`
	ModifyUser           string `json:"modifyUser,omitempty"`
	ThresholdSensitivity string `json:"thresholdSensitivity,omitempty"`
	ApplicationReference struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"applicationReference,omitempty"`
}

// FirewallPolicies contains a list of every Firewall policy on the BIG-IP system.
type FirewallPolicies struct {
	FirewallPolicies []FirewallPolicy `json:"items"`
}

// FirewallPolicy contains information about each Firewall policy. You can use all
// of these fields when modifying a Firewall policy.
type FirewallPolicy struct {
	Kind           string `json:"kind,omitempty"`
	Name           string `json:"name,omitempty"`
	Partition      string `json:"partition,omitempty"`
	FullPath       string `json:"fullPath,omitempty"`
	Generation     int    `json:"generation,omitempty"`
	SelfLink       string `json:"selfLink,omitempty"`
	RulesReference struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"rulesReference,omitempty"`
}

// IPIntelligencePolicies contains a list of every IP Intelligence policy on the BIG-IP system.
type IPIntelligencePolicies struct {
	IPIntelligencePolicies []IPIntelligencePolicy `json:"items"`
}

// IPIntelligencePolicy contains information about each IP Intelligence policy. You can use all
// of these fields when modifying an IP Intelligence policy.
type IPIntelligencePolicy struct {
	Kind                            string `json:"kind,omitempty"`
	Name                            string `json:"name,omitempty"`
	Partition                       string `json:"partition,omitempty"`
	FullPath                        string `json:"fullPath,omitempty"`
	Generation                      int    `json:"generation,omitempty"`
	SelfLink                        string `json:"selfLink,omitempty"`
	DefaultAction                   string `json:"defaultAction,omitempty"`
	DefaultLogBlacklistHitOnly      string `json:"defaultLogBlacklistHitOnly,omitempty"`
	DefaultLogBlacklistWhitelistHit string `json:"defaultLogBlacklistWhitelistHit,omitempty"`
}

// SecurityLogProfiles contains a list of every Security Log profile on the BIG-IP system.
type SecurityLogProfiles struct {
	SecurityLogProfiles []SecurityLogProfile `json:"items"`
}

// SecurityLogProfile contains information about each Security Log profile. You can use all
// of these fields when modifying a Security Log profile.
type SecurityLogProfile struct {
	Kind           string   `json:"kind,omitempty"`
	Name           string   `json:"name,omitempty"`
	Partition      string   `json:"partition,omitempty"`
	FullPath       string   `json:"fullPath,omitempty"`
	Generation     int      `json:"generation,omitempty"`
	SelfLink       string   `json:"selfLink,omitempty"`
	AutoDiscovery  struct{} `json:"autoDiscovery,omitempty"`
	BuiltIn        string   `json:"builtIn,omitempty"`
	Classification struct {
		LogAllClassificationMatches string `json:"logAllClassificationMatches,omitempty"`
	} `json:"classification,omitempty"`
	Description    string   `json:"description,omitempty"`
	Flowspec       struct{} `json:"flowspec,omitempty"`
	Hidden         string   `json:"hidden,omitempty"`
	IPIntelligence struct {
		AggregateRate        int    `json:"aggregate-rate,omitempty"`
		LogGeo               string `json:"log-geo,omitempty"`
		LogRtbh              string `json:"log-rtbh,omitempty"`
		LogScrubber          string `json:"log-scrubber,omitempty"`
		LogShun              string `json:"log-shun,omitempty"`
		LogTranslationFields string `json:"log-translation-fields,omitempty"`
	} `json:"ip-intelligence,omitempty"`
	NAT struct {
		EndInboundSession    string `json:"end-inbound-session,omitempty"`
		EndOutboundSession   string `json:"end-outbound-session,omitempty"`
		Errors               string `json:"errors,omitempty"`
		LogSubscriberID      string `json:"log-subscriber-id,omitempty"`
		LsnLegacyMode        string `json:"lsn-legacy-mode,omitempty"`
		QuotaExceeded        string `json:"quota-exceeded,omitempty"`
		StartInboundSession  string `json:"start-inbound-session,omitempty"`
		StartOutboundSession string `json:"start-outbound-session,omitempty"`
		Format               struct {
			EndInboundSession struct {
				FieldListDelimiter string `json:"field-list-delimiter,omitempty"`
				Type               string `json:"type,omitempty"`
			} `json:"end-inbound-session,omitempty"`
			EndOutboundSession struct {
				FieldListDelimiter string `json:"field-list-delimiter,omitempty"`
				Type               string `json:"type,omitempty"`
			} `json:"end-outbound-session,omitempty"`
			Errors struct {
				FieldListDelimiter string `json:"field-list-delimiter,omitempty"`
				Type               string `json:"type,omitempty"`
			} `json:"errors,omitempty"`
			QuotaExceeded struct {
				FieldListDelimiter string `json:"field-list-delimiter,omitempty"`
				Type               string `json:"type,omitempty"`
			} `json:"quota-exceeded,omitempty"`
			StartInboundSession struct {
				FieldListDelimiter string `json:"field-list-delimiter,omitempty"`
				Type               string `json:"type,omitempty"`
			} `json:"start-inbound-session,omitempty"`
			StartOutboundSession struct {
				FieldListDelimiter string `json:"field-list-delimiter,omitempty"`
				Type               string `json:"type,omitempty"`
			} `json:"start-outbound-session,omitempty"`
		} `json:"format,omitempty"`
		RateLimit struct {
			AggregateRate        int `json:"aggregate-rate,omitempty"`
			EndInboundSession    int `json:"end-inbound-session,omitempty"`
			EndOutboundSession   int `json:"end-outbound-session,omitempty"`
			Errors               int `json:"errors,omitempty"`
			QuotaExceeded        int `json:"quota-exceeded,omitempty"`
			StartInboundSession  int `json:"start-inbound-session,omitempty"`
			StartOutboundSession int `json:"start-outbound-session,omitempty"`
		} `json:"rate-limit,omitempty"`
	} `json:"nat,omitempty"`
	Netflow      struct{} `json:"netflow,omitempty"`
	PacketFilter struct {
		AggregateRate int `json:"aggregate-rate,omitempty"`
	} `json:"packet-filter,omitempty"`
	PortMisuse struct {
		AggregateRate int `json:"aggregate-rate,omitempty"`
	} `json:"port-misuse,omitempty"`
	ProtocolInspection struct {
		LogPacket string `json:"log-packet,omitempty"`
	} `json:"protocol-inspection,omitempty"`
	TrafficStatistics struct {
		ActiveFlows         string `json:"active-flows,omitempty"`
		MissedFlows         string `json:"missed-flows,omitempty"`
		ReapedFlows         string `json:"reaped-flows,omitempty"`
		Syncookies          string `json:"syncookies,omitempty"`
		SyncookiesWhitelist string `json:"syncookies-whitelist,omitempty"`
	} `json:"traffic-statistics,omitempty"`
	ApplicationReference struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"applicationReference,omitempty"`
	NetworkReference struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"networkReference,omitempty"`
	ProtocolDNSReference struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"protocolDnsReference,omitempty"`
	ProtocolSIPReference struct {
		Link            string `json:"link,omitempty"`
		IsSubcollection bool   `json:"isSubcollection,omitempty"`
	} `json:"protocolSipReference,omitempty"`
}

// DOSProfiles returns a list of DOS profiles
func (b *BigIP) DOSProfiles() (*DOSProfiles, error) {
	var dosProfiles DOSProfiles
	err, _ := b.getForEntity(&dosProfiles, uriSecurity, uriDos, uriProfile)
	if err != nil {
		return nil, err
	}

	return &dosProfiles, nil
}

// GetDOSProfile gets a DOS profile by name. Returns nil if the DOS profile does not exist
func (b *BigIP) GetDOSProfile(name string) (*DOSProfile, error) {
	var dosProfile DOSProfile
	err, ok := b.getForEntity(&dosProfile, uriSecurity, uriDos, uriProfile, name)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &dosProfile, nil
}

// AddDOSProfile creates a new DOS profile on the BIG-IP system.
func (b *BigIP) AddDOSProfile(config *DOSProfile) error {
	return b.post(config, uriSecurity, uriDos, uriProfile)
}

// DeleteDOSProfile removes a DOS profile.
func (b *BigIP) DeleteDOSProfile(name string) error {
	return b.delete(uriSecurity, uriDos, uriProfile, name)
}

// ModifyDOSProfile allows you to change any attribute of a DOS profile.
// Fields that can be modified are referenced in the DOSProfile struct.
func (b *BigIP) ModifyDOSProfile(name string, config *DOSProfile) error {
	return b.patch(config, uriSecurity, uriDos, uriProfile, name)
}

// FirewallPolicies returns a list of Firewall policies
func (b *BigIP) FirewallPolicies() (*FirewallPolicies, error) {
	var firewallPolicies FirewallPolicies
	err, _ := b.getForEntity(&firewallPolicies, uriSecurity, uriFirewall, uriPolicy)
	if err != nil {
		return nil, err
	}

	return &firewallPolicies, nil
}

// GetFirewallPolicy gets a Firewall policy by name. Returns nil if the Firewall policy does not exist
func (b *BigIP) GetFirewallPolicy(name string) (*FirewallPolicy, error) {
	var firewallPolicy FirewallPolicy
	err, ok := b.getForEntity(&firewallPolicy, uriSecurity, uriFirewall, uriPolicy, name)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &firewallPolicy, nil
}

// AddFirewallPolicy creates a new Firewall policy on the BIG-IP system.
func (b *BigIP) AddFirewallPolicy(config *FirewallPolicy) error {
	return b.post(config, uriSecurity, uriFirewall, uriPolicy)
}

// DeleteFirewallPolicy removes a Firewall policy.
func (b *BigIP) DeleteFirewallPolicy(name string) error {
	return b.delete(uriSecurity, uriFirewall, uriPolicy, name)
}

// ModifyFirewallPolicy allows you to change any attribute of a Firewall policy.
// Fields that can be modified are referenced in the FirewallPolicy struct.
func (b *BigIP) ModifyFirewallPolicy(name string, config *FirewallPolicy) error {
	return b.patch(config, uriSecurity, uriFirewall, uriPolicy, name)
}

// IPIntelligencePolicies returns a list of IP Intelligence policies
func (b *BigIP) IPIntelligencePolicies() (*IPIntelligencePolicies, error) {
	var ipIntelligencePolicies IPIntelligencePolicies
	err, _ := b.getForEntity(&ipIntelligencePolicies, uriSecurity, uriIPIntelligence, uriPolicy)
	if err != nil {
		return nil, err
	}

	return &ipIntelligencePolicies, nil
}

// GetIPIntelligencePolicy gets an IP Intelligence policy by name. Returns nil if the policy does not exist
func (b *BigIP) GetIPIntelligencePolicy(name string) (*IPIntelligencePolicy, error) {
	var ipIntelligencePolicy IPIntelligencePolicy
	err, ok := b.getForEntity(&ipIntelligencePolicy, uriSecurity, uriIPIntelligence, uriPolicy, name)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &ipIntelligencePolicy, nil
}

// AddIPIntelligencePolicy creates a new IP Intelligence policy on the BIG-IP system.
func (b *BigIP) AddIPIntelligencePolicy(config *IPIntelligencePolicy) error {
	return b.post(config, uriSecurity, uriIPIntelligence, uriPolicy)
}

// DeleteIPIntelligencePolicy removes an IP Intelligence policy.
func (b *BigIP) DeleteIPIntelligencePolicy(name string) error {
	return b.delete(uriSecurity, uriIPIntelligence, uriPolicy, name)
}

// ModifyIPIntelligencePolicy allows you to change any attribute of an IP Intelligence policy.
// Fields that can be modified are referenced in the IPIntelligencePolicy struct.
func (b *BigIP) ModifyIPIntelligencePolicy(name string, config *IPIntelligencePolicy) error {
	return b.patch(config, uriSecurity, uriIPIntelligence, uriPolicy, name)
}

// SecurityLogProfiles returns a list of Security Log profiles
func (b *BigIP) SecurityLogProfiles() (*SecurityLogProfiles, error) {
	var securityLogProfiles SecurityLogProfiles
	err, _ := b.getForEntity(&securityLogProfiles, uriSecurity, uriLog, uriProfile)
	if err != nil {
		return nil, err
	}

	return &securityLogProfiles, nil
}

// GetSecurityLogProfile gets a Security Log profile by name. Returns nil if the profile does not exist
func (b *BigIP) GetSecurityLogProfile(name string) (*SecurityLogProfile, error) {
	var securityLogProfile SecurityLogProfile
	err, ok := b.getForEntity(&securityLogProfile, uriSecurity, uriLog, uriProfile, name)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &securityLogProfile, nil
}

// AddSecurityLogProfile creates a new Security Log profile on the BIG-IP system.
func (b *BigIP) AddSecurityLogProfile(config *SecurityLogProfile) error {
	return b.post(config, uriSecurity, uriLog, uriProfile)
}

// DeleteSecurityLogProfile removes a Security Log profile.
func (b *BigIP) DeleteSecurityLogProfile(name string) error {
	return b.delete(uriSecurity, uriLog, uriProfile, name)
}

// ModifySecurityLogProfile allows you to change any attribute of a Security Log profile.
// Fields that can be modified are referenced in the SecurityLogProfile struct.
func (b *BigIP) ModifySecurityLogProfile(name string, config *SecurityLogProfile) error {
	return b.patch(config, uriSecurity, uriLog, uriProfile, name)
}
