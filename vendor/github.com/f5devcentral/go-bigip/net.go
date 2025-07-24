/*
Original work Copyright © 2015 Scott Ware
Modifications Copyright 2019 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/
package bigip

import (
	"regexp"
	"strings"
)

// Interfaces contains a list of every interface on the BIG-IP system.
type Interfaces struct {
	Interfaces []Interface `json:"items"`
}

// Interface contains information about each individual interface.
type Interface struct {
	Name              string `json:"name,omitempty"`
	FullPath          string `json:"fullPath,omitempty"`
	Generation        int    `json:"generation,omitempty"`
	Bundle            string `json:"bundle,omitempty"`
	Enabled           bool   `json:"enabled,omitempty"`
	FlowControl       string `json:"flowControl,omitempty"`
	ForceGigabitFiber string `json:"forceGigabitFiber,omitempty"`
	IfIndex           int    `json:"ifIndex,omitempty"`
	LLDPAdmin         string `json:"lldpAdmin,omitempty"`
	LLDPTlvmap        int    `json:"lldpTlvmap,omitempty"`
	MACAddress        string `json:"macAddress,omitempty"`
	MediaActive       string `json:"mediaActive,omitempty"`
	MediaFixed        string `json:"mediaFixed,omitempty"`
	MediaMax          string `json:"mediaMax,omitempty"`
	MediaSFP          string `json:"mediaSfp,omitempty"`
	MTU               int    `json:"mtu,omitempty"`
	PreferPort        string `json:"preferPort,omitempty"`
	SFlow             struct {
		PollInterval       int    `json:"pollInterval,omitempty"`
		PollIntervalGlobal string `json:"pollIntervalGlobal,omitempty"`
	} `json:"sflow,omitempty"`
	STP             string `json:"stp,omitempty"`
	STPAutoEdgePort string `json:"stpAutoEdgePort,omitempty"`
	STPEdgePort     string `json:"stpEdgePort,omitempty"`
	STPLinkType     string `json:"stpLinkType,omitempty"`
}

// SelfIPs contains a list of every self IP on the BIG-IP system.
type SelfIPs struct {
	SelfIPs []SelfIP `json:"items"`
}

// SelfIP contains information about each individual self IP. You can use all of
// these fields when modifying a self IP.
type SelfIP struct {
	Name                  string      `json:"name,omitempty"`
	Partition             string      `json:"partition,omitempty"`
	FullPath              string      `json:"fullPath,omitempty"`
	Generation            int         `json:"generation,omitempty"`
	Address               string      `json:"address,omitempty"`
	Floating              string      `json:"floating,omitempty"`
	InheritedTrafficGroup string      `json:"inheritedTrafficGroup,omitempty"`
	TrafficGroup          string      `json:"trafficGroup,omitempty"`
	Unit                  int         `json:"unit,omitempty"`
	Vlan                  string      `json:"vlan,omitempty"`
	AllowService          interface{} `json:"allowService"`
}

// Trunks contains a list of every trunk on the BIG-IP system.
type Trunks struct {
	Trunks []Trunk `json:"items"`
}

// Trunk contains information about each individual trunk. You can use all of
// these fields when modifying a trunk.
type Trunk struct {
	Name               string   `json:"name,omitempty"`
	FullPath           string   `json:"fullPath,omitempty"`
	Generation         int      `json:"generation,omitempty"`
	Bandwidth          int      `json:"bandwidth,omitempty"`
	MemberCount        int      `json:"cfgMbrCount,omitempty"`
	DistributionHash   string   `json:"distributionHash,omitempty"`
	ID                 int      `json:"id,omitempty"`
	LACP               string   `json:"lacp,omitempty"`
	LACPMode           string   `json:"lacpMode,omitempty"`
	LACPTimeout        string   `json:"lacpTimeout,omitempty"`
	LinkSelectPolicy   string   `json:"linkSelectPolicy,omitempty"`
	MACAddress         string   `json:"macAddress,omitempty"`
	STP                string   `json:"stp,omitempty"`
	Type               string   `json:"type,omitempty"`
	WorkingMemberCount int      `json:"workingMbrCount,omitempty"`
	Interfaces         []string `json:"interfaces,omitempty"`
}

// Vlans contains a list of every VLAN on the BIG-IP system.
type Vlans struct {
	Vlans []Vlan `json:"items"`
}

// Vlan contains information about each individual VLAN. You can use all of
// these fields when modifying a VLAN.
type Vlan struct {
	Name            string `json:"name,omitempty"`
	Partition       string `json:"partition,omitempty"`
	FullPath        string `json:"fullPath,omitempty"`
	Generation      int    `json:"generation,omitempty"`
	AutoLastHop     string `json:"autoLastHop,omitempty"`
	CMPHash         string `json:"cmpHash,omitempty"`
	DAGRoundRobin   string `json:"dagRoundRobin,omitempty"`
	Failsafe        string `json:"failsafe,omitempty"`
	FailsafeAction  string `json:"failsafeAction,omitempty"`
	FailsafeTimeout int    `json:"failsafeTimeout,omitempty"`
	IfIndex         int    `json:"ifIndex,omitempty"`
	Learning        string `json:"learning,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	SFlow           struct {
		PollInterval       int    `json:"pollInterval,omitempty"`
		PollIntervalGlobal string `json:"pollIntervalGlobal,omitempty"`
		SamplingRate       int    `json:"samplingRate,omitempty"`
		SamplingRateGlobal string `json:"samplingRateGlobal,omitempty"`
	} `json:"sflow,omitempty"`
	SourceChecking string `json:"sourceChecking,omitempty"`
	Tag            int    `json:"tag,omitempty"`
}

// VlanInterfaces contains a list of Interface(s) attached to a VLAN.
type VlanInterfaces struct {
	VlanInterfaces []VlanInterface `json:"items"`
}

// VlanInterface contains fields to be used when adding an interface to a VLAN.
type VlanInterface struct {
	Name     string `json:"name,omitempty"`
	Tagged   bool   `json:"tagged,omitempty"`
	Untagged bool   `json:"untagged,omitempty"`
}

// Routes contains a list of every route on the BIG-IP system.
type Routes struct {
	Routes []Route `json:"items"`
}

// Route contains information about each individual route. You can use all
// of these fields when modifying a route.
type Route struct {
	Name        string `json:"name,omitempty"`
	Partition   string `json:"partition,omitempty"`
	FullPath    string `json:"fullPath,omitempty"`
	Generation  int    `json:"generation,omitempty"`
	Gateway     string `json:"gw,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	TmInterface string `json:"tmInterface,omitempty"`
	Blackhole   bool   `json:"blackhole,omitempty"`
	//TmInterfaceReference struct {
	//      Link string `json:"link"`
	//} `json:"tmInterfaceReference,omitempty"`
	Network string `json:"network,omitempty"`
}

// RouteDomains contains a list of every route domain on the BIG-IP system.
type RouteDomains struct {
	RouteDomains []RouteDomain `json:"items"`
}

// RouteDomain contains information about each individual route domain. You can use all
// of these fields when modifying a route domain.
type RouteDomain struct {
	Name       string   `json:"name,omitempty"`
	Partition  string   `json:"partition,omitempty"`
	FullPath   string   `json:"fullPath,omitempty"`
	Generation int      `json:"generation,omitempty"`
	ID         int      `json:"id,omitempty"`
	Strict     string   `json:"strict,omitempty"`
	Vlans      []string `json:"vlans,omitempty"`
}

// Tunnels contains a list of tunnel objects on the BIG-IP system.
type Tunnels struct {
	Tunnels []Tunnel `json:"items"`
}

// Tunnel contains information on the tunnel.
// https://devcentral.f5.com/wiki/iControlREST.APIRef_tm_net_tunnels_tunnel.ashx
type Tunnel struct {
	Name             string `json:"name,omitempty"`
	AppService       string `json:"appService,omitempty"`
	Partition        string `json:"partition,omitempty"`
	FullPath         string `json:"fullPath,omitempty"`
	AutoLasthop      string `json:"autoLasthop,omitempty"`
	Description      string `json:"description,omitempty"`
	IdleTimeout      int    `json:"idleTimeout,omitempty"`
	IfIndex          int    `json:"ifIndex,omitempty"`
	Key              int    `json:"key,omitempty"`
	LocalAddress     string `json:"localAddress,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Mtu              int    `json:"mtu,omitempty"`
	Profile          string `json:"profile,omitempty"`
	RemoteAddress    string `json:"remoteAddress,omitempty"`
	SecondaryAddress string `json:"secondaryAddress,omitempty"`
	Tos              string `json:"tos,omitempty"`
	TrafficGroup     string `json:"trafficGroup,omitempty"`
	Transparent      string `json:"transparent,omitempty"`
	UsePmtu          string `json:"usePmtu,omitempty"`
}

type IkePeer struct {
	Name                        string   `json:"name,omitempty"`
	FullPath                    string   `json:"fullPath,omitempty"`
	AppService                  string   `json:"appService,omitempty"`
	CaCertFile                  string   `json:"caCertFile,omitempty"`
	CrlFile                     string   `json:"crlFile,omitempty"`
	DpdDelay                    int      `json:"dpdDelay,omitempty"`
	Lifetime                    int      `json:"lifetime,omitempty"`
	Description                 string   `json:"description,omitempty"`
	GeneratePolicy              string   `json:"generatePolicy,omitempty"`
	Mode                        string   `json:"mode,omitempty"`
	MyCertFile                  string   `json:"myCertFile,omitempty"`
	MyCertKeyFile               string   `json:"myCertKeyFile,omitempty"`
	MyCertKeyPassphrase         string   `json:"myCertKeyPassphrase,omitempty"`
	MyIdType                    string   `json:"myIdType,omitempty"`
	MyIdValue                   string   `json:"myIdValue,omitempty"`
	NatTraversal                string   `json:"natTraversal,omitempty"`
	Passive                     string   `json:"passive,omitempty"`
	PeersCertFile               string   `json:"peersCertFile,omitempty"`
	PeersCertType               string   `json:"peersCertType,omitempty"`
	PeersIdType                 string   `json:"peersIdType,omitempty"`
	PeersIdValue                string   `json:"peersIdValue,omitempty"`
	Phase1AuthMethod            string   `json:"phase1AuthMethod,omitempty"`
	Phase1EncryptAlgorithm      string   `json:"phase1EncryptAlgorithm,omitempty"`
	Phase1HashAlgorithm         string   `json:"phase1HashAlgorithm,omitempty"`
	Phase1PerfectForwardSecrecy string   `json:"phase1PerfectForwardSecrecy,omitempty"`
	PresharedKey                string   `json:"presharedKey,omitempty"`
	PresharedKeyEncrypted       string   `json:"presharedKeyEncrypted,omitempty"`
	Prf                         string   `json:"prf,omitempty"`
	ProxySupport                string   `json:"proxySupport,omitempty"`
	RemoteAddress               string   `json:"remoteAddress,omitempty"`
	ReplayWindowSize            int      `json:"replayWindowSize,omitempty"`
	State                       string   `json:"state,omitempty"`
	TrafficSelector             []string `json:"trafficSelector,omitempty"`
	//TrafficSelector             string   `json:"trafficSelector,omitempty"`
	VerifyCert string   `json:"verifyCert,omitempty"`
	Version    []string `json:"version,omitempty"`
}

// Vxlans contains a list of vlxan profiles on the BIG-IP system.
type Vxlans struct {
	Vxlans []Vxlan `json:"items"`
}

// Vxlan is the structure for the VXLAN profile on the bigip.
// https://devcentral.f5.com/wiki/iControlREST.APIRef_tm_net_tunnels_vxlan.ashx
type Vxlan struct {
	Name              string `json:"name,omitempty"`
	AppService        string `json:"appService,omitempty"`
	DefaultsFrom      string `json:"defaultsFrom,omitempty"`
	Description       string `json:"description,omitempty"`
	EncapsulationType string `json:"encapsulationType,omitempty"`
	FloodingType      string `json:"floodingType,omitempty"`
	Partition         string `json:"partition,omitempty"`
	Port              int    `json:"port,omitempty"`
}

// TrafficSelector is the structure used for Creating IPSec Traffic selectors
// https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_net_ipsec_traffic-selector.html
type TrafficSelector struct {
	Name                 string `json:"name,omitempty"`
	FullPath             string `json:"fullPath,omitempty"`
	Action               string `json:"action,omitempty"`
	Description          string `json:"description,omitempty"`
	DestinationAddress   string `json:"destinationAddress,omitempty"`
	DestinationPort      int    `json:"destinationPort,omitempty"`
	Direction            string `json:"direction,omitempty"`
	IPProtocol           int    `json:"ipProtocol,omitempty"`
	IpsecPolicy          string `json:"ipsecPolicy,omitempty"`
	IpsecPolicyReference struct {
		Link string `json:"link,omitempty"`
	} `json:"ipsecPolicyReference,omitempty"`
	Order         int    `json:"order,omitempty"`
	SourceAddress string `json:"sourceAddress,omitempty"`
	SourcePort    int    `json:"sourcePort,omitempty"`
}

type IPSecPolicy struct {
	Name                           string `json:"name,omitempty"`
	FullPath                       string `json:"fullPath,omitempty"`
	Description                    string `json:"description,omitempty"`
	IkePhase2AuthAlgorithm         string `json:"ikePhase2AuthAlgorithm,omitempty"`
	IkePhase2EncryptAlgorithm      string `json:"ikePhase2EncryptAlgorithm,omitempty"`
	IkePhase2Lifetime              int    `json:"ikePhase2Lifetime,omitempty"`
	IkePhase2LifetimeKilobytes     int    `json:"ikePhase2LifetimeKilobytes,omitempty"`
	IkePhase2PerfectForwardSecrecy string `json:"ikePhase2PerfectForwardSecrecy,omitempty"`
	Ipcomp                         string `json:"ipcomp,omitempty"`
	Mode                           string `json:"mode,omitempty"`
	Protocol                       string `json:"protocol,omitempty"`
	TunnelLocalAddress             string `json:"tunnelLocalAddress,omitempty"`
	TunnelRemoteAddress            string `json:"tunnelRemoteAddress,omitempty"`
}

type IPSecProfile struct {
	Name            string `json:"name,omitempty"`
	Partition       string `json:"partition,omitempty"`
	FullPath        string `json:"fullPath,omitempty"`
	DefaultsFrom    string `json:"defaultsFrom,omitempty"`
	Description     string `json:"description"`
	TrafficSelector string `json:"trafficSelector,omitempty"`
}

const (
	uriNet             = "net"
	uriInterface       = "interface"
	uriSelf            = "self"
	uriTrunk           = "trunk"
	uriTunnels         = "tunnels"
	uriTunnel          = "tunnel"
	uriVxlan           = "vxlan"
	uriVlan            = "vlan"
	uriVlanInterfaces  = "interfaces"
	uriRoute           = "route"
	uriRouteDomain     = "route-domain"
	uriIpsec           = "ipsec"
	uriTrafficselector = "traffic-selector"
	uriIpsecPolicy     = "ipsec-policy"
	uriIkePeer         = "ike-peer"
)

// formatResourceID takes the resource name to
// ensure theres a partition for the Resource ID
func formatResourceID(name string) string {
	// If the name specifies the partition already, then
	// just hand it back.
	regex := regexp.MustCompile(`^~([a-zA-Z0-9-.]+)~`)
	if regex.MatchString(name) {
		return name
	}

	// Otherwise, tack on the Common partition
	// for best practices with the resource_id.
	return "~Common~" + name
}

// Interfaces returns a list of interfaces.
func (b *BigIP) Interfaces() (*Interfaces, error) {
	var interfaces Interfaces
	err, _ := b.getForEntity(&interfaces, uriNet, uriInterface)

	if err != nil {
		return nil, err
	}

	return &interfaces, nil
}

// AddInterfaceToVlan associates the given interface to the specified VLAN.
func (b *BigIP) AddInterfaceToVlan(vlan, iface string, tagged bool) error {
	config := &VlanInterface{}

	config.Name = iface
	if tagged {
		config.Tagged = true
	} else {
		config.Untagged = true
	}

	return b.post(config, uriNet, uriVlan, vlan, uriVlanInterfaces)
}

// GetVlanInterfaces returns a list of interface associated to the specified VLAN.
func (b *BigIP) GetVlanInterfaces(vlan string) (*VlanInterfaces, error) {
	var vlanInterfaces VlanInterfaces
	err, _ := b.getForEntity(&vlanInterfaces, uriNet, uriVlan, vlan, uriVlanInterfaces)
	if err != nil {
		return nil, err
	}

	return &vlanInterfaces, nil
}

// SelfIPs returns a list of self IP's.
func (b *BigIP) SelfIPs() (*SelfIPs, error) {
	var self SelfIPs
	err, _ := b.getForEntity(&self, uriNet, uriSelf)
	if err != nil {
		return nil, err
	}

	return &self, nil
}

// SelfIP returns a named Self IP.
func (b *BigIP) SelfIP(selfip string) (*SelfIP, error) {
	var self SelfIP
	err, _ := b.getForEntity(&self, uriNet, uriSelf, selfip)
	if err != nil {
		return nil, err
	}

	return &self, nil
}

// CreateSelfIP adds a new self IP to the BIG-IP system. For <address>, you
// must include the subnet mask in CIDR notation, i.e.: "10.1.1.1/24".
func (b *BigIP) CreateSelfIP(config *SelfIP) error {
	return b.post(config, uriNet, uriSelf)
}

// DeleteSelfIP removes a self IP.
func (b *BigIP) DeleteSelfIP(name string) error {
	return b.delete(uriNet, uriSelf, name)
}

// ModifySelfIP allows you to change any attribute of a self IP. Fields that
// can be modified are referenced in the SelfIP struct.
func (b *BigIP) ModifySelfIP(name string, config *SelfIP) error {
	return b.put(config, uriNet, uriSelf, name)
}

// Trunks returns a list of trunks.
func (b *BigIP) Trunks() (*Trunks, error) {
	var trunks Trunks
	err, _ := b.getForEntity(&trunks, uriNet, uriTrunk)
	if err != nil {
		return nil, err
	}

	return &trunks, nil
}

// CreateTrunk adds a new trunk to the BIG-IP system. <interfaces> must be
// separated by a comma, i.e.: "1.4, 1.6, 1.8".
func (b *BigIP) CreateTrunk(name, interfaces string, lacp bool) error {
	rawInts := strings.Split(interfaces, ",")
	ints := []string{}

	for _, i := range rawInts {
		ints = append(ints, strings.Trim(i, " "))
	}

	config := &Trunk{
		Name:       name,
		Interfaces: ints,
	}

	if lacp {
		config.LACP = "enabled"
	}

	return b.post(config, uriNet, uriTrunk)
}

// DeleteTrunk removes a trunk.
func (b *BigIP) DeleteTrunk(name string) error {
	return b.delete(uriNet, uriTrunk, name)
}

// ModifyTrunk allows you to change any attribute of a trunk. Fields that
// can be modified are referenced in the Trunk struct.
func (b *BigIP) ModifyTrunk(name string, config *Trunk) error {
	return b.put(config, uriNet, uriTrunk, name)
}

// Vlans returns a list of vlans.
func (b *BigIP) Vlans() (*Vlans, error) {
	var vlans Vlans
	err, _ := b.getForEntity(&vlans, uriNet, uriVlan)

	if err != nil {
		return nil, err
	}

	return &vlans, nil
}

// Vlan returns a named vlan.
func (b *BigIP) Vlan(name string) (*Vlan, error) {
	var vlan Vlan
	err, _ := b.getForEntity(&vlan, uriNet, uriVlan, name)

	if err != nil {
		return nil, err
	}

	return &vlan, nil
}

//// CreateVlan adds a new VLAN to the BIG-IP system.
//func (b *BigIP) CreateVlan(name string, tag int) error {
//	config := &Vlan{
//		Name: name,
//		Tag:  tag,
//	}
//	return b.post(config, uriNet, uriVlan)
//}

// CreateVlan adds a new VLAN to the BIG-IP system.
func (b *BigIP) CreateVlan(config *Vlan) error {
	return b.post(config, uriNet, uriVlan)
}

// DeleteVlan removes a vlan.
func (b *BigIP) DeleteVlan(name string) error {
	return b.delete(uriNet, uriVlan, name)
}

// ModifyVlan allows you to change any attribute of a VLAN. Fields that
// can be modified are referenced in the Vlan struct.
func (b *BigIP) ModifyVlan(name string, config *Vlan) error {
	return b.put(config, uriNet, uriVlan, name)
}

// Routes returns a list of routes.
func (b *BigIP) Routes() (*Routes, error) {
	var routes Routes
	err, _ := b.getForEntity(&routes, uriNet, uriRoute)

	if err != nil {
		return nil, err
	}

	return &routes, nil
}

func (b *BigIP) GetRoute(name string) (*Route, error) {
	var route Route
	//values := []string{}
	//regex := regexp.MustCompile(`^(\/.+\/)?(.+)`)
	//match := regex.FindStringSubmatch(name)
	//log.Printf("[DEBUG] match :%+v", match)
	//if match[1] == "" {
	//      values = append(values, "~Common~")
	//}
	//values = append(values, name)
	//// Join the strings into one.
	//result := strings.Join(values, "")
	//log.Printf("[DEBUG] Route :%+v", result)
	//log.Printf("[DEBUG] Name :%+v", name)

	err, ok := b.getForEntity(&route, uriNet, uriRoute, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &route, nil
}

// CreateRoute adds a new static route to the BIG-IP system. <dest> must include the
// subnet mask in CIDR notation, i.e.: "10.1.1.0/24".
func (b *BigIP) CreateRoute(config *Route) error {
	return b.post(config, uriNet, uriRoute)
}

// DeleteRoute removes a static route.
func (b *BigIP) DeleteRoute(name string) error {
	return b.delete(uriNet, uriRoute, name)
}

// ModifyRoute allows you to change any attribute of a static route. Fields that
// can be modified are referenced in the Route struct.
func (b *BigIP) ModifyRoute(name string, config *Route) error {
	return b.put(config, uriNet, uriRoute, name)
}

// RouteDomains returns a list of route domains.
func (b *BigIP) RouteDomains() (*RouteDomains, error) {
	var rd RouteDomains
	err, _ := b.getForEntity(&rd, uriNet, uriRouteDomain)

	if err != nil {
		return nil, err
	}

	return &rd, nil
}

// CreateRouteDomain adds a new route domain to the BIG-IP system. <vlans> must be separated
// by a comma, i.e.: "vlan1010, vlan1020".
func (b *BigIP) CreateRouteDomain(name string, id int, strict bool, vlans string) error {
	strictIsolation := "enabled"
	vlanMembers := []string{}
	rawVlans := strings.Split(vlans, ",")

	for _, v := range rawVlans {
		vlanMembers = append(vlanMembers, strings.Trim(v, " "))
	}

	if !strict {
		strictIsolation = "disabled"
	}

	config := &RouteDomain{
		Name:   name,
		ID:     id,
		Strict: strictIsolation,
		Vlans:  vlanMembers,
	}

	return b.post(config, uriNet, uriRouteDomain)
}

// DeleteRouteDomain removes a route domain.
func (b *BigIP) DeleteRouteDomain(name string) error {
	return b.delete(uriNet, uriRouteDomain, name)
}

// ModifyRouteDomain allows you to change any attribute of a route domain. Fields that
// can be modified are referenced in the RouteDomain struct.
func (b *BigIP) ModifyRouteDomain(name string, config *RouteDomain) error {
	return b.put(config, uriNet, uriRouteDomain, name)
}

// Tunnels returns a list of tunnels.
func (b *BigIP) Tunnels() (*Tunnels, error) {
	var tunnels Tunnels
	err, _ := b.getForEntity(&tunnels, uriNet, uriTunnels, uriTunnel)
	if err != nil {
		return nil, err
	}

	return &tunnels, nil
}

// GetTunnel fetches the tunnel by it's name.
func (b *BigIP) GetTunnel(name string) (*Tunnel, error) {
	var tunnel Tunnel
	//result := formatResourceID(name)
	err, ok := b.getForEntity(&tunnel, uriNet, uriTunnels, uriTunnel, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &tunnel, nil
}

// AddTunnel adds a new tunnel to the BIG-IP system from a config.
func (b *BigIP) AddTunnel(config *Tunnel) error {
	return b.post(config, uriNet, uriTunnels, uriTunnel)
}

// CreateTunnel adds a new tunnel to the BIG-IP system.
func (b *BigIP) CreateTunnel(config *Tunnel) error {
	/*config := &Tunnel{
		Name:    name,
		Profile: profile,
	}*/

	return b.post(config, uriNet, uriTunnels, uriTunnel)
}

// DeleteTunnel removes a tunnel.
func (b *BigIP) DeleteTunnel(name string) error {
	return b.delete(uriNet, uriTunnels, uriTunnel, name)
}

// ModifyTunnel allows you to change any attribute of a tunnel.
func (b *BigIP) ModifyTunnel(name string, config *Tunnel) error {
	return b.put(config, uriNet, uriTunnels, uriTunnel, name)
}

func (b *BigIP) GetIkePeer(name string) (*IkePeer, error) {
	var ikepeer IkePeer
	//result := formatResourceID(name)
	//log.Printf("[DEBUG] Reading IKE Peer:%+v", name)
	//log.Printf("[DEBUG] Reading IKE Peer from result:%+v",result)
	err, ok := b.getForEntity(&ikepeer, uriNet, uriIpsec, uriIkePeer, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return &ikepeer, nil
}

func (b *BigIP) CreateIkePeer(config *IkePeer) error {
	return b.post(config, uriNet, uriIpsec, uriIkePeer)
}
func (b *BigIP) DeleteIkePeer(name string) error {
	return b.delete(uriNet, uriIpsec, uriIkePeer, name)
}
func (b *BigIP) ModifyIkePeer(name string, config *IkePeer) error {
	return b.patch(config, uriNet, uriIpsec, uriIkePeer, name)
}

// Vxlans returns a list of vxlan profiles.
func (b *BigIP) Vxlans() ([]Vxlan, error) {
	var vxlans Vxlans
	err, _ := b.getForEntity(&vxlans, uriNet, uriTunnels, uriVxlan)
	if err != nil {
		return nil, err
	}

	return vxlans.Vxlans, nil
}

// GetVxlan fetches the vxlan profile by it's name.
func (b *BigIP) GetVxlan(name string) (*Vxlan, error) {
	var vxlan Vxlan
	result := formatResourceID(name)
	err, ok := b.getForEntity(&vxlan, uriNet, uriTunnels, uriVxlan, result)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &vxlan, nil
}

// AddVxlan adds a new vxlan profile to the BIG-IP system.
func (b *BigIP) AddVxlan(config *Vxlan) error {
	return b.post(config, uriNet, uriTunnels, uriVxlan)
}

// CreateVxlan adds a new vxlan profile to the BIG-IP system.
func (b *BigIP) CreateVxlan(name string) error {
	config := &Vxlan{
		Name: name,
	}

	return b.post(config, uriNet, uriTunnels, uriVxlan)
}

// DeleteVxlan removes a vxlan profile.
func (b *BigIP) DeleteVxlan(name string) error {
	return b.delete(uriNet, uriTunnels, uriVxlan, name)
}

// ModifyVxlan allows you to change any attribute of a vxlan profile.
func (b *BigIP) ModifyVxlan(name string, config *Vxlan) error {
	return b.put(config, uriNet, uriTunnels, uriVxlan, name)
}

// CreateTrafficSelector adds a new IPsec Traffic-selctor to the BIG-IP system.
func (b *BigIP) CreateTrafficSelector(config *TrafficSelector) error {
	return b.post(config, uriNet, uriIpsec, uriTrafficselector)
}

// ModifyTrafficSelector allows you to change any attribute of a Traffic-selector.
// Fields that can be modified are referenced in the TrafficSelector struct.
func (b *BigIP) ModifyTrafficSelector(name string, config *TrafficSelector) error {
	return b.patch(config, uriNet, uriIpsec, uriTrafficselector, name)
}

// DeleteTrafficSelector removes specified Traffic-selector.
func (b *BigIP) DeleteTrafficSelector(name string) error {
	return b.delete(uriNet, uriIpsec, uriTrafficselector, name)
}

// GetTrafficselctor returns a named IPsec Traffic selctor.
func (b *BigIP) GetTrafficselctor(name string) (*TrafficSelector, error) {
	var ts TrafficSelector
	err, _ := b.getForEntity(&ts, uriNet, uriIpsec, uriTrafficselector, name)

	if err != nil {
		return nil, err
	}

	return &ts, nil
}

// CreateIPSecPolicy adds a new IPSec policy to the BIG-IP system.
func (b *BigIP) CreateIPSecPolicy(config *IPSecPolicy) error {
	return b.post(config, uriNet, uriIpsec, uriIpsecPolicy)
}

// ModifyIPSecPolicy allows you to change any attribute of a IPSec policy.
// Fields that can be modified are referenced in the IPSec policy struct.
func (b *BigIP) ModifyIPSecPolicy(name string, config *IPSecPolicy) error {
	return b.patch(config, uriNet, uriIpsec, uriIpsecPolicy, name)
}

// DeleteIPSecPolicy removes specified IPSec policy.
func (b *BigIP) DeleteIPSecPolicy(name string) error {
	return b.delete(uriNet, uriIpsec, uriIpsecPolicy, name)
}

// GetIPSecPolicy returns a named IPsec policy.
func (b *BigIP) GetIPSecPolicy(name string) (*IPSecPolicy, error) {
	var ipsec IPSecPolicy
	err, _ := b.getForEntity(&ipsec, uriNet, uriIpsec, uriIpsecPolicy, name)

	if err != nil {
		return nil, err
	}

	return &ipsec, nil
}

// CreateIPSecProfile adds a new IPSec profile to the BIG-IP system.
func (b *BigIP) CreateIPSecProfile(config *IPSecProfile) error {
	return b.post(config, uriNet, uriTunnels, uriIpsec)
}

// ModifyIPSecProfile allows you to change any attribute of a IPSec profile.
// Fields that can be modified are referenced in the IPSec profile struct.
func (b *BigIP) ModifyIPSecProfile(name string, config *IPSecProfile) error {
	return b.patch(config, uriNet, uriTunnels, uriIpsec, name)
}

// DeleteIPSecProfile removes specified IPSec profile.
func (b *BigIP) DeleteIPSecProfile(name string) error {
	return b.delete(uriNet, uriTunnels, uriIpsec, name)
}

// GetIPSecProfile returns a named IPsec profile.
func (b *BigIP) GetIPSecProfile(name string) (*IPSecProfile, error) {
	var ipsec IPSecProfile
	err, _ := b.getForEntity(&ipsec, uriNet, uriTunnels, uriIpsec, name)

	if err != nil {
		return nil, err
	}

	return &ipsec, nil
}
