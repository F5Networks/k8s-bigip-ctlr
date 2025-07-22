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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	//"strings"
	"time"
)

type Version struct {
	Kind     string `json:"kind,omitempty"`
	SelfLink string `json:"selfLink,omitempty"`
	Entries  struct {
		HTTPSLocalhostMgmtTmCliVersion0 struct {
			NestedStats struct {
				Entries struct {
					Active struct {
						Description string `json:"description"`
					} `json:"active,omitempty"`
					Latest struct {
						Description string `json:"description"`
					} `json:"latest,omitempty"`
					Supported struct {
						Description string `json:"description"`
					} `json:"supported,omitempty"`
				} `json:"entries,omitempty"`
			} `json:"nestedStats,omitempty"`
		} `json:"https://localhost/mgmt/tm/cli/version/0,omitempty"`
	} `json:"entries,omitempty"`
}

type NTPs struct {
	NTPs []NTP `json:"items"`
}

type NTP struct {
	Description string   `json:"description"`
	Servers     []string `json:"servers"`
	Timezone    string   `json:"timezone,omitempty"`
}

type BigipCommand struct {
	Command       string `json:"command"`
	UtilCmdArgs   string `json:"utilCmdArgs"`
	CommandResult string `json:"commandResult,omitempty"`
}

type BigipCmdResp struct {
	Code       int           `json:"code"`
	Message    string        `json:"message"`
	ErrorStack []interface{} `json:"errorStack"`
	APIError   int           `json:"apiError"`
}

type DNSs struct {
	DNSs []DNS `json:"items"`
}

type DNS struct {
	Description  string   `json:"description"`
	NameServers  []string `json:"nameServers,"`
	NumberOfDots int      `json:"numberOfDots,omitempty"`
	Search       []string `json:"search"`
}

type Provisions struct {
	Provisions []Provision `json:"items"`
}

type Provision struct {
	Name        string `json:"name,omitempty"`
	FullPath    string `json:"fullPath,omitempty"`
	CpuRatio    int    `json:"cpuRatio,omitempty"`
	DiskRatio   int    `json:"diskRatio,omitempty"`
	Level       string `json:"level,omitempty"`
	MemoryRatio int    `json:"memoryRatio,omitempty"`
}

type Syslogs struct {
	Syslogs []Syslog `json:"items"`
}

type Syslog struct {
	AuthPrivFrom  string
	RemoteServers []RemoteServer
}

type syslogDTO struct {
	AuthPrivFrom  string `json:"authPrivFrom,omitempty"`
	RemoteServers struct {
		Items []RemoteServer `json:"items,omitempty"`
	} `json:"remoteServers,omitempty"`
}

func (p *Syslog) MarshalJSON() ([]byte, error) {
	var dto syslogDTO
	return json.Marshal(dto)
}

func (p *Syslog) UnmarshalJSON(b []byte) error {
	var dto syslogDTO
	err := json.Unmarshal(b, &dto)
	if err != nil {
		return err
	}

	p.AuthPrivFrom = dto.AuthPrivFrom
	p.RemoteServers = dto.RemoteServers.Items

	return nil
}

type RemoteServer struct {
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	RemotePort int    `json:"remotePort,omitempty"`
}

type remoteServerDTO struct {
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	RemotePort int    `json:"remotePort,omitempty"`
}

func (p *RemoteServer) MarshalJSON() ([]byte, error) {
	return json.Marshal(remoteServerDTO{
		Name:       p.Name,
		Host:       p.Host,
		RemotePort: p.RemotePort,
	})
}

func (p *RemoteServer) UnmarshalJSON(b []byte) error {
	var dto remoteServerDTO
	err := json.Unmarshal(b, &dto)
	if err != nil {
		return err
	}

	p.Name = dto.Name
	p.Host = dto.Host
	p.RemotePort = dto.RemotePort

	return nil
}

type SNMPs struct {
	SNMPs []SNMP `json:"items"`
}

type SNMP struct {
	SysContact       string   `json:"sysContact,omitempty"`
	SysLocation      string   `json:"sysLocation,omitempty"`
	AllowedAddresses []string `json:"allowedAddresses,omitempty"`
}

type TRAPs struct {
	SNMPs []SNMP `json:"items"`
}

type TRAP struct {
	Name                     string `json:"name,omitempty"`
	AuthPasswordEncrypted    string `json:"authPasswordEncrypted,omitempty"`
	AuthProtocol             string `json:"authProtocol,omitempty"`
	Community                string `json:"community,omitempty"`
	Description              string `json:"description,omitempty"`
	EngineId                 string `json:"engineId,omitempty"`
	Host                     string `json:"host,omitempty"`
	Port                     int    `json:"port,omitempty"`
	PrivacyPassword          string `json:"privacyPassword,omitempty"`
	PrivacyPasswordEncrypted string `json:"privacyPasswordEncrypted,omitempty"`
	PrivacyProtocol          string `json:"privacyProtocol,omitempty"`
	SecurityLevel            string `json:"securityLevel,omitempty"`
	SecurityName             string `json:"SecurityName,omitempty"`
	Version                  string `json:"version,omitempty"`
}

type Bigiplicenses struct {
	Bigiplicenses []Bigiplicense `json:"items"`
}

type Bigiplicense struct {
	Registration_key string `json:"registrationKey,omitempty"`
	Command          string `json:"command,omitempty"`
}

type LogIPFIXs struct {
	LogIPFIXs []LogIPFIX `json:"items"`
}
type LogIPFIX struct {
	AppService                 string `json:"appService,omitempty"`
	Name                       string `json:"name,omitempty"`
	PoolName                   string `json:"poolName,omitempty"`
	ProtocolVersion            string `json:"protocolVersion,omitempty"`
	ServersslProfile           string `json:"serversslProfile,omitempty"`
	TemplateDeleteDelay        int    `json:"templateDeleteDelay,omitempty"`
	TemplateRetransmitInterval int    `json:"templateRetransmitInterval,omitempty"`
	TransportProfile           string `json:"transportProfile,omitempty"`
}
type LogPublishers struct {
	LogPublishers []LogPublisher `json:"items"`
}
type LogPublisher struct {
	Name  string `json:"name,omitempty"`
	Dests []Destinations
}

type Destinations struct {
	Name      string `json:"name,omitempty"`
	Partition string `json:"partition,omitempty"`
}

type destinationsDTO struct {
	Name      string `json:"name,omitempty"`
	Partition string `json:"partition,omitempty"`
	Dests     struct {
		Items []Destinations `json:"items,omitempty"`
	} `json:"destinationsReference,omitempty"`
}

type ExternalDGFile struct {
	Name       string `json:"name"`
	Partition  string `json:"partition"`
	SourcePath string `json:"sourcePath"`
	Type       string `json:"type"`
}

type OCSP struct {
	Name                       string `json:"name,omitempty"`
	FullPath                   string `json:"fullPath,omitempty"`
	Partition                  string `json:"partition,omitempty"`
	ProxyServerPool            string `json:"proxyServerPool,omitempty"`
	DnsResolver                string `json:"dnsResolver,omitempty"`
	RouteDomain                string `json:"routeDomain,omitempty"`
	ConcurrentConnectionsLimit int64  `json:"concurrentConnectionsLimit,omitempty"`
	ResponderUrl               string `json:"responderUrl,omitempty"`
	ConnectionTimeout          int64  `json:"timeout,omitempty"`
	TrustedResponders          string `json:"trustedResponders,omitempty"`
	ClockSkew                  int64  `json:"clockSkew,omitempty"`
	StatusAge                  int64  `json:"statusAge,omitempty"`
	StrictRespCertCheck        string `json:"strictRespCertCheck,omitempty"`
	CacheTimeout               string `json:"cacheTimeout,omitempty"`
	CacheErrorTimeout          int64  `json:"cacheErrorTimeout,omitempty"`
	SignerCert                 string `json:"signerCert,omitempty"`
	SignerKey                  string `json:"signerKey,omitempty"`
	Passphrase                 string `json:"passphrase,omitempty"`
	SignHash                   string `json:"signHash,omitempty"`
}

func (p *LogPublisher) MarshalJSON() ([]byte, error) {
	return json.Marshal(destinationsDTO{
		Name: p.Name,
		Dests: struct {
			Items []Destinations `json:"items,omitempty"`
		}{Items: p.Dests},
	})
}

func (p *LogPublisher) UnmarshalJSON(b []byte) error {
	var dto destinationsDTO
	err := json.Unmarshal(b, &dto)
	if err != nil {
		return err
	}

	p.Name = dto.Name
	p.Dests = dto.Dests.Items
	return nil
}

const (
	uriSys             = "sys"
	uriTm              = "tm"
	uriCli             = "cli"
	uriUtil            = "util"
	uriBash            = "bash"
	uriVersion         = "version"
	uriNtp             = "ntp"
	uriDNS             = "dns"
	uriProvision       = "provision"
	uriAfm             = "afm"
	uriAsm             = "asm"
	uriApm             = "apm"
	uriAvr             = "avr"
	uriAuth            = "auth"
	uriPartition       = "partition"
	uriRemoteRole      = "remote-role"
	uriRoleInfo        = "role-info"
	uriFolder          = "folder"
	uriIlx             = "ilx"
	uriSyslog          = "syslog"
	uriSnmp            = "snmp"
	uriTraps           = "traps"
	uriLicense         = "license"
	uriLogConfig       = "logConfig"
	uriDestination     = "destination"
	uriIPFIX           = "ipfix"
	uriPublisher       = "publisher"
	uriFile            = "file"
	uriSslCert         = "ssl-cert"
	uriSslKey          = "ssl-key"
	uriDataGroup       = "data-group"
	uriTransaction     = "transaction"
	REST_DOWNLOAD_PATH = "/var/config/rest/downloads"
)

// Certificates represents a list of installed SSL certificates.
type Certificates struct {
	Certificates []Certificate `json:"items,omitempty"`
}

// Certificate represents an SSL Certificate.
type Certificate struct {
	AppService              string                  `json:"appService,omitempty"`
	CachePath               string                  `json:"cachePath,omitempty"`
	CertificateKeyCurveName string                  `json:"certificateKeyCurveName,omitempty"`
	CertificateKeySize      int                     `json:"certificateKeySize,omitempty"`
	CertValidationOptions   []string                `json:"certValidationOptions,omitempty"`
	Checksum                string                  `json:"checksum,omitempty"`
	CreatedBy               string                  `json:"createdBy,omitempty"`
	CreateTime              string                  `json:"createTime,omitempty"`
	Email                   string                  `json:"email,omitempty"`
	ExpirationDate          int64                   `json:"expirationDate,omitempty"`
	ExpirationString        string                  `json:"expirationString,omitempty"`
	Fingerprint             string                  `json:"fingerprint,omitempty"`
	FullPath                string                  `json:"fullPath,omitempty"`
	Generation              int                     `json:"generation,omitempty"`
	IsBundle                string                  `json:"isBundle,omitempty"`
	IsDynamic               string                  `json:"isDynamic,omitempty"`
	Issuer                  string                  `json:"issuer,omitempty"`
	IssuerCert              string                  `json:"issuerCert,omitempty"`
	KeyType                 string                  `json:"keyType,omitempty"`
	LastUpdateTime          string                  `json:"lastUpdateTime,omitempty"`
	Mode                    int                     `json:"mode,omitempty"`
	Name                    string                  `json:"name,omitempty"`
	Partition               string                  `json:"partition,omitempty"`
	Revision                int                     `json:"revision,omitempty"`
	SerialNumber            string                  `json:"serialNumber,omitempty"`
	Size                    uint64                  `json:"size,omitempty"`
	SourcePath              string                  `json:"sourcePath,omitempty"`
	Subject                 string                  `json:"subject,omitempty"`
	SubjectAlternativeName  string                  `json:"subjectAlternativeName,omitempty"`
	SystemPath              string                  `json:"systemPath,omitempty"`
	UpdatedBy               string                  `json:"updatedBy,omitempty"`
	Version                 int                     `json:"version,omitempty"`
	CertValidatorRef        *CertValidatorReference `json:"certValidatorsReference,omitempty"`
}

type CertValidatorReference struct {
	Items []CertValidatorState `json:"items,omitempty"`
}

type CertValidatorState struct {
	Name      string `json:"name,omitempty"`
	Partition string `json:"partition,omitempty"`
	FullPath  string `json:"fullPath,omitempty"`
}

// Keys represents a list of installed keys.
type Keys struct {
	Keys []Key `json:"items,omitempty"`
}

// Key represents a private key associated with a certificate.
type Key struct {
	AppService     string `json:"appService,omitempty"`
	CachePath      string `json:"cachePath,omitempty"`
	Checksum       string `json:"checksum,omitempty"`
	CreatedBy      string `json:"createdBy,omitempty"`
	CreateTime     string `json:"createTime,omitempty"`
	CurveName      string `json:"curveName,omitempty"`
	FullPath       string `json:"fullPath,omitempty"`
	Generation     int    `json:"generation,omitempty"`
	IsDynamic      string `json:"isDynamic,omitempty"`
	KeySize        int    `json:"keySize,omitempty"`
	KeyType        string `json:"keyType,omitempty"`
	LastUpdateTime string `json:"lastUpdateTime,omitempty"`
	Mode           int    `json:"mode,omitempty"`
	Name           string `json:"name,omitempty"`
	Partition      string `json:"partition,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
	Revision       int    `json:"revision,omitempty"`
	SecurityType   string `json:"securityType,omitempty"`
	Size           uint64 `json:"size,omitempty"`
	SourcePath     string `json:"sourcePath,omitempty"`
	SystemPath     string `json:"systemPath,omitempty"`
	UpdatedBy      string `json:"updatedBy,omitempty"`
}

type Transaction struct {
	TransID          int64  `json:"transId,omitempty"`
	State            string `json:"state,omitempty"`
	TimeoutSeconds   int64  `json:"timeoutSeconds,omitempty"`
	AsyncExecution   bool   `json:"asyncExecution,omitempty"`
	ValidateOnly     bool   `json:"validateOnly,omitempty"`
	ExecutionTimeout int64  `json:"executionTimeout,omitempty"`
	ExecutionTime    int64  `json:"executionTime,omitempty"`
	FailureReason    string `json:"failureReason,omitempty"`
}

type Partition struct {
	Name        string `json:"name,omitempty"`
	RouteDomain int    `json:"defaultRouteDomain"`
	Description string `json:"description,omitempty"`
}

type RoleInfo struct {
	Name          string `json:"name,omitempty"`
	Attribute     string `json:"attribute"`
	Console       string `json:"console,omitempty"`
	Deny          string `json:"deny,omitempty"`
	Description   string `json:"description,omitempty"`
	LineOrder     int    `json:"lineOrder"`
	Role          string `json:"role,omitempty"`
	UserPartition string `json:"userPartition,omitempty"`
}

// Certificates returns a list of certificates.
func (b *BigIP) Certificates() (*Certificates, error) {
	var certs Certificates
	err, _ := b.getForEntity(&certs, uriSys, uriFile, uriSslCert)
	if err != nil {
		return nil, err
	}

	return &certs, nil
}

// AddCertificate installs a certificate.
func (b *BigIP) AddCertificate(cert *Certificate) error {
	return b.post(cert, uriSys, uriFile, uriSslCert)
}

// AddExternalDatagroupfile adds datagroup file
func (b *BigIP) AddExternalDatagroupfile(dataGroup *ExternalDGFile) error {
	return b.post(dataGroup, uriSys, uriFile, uriDataGroup)
}

// DeleteExternalDatagroupfile removes a Datagroup file.
func (b *BigIP) DeleteExternalDatagroupfile(name string) error {
	return b.delete(uriSys, uriFile, uriDataGroup, name)
}

// ModifyExternalDatagroupfile modify datagroup file
func (b *BigIP) ModifyExternalDatagroupfile(dgName string, dataGroup *ExternalDGFile) error {
	return b.patch(dataGroup, uriSys, uriFile, uriDataGroup, dgName)
}

// ModifyCertificate installs a certificate.
func (b *BigIP) ModifyCertificate(certName string, cert *Certificate) error {
	return b.patch(cert, uriSys, uriFile, uriSslCert, certName, "?expandSubcollections=true")
}

// UploadCertificate copies a certificate local disk to BIGIP
func (b *BigIP) UploadCertificate(certpath string, cert *Certificate) error {
	certbyte := []byte(certpath)
	_, err := b.UploadBytes(certbyte, cert.Name)
	if err != nil {
		return err
	}
	sourcepath := "file://" + REST_DOWNLOAD_PATH + "/" + cert.Name
	log.Printf("[DEBUG] sourcepath :%+v", sourcepath)

	cert.SourcePath = sourcepath
	log.Printf("cert: %+v\n", cert)
	err = b.AddCertificate(cert)
	if err != nil {
		return err
	}
	return nil
}

// GetCertificate retrieves a Certificate by name. Returns nil if the certificate does not exist
func (b *BigIP) GetCertificate(name string) (*Certificate, error) {
	var cert Certificate
	err, ok := b.getForEntity(&cert, uriSys, uriFile, uriSslCert, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &cert, nil
}

// DeleteCertificate removes a certificate.
func (b *BigIP) DeleteCertificate(name string) error {
	return b.delete(uriSys, uriFile, uriSslCert, name)
}

// UpdateCertificate copies a certificate local disk to BIGIP
func (b *BigIP) UpdateCertificate(certpath string, cert *Certificate) error {
	certbyte := []byte(certpath)
	_, err := b.UploadBytes(certbyte, cert.Name)
	if err != nil {
		return err
	}
	sourcepath := "file://" + REST_DOWNLOAD_PATH + "/" + cert.Name

	cert.SourcePath = sourcepath
	certName := fmt.Sprintf("/%s/%s", cert.Partition, cert.Name)
	log.Printf("certName: %+v\n", certName)
	err = b.ModifyCertificate(certName, cert)
	if err != nil {
		return err
	}
	return nil
}

// UploadKey copies a certificate key from local disk to BIGIP
func (b *BigIP) UploadKey(keyname, keypath string) (string, error) {
	keybyte := []byte(keypath)
	_, err := b.UploadBytes(keybyte, keyname)
	if err != nil {
		return "", err
	}
	sourcepath := "file://" + REST_DOWNLOAD_PATH + "/" + keyname
	log.Println("[DEBUG] string:", sourcepath)
	return sourcepath, nil
}

// UpdateKey copies a certificate key from local disk to BIGIP
func (b *BigIP) UpdateKey(keyname, keypath, partition string) error {
	keybyte := []byte(keypath)
	_, err := b.UploadBytes(keybyte, keyname)
	if err != nil {
		return err
	}
	sourcepath := "file://" + REST_DOWNLOAD_PATH + "/" + keyname
	log.Println("[DEBUG]string:", sourcepath)
	certkey := Key{
		Name:       keyname,
		SourcePath: sourcepath,
		Partition:  partition,
	}
	keyName := fmt.Sprintf("/%s/%s", partition, keyname)
	log.Printf("[DEBUG]keyName: %+v\n", keyName)
	err = b.ModifyKey(keyName, &certkey)
	if err != nil {
		return err
	}
	return nil
}

// Keys returns a list of keys.
func (b *BigIP) Keys() (*Keys, error) {
	var keys Keys
	err, _ := b.getForEntity(&keys, uriSys, uriFile, uriSslKey)
	if err != nil {
		return nil, err
	}

	return &keys, nil
}

// AddKey installs a key.
func (b *BigIP) AddKey(config *Key) error {
	return b.post(config, uriSys, uriFile, uriSslKey)
}

// ModifyKey Updates a key.
func (b *BigIP) ModifyKey(keyName string, config *Key) error {
	return b.patch(config, uriSys, uriFile, uriSslKey, keyName)
}

// GetKey retrieves a key by name. Returns nil if the key does not exist.
func (b *BigIP) GetKey(name string) (*Key, error) {
	var key Key
	err, ok := b.getForEntity(&key, uriSys, uriFile, uriSslKey, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &key, nil
}

// DeleteKey removes a key.
func (b *BigIP) DeleteKey(name string) error {
	return b.delete(uriSys, uriFile, uriSslKey, name)
}

func (b *BigIP) CreateNTP(description string, servers []string, timezone string) error {
	config := &NTP{
		Description: description,
		Servers:     servers,
		Timezone:    timezone,
	}

	return b.patch(config, uriSys, uriNtp)
}

func (b *BigIP) ModifyNTP(config *NTP) error {
	return b.patch(config, uriSys, uriNtp)
}

func (b *BigIP) NTPs() (*NTP, error) {
	var ntp NTP
	err, _ := b.getForEntity(&ntp, uriSys, uriNtp)

	if err != nil {
		return nil, err
	}
	return &ntp, nil
}

func (b *BigIP) BigipVersion() (*Version, error) {
	var bigipversion Version
	err, _ := b.getForEntity(&bigipversion, uriMgmt, uriTm, uriCli, uriVersion)

	if err != nil {
		return nil, err
	}
	return &bigipversion, nil
}

func (b *BigIP) RunCommand(config *BigipCommand) (*BigipCommand, error) {
	var respRef BigipCommand
	resp, err := b.postReq(config, uriMgmt, uriTm, uriUtil, uriBash)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(resp, &respRef)
	return &respRef, nil
}

func (b *BigIP) CreateDNS(description string, nameservers []string, numberofdots int, search []string) error {
	config := &DNS{
		Description:  description,
		NameServers:  nameservers,
		NumberOfDots: numberofdots,
		Search:       search,
	}
	return b.patch(config, uriSys, uriDNS)
}

func (b *BigIP) ModifyDNS(config *DNS) error {
	return b.patch(config, uriSys, uriDNS)
}

// DNS & NTP resource does not support Delete API
func (b *BigIP) DNSs() (*DNS, error) {
	var dns DNS
	err, _ := b.getForEntity(&dns, uriSys, uriDNS)

	if err != nil {
		return nil, err
	}

	return &dns, nil
}

func (b *BigIP) CreateProvision(name string, fullPath string, cpuRatio int, diskRatio int, level string, memoryRatio int) error {
	config := &Provision{
		Name:        name,
		FullPath:    fullPath,
		CpuRatio:    cpuRatio,
		DiskRatio:   diskRatio,
		Level:       level,
		MemoryRatio: memoryRatio,
	}
	if name == "asm" {
		return b.put(config, uriSys, uriProvision, uriAsm)
	}
	if name == "afm" {
		return b.put(config, uriSys, uriProvision, uriAfm)

	}
	if name == "gtm" {
		return b.put(config, uriSys, uriProvision, uriGtm)
	}

	if name == "apm" {
		return b.put(config, uriSys, uriProvision, uriApm)
	}

	if name == "avr" {
		return b.put(config, uriSys, uriProvision, uriAvr)
	}
	if name == "ilx" {
		return b.put(config, uriSys, uriProvision, uriIlx)
	}
	return nil
}

func (b *BigIP) ProvisionModule(config *Provision) error {
	log.Printf(" Module Provision:%v", config)
	if config.Name == "asm" {
		return b.put(config, uriSys, uriProvision, uriAsm)
	}
	if config.Name == "afm" {
		return b.put(config, uriSys, uriProvision, uriAfm)
	}
	if config.Name == "gtm" {
		return b.put(config, uriSys, uriProvision, uriGtm)
	}
	if config.Name == "apm" {
		return b.put(config, uriSys, uriProvision, uriApm)
	}
	if config.Name == "avr" {
		return b.put(config, uriSys, uriProvision, uriAvr)
	}
	if config.Name == "ilx" {
		return b.put(config, uriSys, uriProvision, uriIlx)
	}
	return nil
}

func (b *BigIP) DeleteProvision(name string) error {
	// Delete API does not exists for resource Provision
	return b.delete(uriSys, uriProvision, uriIlx, name)
}

func (b *BigIP) Provisions(name string) (*Provision, error) {
	var provision Provision
	if name == "afm" {
		err, _ := b.getForEntity(&provision, uriSys, uriProvision, uriAfm)

		if err != nil {
			return nil, err
		}
	}
	if name == "asm" {
		err, _ := b.getForEntity(&provision, uriSys, uriProvision, uriAsm)

		if err != nil {
			return nil, err
		}
	}
	if name == "gtm" {
		err, _ := b.getForEntity(&provision, uriSys, uriProvision, uriGtm)

		if err != nil {
			return nil, err
		}
	}
	if name == "apm" {
		err, _ := b.getForEntity(&provision, uriSys, uriProvision, uriApm)

		if err != nil {
			return nil, err
		}
	}
	if name == "avr" {
		err, _ := b.getForEntity(&provision, uriSys, uriProvision, uriAvr)

		if err != nil {
			return nil, err
		}

	}
	if name == "ilx" {
		err, _ := b.getForEntity(&provision, uriSys, uriProvision, uriIlx)

		if err != nil {
			return nil, err
		}

	}

	log.Println("Display ****************** provision  ", provision)
	return &provision, nil
}

func (b *BigIP) Syslogs() (*Syslog, error) {
	var syslog Syslog
	err, _ := b.getForEntity(&syslog, uriSys, uriSyslog)

	if err != nil {
		return nil, err
	}

	return &syslog, nil
}

func (b *BigIP) CreateSyslog(r *Syslog) error {
	return b.patch(r, uriSys, uriSyslog)
}

func (b *BigIP) ModifySyslog(r *Syslog) error {
	return b.put(r, uriSys, uriSyslog)
}

func (b *BigIP) CreateSNMP(sysContact string, sysLocation string, allowedAddresses []string) error {
	config := &SNMP{
		SysContact:       sysContact,
		SysLocation:      sysLocation,
		AllowedAddresses: allowedAddresses,
	}

	return b.patch(config, uriSys, uriSnmp)
}

func (b *BigIP) ModifySNMP(config *SNMP) error {
	return b.put(config, uriSys, uriSnmp)
}

func (b *BigIP) SNMPs() (*SNMP, error) {
	var snmp SNMP
	err, _ := b.getForEntity(&snmp, uriSys, uriSnmp)

	if err != nil {
		return nil, err
	}

	return &snmp, nil
}

func (b *BigIP) CreateTRAP(name string, authPasswordEncrypted string, authProtocol string, community string, description string, engineId string, host string, port int, privacyPassword string, privacyPasswordEncrypted string, privacyProtocol string, securityLevel string, securityName string, version string) error {
	config := &TRAP{
		Name:                     name,
		AuthPasswordEncrypted:    authPasswordEncrypted,
		AuthProtocol:             authProtocol,
		Community:                community,
		Description:              description,
		EngineId:                 engineId,
		Host:                     host,
		Port:                     port,
		PrivacyPassword:          privacyPassword,
		PrivacyPasswordEncrypted: privacyPasswordEncrypted,
		PrivacyProtocol:          privacyProtocol,
		SecurityLevel:            securityLevel,
		SecurityName:             securityName,
		Version:                  version,
	}
	return b.post(config, uriSys, uriSnmp, uriTraps)
}

func (b *BigIP) StartTransaction() (*Transaction, error) {
	b.Transaction = ""
	body := make(map[string]interface{})
	resp, err := b.postReq(body, uriMgmt, uriTm, uriTransaction)

	if err != nil {
		return nil, fmt.Errorf("error encountered while starting transaction: %v", err)
	}
	transaction := &Transaction{}
	err = json.Unmarshal(resp, transaction)
	if err != nil {
		return nil, err
	}
	log.Printf("[INFO] Transaction: %v", transaction)
	b.Transaction = fmt.Sprint(transaction.TransID)
	return transaction, nil
}

func (b *BigIP) CommitTransaction(tId int64) error {
	b.Transaction = ""
	commitTransaction := map[string]interface{}{
		"state": "VALIDATING",
	}
	log.Printf("[INFO] Commiting Transaction with TransactionID: %v", tId)

	err := b.patch(commitTransaction, uriMgmt, uriTm, uriTransaction, strconv.Itoa(int(tId)))
	if err != nil {
		return fmt.Errorf("%s", err)
	}
	return nil
}

func (b *BigIP) ModifyTRAP(config *TRAP) error {
	return b.patch(config, uriSys, uriSnmp, uriTraps)
}

func (b *BigIP) TRAPs(name string) (*TRAP, error) {
	var traps TRAP
	err, _ := b.getForEntity(&traps, uriSys, uriSnmp, uriTraps, name)

	if err != nil {
		return nil, err
	}

	return &traps, nil
}

func (b *BigIP) DeleteTRAP(name string) error {
	return b.delete(uriSys, uriSnmp, uriTraps, name)
}

func (b *BigIP) Bigiplicenses() (*Bigiplicense, error) {
	var bigiplicense Bigiplicense
	err, _ := b.getForEntity(&bigiplicense, uriSys, uriLicense)

	if err != nil {
		return nil, err
	}

	return &bigiplicense, nil
}

func (b *BigIP) GetBigipLiceseStatus() (map[string]interface{}, error) {
	bigipLicense := make(map[string]interface{})
	err, _ := b.getForEntityNew(&bigipLicense, uriMgmt, uriTm, uriSys, uriLicense)
	c := 0
	for err != nil {
		time.Sleep(10 * time.Second)
		c++
		err, _ = b.getForEntityNew(&bigipLicense, uriMgmt, uriTm, uriSys, uriLicense)
		if c == 15 {
			log.Printf("[DEBUG] Device is not up even after waiting for 120 seconds")
			return nil, err
		}
	}
	return bigipLicense, nil
}

func (b *BigIP) CreateBigiplicense(command, registration_key string) error {
	config := &Bigiplicense{
		Command:          command,
		Registration_key: registration_key,
	}

	return b.post(config, uriSys, uriLicense)
}

func (b *BigIP) ModifyBigiplicense(config *Bigiplicense) error {
	return b.put(config, uriSys, uriLicense)
}

func (b *BigIP) LogIPFIXs() (*LogIPFIX, error) {
	var logipfix LogIPFIX
	err, _ := b.getForEntity(&logipfix, uriSys, uriLogConfig, uriDestination, uriIPFIX)

	if err != nil {
		return nil, err
	}

	return &logipfix, nil
}

func (b *BigIP) CreateLogIPFIX(name, appService, poolName, protocolVersion, serversslProfile string, templateDeleteDelay, templateRetransmitInterval int, transportProfile string) error {
	config := &LogIPFIX{
		Name:                       name,
		AppService:                 appService,
		PoolName:                   poolName,
		ProtocolVersion:            protocolVersion,
		ServersslProfile:           serversslProfile,
		TemplateDeleteDelay:        templateDeleteDelay,
		TemplateRetransmitInterval: templateRetransmitInterval,
		TransportProfile:           transportProfile,
	}

	return b.post(config, uriSys, uriLogConfig, uriDestination, uriIPFIX)
}

func (b *BigIP) ModifyLogIPFIX(config *LogIPFIX) error {
	return b.put(config, uriSys, uriLogConfig, uriDestination, uriIPFIX)
}

func (b *BigIP) DeleteLogIPFIX(name string) error {
	return b.delete(uriSys, uriLogConfig, uriDestination, uriIPFIX, name)
}

func (b *BigIP) LogPublisher() (*LogPublisher, error) {
	var logpublisher LogPublisher
	err, _ := b.getForEntity(&logpublisher, uriSys, uriLogConfig, uriPublisher)

	if err != nil {
		return nil, err
	}

	return &logpublisher, nil
}

func (b *BigIP) CreateLogPublisher(r *LogPublisher) error {
	return b.post(r, uriSys, uriLogConfig, uriPublisher)
}

func (b *BigIP) ModifyLogPublisher(r *LogPublisher) error {
	return b.put(r, uriSys, uriLogConfig, uriPublisher)
}

func (b *BigIP) DeleteLogPublisher(name string) error {
	return b.delete(uriSys, uriLogConfig, uriPublisher, name)
}

// UploadDatagroup copies a template set from local disk to BIGIP
func (b *BigIP) UploadDatagroup(tmplpath *os.File, dgname, partition, dgtype string, createDg bool) error {
	_, err := b.UploadDataGroupFile(tmplpath, dgname)
	if err != nil {
		return err
	}
	sourcepath := "file://" + REST_DOWNLOAD_PATH + "/" + dgname
	log.Printf("[DEBUG] sourcepath :%+v", sourcepath)
	dataGroup := ExternalDGFile{
		Name:       dgname,
		SourcePath: sourcepath,
		Partition:  partition,
		Type:       dgtype,
	}
	log.Printf("External DG: %+v\n", dataGroup)
	if createDg {
		err = b.AddExternalDatagroupfile(&dataGroup)
		if err != nil {
			return err
		}
	} else {
		err = b.ModifyExternalDatagroupfile(fmt.Sprintf("/%s/%s", partition, dgname), &dataGroup)
		if err != nil {
			return err
		}
	}

	dataGroup2 := ExternalDG{
		Name:             dgname,
		ExternalFileName: fmt.Sprintf("/%s/%s", partition, dgname),
		FullPath:         fmt.Sprintf("/%s/%s", partition, dgname),
	}
	if createDg {
		err = b.AddExternalDataGroup(&dataGroup2)
		if err != nil {
			return err
		}
	} else {
		err = b.ModifyExternalDataGroup(&dataGroup2)
		if err != nil {
			return err
		}
	}
	return nil
}

// Upload a file
func (b *BigIP) UploadDataGroupFile(f *os.File, tmpName string) (*Upload, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	log.Printf("tmpName:%+v", tmpName)
	return b.Upload(f, info.Size(), uriShared, uriFileTransfer, uriUploads, tmpName)
}

func (b *BigIP) CreateOCSP(ocsp *OCSP) error {
	return b.post(ocsp, uriSys, "crypto", "cert-validator", "ocsp")
}

func (b *BigIP) ModifyOCSP(name string, ocsp *OCSP) error {
	return b.put(ocsp, uriSys, "crypto", "cert-validator", "ocsp", name)
}

func (b *BigIP) GetOCSP(name string) (*OCSP, error) {
	var ocsp OCSP
	err, _ := b.getForEntity(&ocsp, uriSys, "crypto", "cert-validator", "ocsp", name)

	if err != nil {
		return nil, err
	}

	js, err := json.Marshal(ocsp)

	if err != nil {
		return nil, fmt.Errorf("error encountered while marshalling ocsp: %v", err)
	}

	if string(js) == "{}" {
		return nil, nil
	}

	return &ocsp, nil
}

func (b *BigIP) DeleteOCSP(name string) error {
	return b.delete(uriSys, "crypto", "cert-validator", "ocsp", name)
}

func (b *BigIP) CreatePartition(partition *Partition) error {
	return b.post(partition, uriAuth, uriPartition)
}

func (b *BigIP) GetPartition(name string) (*Partition, error) {
	var partition Partition
	err, ok := b.getForEntity(&partition, uriAuth, uriPartition, name)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &partition, err
}

func (b *BigIP) ModifyPartition(name string, partition *Partition) error {
	return b.patch(partition, uriAuth, uriPartition, name)
}

func (b *BigIP) DeletePartition(name string) error {
	return b.delete(uriAuth, uriPartition, name)
}

func (b *BigIP) ModifyFolderDescription(partition string, body map[string]string) error {
	partition = fmt.Sprintf("~%s", partition)
	return b.patch(body, uriSys, uriFolder, partition)
}

func (b *BigIP) CreateRoleInfo(roleInfo *RoleInfo) error {
	return b.post(roleInfo, uriAuth, uriRemoteRole, uriRoleInfo)
}

func (b *BigIP) GetRoleInfo(name string) (*RoleInfo, error) {
	var roleInfo RoleInfo
	err, ok := b.getForEntity(&roleInfo, uriAuth, uriRemoteRole, uriRoleInfo, name)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return &roleInfo, err
}

func (b *BigIP) ModifyRoleInfo(name string, roleInfo *RoleInfo) error {
	return b.patch(roleInfo, uriAuth, uriRemoteRole, uriRoleInfo, name)
}

func (b *BigIP) DeleteRoleInfo(name string) error {
	return b.delete(uriAuth, uriRemoteRole, uriRoleInfo, name)
}
