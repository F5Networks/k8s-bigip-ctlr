package teem

import (
	"fmt"
	"os"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"github.com/f5devcentral/go-bigip/f5teem"
	"github.com/google/uuid"
)

// ResourceTypes structure maintains a map of namespaces to resource count
type ResourceTypes struct {
	Ingresses       map[string]int
	Routes          map[string]int
	Configmaps      map[string]int
	VirtualServer   map[string]int
	TransportServer map[string]int
	ExternalDNS     map[string]int
	IngressLink     map[string]int
	IPAMVS          map[string]int
	IPAMTS          map[string]int
	IPAMSvcLB       map[string]int
}

// TeemsData structure contains supporting data to be posted to TEEM's server
type TeemsData struct {
	sync.Mutex
	CisVersion      string
	SDNType         string
	Agent           string
	PoolMemberType  string
	DateOfCISDeploy string
	PlatformInfo    string
	ResourceType    ResourceTypes
	AccessEnabled   bool // Will be set to false if network rules don't permit
}

const (
	TOTAL      = "total"
	staging    = "staging"
	production = "production"
)

// PostTeemsData posts data to TEEM server and returns a boolean response useful to decide if network rules permit to access server
func (td *TeemsData) PostTeemsData() bool {
	if !td.AccessEnabled {
		return false
	}
	apiEnv := os.Getenv("TEEM_API_ENVIRONMENT")
	var apiKey string
	if apiEnv != "" {
		if apiEnv == staging {
			apiKey = os.Getenv("TEEM_API_KEY")
			if len(apiKey) == 0 {
				log.Error("API key missing to post to staging teem server")
				return false
			}
		} else if apiEnv != production {
			log.Error("Invalid TEEM_API_ENVIRONMENT. Unset to use production server")
			return false
		}
	}
	// Retry only once upon failure
	var retryCount = 1
	var accessEnabled = true

	assetInfo := f5teem.AssetInfo{
		Name:    "CIS-Ecosystem",
		Version: fmt.Sprintf("CIS/v%v", td.CisVersion),
		Id:      uuid.New().String(),
	}
	teemDevice := f5teem.AnonymousClient(assetInfo, apiKey)
	types := []map[string]int{td.ResourceType.IngressLink, td.ResourceType.Ingresses, td.ResourceType.Routes,
		td.ResourceType.Configmaps, td.ResourceType.VirtualServer, td.ResourceType.TransportServer,
		td.ResourceType.ExternalDNS, td.ResourceType.IPAMVS, td.ResourceType.IPAMTS, td.ResourceType.IPAMSvcLB}
	var sum int
	for _, rscType := range types {
		sum = 0
		rscType[TOTAL] = 0 // Reset previous iteration sum
		for _, count := range rscType {
			sum += count
		}
		rscType[TOTAL] = sum
	}
	data := map[string]interface{}{
		"PlatformInfo":             td.PlatformInfo,
		"Agent":                    td.Agent,
		"DateOfCISDeploy":          td.DateOfCISDeploy,
		"Mode":                     td.PoolMemberType,
		"SDNType":                  td.SDNType,
		"IngressCount":             td.ResourceType.Ingresses[TOTAL],
		"RoutesCount":              td.ResourceType.Routes[TOTAL],
		"ConfigmapsCount":          td.ResourceType.Configmaps[TOTAL],
		"VirtualServerCount":       td.ResourceType.VirtualServer[TOTAL],
		"TransportServerCount":     td.ResourceType.TransportServer[TOTAL],
		"ExternalDNSCount":         td.ResourceType.ExternalDNS[TOTAL],
		"IngressLinkCount":         td.ResourceType.IngressLink[TOTAL],
		"IPAMVirtualServerCount":   td.ResourceType.IPAMVS[TOTAL],
		"IPAMTransportServerCount": td.ResourceType.IPAMTS[TOTAL],
		"IPAMSvcLBCount":           td.ResourceType.IPAMSvcLB[TOTAL],
	}
	for retryCount >= 0 {
		err := teemDevice.Report(data, "CIS Telemetry Data", "1")
		if err != nil {
			log.Errorf("Error reporting telemetry data :%v", err)
			retryCount--
			if retryCount < 0 {
				accessEnabled = false
			}
		} else {
			retryCount = -1
		}
	}

	return accessEnabled
}
