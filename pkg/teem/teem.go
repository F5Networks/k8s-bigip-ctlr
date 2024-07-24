package teem

import (
	//"fmt"
	//"os"
	//"strings"
	"sync"
	//log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	//"github.com/f5devcentral/go-bigip/f5teem"
	//"github.com/google/uuid"
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
	NativeRoutes    map[string]int
	RouteGroups     map[string]int
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
	RegistrationKey string
	ClusterCount    int
}

const (
	TOTAL      = "total"
	staging    = "staging"
	production = "production"
)

// PostTeemsData posts data to TEEM server and returns a boolean response useful to decide if network rules permit to access server
//func (td *TeemsData) PostTeemsData() bool {
//	if !td.AccessEnabled {
//		return false
//	}
//	apiEnv := os.Getenv("TEEM_API_ENVIRONMENT")
//	var apiKey string
//	if apiEnv != "" {
//		if apiEnv == staging {
//			apiKey = os.Getenv("TEEM_API_KEY")
//			if len(apiKey) == 0 {
//				log.Error("API key missing to post to staging teem server")
//				return false
//			}
//		} else if apiEnv != production {
//			log.Error("Invalid TEEM_API_ENVIRONMENT. Unset to use production server")
//			return false
//		}
//	}
//	td.Lock()
//	assetInfo := f5teem.AssetInfo{
//		Name:    "CIS-Ecosystem",
//		Version: fmt.Sprintf("CIS/v%v", td.CisVersion),
//		Id:      uuid.New().String(),
//	}
//	teemDevice := f5teem.AnonymousClient(assetInfo, apiKey)
//	types := []map[string]int{td.ResourceType.IngressLink, td.ResourceType.Ingresses, td.ResourceType.Routes,
//		td.ResourceType.Configmaps, td.ResourceType.VirtualServer, td.ResourceType.TransportServer,
//		td.ResourceType.ExternalDNS, td.ResourceType.IPAMVS, td.ResourceType.IPAMTS, td.ResourceType.IPAMSvcLB,
//		td.ResourceType.NativeRoutes, td.ResourceType.RouteGroups}
//	for _, rscType := range types {
//		sum := 0
//		rscType[TOTAL] = 0 // Reset previous iteration sum
//		for _, count := range rscType {
//			sum += count
//		}
//		rscType[TOTAL] = sum
//	}
//	data := map[string]interface{}{
//		"platformInfo":             td.PlatformInfo,
//		"agent":                    td.Agent,
//		"dateOfCISDeploy":          td.DateOfCISDeploy,
//		"mode":                     td.PoolMemberType,
//		"sdnType":                  td.SDNType,
//		"registrationKey":          td.RegistrationKey,
//		"clusterCount":             td.ClusterCount,
//		"ingressCount":             td.ResourceType.Ingresses[TOTAL],
//		"routesCount":              td.ResourceType.Routes[TOTAL],
//		"configmapsCount":          td.ResourceType.Configmaps[TOTAL],
//		"virtualServerCount":       td.ResourceType.VirtualServer[TOTAL],
//		"transportServerCount":     td.ResourceType.TransportServer[TOTAL],
//		"externalDNSCount":         td.ResourceType.ExternalDNS[TOTAL],
//		"ingressLinkCount":         td.ResourceType.IngressLink[TOTAL],
//		"ipamVirtualServerCount":   td.ResourceType.IPAMVS[TOTAL],
//		"ipamTransportServerCount": td.ResourceType.IPAMTS[TOTAL],
//		"ipamSvcLBCount":           td.ResourceType.IPAMSvcLB[TOTAL],
//		"NativeRoutesCount":        td.ResourceType.NativeRoutes[TOTAL],
//		"RouteGroupsCount":         td.ResourceType.RouteGroups[TOTAL],
//	}
//	td.Unlock()
//	err := teemDevice.Report(data, "CIS Telemetry Data", "1")
//	if err != nil && !strings.Contains(err.Error(), "request-limit") {
//		//log teem error for debugging
//		//teems send error code 429 with request-limit, if the limit 30 requests per hour is hit
//		//TEEM will start accepting them again automatically after the waiting period.
//		log.Debugf("Error reporting telemetry data :%v", err)
//		td.AccessEnabled = false
//	}
//	return td.AccessEnabled
//}
