package ipmanager

import (
	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"os"
	"reflect"
	"strings"
	"sync"
	"unicode"
)

type (
	IPAMHandler struct {
		done           chan bool
		kubeIPAMClient *extClient.Clientset
		IPAMCR         string
		ctlrId         string
		IpamCli        *ipammachinery.IPAMClient
		// key of the map is IPSpec.Key
		ipamCache         ipamCache
		FirstPostResponse bool
		// key is IPSec.Key and value is map of ResouceInfo
		IpamResourceStore map[ficV1.HostSpec]map[ResourceRef]struct{}
	}
	ipamCache struct {
		// key is hostSpec and value is assigned ip address
		ipamCacheMap map[ficV1.HostSpec]string
		sync.RWMutex
	}
	ResourceRef struct {
		Kind      string
		Name      string
		Namespace string
	}
)

const (
	IPAMNamespace = "kube-system"
	ipamCRName    = "ipam"
	NotEnabled    = iota
	InvalidInput
	NotRequested
	Requested
	Allocated
)

func NewIpamHandler(ctlrId string, config *rest.Config, ipamCli *ipammachinery.IPAMClient) *IPAMHandler {
	// setup kube client for ipam
	kubeIPAMClient, err := extClient.NewForConfig(config)
	if err != nil {
		log.Errorf("Failed to create client: %v", err)
	}
	return &IPAMHandler{
		done:           make(chan bool),
		kubeIPAMClient: kubeIPAMClient,
		IpamCli:        ipamCli,
		ctlrId:         ctlrId,
		ipamCache: ipamCache{
			make(map[ficV1.HostSpec]string),
			sync.RWMutex{},
		},
		IpamResourceStore: make(map[ficV1.HostSpec]map[ResourceRef]struct{}),
	}
}

// Register IPAM CRD
func (h *IPAMHandler) RegisterIPAMCRD() {
	err := ipammachinery.RegisterCRD(h.kubeIPAMClient)
	if err != nil {
		log.Errorf("[IPAM] error while registering CRD %v", err)
	}
}

// Create IPAM CRD
func (h *IPAMHandler) CreateIPAMResource() error {

	frameIPAMResourceName := func() string {
		prtn := ""
		for _, ch := range h.ctlrId {
			elem := string(ch)
			if unicode.IsUpper(ch) {
				elem = strings.ToLower(elem) + "-"
			}
			prtn += elem
		}
		if string(prtn[len(prtn)-1]) == "-" {
			prtn = prtn + ipamCRName
		} else {
			prtn = prtn + "." + ipamCRName
		}

		prtn = strings.Replace(prtn, "_", "-", -1)
		prtn = strings.Replace(prtn, "--", "-", -1)

		hostsplit := strings.Split(os.Getenv("HOSTNAME"), "-")
		var host string
		if len(hostsplit) > 2 {
			host = strings.Join(hostsplit[0:len(hostsplit)-2], "-")
		} else {
			host = strings.Join(hostsplit, "-")
		}
		return strings.Join([]string{host, prtn}, ".")
	}

	crName := frameIPAMResourceName()
	f5ipam := &ficV1.IPAM{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      crName,
			Namespace: IPAMNamespace,
		},
		Spec: ficV1.IPAMSpec{
			HostSpecs: make([]*ficV1.HostSpec, 0),
		},
		Status: ficV1.IPAMStatus{
			IPStatus: make([]*ficV1.IPSpec, 0),
		},
	}
	h.IPAMCR = IPAMNamespace + "/" + crName

	ipamCR, err := h.IpamCli.Create(f5ipam)
	if err == nil {
		log.Debugf("[IPAM] Created IPAM Custom Resource: \n%v\n", ipamCR)
		return nil
	}

	log.Debugf("[IPAM] error while creating IPAM custom resource %v", err.Error())
	return err
}

func (h *IPAMHandler) GetIPAMCR() *ficV1.IPAM {
	cr := strings.Split(h.IPAMCR, "/")
	if len(cr) != 2 {
		log.Errorf("[IPAM] error while retrieving IPAM namespace and name.")
		return nil
	}
	ipamCR, err := h.IpamCli.Get(cr[0], cr[1])
	if err != nil {
		log.Errorf("[IPAM] error while retrieving IPAM custom resource.")
		return nil
	}
	return ipamCR
}

// UpdateResourceRef function to update the IPAM Resource store
func (h *IPAMHandler) UpdateResourceRef(key ficV1.HostSpec, ref ResourceRef) {
	if _, ok := h.IpamResourceStore[key]; !ok {
		h.IpamResourceStore[key] = make(map[ResourceRef]struct{})
	}
	h.IpamResourceStore[key][ref] = struct{}{}
}

// RemoveResourceRef function to remove the resource ref entry from IPAM Resource store
func (h *IPAMHandler) RemoveResourceRef(key ficV1.HostSpec, ref ResourceRef) {
	if resources, ok := h.IpamResourceStore[key]; ok {
		if _, ok := resources[ref]; ok {
			delete(resources, ref)
		}
		if len(resources) == 0 {
			delete(h.IpamResourceStore, key)
		}
	}
}

// Request IPAM for virtual IP address
func (h *IPAMHandler) RequestIP(ipamLabel string, host string, key string, ref ResourceRef) (string, int) {

	if ipamLabel == "" || key == "" {
		return "", InvalidInput
	}

	hostSpec := ficV1.HostSpec{
		Key:       key,
		Host:      host,
		IPAMLabel: ipamLabel,
	}

	if ip, ok := h.GetIpAddressForHostSpec(hostSpec); ok && ip != "" {
		return ip, Allocated
	}

	ipamCR := h.GetIPAMCR()
	if ipamCR == nil {
		return "", NotEnabled
	}

	var ip string
	var ipReleased bool

	// update the resource ref
	h.UpdateResourceRef(hostSpec, ref)

	for _, ipst := range ipamCR.Status.IPStatus {
		if ipst.IPAMLabel == ipamLabel && ipst.Key == key && ipst.Host == host {
			// IP will be returned later when availability of corresponding spec is confirmed
			ip = ipst.IP
		}
	}

	for _, hst := range ipamCR.Spec.HostSpecs {
		if hst.Key == key {
			if hst.IPAMLabel == ipamLabel {
				if ip != "" {
					// IP extracted from the corresponding status of the spec
					return ip, Allocated
				}

				// HostSpec is already updated with IPAMLabel and Host but IP not got allocated yet
				return "", Requested
			} else {
				// Different Label for same key, this indicates Label is updated
				// Release the old IP, so that new IP can be requested
				h.ReleaseIP(hst.IPAMLabel, host, hst.Key, ref)
				ipReleased = true
				break
			}
		}
	}

	if ip != "" && !ipReleased {
		// Status is available for non-existing Spec
		// Let the resource get cleaned up and re request later
		return "", NotRequested
	}

	// update the cache
	h.AddHostSpec(hostSpec)
	ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
	ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs, &hostSpec)

	_, err := h.IpamCli.Update(ipamCR)
	if err != nil {
		log.Errorf("[IPAM] Error updating IPAM CR : %v", err)
		return "", NotRequested
	}

	log.Debugf("[IPAM] Updated IPAM CR.")
	return "", Requested

}

func (h *IPAMHandler) ReleaseIP(ipamLabel string, host string, key string, ref ResourceRef) string {
	ipamCR := h.GetIPAMCR()
	var ip string
	if ipamCR == nil || ipamLabel == "" {
		return ip
	}
	hostSpec := ficV1.HostSpec{
		Key:       key,
		Host:      host,
		IPAMLabel: ipamLabel,
	}
	// Remove the resource ref
	h.RemoveResourceRef(hostSpec, ref)
	index := -1

	//Find index for deleted key
	for i, hSpec := range ipamCR.Spec.HostSpecs {
		if hSpec.IPAMLabel == ipamLabel && hSpec.Key == key && hSpec.Host == host {
			index = i
			break
		}
	}
	//Find IP address for deleted host
	for _, ipst := range ipamCR.Status.IPStatus {
		if ipst.IPAMLabel == ipamLabel && ipst.Key == key {
			ip = ipst.IP
			break
		}
	}
	if index != -1 {
		_, err := h.RemoveIPAMCRHostSpec(ipamCR, hostSpec, index)
		if err != nil {
			log.Errorf("[IPAM] ipam hostspec update error: %v", err)
			return ""
		}
		log.Debug("[IPAM] Updated IPAM CR hostspec while releasing IP.")
	}
	return ip
}

func (h *IPAMHandler) RemoveIPAMCRHostSpec(ipamCR *ficV1.IPAM, key ficV1.HostSpec, index int) (res *ficV1.IPAM, err error) {
	if _, ok := h.IpamResourceStore[key]; !ok {
		h.ipamCache.Lock()
		delete(h.ipamCache.ipamCacheMap, key)
		h.ipamCache.Unlock()
		ipamCR.Spec.HostSpecs = append(ipamCR.Spec.HostSpecs[:index], ipamCR.Spec.HostSpecs[index+1:]...)
		ipamCR.SetResourceVersion(ipamCR.ResourceVersion)
		return h.IpamCli.Update(ipamCR)
	}
	return res, err
}

func (h *IPAMHandler) RemoveUnusedIPAMEntries() {
	if !h.FirstPostResponse {
		h.FirstPostResponse = true
		// Remove Unused IPAM entries in IPAM CR after CIS restarts, applicable to only first PostCall
		cisUsedIPAM := &ficV1.IPAM{
			ObjectMeta: metaV1.ObjectMeta{
				Labels: make(map[string]string),
			},
		}
		ipamCR := h.GetIPAMCR()
		for _, hostSpec := range ipamCR.Spec.HostSpecs {
			h.ipamCache.RLock()
			if _, ok := h.ipamCache.ipamCacheMap[*hostSpec]; ok {
				cisUsedIPAM.Spec.HostSpecs = append(cisUsedIPAM.Spec.HostSpecs, hostSpec)
			}
			h.ipamCache.RUnlock()
		}
		if !reflect.DeepEqual(ipamCR.Spec, cisUsedIPAM.Spec) {
			_, err := h.IpamCli.Update(cisUsedIPAM)
			if err != nil {
				log.Errorf("[IPAM] Error updating IPAM CR : %v", err)
			}
		}
	}
}

// GetIpAddressForHostSpec function to check if fic ipSpec exists in the ipam context
func (h *IPAMHandler) GetIpAddressForHostSpec(key ficV1.HostSpec) (string, bool) {
	h.ipamCache.RLock()
	defer h.ipamCache.RUnlock()
	ipAdd, exists := h.ipamCache.ipamCacheMap[key]
	return ipAdd, exists
}

// AddHostSpec function to add ipSpec to the ipam context
func (h *IPAMHandler) AddHostSpec(key ficV1.HostSpec) {
	h.ipamCache.Lock()
	defer h.ipamCache.Unlock()
	h.ipamCache.ipamCacheMap[key] = ""
}

// function to add ipSpec to the ipam context
func (h *IPAMHandler) UpdateCacheWithIpAddress(key ficV1.HostSpec, ipAdd string) {
	h.ipamCache.Lock()
	defer h.ipamCache.Unlock()
	h.ipamCache.ipamCacheMap[key] = ipAdd
}
