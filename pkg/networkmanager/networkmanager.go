package networkmanager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	InstancesURI         = "/api/v1/spaces/default/instances/"
	InventoryURI         = "/api/device/v1/inventory"
	L3Forwards           = "/l3forwards"
	TaskBaseURI          = "/api/task-manager"
	L3RouteGateway       = "L3RouteGateway"
	Completed            = "COMPLETED"
	Failed               = "FAILED"
	Create               = "CREATE"
	Delete               = "DELETE"
	networkManagerPrefix = "[NetworkManager]"
	timeoutSmall         = 2 * time.Second
	timeoutLarge         = 180 * time.Second
	DefaultL3Network     = "Default"
	Ok                   = "Ok"
)

// NetworkManager is responsible for managing the network objects on central manager.
type (
	NetworkManager struct {
		CMTokenManager *tokenmanager.TokenManager
		L3ForwardStore *L3ForwardStore
		DeviceMap      map[string]string
		ClusterName    string
		NetworkChan    chan *NetworkConfigRequest
		httpClient     *http.Client
	}

	BigIP struct {
		IPaddress  string
		InstanceId string
	}

	// RouteStore static route config store for each instance key is the instance id
	RouteStore map[BigIP]map[StaticRouteConfig]L3Forward

	// L3ForwardStore static route config store for each instance key is the instance id
	L3ForwardStore struct {
		InstanceStaticRoutes       map[string]StaticRouteMap
		CachedInstanceStaticRoutes map[string]map[StaticRouteConfig]struct{}
		sync.RWMutex
	}

	StaticRouteMap map[StaticRouteConfig]L3Forward

	// L3Forward struct represents the structure of the L3Forward in the JSON response
	L3Forward struct {
		ID     string            `json:"id,omitempty"`
		VRF    string            `json:"vrf"`
		Name   string            `json:"name"`
		Config StaticRouteConfig `json:"config"`
	}

	// StaticRouteConfig struct represents the structure of the StaticRouteConfig in the L3Forward
	StaticRouteConfig struct {
		Gateway       string `json:"gateway"`
		Destination   string `json:"destination"`
		L3ForwardType string `json:"l3ForwardType"`
	}

	// NetworkConfigRequest represents the network config request
	NetworkConfigRequest struct {
		NetworkConfig interface{}
		BigIp         BigIP
		Action        string
		retryTimeout  int
	}
)

func NewNetworkManager(tm *tokenmanager.TokenManager, clusterName string) *NetworkManager {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// TODO: Make sure appMgr sets certificates in bigipInfo
	certs := []byte(tm.TrustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debugf("%v No certs appended, using only system certs", networkManagerPrefix)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tm.SslInsecure,
			RootCAs:            rootCAs,
		},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   timeoutLarge,
	}
	routeStore := L3ForwardStore{
		make(map[string]StaticRouteMap),
		make(map[string]map[StaticRouteConfig]struct{}),
		sync.RWMutex{},
	}
	return &NetworkManager{
		CMTokenManager: tm,
		ClusterName:    clusterName,
		DeviceMap:      make(map[string]string),
		L3ForwardStore: &routeStore,
		NetworkChan:    make(chan *NetworkConfigRequest, 1),
		httpClient:     httpClient,
	}
}

// SetInstanceIds performs an HTTP GET request to the API, extracts address and ID mappings, and stores them
func (nm *NetworkManager) SetInstanceIds(bigIpConfigs []cisapiv1.BigIpConfig, controllerID string) error {

	// initialize the device map
	nm.DeviceMap = make(map[string]string)
	// set the monitored bigips
	monitoredBigIps := make(map[string]struct{})
	for _, bigIpConfig := range bigIpConfigs {
		monitoredBigIps[bigIpConfig.BigIpAddress] = struct{}{}
	}

	// delete the old entries from the L3ForwardStore
	nm.L3ForwardStore.Lock()
	for instanceId := range nm.L3ForwardStore.InstanceStaticRoutes {
		if _, ok := monitoredBigIps[instanceId]; !ok {
			delete(nm.L3ForwardStore.InstanceStaticRoutes, instanceId)
		}
	}
	nm.L3ForwardStore.Unlock()

	// Create request
	req, err := http.NewRequest("GET", nm.CMTokenManager.ServerURL+InventoryURI, nil)
	if err != nil {
		return err
	}

	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+nm.CMTokenManager.GetToken())

	// Perform request
	resp, err := nm.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	// Decode JSON response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	if embedded, ok := response["_embedded"].(map[string]interface{}); ok {
		if devicesArray, ok := embedded["devices"].([]interface{}); ok {
			for _, deviceData := range devicesArray {
				if device, ok := deviceData.(map[string]interface{}); ok {
					address, addressOk := device["address"].(string)
					id, idOk := device["id"].(string)
					if addressOk && idOk {
						// Add if the bigip is monitored
						if _, ok := monitoredBigIps[address]; ok {
							nm.DeviceMap[address] = id
							nm.L3ForwardStore.Lock()
							if _, ok := nm.L3ForwardStore.InstanceStaticRoutes[id]; !ok {
								staticRouteMap, err := nm.GetL3ForwardsFromInstance(id, controllerID)
								if err != nil {
									log.Errorf("%v Error getting static routes for instance %v: %v", networkManagerPrefix, id, err)
									nm.L3ForwardStore.Unlock()
									return nil
								}
								nm.L3ForwardStore.InstanceStaticRoutes[id] = staticRouteMap
								nm.L3ForwardStore.CachedInstanceStaticRoutes[id] = map[StaticRouteConfig]struct{}{}
							}
							nm.L3ForwardStore.Unlock()
						}
					}
				}
			}
		}
	}
	return nil
}

// GetL3ForwardsFromInstance performs an HTTP GET request to the API, extracts name and route information, and stores them
func (nm *NetworkManager) GetL3ForwardsFromInstance(instanceId string, controllerID string) (StaticRouteMap, error) {

	// Create request
	req, err := http.NewRequest("GET", nm.CMTokenManager.ServerURL+InstancesURI+instanceId+L3Forwards, nil)
	if err != nil {
		return nil, err
	}

	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+nm.CMTokenManager.GetToken())

	// Perform request
	resp, err := nm.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	// Decode JSON response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	var staticRoutes = make(map[StaticRouteConfig]L3Forward)
	if embedded, ok := response["_embedded"].(map[string]interface{}); ok {
		if l3ForwardsArray, ok := embedded["l3forwards"].([]interface{}); ok {
			for _, l3ForwardData := range l3ForwardsArray {
				if l3Forward, ok := l3ForwardData.(map[string]interface{}); ok {
					name, nameOk := l3Forward["payload"].(map[string]interface{})["name"].(string)
					if nameOk {
						routeNameArray := strings.Split(name, "/")
						if len(routeNameArray) == 0 || routeNameArray[0] != controllerID {
							// ControllerID is not present or not matching in the l3Forward name, so skip this L3Forward
							// as it's not be created by this CIS
							continue
						}
					}
					id, idOk := l3Forward["id"].(string)

					configData, configOk := l3Forward["payload"].(map[string]interface{})["config"].(map[string]interface{})
					config := StaticRouteConfig{}
					if configOk {
						config.Gateway, _ = configData["gateway"].(string)
						config.Destination, _ = configData["destination"].(string)
						config.L3ForwardType, _ = configData["l3ForwardType"].(string)
					}

					vrfData, vrfOk := l3Forward["payload"].(map[string]interface{})["vrf"].(string)

					if idOk && nameOk && vrfOk {
						staticRoutes[config] = L3Forward{
							ID:     id,
							Name:   name,
							Config: config,
							VRF:    vrfData,
						}
					}
				}
			}
		}
	}
	return staticRoutes, nil
}

// DeleteL3Forward sends an HTTP DELETE request to delete an L3Forward with the given ID
func (nm *NetworkManager) DeleteL3Forward(instanceId, l3ForwardID string) error {

	// Create request URL
	url := fmt.Sprintf("%s/%s", nm.CMTokenManager.ServerURL+InstancesURI+instanceId+L3Forwards, l3ForwardID)

	// Create request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+nm.CMTokenManager.GetToken())
	log.Debugf("%v PNK DeleteL3Forward url %v req %v", networkManagerPrefix, url, req)

	// Perform request
	resp, err := nm.httpClient.Do(req)
	log.Debugf("%v PNK DeleteL3Forward resp %v err %v", networkManagerPrefix, resp, err)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	log.Debugf("%v PNK DeleteL3Forward resp.StatusCode %v != http.StatusAccepted %v ", networkManagerPrefix, resp.StatusCode, http.StatusAccepted)
	// Check response status code
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("%v API request failed with status code: %d", networkManagerPrefix, resp.StatusCode)
	}

	var response map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	log.Debugf("%v PNK DeleteL3Forward response %v err %v", networkManagerPrefix, response, err)
	// Get the task URI from the response
	taskRef, _ := GetTaskURIAndObjectIdFromResponse(response)
	if taskRef == "" {
		return fmt.Errorf("%v task URI not found in response", networkManagerPrefix)
	}
	log.Debugf("%v PNK DeleteL3Forward taskRef %v", networkManagerPrefix, taskRef)
	// Get the task status
	var taskStatus, failureReason string
	for {
		time.Sleep(timeoutSmall)
		taskStatus, failureReason, err = nm.GetTaskStatus(taskRef)
		if err != nil || taskStatus == Completed || taskStatus == Failed {
			break
		}
	}
	log.Debugf("%v PNK DeleteL3Forward taskStatus %v failureReason %v err %v", networkManagerPrefix, taskStatus, failureReason, err)
	if taskStatus != Completed {
		if err != nil {
			return fmt.Errorf("%v task did not completed with error: %s", networkManagerPrefix, err)
		}
		return fmt.Errorf("%v task did not completed with status: %s and failure reason: %s", networkManagerPrefix, taskStatus, failureReason)
	}
	return nil
}

// GetTaskStatus sends an HTTP GET request to get the task status of the given task ID
func (nm *NetworkManager) GetTaskStatus(taskRef string) (string, string, error) {

	// Create request
	req, err := http.NewRequest("GET", nm.CMTokenManager.ServerURL+taskRef, nil)
	log.Debugf("%v PNK GetTaskStatus req %v err %v", networkManagerPrefix, req, err)
	if err != nil {
		return "", "", err
	}

	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+nm.CMTokenManager.GetToken())

	log.Debugf("%v PNK GetTaskStatus full req %v ", networkManagerPrefix, req)
	// Perform request
	resp, err := nm.httpClient.Do(req)
	log.Debugf("%v PNK GetTaskStatus resp %v err %v", networkManagerPrefix, resp, err)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	log.Debugf("%v PNK GetTaskStatus resp.StatusCode %v != http.StatusOK %v ", networkManagerPrefix, resp.StatusCode, http.StatusOK)
	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%v API request failed with status code: %d", networkManagerPrefix, resp.StatusCode)
	}

	// Decode JSON response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", "", err
	}
	log.Debugf("%v PNK GetTaskStatus response %v err %v", networkManagerPrefix, response, err)
	if status, ok := response["status"].(string); ok {
		failureReason, ok := response["failure_reason"].(string)
		if !ok {
			return status, "", nil
		}
		return status, failureReason, nil
	}

	return "", "", nil
}

// PostL3Forward sends an HTTP POST request to create an L3Forward with the given data
func (nm *NetworkManager) PostL3Forward(apiURL, authToken string, l3ForwardReq *L3Forward) error {
	// Convert L3ForwardRequest to JSON
	reqBody, err := json.Marshal(l3ForwardReq)
	if err != nil {
		return err
	}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	// Set Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Set authorization header
	req.Header.Set("Authorization", "Bearer "+authToken)

	log.Debugf("%v PNK PostL3Forward req %v", networkManagerPrefix, req)
	// Perform request
	resp, err := nm.httpClient.Do(req)
	log.Debugf("%v PNK PostL3Forward resp %v err %v", networkManagerPrefix, resp, err)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	log.Debugf("%v PNK PostL3Forward resp.StatusCode %v != http.StatusAccepted %v ", networkManagerPrefix, resp.StatusCode, http.StatusAccepted)
	// Check response status code
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("%v API request failed with status code: %d", networkManagerPrefix, resp.StatusCode)
	}

	var response map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	// Get the task URI from the response
	taskRef, objectId := GetTaskURIAndObjectIdFromResponse(response)
	if taskRef == "" {
		return fmt.Errorf("%v task URI not found in response", networkManagerPrefix)
	}
	log.Debugf("%v PNK PostL3Forward taskRef %v objectId %v", networkManagerPrefix, taskRef, objectId)

	// Get the task status
	var taskStatus, failureReason string
	for {
		time.Sleep(timeoutSmall)
		taskStatus, failureReason, err = nm.GetTaskStatus(taskRef)
		if err != nil || taskStatus == Completed || taskStatus == Failed {
			break
		}
	}
	log.Debugf("%v PNK PostL3Forward taskStatus %v failureReason %v err %v", networkManagerPrefix, taskStatus, failureReason, err)
	if taskStatus != Completed {
		if err != nil {
			return fmt.Errorf("%v task did not completed with error: %s", networkManagerPrefix, err)
		}
		return fmt.Errorf("%v task did not completed with status: %s and failure reason: %s", networkManagerPrefix, taskStatus, failureReason)
	}

	// set the task id for the l3 forward
	l3ForwardReq.ID = objectId

	return nil
}

// GetTaskURIAndObjectIdFromResponse pafses the JSON response from the response
func GetTaskURIAndObjectIdFromResponse(response map[string]interface{}) (string, string) {
	var taskRef, objectid string
	if links, ok := response["_links"].(map[string]interface{}); ok {
		if taskLink, ok := links["task"].(map[string]interface{}); ok {
			if taskURI, statusOk := taskLink["href"].(string); statusOk {
				taskRef = taskURI
			}
		}
	}
	if path, ok := response["path"].(string); ok {
		parts := strings.Split(path, "/")
		objectid = parts[len(parts)-1]
	}
	return taskRef, objectid
}

func (nm *NetworkManager) NetworkRequestHandler(store interface{}) {
	log.Debugf("%v PNK NetworkRequestHandler store %v ", networkManagerPrefix, store)
	switch store.(type) {
	case RouteStore:
		routeStore := store.(RouteStore)
		// Create the new l3 forwards
		for bigip, rMap := range routeStore {
			nm.L3ForwardStore.RLock()
			log.Debugf("%v PNK NetworkRequestHandler rMap %v ", networkManagerPrefix, rMap)
			log.Debugf("%v PNK NetworkRequestHandler nm.L3ForwardStore.InstanceStaticRoutes %v ", networkManagerPrefix, nm.L3ForwardStore.InstanceStaticRoutes)
			log.Debugf("%v PNK NetworkRequestHandler nm.L3ForwardStore.CachedInstanceStaticRoutes %v ", networkManagerPrefix, nm.L3ForwardStore.CachedInstanceStaticRoutes)
			// Create Scenerio
			// rmap : Master, worker0, worker1 (live but not applied)
			// instanceStaticRoutes : Master, worker0
			// cachedIsr: Master, worker0
			// cachedInstanceStaticRoutes : None

			if cachedIsr, ok := nm.L3ForwardStore.InstanceStaticRoutes[bigip.InstanceId]; ok {
				// enqueue the deleted routes
				for config, l3Forward := range cachedIsr {
					if _, ok := rMap[config]; !ok {
						log.Debugf("%v PNK Delete NetworkRequestHandler config %v ", networkManagerPrefix, config)
						nm.NetworkChan <- &NetworkConfigRequest{
							NetworkConfig: l3Forward,
							BigIp:         bigip,
							Action:        Delete,
						}
					}
				}
				// enqueue the created routes
				for config, l3Forward := range rMap {
					if _, ok := cachedIsr[config]; !ok {
						log.Debugf("%v PNK Create NetworkRequestHandler config %v ", networkManagerPrefix, config)
						nm.NetworkChan <- &NetworkConfigRequest{
							NetworkConfig: l3Forward,
							BigIp:         bigip,
							Action:        Create,
						}
					}
				}
			}
			nm.L3ForwardStore.RUnlock()
		}
	}

}

func (nm *NetworkManager) NetworkConfigHandler() {
	for req := range nm.NetworkChan {
		log.Debugf("%v PNK Received on Channel NetworkConfigHandler req %v ", networkManagerPrefix, req)
		switch req.NetworkConfig.(type) {
		case L3Forward:
			l3Forward := req.NetworkConfig.(L3Forward)
			if l3Forward.Config.L3ForwardType == L3RouteGateway {
				go nm.HandleL3ForwardRequest(req, &l3Forward)
			}
		default:
			log.Errorf("%v unknown network config type %v", networkManagerPrefix, req.NetworkConfig)
		}
	}
}

func (nm *NetworkManager) HandleL3ForwardRequest(req *NetworkConfigRequest, l3Forward *L3Forward) {
	if req.retryTimeout != 0 {
		log.Debugf("%v Posting request after %v seconds", networkManagerPrefix, req.retryTimeout)
		time.Sleep(time.Duration(req.retryTimeout) * time.Second)
	} else {
		log.Debugf("%v Posting request %v", networkManagerPrefix, req)
	}
	// bigipStatus
	bigipStatus := cisapiv1.BigIPStatus{
		BigIPAddress: req.BigIp.IPaddress,
	}
	log.Debugf("%v PNK HandleL3ForwardRequest req.Action %v ", networkManagerPrefix, req.Action)
	log.Debugf("%v PNK HandleL3ForwardRequest req %v ", networkManagerPrefix, req)
	switch req.Action {
	case Create:
		// check if the l3 forward already exists
		if nm.L3ForwardStore.getL3ForwardEntry(req.BigIp.InstanceId, *l3Forward) {
			log.Debugf("%v l3 forward already exists hence skipping the creation: %v", networkManagerPrefix, l3Forward)
			return
		}

		log.Debugf("%v PNK create event Entry not exists in getL3ForwardEntry", networkManagerPrefix)
		// check if the entry is present in the cache
		// if present(true) means event is in progress - skip the processing of event
		// if not(false) means this is a new event and will be processed further
		if nm.L3ForwardStore.checkL3ForwardEntryInCache(req.BigIp.InstanceId, req.retryTimeout, *l3Forward) {
			return
		}
		log.Debugf("%v PNK create event Entry not exists in checkL3ForwardEntryInCache", networkManagerPrefix)

		// create the l3 forward
		err := nm.PostL3Forward(nm.CMTokenManager.ServerURL+InstancesURI+req.BigIp.InstanceId+L3Forwards, nm.CMTokenManager.GetToken(), l3Forward)
		log.Debugf("%v PNK create event PostL3Forward", networkManagerPrefix)
		if err != nil {
			log.Debugf("%v PNK error while creating l3 forward %v", networkManagerPrefix, err)
			bigipStatus.L3Status = &cisapiv1.L3Status{
				Message:       Create + Failed,
				Error:         fmt.Sprintf("%v error while creating l3 forward %v", networkManagerPrefix, err),
				LastSubmitted: metav1.Now(),
			}
			nm.CMTokenManager.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &bigipStatus)
			// as the request is failed retrying the request
			req.retryTimeout = getRetryTimeout(req.retryTimeout)
			nm.NetworkChan <- req
			return
		}
		log.Debugf("%v successfully created l3 forward %v", networkManagerPrefix, l3Forward)
		bigipStatus.L3Status = &cisapiv1.L3Status{
			Message:       Ok,
			LastSubmitted: metav1.Now(),
		}
		nm.CMTokenManager.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &bigipStatus)
		log.Debugf("%v PNK successfully created l3 forward Add Request %v", networkManagerPrefix, l3Forward)
		nm.L3ForwardStore.addL3ForwardEntry(req.BigIp.InstanceId, *l3Forward)
		log.Debugf("%v PNK successfully created l3 forward addL3ForwardEntry Add Request addL3ForwardEntry %v", networkManagerPrefix, l3Forward)
		// once event is processed remove entry from cache
		// nm.L3ForwardStore.addL3ForwardEntryFromCache(req.BigIp.InstanceId, *l3Forward)
		// log.Debugf("%v PNK successfully created l3 forward Add Request addL3ForwardEntry addL3ForwardEntryFromCache %v", networkManagerPrefix, l3Forward)
	case Delete:
		log.Warningf("%v delete event", networkManagerPrefix)
		// check if the l3 forward already exists
		if !nm.L3ForwardStore.getL3ForwardEntry(req.BigIp.InstanceId, *l3Forward) {
			log.Debugf("%v l3 forward does not exist hence skipping the deletion: %v", networkManagerPrefix, l3Forward)
			return
		}
		// delete the l3 forward
		err := nm.DeleteL3Forward(req.BigIp.InstanceId, l3Forward.ID)
		log.Debugf("%v PNK delete event DeleteL3Forward err: %v", networkManagerPrefix, err)
		if err != nil {
			log.Debugf("%v PNK error while deleting l3 forward %v", networkManagerPrefix, err)
			bigipStatus.L3Status = &cisapiv1.L3Status{
				Message:       Delete + Failed,
				Error:         fmt.Sprintf("%v error while deleting l3 forward %v", networkManagerPrefix, err),
				LastSubmitted: metav1.Now(),
			}
			nm.CMTokenManager.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &bigipStatus)
			req.retryTimeout = getRetryTimeout(req.retryTimeout)
			// as the request is failed retrying the request
			nm.NetworkChan <- req
			return
		}
		bigipStatus.L3Status = &cisapiv1.L3Status{
			Message:       Ok,
			LastSubmitted: metav1.Now(),
		}
		nm.CMTokenManager.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &bigipStatus)
		log.Debugf("%v successfully deleted l3 forward %v", networkManagerPrefix, l3Forward)
		nm.L3ForwardStore.deleteL3ForwardEntry(req.BigIp.InstanceId, l3Forward.Config)
		log.Debugf("%v PNK successfully deleted l3 forward deleteL3ForwardEntry %v", networkManagerPrefix, l3Forward)
		// once event is processed remove entry from cache
		nm.L3ForwardStore.removeL3ForwardEntryFromCache(req.BigIp.InstanceId, *l3Forward)
		log.Debugf("%v PNK successfully deleted l3 forward removeL3ForwardEntryFromCache %v", networkManagerPrefix, l3Forward)
	}
}

func (fs *L3ForwardStore) deleteL3ForwardEntry(instanceId string, config StaticRouteConfig) {
	fs.Lock()
	defer fs.Unlock()
	if isr, ok := fs.InstanceStaticRoutes[instanceId]; ok {
		delete(isr, config)
	}
	// log.Debugf("%v PNK deleteL3ForwardEntry  fs.CachedInstanceStaticRoutes %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes)
	// log.Debugf("%v PNK deleteL3ForwardEntry config %v", networkManagerPrefix, config)
}

func (fs *L3ForwardStore) getL3ForwardEntry(instanceId string, l3Forward L3Forward) bool {
	fs.RLock()
	defer fs.RUnlock()
	if isr, ok := fs.InstanceStaticRoutes[instanceId]; ok {
		if _, ok = isr[l3Forward.Config]; ok {
			log.Debugf("%v PNK L3Forward *** Exists ******* getL3ForwardEntry  fs.InstanceStaticRoutes[instanceId] %v", networkManagerPrefix, fs.InstanceStaticRoutes[instanceId])
			return ok
		}
	}
	// log.Debugf("%v PNK getL3ForwardEntry  fs.CachedInstanceStaticRoutes %v", networkManagerPrefix, fs.InstanceStaticRoutes)
	// log.Debugf("%v PNK getL3ForwardEntry l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)
	return false
}

func (fs *L3ForwardStore) checkL3ForwardEntryInCache(bigIpInstanceId string, retryTimeOut int, l3Forward L3Forward) bool {
	fs.Lock()
	defer fs.Unlock()
	// if retryTimeOut >0, means it's a retry scenario
	if retryTimeOut > 0 {
		return false
	}
	// log.Debugf("%v PNK before checkL3ForwardEntryInCache  fs.CachedInstanceStaticRoutes[bigIpInstanceId] %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes[bigIpInstanceId])
	// log.Debugf("%v PNK before checkL3ForwardEntryInCache l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)
	if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId]; !ok {
		fs.CachedInstanceStaticRoutes[bigIpInstanceId] = map[StaticRouteConfig]struct{}{}
	}
	if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config]; !ok {
		fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config] = struct{}{}
		// log.Debugf("%v PNK Filled checkL3ForwardEntryInCache  fs.CachedInstanceStaticRoutes[bigIpInstanceId] %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes[bigIpInstanceId])
		// log.Debugf("%v PNK Filled checkL3ForwardEntryInCache l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)

		return false
	}
	// log.Debugf("%v PNK after checkL3ForwardEntryInCache  fs.CachedInstanceStaticRoutes[bigIpInstanceId] %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes[bigIpInstanceId])
	// log.Debugf("%v PNK after checkL3ForwardEntryInCache l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)

	return true
}

func (fs *L3ForwardStore) removeL3ForwardEntryFromCache(bigIpInstanceId string, l3Forward L3Forward) {
	fs.Lock()
	defer fs.Unlock()
	if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId]; ok {
		if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config]; ok {
			delete(fs.CachedInstanceStaticRoutes[bigIpInstanceId], l3Forward.Config)
		}
	}
	// log.Debugf("%v PNK removeL3ForwardEntryFromCache  fs.CachedInstanceStaticRoutes %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes)
	// log.Debugf("%v PNK removeL3ForwardEntryFromCache l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)
}

func (fs *L3ForwardStore) addL3ForwardEntryFromCache(bigIpInstanceId string, l3Forward L3Forward) {
	fs.Lock()
	defer fs.Unlock()

	if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId]; !ok {
		fs.CachedInstanceStaticRoutes[bigIpInstanceId] = map[StaticRouteConfig]struct{}{}
	}
	if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config]; !ok {
		fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config] = struct{}{}
	}
	// if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId]; ok {
	// 	if _, ok := fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config]; !ok {
	// 		fs.CachedInstanceStaticRoutes[bigIpInstanceId][l3Forward.Config] = struct{}{}
	// 	}
	// }
	// log.Debugf("%v PNK addL3ForwardEntryFromCache  fs.CachedInstanceStaticRoutes %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes)
	// log.Debugf("%v PNK addL3ForwardEntryFromCache l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)
}

func (fs *L3ForwardStore) addL3ForwardEntry(instanceId string, l3Forward L3Forward) {
	// log.Debugf("%v PNK before addL3ForwardEntry  fs.CachedInstanceStaticRoutes %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes)
	// log.Debugf("%v PNK before addL3ForwardEntry l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)
	fs.Lock()
	defer fs.Unlock()
	if isr, ok := fs.InstanceStaticRoutes[instanceId]; ok {
		isr[l3Forward.Config] = l3Forward
	}
	// log.Debugf("%v PNK after addL3ForwardEntry  fs.CachedInstanceStaticRoutes %v", networkManagerPrefix, fs.CachedInstanceStaticRoutes)
	// log.Debugf("%v PNK after addL3ForwardEntry l3Forward.Config %v", networkManagerPrefix, l3Forward.Config)
}

func getRetryTimeout(retryTimeout int) int {
	// // Reset to 0 after 64 seconds
	if retryTimeout >= 64 {
		retryTimeout = 0
	}
	if retryTimeout == 0 {
		retryTimeout = 1
	} else {
		retryTimeout = retryTimeout * 2
	}
	return retryTimeout
}
