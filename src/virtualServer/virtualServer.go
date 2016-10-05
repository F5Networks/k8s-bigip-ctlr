package virtualServer

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strconv"
	"sync"

	"eventStream"
	log "velcro/vlogger"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/v1"
	"k8s.io/client-go/1.4/pkg/fields"
)

// Definition of a Big-IP Virtual Server config
// Most of this comes directly from a ConfigMap, with the exception
// of NodePort and Nodes, which are dynamic
// For more information regarding this structure and data model:
//  velcro/schemas/bigip-virtual-server_[version].json
type VirtualServerConfig struct {
	VirtualServer struct {
		Backend struct {
			ServiceName string   `json:"serviceName"`
			ServicePort int      `json:"servicePort"`
			NodePort    int32    `json:"nodePort"`
			Nodes       []string `json:"nodes"`
		} `json:"backend"`
		Frontend struct {
			// Mutual parameter, partition
			Partition string `json:"partition"`

			// VirtualServer parameters
			Balance        string `json:"balance,omitempty"`
			Mode           string `json:"mode,omitempty"`
			VirtualAddress *struct {
				BindAddr string `json:"bindAddr,omitempty"`
				Port     int    `json:"port,omitempty"`
			} `json:"virtualAddress,omitempty"`

			// iApp parameters
			IApp          string            `json:"iapp,omitempty"`
			IAppTableName string            `json:"iappTableName,omitempty"`
			IAppOptions   map[string]string `json:"iappOptions,omitempty"`
			IAppVariables map[string]string `json:"iappVariables,omitempty"`
		} `json:"frontend"`
	} `json:"virtualServer"`
}

type VirtualServerConfigs []VirtualServerConfig

func (slice VirtualServerConfigs) Len() int {
	return len(slice)
}

func (slice VirtualServerConfigs) Less(i, j int) bool {
	return slice[i].VirtualServer.Backend.ServiceName <
		slice[j].VirtualServer.Backend.ServiceName
}

func (slice VirtualServerConfigs) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Output file as an JSON array of Virtual Server configs
type outputConfigs struct {
	Services VirtualServerConfigs `json:"services"`
}

// Output file of Big-IP Virtual Server configs
var OutputFilename string = "/tmp/f5-k8s-controller.config." + strconv.Itoa(os.Getpid()) + ".json"

// Map of Virtual Server configs
var virtualServers map[string]VirtualServerConfig

// Nodes from previous iteration of node polling
var oldNodes []string

// Mutex to control access to node data
// FIXME: Simple synchronization for now, it remains to be determined if we'll
// need something more complicated (channels, etc?)
var mutex = &sync.Mutex{}

// Package init
func init() {
	virtualServers = make(map[string]VirtualServerConfig)
}

// Process Service objects from the eventStream
func ProcessServiceUpdate(
	kubeClient kubernetes.Interface,
	changeType eventStream.ChangeType,
	obj interface{}) {

	updated := false

	if changeType == eventStream.Replaced {
		v := obj.([]interface{})
		log.Debugf("ProcessServiceUpdate (%v) for %v Services", changeType, len(v))
		for _, item := range v {
			updated = processService(kubeClient, changeType, item.(*v1.Service)) || updated
		}
	} else {
		log.Debugf("ProcessServiceUpdate (%v) for 1 Service", changeType)
		updated = processService(kubeClient, changeType, obj.(*v1.Service)) || updated
	}

	if updated {
		// Output the Big-IP config
		outputConfig()
	}
}

// Process ConfigMap objects from the eventStream
func ProcessConfigMapUpdate(
	kubeClient kubernetes.Interface,
	changeType eventStream.ChangeType,
	obj interface{}) {

	updated := false

	if changeType == eventStream.Replaced {
		v := obj.([]interface{})
		for _, item := range v {
			log.Debugf("ProcessConfigMapUpdate (%v) for %v ConfigMaps", changeType, len(v))
			updated = processConfigMap(kubeClient, changeType, item.(*v1.ConfigMap)) || updated
		}
	} else {
		log.Debugf("ProcessConfigMapUpdate (%v) for 1 ConfigMap", changeType)
		updated = processConfigMap(kubeClient, changeType, obj.(*v1.ConfigMap)) || updated
	}

	if updated {
		// Output the Big-IP config
		outputConfig()
	}
}

// Process a change in Service state
func processService(
	kubeClient kubernetes.Interface,
	changeType eventStream.ChangeType,
	svc *v1.Service) bool {

	serviceName := svc.ObjectMeta.Name
	updateConfig := false

	// Check if the service that changed is associated with a ConfigMap
	if vs, ok := virtualServers[serviceName]; ok {
		switch changeType {
		case eventStream.Added, eventStream.Replaced, eventStream.Updated:
			if svc.Spec.Type == v1.ServiceTypeNodePort {
				vs.VirtualServer.Backend.NodePort = svc.Spec.Ports[0].NodePort
				vs.VirtualServer.Backend.Nodes = getNodesFromCache()
				virtualServers[serviceName] = vs
			}
		case eventStream.Deleted:
			vs.VirtualServer.Backend.NodePort = 0
			vs.VirtualServer.Backend.Nodes = nil
			virtualServers[serviceName] = vs
		}
		updateConfig = true
	}

	return updateConfig
}

// Process a change in ConfigMap state
func processConfigMap(
	kubeClient kubernetes.Interface,
	changeType eventStream.ChangeType,
	cm *v1.ConfigMap) bool {

	var cfg VirtualServerConfig

	// Initialize node info. This isn't present in the ConfigMap,
	// so initialize with defaults
	cfg.VirtualServer.Backend.NodePort = 0
	cfg.VirtualServer.Backend.Nodes = make([]string, 1)
	verified := false

	// Decode the JSON data in the ConfigMap
	for _, value := range cm.Data {
		err := json.Unmarshal([]byte(value), &cfg)
		if err == nil {
			switch changeType {
			case eventStream.Added, eventStream.Replaced, eventStream.Updated:
				verified = true
				serviceName := cfg.VirtualServer.Backend.ServiceName

				svcs := getService(kubeClient, serviceName)
				if len(svcs.Items) != 0 {
					svc := svcs.Items[0]
					// Check if service is of type NodePort
					if svc.Spec.Type == v1.ServiceTypeNodePort {
						cfg.VirtualServer.Backend.NodePort = svc.Spec.Ports[0].NodePort
						cfg.VirtualServer.Backend.Nodes = getNodesFromCache()
					}
				}
				virtualServers[serviceName] = cfg
			case eventStream.Deleted:
				verified = true
				delete(virtualServers, cfg.VirtualServer.Backend.ServiceName)
			}
		}
	}

	if !verified {
		// Wasn't a ConfigMap we care about
		return false
	}

	return true
}

// Check for a change in Node state
func ProcessNodeUpdate(kubeClient kubernetes.Interface, internal bool) {
	newNodes, err := getNodeAddresses(kubeClient, internal)
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}
	sort.Strings(newNodes)

	mutex.Lock()
	// Compare last set of nodes with new one
	if !reflect.DeepEqual(newNodes, oldNodes) {
		log.Infof("ProcessNodeUpdate: Change in Node state detected")
		for serviceName, vs := range virtualServers {
			vs.VirtualServer.Backend.Nodes = newNodes
			virtualServers[serviceName] = vs
		}
		// Output the Big-IP config
		outputConfig()

		// Update node cache
		oldNodes = newNodes
	}
	mutex.Unlock()
}

// Dump out the Virtual Server configs to a file
func outputConfig() {
	var outputs outputConfigs

	// Initialize the Services array as empty; json.Marshal() writes
	// an uninitialized array as 'null', but we want an empty array
	// written as '[]' instead
	outputs.Services = []VirtualServerConfig{}

	// Filter the configs to only those that have active services
	for _, vs := range virtualServers {
		if vs.VirtualServer.Backend.NodePort != 0 {
			outputs.Services = append(outputs.Services, vs)
		}
	}
	output, err := json.Marshal(outputs)

	if err == nil {
		err := ioutil.WriteFile(OutputFilename, output, 0644)

		if err == nil {
			log.Infof("Wrote %v Virtual Server configs to file %v", len(outputs.Services), OutputFilename)
			log.Debugf("Output: %s", string(output))
		} else {
			log.Errorf("Failed to write Big-IP config data: %v", err)
		}
	}
}

// Get a Service by name
func getService(kubeClient kubernetes.Interface,
	serviceName string) *v1.ServiceList {
	selector := fields.OneTermEqualSelector("metadata.name", serviceName)
	options := api.ListOptions{FieldSelector: selector}
	svcs, err := kubeClient.Core().Services("").List(options)

	if err != nil {
		log.Warningf("Failed to get services: %v", err)
	}
	return svcs
}

// Return a copy of the node cache
func getNodesFromCache() []string {
	mutex.Lock()
	nodes := oldNodes
	mutex.Unlock()

	return nodes
}

// Get a list of Node addresses
func getNodeAddresses(kubeClient kubernetes.Interface,
	internal bool) ([]string, error) {
	addrs := []string{}

	nodes, err := kubeClient.Core().Nodes().List(api.ListOptions{})
	if err != nil {
		return nil, err
	}

	var addrType v1.NodeAddressType
	if internal {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	for _, node := range nodes.Items {
		if node.Spec.Unschedulable {
			// Skip master node
			continue
		} else {
			nodeAddrs := node.Status.Addresses
			for _, addr := range nodeAddrs {
				if addr.Type == addrType {
					addrs = append(addrs, addr.Address)
				}
			}
		}
	}

	return addrs, nil
}
