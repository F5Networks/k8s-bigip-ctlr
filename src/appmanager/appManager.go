/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	log "f5/vlogger"
	"tools/writer"
	"watchmanager"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/runtime"
)

const (
	endpoints int = iota
	configmaps
	services
)

var objInterfaces = [3]runtime.Object{
	&v1.Endpoints{},
	&v1.ConfigMap{},
	&v1.Service{},
}

type Manager struct {
	vservers     *VirtualServers
	kubeClient   kubernetes.Interface
	configWriter writer.Writer
	watchManager watchmanager.Manager
	// Use internal node IPs
	useNodeInternal bool
	// Running in nodeport (or cluster) mode
	isNodePort bool
	// Watch all namespaces
	watchAllNamespaces bool
	// Mutex to control access to node data
	// FIXME: Simple synchronization for now, it remains to be determined if we'll
	// need something more complicated (channels, etc?)
	oldNodesMutex sync.Mutex
	// Nodes from previous iteration of node polling
	oldNodes []string
}

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	KubeClient         kubernetes.Interface
	ConfigWriter       writer.Writer
	WatchManager       watchmanager.Manager
	UseNodeInternal    bool
	IsNodePort         bool
	WatchAllNamespaces bool
}

// Create and return a new app manager that meets the Manager interface
func NewManager(params *Params) *Manager {
	return &Manager{
		vservers:           NewVirtualServers(),
		kubeClient:         params.KubeClient,
		configWriter:       params.ConfigWriter,
		watchManager:       params.WatchManager,
		useNodeInternal:    params.UseNodeInternal,
		isNodePort:         params.IsNodePort,
		watchAllNamespaces: params.WatchAllNamespaces,
	}
}

func (appMgr *Manager) IsNodePort() bool {
	return appMgr.isNodePort
}

func (appMgr *Manager) UseNodeInternal() bool {
	return appMgr.useNodeInternal
}

func (appMgr *Manager) ConfigWriter() writer.Writer {
	return appMgr.configWriter
}

func (appMgr *Manager) WatchManager() watchmanager.Manager {
	return appMgr.watchManager
}

// Process Service objects from the controller
func (appMgr *Manager) ProcessServiceUpdate(
	changeType changeType,
	obj ChangedObject,
) {

	updated := false

	updated = appMgr.processService(changeType, obj)

	if updated {
		// Output the Big-IP config
		appMgr.outputConfig()
	}
}

// Process ConfigMap objects from the controller
func (appMgr *Manager) ProcessConfigMapUpdate(
	changeType changeType,
	obj ChangedObject,
) {
	updated := false

	updated = appMgr.processConfigMap(changeType, obj)

	if updated {
		// Output the Big-IP config
		appMgr.outputConfig()
	}
}

func (appMgr *Manager) ProcessEndpointsUpdate(
	changeType changeType,
	obj ChangedObject,
) {

	updated := false

	updated = appMgr.processEndpoints(changeType, obj)

	if updated {
		// Output the Big-IP config
		appMgr.outputConfig()
	}
}

func getEndpointsForService(
	portName string,
	eps *v1.Endpoints,
) []string {
	var ipPorts []string

	if eps == nil {
		return ipPorts
	}

	for _, subset := range eps.Subsets {
		for _, p := range subset.Ports {
			if portName == p.Name {
				port := strconv.Itoa(int(p.Port))
				for _, addr := range subset.Addresses {
					var b bytes.Buffer
					b.WriteString(addr.IP)
					b.WriteRune(':')
					b.WriteString(port)
					ipPorts = append(ipPorts, b.String())
				}
			}
		}
	}
	if 0 != len(ipPorts) {
		sort.Strings(ipPorts)
	}
	return ipPorts
}

func (appMgr *Manager) getEndpointsForNodePort(
	nodePort int32,
) []string {
	port := strconv.Itoa(int(nodePort))
	nodes := appMgr.getNodesFromCache()
	for i, v := range nodes {
		var b bytes.Buffer
		b.WriteString(v)
		b.WriteRune(':')
		b.WriteString(port)
		nodes[i] = b.String()
	}

	return nodes
}

// Process a change in Service state
func (appMgr *Manager) processService(
	changeType changeType,
	o ChangedObject,
) bool {

	var svc *v1.Service
	rmvdPortsMap := make(map[int32]*struct{})
	switch changeType {
	case added:
		svc = o.New.(*v1.Service)
	case updated:
		svc = o.New.(*v1.Service)
		oldSvc := o.Old.(*v1.Service)

		for _, o := range oldSvc.Spec.Ports {
			rmvdPortsMap[o.Port] = nil
		}
	case deleted:
		svc = o.Old.(*v1.Service)
	}

	log.Debugf("Process Service watch - change type: %v name: %v namespace: %v",
		changeType, svc.ObjectMeta.Name, svc.ObjectMeta.Namespace)

	test := appMgr.WatchManager().NamespaceExists(
		svc.ObjectMeta.Namespace,
		objInterfaces[services])
	if !test {
		return false
	}

	serviceName := svc.ObjectMeta.Name
	updateConfig := false
	namespace := svc.ObjectMeta.Namespace

	// Check if the service that changed is associated with a ConfigMap
	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	for _, portSpec := range svc.Spec.Ports {
		if vsMap, ok := appMgr.vservers.GetAll(serviceKey{serviceName, portSpec.Port, namespace}); ok {
			delete(rmvdPortsMap, portSpec.Port)
			for _, vs := range vsMap {
				switch changeType {
				case added, updated:
					if appMgr.IsNodePort() {
						if svc.Spec.Type == v1.ServiceTypeNodePort {
							log.Debugf("Service backend matched %+v: using node port %v",
								serviceKey{serviceName, portSpec.Port, namespace}, portSpec.NodePort)
							vs.MetaData.Active = true
							vs.MetaData.NodePort = portSpec.NodePort
							vs.VirtualServer.Backend.PoolMemberAddrs = appMgr.getEndpointsForNodePort(portSpec.NodePort)
							updateConfig = true
						}
					} else {
						item, found, _ := appMgr.WatchManager().GetStoreItem(namespace, "endpoints", serviceName)
						eps, _ := item.(*v1.Endpoints)
						ipPorts := getEndpointsForService(portSpec.Name, eps)

						vs.MetaData.Active = true
						vs.VirtualServer.Backend.PoolMemberAddrs = ipPorts
						updateConfig = true

						if found {
							log.Debugf("Found endpoints for backend %+v: %v",
								serviceKey{serviceName, portSpec.Port, namespace}, ipPorts)
						} else {
							log.Debugf("No endpoints found for backend %+v - waiting for endpoints update",
								serviceKey{serviceName, portSpec.Port, namespace})
						}
					}
				case deleted:
					vs.MetaData.Active = false
					vs.VirtualServer.Backend.PoolMemberAddrs = nil
					updateConfig = true
					log.Debugf("Service delete matching backend %+v deactivating config",
						serviceKey{serviceName, portSpec.Port, namespace})
				}
			}
		}
	}
	for p, _ := range rmvdPortsMap {
		if vsMap, ok := appMgr.vservers.GetAll(serviceKey{serviceName, p, namespace}); ok {
			for _, vs := range vsMap {
				vs.MetaData.Active = false
				vs.VirtualServer.Backend.PoolMemberAddrs = nil
				updateConfig = true
				log.Debugf("Service update removed matching backend %+v deactivating config",
					serviceKey{serviceName, p, namespace})
			}
		}
	}

	return updateConfig
}

// Process a change in ConfigMap state
func (appMgr *Manager) processConfigMap(
	changeType changeType,
	o ChangedObject,
) bool {
	var cfg *VirtualServerConfig

	verified := false

	var cm *v1.ConfigMap
	var oldCm *v1.ConfigMap
	switch changeType {
	case added:
		cm = o.New.(*v1.ConfigMap)
	case updated:
		cm = o.New.(*v1.ConfigMap)
		oldCm = o.Old.(*v1.ConfigMap)
	case deleted:
		cm = o.Old.(*v1.ConfigMap)
	}

	log.Debugf("Process ConfigMap watch - change type: %v name: %v namespace: %v",
		changeType, cm.ObjectMeta.Name, cm.ObjectMeta.Namespace)

	namespace := cm.ObjectMeta.Namespace
	if !appMgr.watchAllNamespaces {
		test := appMgr.WatchManager().NamespaceExists(namespace, objInterfaces[configmaps])
		if !test {
			log.Debugf("Receiving service updates for unwatched namespace %s", cm.ObjectMeta.Namespace)
			return false
		}
	}

	// Decode the JSON data in the ConfigMap
	cfg, err := parseVirtualServerConfig(cm)
	if nil != err {
		log.Warningf("Could not get config for ConfigMap: %v - %v",
			cm.ObjectMeta.Name, err)
		// If virtual server exists for invalid configmap, delete it
		if nil != cfg {
			if _, ok := appMgr.vservers.Get(
				serviceKey{cfg.VirtualServer.Backend.ServiceName,
					cfg.VirtualServer.Backend.ServicePort, namespace}, formatVirtualServerName(cm)); ok {
				appMgr.vservers.Lock()
				defer appMgr.vservers.Unlock()
				appMgr.vservers.Delete(serviceKey{cfg.VirtualServer.Backend.ServiceName,
					cfg.VirtualServer.Backend.ServicePort, namespace}, formatVirtualServerName(cm))
				delete(cm.ObjectMeta.Annotations, "status.virtual-server.f5.com/ip")
				appMgr.kubeClient.CoreV1().ConfigMaps(cm.ObjectMeta.Namespace).Update(cm)
				log.Warningf("Deleted virtual server associated with ConfigMap: %v", cm.ObjectMeta.Name)
				return true
			}
		}
		return false
	}

	serviceName := cfg.VirtualServer.Backend.ServiceName
	servicePort := cfg.VirtualServer.Backend.ServicePort
	vsName := formatVirtualServerName(cm)

	switch changeType {
	case added, updated:
		eh := NewEventHandler(appMgr)
		serviceStore, err := appMgr.WatchManager().Add(namespace, "services", "", objInterfaces[services], eh)
		if nil != err {
			log.Warningf("Failed to add services watch for namespace %v: %v", namespace, err)
			return false
		}
		log.Debugf(`Looking for service "%s" in namespace "%s" as specified by ConfigMap "%s".`,
			serviceName, namespace, cm.ObjectMeta.Name)
		realsvc, found, err := serviceStore.GetByKey(namespace + "/" + serviceName)
		// If the item isn't found skip this block and create a placeholder entry
		// which will be processed when we get our initial add from the watch
		svc, _ := realsvc.(*v1.Service)
		if nil == err {
			// Check if service is of type NodePort
			if appMgr.IsNodePort() {
				if found {
					if svc.Spec.Type == v1.ServiceTypeNodePort {
						for _, portSpec := range svc.Spec.Ports {
							if portSpec.Port == servicePort {
								log.Debugf("Service backend matched %+v: using node port %v",
									serviceKey{serviceName, portSpec.Port, namespace}, portSpec.NodePort)

								cfg.MetaData.Active = true
								cfg.MetaData.NodePort = portSpec.NodePort
								cfg.VirtualServer.Backend.PoolMemberAddrs = appMgr.getEndpointsForNodePort(portSpec.NodePort)
							}
						}
					} else {
						log.Debugf("Requested service backend %+v not of NodePort type",
							serviceKey{serviceName, servicePort, namespace})
					}
				} else {
					log.Debugf("Requested service backend %+v not found - waiting for service update",
						serviceKey{serviceName, servicePort, namespace})
				}
			} else {
				epStore, epErr := appMgr.WatchManager().Add(namespace, "endpoints", "", objInterfaces[endpoints], eh)
				if nil != epErr {
					log.Warningf("Failed to add endpoints watch for namespace %v: %v", namespace, epErr)
					return false
				}

				item, _, _ := epStore.GetByKey(namespace + "/" + serviceName)
				if found {
					eps, _ := item.(*v1.Endpoints)
					for _, portSpec := range svc.Spec.Ports {
						if portSpec.Port == servicePort {
							ipPorts := getEndpointsForService(portSpec.Name, eps)

							log.Debugf("Found endpoints for backend %+v: %v",
								serviceKey{serviceName, portSpec.Port, namespace}, ipPorts)

							cfg.MetaData.Active = true
							cfg.VirtualServer.Backend.PoolMemberAddrs = ipPorts
						}
					}
				} else {
					log.Debugf("Requested service backend %+v not found - waiting for service update",
						serviceKey{serviceName, servicePort, namespace})
				}
			}
		}

		var oldCfg *VirtualServerConfig
		backendChange := false
		if updated == changeType {
			oldCfg, err = parseVirtualServerConfig(oldCm)
			if nil != err {
				log.Warningf("Cannot parse previous value for ConfigMap %s",
					oldCm.ObjectMeta.Name)
			} else {
				oldName := oldCfg.VirtualServer.Backend.ServiceName
				oldPort := oldCfg.VirtualServer.Backend.ServicePort
				if oldName != cfg.VirtualServer.Backend.ServiceName ||
					oldPort != cfg.VirtualServer.Backend.ServicePort {
					backendChange = true
				}
			}
		}

		appMgr.vservers.Lock()
		defer appMgr.vservers.Unlock()
		if added == changeType {
			if _, ok := appMgr.vservers.Get(serviceKey{serviceName, servicePort, namespace}, vsName); ok {
				log.Warningf(
					"Overwriting existing entry for backend %+v - change type: %v",
					serviceKey{serviceName, servicePort, namespace}, changeType)
			}
		} else if updated == changeType && true == backendChange {
			if _, ok := appMgr.vservers.Get(serviceKey{serviceName, servicePort, namespace}, vsName); ok {
				log.Warningf(
					"Overwriting existing entry for backend %+v - change type: %v",
					serviceKey{serviceName, servicePort, namespace}, changeType)
			}
			appMgr.vservers.Delete(
				serviceKey{oldCfg.VirtualServer.Backend.ServiceName,
					oldCfg.VirtualServer.Backend.ServicePort, namespace}, vsName)
		}
		cfg.VirtualServer.Frontend.VirtualServerName = vsName
		appMgr.vservers.Assign(serviceKey{serviceName, servicePort, namespace},
			vsName, cfg)

		// Set a status annotation to contain the virtualAddress bindAddr
		if cfg.VirtualServer.Frontend.IApp == "" && cfg.VirtualServer.Frontend.VirtualAddress != nil {
			if cfg.VirtualServer.Frontend.VirtualAddress.BindAddr != "" {
				var doUpdate bool
				if cm.ObjectMeta.Annotations == nil {
					cm.ObjectMeta.Annotations = make(map[string]string)
					doUpdate = true
				} else if cm.ObjectMeta.Annotations["status.virtual-server.f5.com/ip"] !=
					cfg.VirtualServer.Frontend.VirtualAddress.BindAddr {
					doUpdate = true
				}

				if doUpdate {
					cm.ObjectMeta.Annotations["status.virtual-server.f5.com/ip"] =
						cfg.VirtualServer.Frontend.VirtualAddress.BindAddr
					_, err = appMgr.kubeClient.CoreV1().ConfigMaps(cm.ObjectMeta.Namespace).Update(cm)
					if nil != err {
						log.Warningf("Error when creating status IP annotation: %s", err)
					} else {
						log.Debugf("Updating ConfigMap %+v annotation - %v: %v",
							serviceKey{serviceName, servicePort, namespace}, "status.virtual-server.f5.com/ip",
							cfg.VirtualServer.Frontend.VirtualAddress.BindAddr)
					}
				}
			}
		}
		verified = true
	case deleted:
		appMgr.vservers.Lock()
		defer appMgr.vservers.Unlock()
		appMgr.vservers.Delete(serviceKey{serviceName, servicePort, namespace}, vsName)
		verified = true
		log.Debugf("ConfigMap delete %+v deactivating config",
			serviceKey{serviceName, servicePort, namespace})
	}

	return verified
}

func (appMgr *Manager) processEndpoints(
	changeType changeType,
	o ChangedObject,
) bool {

	var eps *v1.Endpoints
	switch changeType {
	case added, updated:
		eps = o.New.(*v1.Endpoints)
	case deleted:
		eps = o.Old.(*v1.Endpoints)
	}

	serviceName := eps.ObjectMeta.Name
	namespace := eps.ObjectMeta.Namespace

	log.Debugf("Process Endpoints watch - change type: %v name: %v namespace: %v",
		changeType, serviceName, namespace)

	item, _, _ := appMgr.WatchManager().GetStoreItem(namespace, "services", serviceName)

	if nil == item {
		return false
	}
	svc := item.(*v1.Service)

	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()

	updateConfig := false
	for _, portSpec := range svc.Spec.Ports {
		if vsMap, ok := appMgr.vservers.GetAll(serviceKey{serviceName, portSpec.Port, namespace}); ok {
			for _, vs := range vsMap {
				switch changeType {
				case added, updated:
					ipPorts := getEndpointsForService(portSpec.Name, eps)
					if !reflect.DeepEqual(ipPorts, vs.VirtualServer.Backend.PoolMemberAddrs) {

						log.Debugf("Updating endpoints for backend: %+v: from %v to %v",
							serviceKey{serviceName, portSpec.Port, namespace},
							vs.VirtualServer.Backend.PoolMemberAddrs, ipPorts)

						vs.VirtualServer.Backend.PoolMemberAddrs = ipPorts
						updateConfig = true
					}
				case deleted:
					vs.VirtualServer.Backend.PoolMemberAddrs = nil
					updateConfig = true
				}
			}
		}
	}

	return updateConfig
}

// Check for a change in Node state
func (appMgr *Manager) ProcessNodeUpdate(
	obj interface{}, err error,
) {
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}

	newNodes, err := appMgr.getNodeAddresses(obj)
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}
	sort.Strings(newNodes)

	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()
	// Compare last set of nodes with new one
	if !reflect.DeepEqual(newNodes, appMgr.oldNodes) {
		log.Infof("ProcessNodeUpdate: Change in Node state detected")
		appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
			port := strconv.Itoa(int(cfg.MetaData.NodePort))
			var newAddrPorts []string
			for _, node := range newNodes {
				var b bytes.Buffer
				b.WriteString(node)
				b.WriteRune(':')
				b.WriteString(port)
				newAddrPorts = append(newAddrPorts, b.String())
			}
			cfg.VirtualServer.Backend.PoolMemberAddrs = newAddrPorts
		})
		// Output the Big-IP config
		appMgr.outputConfigLocked()

		// Update node cache
		appMgr.oldNodes = newNodes
	}
}

// Dump out the Virtual Server configs to a file
func (appMgr *Manager) outputConfig() {
	appMgr.vservers.Lock()
	appMgr.outputConfigLocked()
	appMgr.vservers.Unlock()
}

// Dump out the Virtual Server configs to a file
// This function MUST be called with the virtualServers
// lock held.
func (appMgr *Manager) outputConfigLocked() {

	// Initialize the Services array as empty; json.Marshal() writes
	// an uninitialized array as 'null', but we want an empty array
	// written as '[]' instead
	services := VirtualServerConfigs{}

	// Filter the configs to only those that have active services
	appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
		if cfg.MetaData.Active == true {
			services = append(services, cfg)
		}
	})

	doneCh, errCh, err := appMgr.ConfigWriter().SendSection("services", services)
	if nil != err {
		log.Warningf("Failed to write Big-IP config data: %v", err)
	} else {
		select {
		case <-doneCh:
			log.Infof("Wrote %v Virtual Server configs", len(services))
			if log.LL_DEBUG == log.GetLogLevel() {
				output, err := json.Marshal(services)
				if nil != err {
					log.Warningf("Failed creating output debug log: %v", err)
				} else {
					log.Debugf("Services: %s", output)
				}
			}
		case e := <-errCh:
			log.Warningf("Failed to write Big-IP config data: %v", e)
		case <-time.After(time.Second):
			log.Warning("Did not receive config write response in 1s")
		}
	}
}

// Return a copy of the node cache
func (appMgr *Manager) getNodesFromCache() []string {
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()
	nodes := make([]string, len(appMgr.oldNodes))
	copy(nodes, appMgr.oldNodes)

	return nodes
}

// Get a list of Node addresses
func (appMgr *Manager) getNodeAddresses(
	obj interface{},
) ([]string, error) {
	nodes, ok := obj.([]v1.Node)
	if false == ok {
		return nil,
			fmt.Errorf("poll update unexpected type, interface is not []v1.Node")
	}

	addrs := []string{}

	var addrType v1.NodeAddressType
	if appMgr.UseNodeInternal() {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	for _, node := range nodes {
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

// RemoveNamespace cleans up all virtual servers that reference a removed namespace
func (appMgr *Manager) RemoveNamespace(ns string) {
	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
		if key.Namespace == ns {
			appMgr.vservers.Delete(key, "")
		}
	})
	appMgr.outputConfigLocked()
}
