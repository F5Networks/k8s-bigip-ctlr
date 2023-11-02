/*-
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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

package vxlan

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/writer"

	"encoding/json"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type fdbSection struct {
	TunnelName string      `json:"name"`
	Records    []fdbRecord `json:"records"`
}

type fdbRecord struct {
	Name     string `json:"name,omitempty"`
	Endpoint string `json:"endpoint"`
}

type arpSection struct {
	Entries []arpEntry `json:"arps"`
}

type arpEntry struct {
	Name    string `json:"name"`
	IPAddr  string `json:"ipAddress"`
	MACAddr string `json:"macAddress"`
}

type VxlanMgr struct {
	mode             string
	vxLAN            string
	ciliumTunnelName string
	useNodeInt       bool
	config           writer.Writer
	podChan          <-chan interface{}
}

func NewVxlanMgr(
	mode string,
	vxLAN string,
	ciliumTunnelName string,
	useNodeInternal bool,
	config writer.Writer,
	eventChan <-chan interface{},
) (*VxlanMgr, error) {
	if 0 == len(mode) {
		return nil, fmt.Errorf("required parameter mode not supplied")
	} else if 0 == len(vxLAN) {
		return nil, fmt.Errorf("required parameter vxlan not supplied")
	} else if nil == config {
		return nil, fmt.Errorf("required parameter ConfigWriter not supplied")
	}

	if "maintain" != mode {
		return nil, fmt.Errorf("unsupported mode supplied: %s", mode)
	}

	vxMgr := &VxlanMgr{
		mode:             mode,
		vxLAN:            vxLAN,
		ciliumTunnelName: ciliumTunnelName,
		useNodeInt:       useNodeInternal,
		config:           config,
		podChan:          eventChan,
	}

	return vxMgr, nil
}

func (vxm *VxlanMgr) ProcessNodeUpdate(obj interface{}) {
	nodes, ok := obj.([]v1.Node)
	if false == ok {
		log.Warningf("[VxLAN] Vxlan manager (%s) received poll update with unexpected type",
			vxm.vxLAN)
		return
	}
	log.Debugf("[VxLAN] Processing Node Updates for FDB")
	var records []fdbRecord
	var addrType v1.NodeAddressType
	if vxm.useNodeInt {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	for _, node := range nodes {
		// Ignore the Nodes with status NotReady
		var notExecutable bool
		for _, nodeCondition := range node.Status.Conditions {
			if nodeCondition.Type == v1.NodeReady && nodeCondition.Status != v1.ConditionTrue {
				notExecutable = true
				break
			}
		}
		if notExecutable == true {
			continue
		}
		nodeAddrs := node.Status.Addresses
		rec := fdbRecord{}
		for _, addr := range nodeAddrs {
			if addr.Type == addrType {
				rec.Endpoint = addr.Address
				// Initially set the name to a fake MAC (for OpenShift use)
				// For flannel, this will be overwritten with the real MAC
				rec.Name = ipv4ToMac(addr.Address)
			}
		}
		// Will only exist in Flannel/Kubernetes
		if pip, ok := node.ObjectMeta.Annotations["flannel.alpha.coreos.com/public-ip"]; ok {
			if rec.Endpoint != pip {
				rec.Endpoint = pip
			}
		}
		if atn, ok := node.ObjectMeta.Annotations["flannel.alpha.coreos.com/backend-data"]; ok {
			mac, err := parseVtepMac(atn, node.ObjectMeta.Name)
			if nil != err {
				log.Errorf("[VxLAN] %v", err)
			} else if rec.Endpoint != "" {
				rec.Name = mac
			}
		}
		if rec != (fdbRecord{}) {
			records = append(records, rec)
		}
	}

	doneCh, errCh, err := vxm.config.SendSection(
		"vxlan-fdb",
		fdbSection{
			TunnelName: vxm.vxLAN,
			Records:    records,
		},
	)

	if nil != err {
		log.Warningf("[VxLAN] Vxlan manager (%s) failed to write fdb config section: %v",
			vxm.vxLAN, err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("[VxLAN] Vxlan manager (%s) wrote config section: %v",
				vxm.vxLAN, records)
		case e := <-errCh:
			log.Warningf("[VxLAN] Vxlan manager (%s) failed to write config section: %v",
				vxm.vxLAN, e)
		case <-time.After(time.Second):
			log.Warningf("[VxLAN] Vxlan manager (%s) did not receive write response in 1s",
				vxm.vxLAN)
		}
	}
}

// Convert an IPV4 string to a fake MAC address.
func ipv4ToMac(addr string) string {
	ip := strings.Split(addr, ".")
	if len(ip) != 4 {
		log.Errorf("[VxLAN] Bad IPv4 address format specified for FDB record: %s", addr)
		return ""
	}
	var intIP [4]int
	for i, val := range ip {
		intIP[i], _ = strconv.Atoi(val)
	}
	return fmt.Sprintf("0a:0a:%02x:%02x:%02x:%02x", intIP[0], intIP[1], intIP[2], intIP[3])
}

// Listen for updates from resource containing pod names (for arp entries)
func (vxm *VxlanMgr) ProcessAppmanagerEvents(kubeClient kubernetes.Interface) {
	go func() {
		log.Debugf("[VxLAN] Vxlan Manager waiting for pod events from appManager.")
		for {
			select {
			case pods := <-vxm.podChan:
				if pods, ok := pods.([]resource.Member); ok {
					vxm.addArpForPods(pods, kubeClient)
				} else {
					log.Errorf("[VxLAN] Vxlan Manager could not read Endpoints from appManager channel.")
				}
			}
		}
	}()
	return
}

func (vxm *VxlanMgr) handleARPForCilium() {
	// Send Empty arp block as Cilium CNI does not require static ARP addition
	doneCh, errCh, err := vxm.config.SendSection(
		"vxlan-arp",
		arpSection{},
	)
	vxm.handleVxLANMgrChannel(doneCh, errCh, err, arpSection{})
}

func (vxm *VxlanMgr) addArpForPods(pods interface{}, kubeClient kubernetes.Interface) {
	arps := arpSection{}
	kubePods, err := kubeClient.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if nil != err {
		log.Errorf("[VxLAN] Vxlan Manager could not list Kubernetes Pods for ARP entries: %v", err)
		return
	}
	// Send Empty arp block as "Cilium does not require static ARP addition"
	for _, kPod := range kubePods.Items {
		if len(vxm.ciliumTunnelName) > 0 {
			vxm.handleARPForCilium()
			return
		} else if strings.Contains(kPod.Name, "cilium") && kPod.Status.Phase == "Running" {
			vxm.handleARPForCilium()
			return
		}
	}
	kubeNodes, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if nil != err {
		log.Errorf("[VxLAN] Vxlan Manager could not list Kubernetes Nodes for ARP entries: %v", err)
		return
	}
	for _, pod := range pods.([]resource.Member) {
		var mac string
		mac, err = getVtepMac(pod, kubePods, kubeNodes)
		if nil != err {
			log.Errorf("[VxLAN] %v", err)
			return
		}
		entry := arpEntry{
			Name:    fmt.Sprintf("k8s-%v", pod.Address),
			IPAddr:  pod.Address,
			MACAddr: mac,
		}
		arps.Entries = append(arps.Entries, entry)
	}
	doneCh, errCh, err := vxm.config.SendSection(
		"vxlan-arp",
		arps,
	)
	vxm.handleVxLANMgrChannel(doneCh, errCh, err, arps)
}

func (vxm *VxlanMgr) handleVxLANMgrChannel(doneCh <-chan struct{}, errCh <-chan error, err error, arps arpSection) {
	if nil != err {
		log.Warningf("[VxLAN] Vxlan manager (%s) failed to write arp config section: %v",
			vxm.vxLAN, err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("[VxLAN] Vxlan manager (%s) wrote config section: %v",
				vxm.vxLAN, arps)
		case e := <-errCh:
			log.Warningf("[VxLAN] Vxlan manager (%s) failed to write config section: %v",
				vxm.vxLAN, e)
		case <-time.After(time.Second):
			log.Warningf("[VxLAN] Vxlan manager (%s) did not receive write response in 1s",
				vxm.vxLAN)
		}
	}
}

// Gets the VtepMac from the Node running this Pod
func getVtepMac(
	pod resource.Member,
	kubePods *v1.PodList,
	kubeNodes *v1.NodeList,
) (string, error) {
	for _, kPod := range kubePods.Items {
		// Found the Pod with this address
		if kPod.Status.PodIP == pod.Address {
			// Get the Node for this Pod
			for _, node := range kubeNodes.Items {
				if _, ok := node.ObjectMeta.Annotations["flannel.alpha.coreos.com/public-ip"]; ok &&
					node.ObjectMeta.Name == kPod.Spec.NodeName {
					if mac, ok :=
						node.ObjectMeta.Annotations["flannel.alpha.coreos.com/backend-data"]; ok {
						return parseVtepMac(mac, node.ObjectMeta.Name)
					}
				}
			}
		}
	}
	return "", fmt.Errorf("Vxlan manager could not get VtepMac for %s's node.", pod.Address)
}

func parseVtepMac(mac, nodeName string) (string, error) {
	var macDict map[string]interface{}
	json.Unmarshal([]byte(mac), &macDict)
	if macAddr, ok := macDict["VtepMAC"]; ok {
		return macAddr.(string), nil
	}
	err := fmt.Errorf("flannel.alpha.coreos.com/backend-data annotation for "+
		"node '%s' has invalid format; cannot validate VtepMac. "+
		"Should be of the form: '{\"VtepMAC\":\"<mac>\"}'", nodeName)
	return "", err
}
