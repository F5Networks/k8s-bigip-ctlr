package controller

import (
	"encoding/json"
	"fmt"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"
)

func (ctlr *Controller) SetupNodeProcessing(clusterName string) error {
	var nodesIntfc []interface{}
	if clusterName == "" {
		nodesIntfc = ctlr.nodeInformer.nodeInformer.GetIndexer().List()
	} else {
		if nodeInf, ok := ctlr.multiClusterNodeInformers[clusterName]; ok {
			nodesIntfc = nodeInf.nodeInformer.GetIndexer().List()
		}
	}

	var nodesList []v1.Node
	for _, obj := range nodesIntfc {
		node := obj.(*v1.Node)
		nodesList = append(nodesList, *node)
	}
	sort.Sort(NodeList(nodesList))
	ctlr.ProcessNodeUpdate(nodesList, clusterName)
	// adding the bigip_monitored_nodes	metrics
	bigIPPrometheus.MonitoredNodes.WithLabelValues(ctlr.nodeLabelSelector).Set(float64(len(ctlr.oldNodes)))
	if ctlr.PoolMemberType == NodePort {
		return nil
	}
	if ctlr.StaticRoutingMode {
		if !ctlr.initState {
			// external cluster config is not processed in init stage before local node informer state
			// handle static routes update after external cluster config is processed
			// So process nodes on updates after init state
			clusterNodes := ctlr.getNodesFromAllClusters()
			ctlr.processStaticRouteUpdate(clusterNodes)
		}
	} else if ctlr.vxlanMgr != nil {
		// Register vxMgr to watch for node updates to process fdb records
		ctlr.vxlanMgr.ProcessNodeUpdate(nodesList)
	}
	return nil
}

// ProcessNodeUpdate Check for a change in Node state
func (ctlr *Controller) ProcessNodeUpdate(obj interface{}, clusterName string) {
	newNodes, err := ctlr.getNodes(obj)
	if nil != err {
		log.Warningf("%v Unable to get list of nodes %v, err=%+v", ctlr.getMultiClusterLog(), getClusterLog(clusterName), err)
		return
	}
	// process the node and update the all pool members for the cluster
	if !ctlr.initState {
		if clusterName == "" {
			// Compare last set of nodes with new one
			if !reflect.DeepEqual(newNodes, ctlr.oldNodes) {
				log.Debugf("Processing Node Updates for local cluster")
				// Update node cache
				ctlr.oldNodes = newNodes
				if _, ok := ctlr.multiClusterResources.clusterSvcMap.Load(clusterName); ok {
					ctlr.UpdatePoolMembersForNodeUpdate(clusterName)
				}
			}
		} else {
			if nodeInf, ok := ctlr.multiClusterNodeInformers[clusterName]; ok {
				// Compare last set of nodes with new one
				if !reflect.DeepEqual(newNodes, nodeInf.oldNodes) {
					log.Debugf("[MultiCluster] Processing Node Updates for cluster: %s", clusterName)
					// Update node cache
					nodeInf.oldNodes = newNodes
					if &ctlr.multiClusterResources.clusterSvcMap != nil {
						if _, ok := ctlr.multiClusterResources.clusterSvcMap.Load(clusterName); ok {
							ctlr.UpdatePoolMembersForNodeUpdate(clusterName)
						}
					}
				}
			}
		}
	} else {
		// Initialize controller nodes on our first pass through
		log.Debugf("%v Initialising controller monitored kubernetes nodes %v", ctlr.getMultiClusterLog(), getClusterLog(clusterName))
		if clusterName == "" {
			ctlr.oldNodes = newNodes
		} else {
			if nodeInf, ok := ctlr.multiClusterNodeInformers[clusterName]; ok {
				// Update node cache
				nodeInf.oldNodes = newNodes
			}
		}
	}
}

func (ctlr *Controller) UpdatePoolMembersForNodeUpdate(clusterName string) {
	if sKey, ok := ctlr.multiClusterResources.clusterSvcMap.Load(clusterName); ok {
		svcKeys, _ := sKey.(MultiClusterServicePoolMap)
		for svcKey, _ := range svcKeys {
			ctlr.updatePoolMembersForService(svcKey, false)
		}
		key := &rqKey{
			kind: NodeUpdate,
		}
		ctlr.resourceQueue.Add(key)
	}
}

// Return a copy of the node cache
func (ctlr *Controller) getNodesFromCache(clusterName string) []Node {
	var nodes []Node
	if clusterName == "" {
		nodes = make([]Node, len(ctlr.oldNodes))
		copy(nodes, ctlr.oldNodes)
	} else {
		if nodeInf, ok := ctlr.multiClusterNodeInformers[clusterName]; ok {
			nodes = make([]Node, len(nodeInf.oldNodes))
			copy(nodes, nodeInf.oldNodes)
		}
	}
	return nodes
}

// Get a list of Node addresses
func (ctlr *Controller) getNodes(
	obj interface{},
) ([]Node, error) {

	nodes, ok := obj.([]v1.Node)
	if false == ok {
		return nil,
			fmt.Errorf("poll update unexpected type, interface is not []v1.Node")
	}

	watchedNodes := []Node{}

	var addrType v1.NodeAddressType
	if ctlr.UseNodeInternal {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	// Append list of nodes to watchedNodes
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
		for _, addr := range nodeAddrs {
			if addr.Type == addrType {
				n := Node{
					Name:   node.ObjectMeta.Name,
					Addr:   addr.Address,
					Labels: make(map[string]string),
				}
				for k, v := range node.ObjectMeta.Labels {
					n.Labels[k] = v
				}
				watchedNodes = append(watchedNodes, n)
			}
		}
	}

	return watchedNodes, nil
}

func (ctlr *Controller) getNodesWithLabel(
	nodeMemberLabel, clusterName string,
) []Node {
	allNodes := ctlr.getNodesFromCache(clusterName)
	label := strings.Split(nodeMemberLabel, "=")
	if len(label) != 2 {
		log.Warningf("Invalid NodeMemberLabel: %v %v", nodeMemberLabel, getClusterLog(clusterName))
		return nil
	}
	labelKey := label[0]
	labelValue := label[1]
	var nodes []Node
	for _, node := range allNodes {
		if node.Labels[labelKey] == labelValue {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func ciliumPodCidr(annotation map[string]string) string {
	if subnet, ok := annotation[CiliumK8sNodeSubnetAnnotation13]; ok {
		return subnet
	} else if subnet, ok := annotation[CiliumK8sNodeSubnetAnnotation12]; ok {
		return subnet
	}
	return ""
}

func (ctlr *Controller) processStaticRouteUpdate(
	nodes []interface{},
) {
	//if static-routing-mode process static routes
	var addrType v1.NodeAddressType
	if ctlr.UseNodeInternal {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}
	log.Debugf("Processing Node Updates for static routes")
	routes := routeSection{}
	for _, obj := range nodes {
		node := obj.(*v1.Node)
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
		route := routeConfig{}
		// For ovn-k8s get pod subnet and node ip from annotation
		if ctlr.OrchestrationCNI == OVN_K8S {
			annotations := node.Annotations
			if nodeSubnetAnn, ok := annotations[OVNK8sNodeSubnetAnnotation]; !ok {
				log.Warningf("Node subnet annotation %v not found on node %v static route not added", OVNK8sNodeSubnetAnnotation, node.Name)
				continue
			} else {
				nodesubnet, err := parseNodeSubnet(nodeSubnetAnn, node.Name)
				if err != nil {
					log.Warningf("Node subnet annotation %v not properly configured for node %v:%v", OVNK8sNodeSubnetAnnotation, node.Name, err)
					continue
				}
				route.Network = nodesubnet
			}
			if ctlr.StaticRouteNodeCIDR != "" {
				_, nodenetwork, err := net.ParseCIDR(ctlr.StaticRouteNodeCIDR)
				if err != nil {
					log.Errorf("Unable to parse cidr %v with error %v", ctlr.StaticRouteNodeCIDR, err)
					continue
				} else {
					var hostaddresses string
					var ok bool
					var nodeIP string
					var err error
					if hostaddresses, ok = annotations[OVNK8sNodeIPAnnotation2]; !ok {
						//For ocp 4.14 and above check for new annotation
						if hostaddresses, ok = annotations[OvnK8sNodeIPAnnotation3]; !ok {
							log.Warningf("Host addresses annotation %v not found on node %v static route not added", OVNK8sNodeIPAnnotation2, node.Name)
							continue
						} else {
							nodeIP, err = parseHostCIDRS(hostaddresses, nodenetwork)
							if err != nil {
								log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OvnK8sNodeIPAnnotation3, node.Name, err)
								continue
							}
							route.Gateway = nodeIP
							route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
						}
					} else {
						nodeIP, err = parseHostAddresses(hostaddresses, nodenetwork)
						if err != nil {
							log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OVNK8sNodeIPAnnotation2, node.Name, err)
							continue
						}
						route.Gateway = nodeIP
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
					}
				}
			} else {
				if nodeIPAnn, ok := annotations[OVNK8sNodeIPAnnotation]; !ok {
					log.Warningf("Node IP annotation %v not found on node %v static route not added", OVNK8sNodeSubnetAnnotation, node.Name)
					continue
				} else {
					nodeIP, err := parseNodeIP(nodeIPAnn, node.Name)
					if err != nil {
						log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OVNK8sNodeIPAnnotation, node.Name, err)
						continue
					}
					route.Gateway = nodeIP
					route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
				}
			}
		} else if ctlr.OrchestrationCNI == CILIUM_K8S {
			nodesubnet := ciliumPodCidr(node.ObjectMeta.Annotations)
			if nodesubnet == "" {
				log.Warningf("Cilium node podCIDR annotation not found on node %v, node has spec.podCIDR ?", node.Name)
				continue
			} else {
				route.Network = nodesubnet
				nodeAddrs := node.Status.Addresses
				for _, addr := range nodeAddrs {
					if addr.Type == addrType {
						route.Gateway = addr.Address
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, addr.Address)
					}
				}

			}
		} else {
			//For k8s CNI like flannel, antrea etc we can get subnet from node spec
			podCIDR := node.Spec.PodCIDR
			if podCIDR != "" {
				route.Network = podCIDR
				nodeAddrs := node.Status.Addresses
				for _, addr := range nodeAddrs {
					if addr.Type == addrType {
						route.Gateway = addr.Address
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, addr.Address)
					}
				}
			} else {
				log.Debugf("podCIDR is not found on node %v so not adding the static route for node", node.Name)
				continue
			}
		}
		routes.Entries = append(routes.Entries, route)
	}
	doneCh, errCh, err := ctlr.Agent.ConfigWriter.SendSection("static-routes", routes)

	if nil != err {
		log.Warningf("Failed to write static routes config section: %v", err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("Wrote static route config section: %v", routes)
		case e := <-errCh:
			log.Warningf("Failed to write static route config section: %v", e)
		case <-time.After(time.Second):
			log.Warningf("Did not receive write response in 1s")
		}
	}
}

func parseNodeSubnet(ann, nodeName string) (string, error) {
	var subnetDict map[string]interface{}
	json.Unmarshal([]byte(ann), &subnetDict)
	if nodeSubnet, ok := subnetDict["default"]; ok {
		switch nodeSubnetObj := nodeSubnet.(type) {
		case string:
			return nodeSubnet.(string), nil
		case []interface{}:
			for _, subnet := range nodeSubnetObj {
				ip, _, err := net.ParseCIDR(subnet.(string))
				if err != nil {
					log.Errorf("Unable to parse cidr for subnet %v with err %v", subnet, err)
				} else {
					//check for ipv4 address
					if nil != ip.To4() {
						return subnet.(string), nil
					}
				}
			}
		default:
			return "", fmt.Errorf("Unsupported annotation format")
		}
	}
	err := fmt.Errorf("%s annotation for "+
		"node '%s' has invalid format; cannot validate node subnet. "+
		"Should be of the form: '{\"default\":\"<node-subnet>\"}'", OVNK8sNodeSubnetAnnotation, nodeName)
	return "", err
}

func parseNodeIP(ann, nodeName string) (string, error) {
	var IPDict map[string]interface{}
	json.Unmarshal([]byte(ann), &IPDict)
	if IP, ok := IPDict["ipv4"]; ok {
		ipmask := IP.(string)
		nodeip := strings.Split(ipmask, "/")[0]
		return nodeip, nil
	}
	err := fmt.Errorf("%s annotation for "+
		"node '%s' has invalid format; cannot validate node IP. "+
		"Should be of the form: '{\"ipv4\":\"<node-ip>\"}'", OVNK8sNodeIPAnnotation, nodeName)
	return "", err
}

func parseHostAddresses(ann string, nodenetwork *net.IPNet) (string, error) {
	var hostaddresses []string
	json.Unmarshal([]byte(ann), &hostaddresses)
	for _, IP := range hostaddresses {
		ip := net.ParseIP(IP)
		if nodenetwork.Contains(ip) {
			return ip.String(), nil
		}
	}
	err := fmt.Errorf("Cannot get nodeip from %s within nodenetwork %v", OVNK8sNodeIPAnnotation2, nodenetwork)
	return "", err
}

func parseHostCIDRS(ann string, nodenetwork *net.IPNet) (string, error) {
	var hostcidrs []string
	json.Unmarshal([]byte(ann), &hostcidrs)
	for _, cidr := range hostcidrs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("Unable to parse cidr %v with error %v", cidr, err)
		} else {
			if nodenetwork.Contains(ip) {
				return ip.String(), nil
			}
		}
	}
	err := fmt.Errorf("Cannot get nodeip from %s within nodenetwork %v", OvnK8sNodeIPAnnotation3, nodenetwork)
	return "", err
}
