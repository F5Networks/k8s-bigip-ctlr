package controller

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
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
		clusterNodes := ctlr.getNodesFromAllClusters()
		ctlr.processStaticRouteUpdate(clusterNodes)
	} else if ctlr.vxlanMgr != nil {
		// Register vxMgr to watch for node updates to process fdb records
		ctlr.vxlanMgr.ProcessNodeUpdate(nodesList)
	}
	return nil
}

//func (ctlr *Controller) SetupNodeProcessing() error {
//	//when there is update from node informer get list of nodes from nodeinformer cache
//	ns := ""
//	if ctlr.watchingAllNamespaces() {
//		ns = ""
//	} else {
//		for k := range ctlr.namespaces {
//			ns = k
//			break
//		}
//	}
//	appInf, _ := ctlr.getNamespacedCommonInformer(ns)
//	nodes := appInf.nodeInformer.GetIndexer().List()
//	var nodeslist []v1.Node
//	for _, obj := range nodes {
//		node := obj.(*v1.Node)
//		nodeslist = append(nodeslist, *node)
//	}
//	sort.Sort(NodeList(nodeslist))
//	ctlr.ProcessNodeUpdate(nodeslist)
//	// adding the bigip_monitored_nodes	metrics
//	bigIPPrometheus.MonitoredNodes.WithLabelValues(ctlr.nodeLabelSelector).Set(float64(len(ctlr.oldNodes)))
//	if ctlr.StaticRoutingMode {
//		ctlr.processStaticRouteUpdate(nodes)
//	} else if 0 != len(ctlr.vxlanMode) {
//		// If partition is part of vxlanName, extract just the tunnel name
//		tunnelName := ctlr.vxlanName
//		cleanPath := strings.TrimLeft(ctlr.vxlanName, "/")
//		slashPos := strings.Index(cleanPath, "/")
//		if slashPos != -1 {
//			tunnelName = cleanPath[slashPos+1:]
//		}
//		vxMgr, err := vxlan.NewVxlanMgr(
//			ctlr.vxlanMode,
//			tunnelName,
//			ctlr.ciliumTunnelName,
//			ctlr.UseNodeInternal,
//			ctlr.Agent.ConfigWriter,
//			ctlr.Agent.EventChan,
//		)
//		if nil != err {
//			return fmt.Errorf("error creating vxlan manager: %v", err)
//		}
//
//		// Register vxMgr to watch for node updates to process fdb records
//		vxMgr.ProcessNodeUpdate(nodeslist)
//		if ctlr.Agent.EventChan != nil && !ctlr.Agent.disableARP {
//			// It handles arp entries related to PoolMembers
//			vxMgr.ProcessAppmanagerEvents(ctlr.kubeClient)
//		}
//	}
//
//	return nil
//}

// Check for a change in Node state
// ProcessNodeUpdate Check for a change in Node state
func (ctlr *Controller) ProcessNodeUpdate(obj interface{}, clusterName string) {
	newNodes, err := ctlr.getNodes(obj)
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}
	// process the node and update the all pool members for the cluster
	if !ctlr.initState {
		if clusterName == "" {
			// Compare last set of nodes with new one
			if !reflect.DeepEqual(newNodes, ctlr.oldNodes) {
				log.Debugf("Processing Node Updates for current cluster")
				// Update node cache
				ctlr.oldNodes = newNodes
				//if _, ok := ctlr.multiClusterResources.clusterSvcMap[clusterName]; ok {
				ctlr.UpdatePoolMembersForNodeUpdate(clusterName)
				//}
			}
		} else {
			if nodeInf, ok := ctlr.multiClusterNodeInformers[clusterName]; ok {
				// Compare last set of nodes with new one
				if !reflect.DeepEqual(newNodes, nodeInf.oldNodes) {
					log.Debugf("Processing Node Updates for %v", clusterName)
					// Update node cache
					nodeInf.oldNodes = newNodes
					if ctlr.multiClusterResources.clusterSvcMap != nil {
						if _, ok := ctlr.multiClusterResources.clusterSvcMap[clusterName]; ok {
							ctlr.UpdatePoolMembersForNodeUpdate(clusterName)
						}
					}
				}
			}
		}
	} else {
		// Initialize controller nodes on our first pass through
		log.Debugf("Initialising controller monitored kubernetes nodes.")
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
	if svcKeys, ok := ctlr.multiClusterResources.clusterSvcMap[clusterName]; ok {
		for svcKey, _ := range svcKeys {
			ctlr.updatePoolMembersForService(svcKey)
		}
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
		for _, t := range node.Spec.Taints {
			if v1.TaintEffectNoExecute == t.Effect {
				notExecutable = true
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
		log.Warningf("Invalid NodeMemberLabel: %v", nodeMemberLabel)
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

	routes := routeSection{}
	for _, obj := range nodes {
		node := obj.(*v1.Node)
		// Ignore the Nodes with status NotReady
		var notExecutable bool
		for _, t := range node.Spec.Taints {
			if v1.TaintEffectNoExecute == t.Effect {
				notExecutable = true
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
