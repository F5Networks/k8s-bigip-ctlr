package controller

import (
	"context"
	"encoding/json"
	"fmt"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"
)

func (ctlr *Controller) SetupNodeProcessing(clusterName string) error {
	var nodesIntfc []interface{}
	if infStore, ok := ctlr.multiClusterHandler.ClusterConfigs[clusterName]; ok {
		nodesIntfc = infStore.nodeInformer.nodeInformer.GetIndexer().List()
	}

	var nodesList []v1.Node
	for _, obj := range nodesIntfc {
		node := obj.(*v1.Node)
		nodesList = append(nodesList, *node)
	}
	sort.Sort(NodeList(nodesList))
	ctlr.ProcessNodeUpdate(nodesList, clusterName)
	// adding the bigip_monitored_nodes	metrics
	if nodesList != nil {
		bigIPPrometheus.MonitoredNodes.WithLabelValues(ctlr.multiClusterHandler.ClusterConfigs[clusterName].nodeLabelSelector).Set(float64(len(ctlr.multiClusterHandler.ClusterConfigs[clusterName].oldNodes)))
	}
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
		if config, ok := ctlr.multiClusterHandler.ClusterConfigs[clusterName]; ok {
			// Compare last set of nodes with new one
			if !reflect.DeepEqual(newNodes, config.oldNodes) {
				log.Debugf("[MultiCluster] Processing Node Updates for cluster: %s", clusterName)
				// Update node cache
				config.oldNodes = newNodes
				ctlr.UpdatePoolMembersForNodeUpdate(clusterName)
			}
		}
	} else {
		// Initialize controller nodes on our first pass through
		log.Debugf("%v Initialising controller monitored kubernetes nodes %v", ctlr.getMultiClusterLog(), getClusterLog(clusterName))
		if config, ok := ctlr.multiClusterHandler.ClusterConfigs[clusterName]; ok {
			// Update node cache
			config.oldNodes = newNodes
		}
	}
}

func (ctlr *Controller) UpdatePoolMembersForNodeUpdate(clusterName string) {
	// Add a request to the resource queue to update the pool members
	key := &rqKey{
		kind:        NodeUpdate,
		clusterName: clusterName,
	}
	ctlr.resourceQueue.Add(key)
}

// Return a copy of the node cache
func (ctlr *Controller) getNodesFromCache(clusterName string) []Node {
	var nodes []Node
	if config, ok := ctlr.multiClusterHandler.ClusterConfigs[clusterName]; ok {
		nodes = make([]Node, len(config.oldNodes))
		copy(nodes, config.oldNodes)
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
	if label[1] == "\"\"" {
		label[1] = ""
	}
	labelKey := label[0]
	labelValue := label[1]
	var nodes []Node
	for _, node := range allNodes {
		if val, ok := node.Labels[labelKey]; ok && val == labelValue {
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
	routes.CISIdentifier = ctlr.Partition + "_" + strings.TrimPrefix(ctlr.Agent.PostManager.BIGIPURL, "https://")
	nodePodCIDRMap := ctlr.GetNodePodCIDRMap()
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
		route.Description = routes.CISIdentifier
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
							routes.Entries = append(routes.Entries, route)
						}
					} else {
						nodeIP, err = parseHostAddresses(hostaddresses, nodenetwork)
						if err != nil {
							log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OVNK8sNodeIPAnnotation2, node.Name, err)
							continue
						}
						route.Gateway = nodeIP
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
						routes.Entries = append(routes.Entries, route)
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
					routes.Entries = append(routes.Entries, route)
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
						routes.Entries = append(routes.Entries, route)
					}
				}

			}
		} else if ctlr.OrchestrationCNI == CALICO_K8S {
			if nodePodCIDRMap != nil && len(nodePodCIDRMap) > 0 {
				if len(nodePodCIDRMap) != len(nodes) {
					//Wait for some time to get the nodePodCIDRMap in case a new node is added, it takes some time to create the block affinity for node
					time.Sleep(1 * time.Second)
					nodePodCIDRMap = ctlr.GetNodePodCIDRMap()
				}
				if nodeIPValue, ok := node.Annotations[CALICONodeIPAnnotation]; ok {
					for _, bacidr := range nodePodCIDRMap {
						if bacidr.nodeName == node.Name {
							route.Gateway = strings.Split(nodeIPValue, "/")[0]
							route.Name = fmt.Sprintf("k8s-%v", bacidr.baName)
							route.Network = bacidr.cidr
							routes.Entries = append(routes.Entries, route)
						} else {
							log.Warningf("Pod Network not found for node %v, static route not added", node.Name)
							continue
						}
					}
				} else {
					log.Warningf("Host addresses annotation %v not found on node %v ,static route not added", CALICONodeIPAnnotation, node.Name)
					continue
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
						routes.Entries = append(routes.Entries, route)
					}
				}
			} else {
				log.Debugf("podCIDR is not found on node %v so not adding the static route for node", node.Name)
				continue
			}
		}
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

func (ctlr *Controller) GetNodePodCIDRMap() []BlockAffinitycidr {
	var bacidrs []BlockAffinitycidr
	if ctlr.OrchestrationCNI == CALICO_K8S {
		// Retrieve Calico Block Affinity
		blockAffinitiesRaw, err := ctlr.multiClusterHandler.ClusterConfigs[ctlr.multiClusterHandler.LocalClusterName].kubeClient.Discovery().RESTClient().Get().AbsPath(CALICO_API_BLOCK_AFFINITIES).DoRaw(context.TODO())
		if err != nil {
			log.Warningf("Calico blockaffinity resource not found on the cluster, getting error %v", err)
			return bacidrs
		}
		// Define a map to store the unmarshalled data
		var blockAffinities unstructured.UnstructuredList

		// Unmarshal the JSON data into the unstructured list
		err = json.Unmarshal(blockAffinitiesRaw, &blockAffinities)
		if err != nil {
			log.Errorf("Unable to unmarshall block affinity resource %v, getting error %v", string(blockAffinitiesRaw), err)
			return bacidrs
		}
		for _, blockAffinity := range blockAffinities.Items {
			// Access the spec field from the unstructured object
			specData := blockAffinity.Object["spec"].(map[string]interface{})
			bacidr := BlockAffinitycidr{}
			bacidr.baName = blockAffinity.Object["metadata"].(map[string]interface{})["name"].(string)
			bacidr.nodeName = specData["node"].(string)
			bacidr.cidr = specData["cidr"].(string)
			bacidrs = append(bacidrs, bacidr)
		}
	}
	return bacidrs
}

func (ctlr *Controller) processBlockAffinities(clusterName string) {
	var baListInf []interface{}
	if infStore, ok := ctlr.multiClusterHandler.ClusterConfigs[clusterName]; ok {
		baListInf = infStore.dynamicInformers.CalicoBlockAffinityInformer.Informer().GetIndexer().List()
	}
	routes := routeSection{}
	routes.CISIdentifier = ctlr.Partition + "_" + strings.TrimPrefix(ctlr.Agent.PostManager.BIGIPURL, "https://")
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(clusterName)
	for _, obj := range baListInf {
		blockAffinity := obj.(*unstructured.Unstructured)
		baJSON, found, err := unstructured.NestedStringMap(blockAffinity.UnstructuredContent(), "spec")
		if err != nil || !found {
			log.Debugf("calico blockaffinity spec not found: %+v", err)
			continue
		}
		baName := blockAffinity.Object["metadata"].(map[string]interface{})["name"]
		route := routeConfig{}
		route.Description = routes.CISIdentifier
		if clusterConfig != nil {
			nodes := clusterConfig.oldNodes
			cidr := baJSON["cidr"]
			nodeName := baJSON["node"]
			//check if node is in watched nodes
			for _, node := range nodes {
				if node.Name == nodeName {
					route.Gateway = node.Addr
					route.Name = fmt.Sprintf("k8s-%v", baName)
					route.Network = cidr
					routes.Entries = append(routes.Entries, route)
					break
				}
			}
		}
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
