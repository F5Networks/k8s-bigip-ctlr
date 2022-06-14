package controller

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/vxlan"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

func (ctlr *Controller) SetupNodePolling(
	nodePollInterval int,
	nodeLabelSelector string,
	vxlanMode string,
	vxlanName string,
) error {
	intervalFactor := time.Duration(nodePollInterval)
	ctlr.nodePoller = pollers.NewNodePoller(ctlr.kubeClient, intervalFactor*time.Second, nodeLabelSelector)

	// Register appMgr to watch for node updates to keep track of watched nodes
	err := ctlr.nodePoller.RegisterListener(ctlr.ProcessNodeUpdate)
	if nil != err {
		return fmt.Errorf("error registering node update listener: %v",
			err)
	}

	if 0 != len(vxlanMode) {
		// If partition is part of vxlanName, extract just the tunnel name
		tunnelName := vxlanName
		cleanPath := strings.TrimLeft(vxlanName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos != -1 {
			tunnelName = cleanPath[slashPos+1:]
		}
		vxMgr, err := vxlan.NewVxlanMgr(
			vxlanMode,
			tunnelName,
			ctlr.UseNodeInternal,
			ctlr.Agent.ConfigWriter,
			ctlr.Agent.EventChan,
		)
		if nil != err {
			return fmt.Errorf("error creating vxlan manager: %v", err)
		}

		// Register vxMgr to watch for node updates to process fdb records
		err = ctlr.nodePoller.RegisterListener(vxMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for vxlan mode: %v",
				err)
		}
		if ctlr.Agent.EventChan != nil {
			// It handles arp entries related to PoolMembers
			vxMgr.ProcessAppmanagerEvents(ctlr.kubeClient)
		}
	}

	return nil
}

// Check for a change in Node state
func (ctlr *Controller) ProcessNodeUpdate(
	obj interface{}, err error,
) {
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}

	newNodes, err := ctlr.getNodes(obj)
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}

	// Only check for updates once we are out of initial state
	if !ctlr.initState {
		// Compare last set of nodes with new one
		if !reflect.DeepEqual(newNodes, ctlr.oldNodes) {
			log.Debugf("Processing Node Updates")
			// Handle NodeLabelUpdates
			if ctlr.PoolMemberType == NodePort {
				if ctlr.watchingAllNamespaces() {
					crInf, _ := ctlr.getNamespacedInformer("")
					virtuals := crInf.vsInformer.GetIndexer().List()
					if len(virtuals) != 0 {
						for _, virtual := range virtuals {
							vs := virtual.(*cisapiv1.VirtualServer)
							qKey := &rqKey{
								vs.ObjectMeta.Namespace,
								VirtualServer,
								vs.ObjectMeta.Name,
								vs,
								Update,
							}
							ctlr.rscQueue.Add(qKey)
						}
					}
					transportVirtuals := crInf.tsInformer.GetIndexer().List()
					if len(transportVirtuals) != 0 {
						for _, virtual := range transportVirtuals {
							vs := virtual.(*cisapiv1.TransportServer)
							qKey := &rqKey{
								vs.ObjectMeta.Namespace,
								TransportServer,
								vs.ObjectMeta.Name,
								vs,
								Update,
							}
							ctlr.rscQueue.Add(qKey)
						}
					}

				} else {
					ctlr.namespacesMutex.Lock()
					defer ctlr.namespacesMutex.Unlock()
					for ns, _ := range ctlr.namespaces {
						virtuals := ctlr.getAllVirtualServers(ns)
						transportVirtuals := ctlr.getAllTransportServers(ns)
						for _, virtual := range virtuals {
							qKey := &rqKey{
								ns,
								VirtualServer,
								virtual.ObjectMeta.Name,
								virtual,
								Update,
							}
							ctlr.rscQueue.Add(qKey)
						}
						for _, virtual := range transportVirtuals {
							qKey := &rqKey{
								ns,
								TransportServer,
								virtual.ObjectMeta.Name,
								virtual,
								Update,
							}
							ctlr.rscQueue.Add(qKey)
						}
					}
				}
			}
			// Update node cache
			ctlr.oldNodes = newNodes
		}
	} else {
		// Initialize controller nodes on our first pass through
		ctlr.oldNodes = newNodes
	}
}

// Return a copy of the node cache
func (ctlr *Controller) getNodesFromCache() []Node {
	nodes := make([]Node, len(ctlr.oldNodes))
	copy(nodes, ctlr.oldNodes)

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
	nodeMemberLabel string,
) []Node {
	allNodes := ctlr.getNodesFromCache()

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
