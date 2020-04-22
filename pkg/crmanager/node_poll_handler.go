package crmanager

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/vxlan"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

func (crMgr *CRManager) SetupNodePolling(
	nodePollInterval int,
	nodeLabelSelector string,
	vxlanMode string,
	vxlanName string,
) error {
	intervalFactor := time.Duration(nodePollInterval)
	crMgr.nodePoller = pollers.NewNodePoller(crMgr.kubeClient, intervalFactor*time.Second, nodeLabelSelector)

	// Register appMgr to watch for node updates to keep track of watched nodes
	err := crMgr.nodePoller.RegisterListener(crMgr.ProcessNodeUpdate)
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
			crMgr.UseNodeInternal,
			crMgr.Agent.ConfigWriter,
			crMgr.Agent.EventChan,
		)
		if nil != err {
			return fmt.Errorf("error creating vxlan manager: %v", err)
		}

		// Register vxMgr to watch for node updates to process fdb records
		err = crMgr.nodePoller.RegisterListener(vxMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for vxlan mode: %v",
				err)
		}
		if crMgr.Agent.EventChan != nil {
			// It handles arp entries related to PoolMembers
			vxMgr.ProcessAppmanagerEvents(crMgr.kubeClient)
		}
	}

	return nil
}

type Node struct {
	Name string
	Addr string
}

// Check for a change in Node state
func (crMgr *CRManager) ProcessNodeUpdate(
	obj interface{}, err error,
) {
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}

	newNodes, err := crMgr.getNodes(obj)
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}

	// Only check for updates once we are out of initial state
	if !crMgr.initState {
		// Compare last set of nodes with new one
		if !reflect.DeepEqual(newNodes, crMgr.oldNodes) {
			log.Infof("ProcessNodeUpdate: Change in Node state detected")

			for _, ns := range crMgr.namespaces {
				virtuals := crMgr.getAllVirtualServers(ns)
				for _, virtual := range virtuals {
					qKey := &rqKey{
						ns,
						VirtualServer,
						virtual.ObjectMeta.Name,
						virtual,
					}
					crMgr.rscQueue.Add(qKey)
				}
			}

			// Update node cache
			crMgr.oldNodes = newNodes
		}
	} else {
		// Initialize crMgr nodes on our first pass through
		crMgr.oldNodes = newNodes
	}
}

// Return a copy of the node cache
func (crMgr *CRManager) getNodesFromCache() []Node {
	nodes := make([]Node, len(crMgr.oldNodes))
	copy(nodes, crMgr.oldNodes)

	return nodes
}

// Get a list of Node addresses
func (crMgr *CRManager) getNodes(
	obj interface{},
) ([]Node, error) {

	nodes, ok := obj.([]v1.Node)
	if false == ok {
		return nil,
			fmt.Errorf("poll update unexpected type, interface is not []v1.Node")
	}

	watchedNodes := []Node{}

	var addrType v1.NodeAddressType
	if crMgr.UseNodeInternal {
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
					Name: node.ObjectMeta.Name,
					Addr: addr.Address,
				}
				watchedNodes = append(watchedNodes, n)
			}
		}
	}

	return watchedNodes, nil
}
