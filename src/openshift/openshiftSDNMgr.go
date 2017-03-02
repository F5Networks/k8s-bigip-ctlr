package openshift

import (
	"fmt"
	"time"

	log "f5/vlogger"
	"tools/writer"

	"k8s.io/client-go/1.4/pkg/api/v1"
)

type sdnSection struct {
	VxLAN string   `json:"vxlan-name"`
	Nodes []string `json:"vxlan-node-ips"`
}

type OpenshiftSDNMgr struct {
	mode       string
	vxLAN      string
	useNodeInt bool
	config     writer.Writer
}

func NewOpenshiftSDNMgr(
	mode string,
	vxLAN string,
	useNodeInternal bool,
	config writer.Writer,
) (*OpenshiftSDNMgr, error) {
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

	osMgr := &OpenshiftSDNMgr{
		mode:       mode,
		vxLAN:      vxLAN,
		useNodeInt: useNodeInternal,
		config:     config,
	}

	return osMgr, nil
}

func (osm *OpenshiftSDNMgr) ProcessNodeUpdate(obj interface{}, err error) {
	if nil != err {
		log.Warningf("Openshift manager (%s) unable to get list of nodes: %v",
			osm.vxLAN, err)
		return
	}

	nodes, ok := obj.([]v1.Node)
	if false == ok {
		log.Warningf("Openshift manager (%s) received poll update with unexpected type",
			osm.vxLAN)
		return
	}

	var addrs []string
	var addrType v1.NodeAddressType
	if osm.useNodeInt {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	for _, node := range nodes {
		if node.Spec.Unschedulable {
			// Skip unschedulable nodes
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

	doneCh, errCh, err := osm.config.SendSection(
		"openshift-sdn",
		sdnSection{
			VxLAN: osm.vxLAN,
			Nodes: addrs,
		},
	)

	if nil != err {
		log.Warningf("Openshift manager (%s) failed to write config section: %v",
			osm.vxLAN, err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("Openshift manager (%s) wrote config section: %v",
				osm.vxLAN, addrs)
		case e := <-errCh:
			log.Warningf("Openshift manager (%s) failed to write config section: %v",
				osm.vxLAN, e)
		case <-time.After(time.Second):
			log.Warningf("Openshift manager (%s) did not receive write response in 1s",
				osm.vxLAN)
		}
	}
}
