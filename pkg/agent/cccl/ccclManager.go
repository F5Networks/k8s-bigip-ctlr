/*-
 * Copyright (c) 2016-2019, F5 Networks, Inc.
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

package cccl

import (
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/health"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/vxlan"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/pkg/prometheus"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"os"
	"strings"
	"time"

	//routeapi "github.com/openshift/api/route/v1"
)



// AS3AS3Manager holds all the AS3 orchestration specific Data
type CCCLManager struct {
	configWriter		writer.Writer
	eventChan     		chan interface{}
	vxlanName     		string
	vxlanMode           string
	flannelName   		string
	pythonBaseDir 		string
	subPid        		int
	nodePollInterval	int
	useNodeInternal     bool
	nodeLabelSelector   string
	kubeClient          kubernetes.Interface
	processNodeUpdate   func (obj interface{}, err error)
	NodePoller          pollers.Poller
	httpAddress         string
	AgentRequestConfig
	GlobalSection
	BigIPSection
}


const (
)

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	KubeClient             kubernetes.Interface
	ConfigWriter           writer.Writer
	EventChan              chan interface{}
	restClient             rest.Interface
	//SchemaLocal            string
	Agent                  string
	VxLanName              string
	VxlanMode              string
	FlannelName            string
	PythonBaseDir          string
	NodePollInterval	   int
	NodeLabelSelector      string
	HttpAddress            string
	UseNodeInternal        bool
	ProcessNodeUpdate      func (obj interface{}, err error)
	agentRequestChan       chan AgentRequestConfig
	GlobalSection
	BigIPSection
}

type AgentRequestConfig struct {
	//PoolMembers    map[string]endPoints
	resources      *Resources
	customProfiles *CustomProfileStore
	irulesMap      IRulesMap
	intDgMap       InternalDataGroupMap
	intF5Res       InternalF5ResourcesGroup
}

type GlobalSection struct {
	LogLevel       string `json:"log-level,omitempty"`
	VerifyInterval int    `json:"verify-interval,omitempty"`
	VXLANPartition string `json:"vxlan-partition,omitempty"`
}

type BigIPSection struct {
	BigIPUsername   string   `json:"username,omitempty"`
	BigIPPassword   string   `json:"password,omitempty"`
	BigIPURL        string   `json:"url,omitempty"`
	BigIPPartitions []string `json:"partitions,omitempty"`
}

// Create and return a new app manager that meets the Manager interface
func NewCCCLManager(params *Params) *CCCLManager {
	CCCLManager := CCCLManager{
		configWriter:           getConfigWriter(),
		eventChan:              params.EventChan,
		GlobalSection:			params.GlobalSection,
		BigIPSection:			params.BigIPSection,
		pythonBaseDir:          params.PythonBaseDir,
		useNodeInternal:        params.UseNodeInternal,
		processNodeUpdate:      params.ProcessNodeUpdate,

		//schemaLocal:            params.SchemaLocal,
	}
	return &CCCLManager
}

func (c *CCCLManager) ConfigWriter() writer.Writer {
	return c.configWriter
}

func (c *CCCLManager) UseNodeInternal() bool {
	return c.useNodeInternal
}

func  getConfigWriter() writer.Writer {
	configWriter, err := writer.NewConfigWriter()
	if nil != err {
		log.Fatalf("Failed creating ConfigWriter tool: %v", err)
		os.Exit(1)
	}
	return configWriter
}

func (c *CCCLManager) setupL2L3() {
	var eventChan chan interface{}
	if len(c.flannelName) > 0 {
		eventChan = make(chan interface{})
		c.eventChan = eventChan
	}

	// If running in VXLAN mode, extract the partition name from the tunnel
	// to be used in configuring a net instance of CCCL for that partition
	if len(c.vxlanName) > 0 {
		cleanPath := strings.TrimLeft(c.vxlanName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos == -1 {
			// No partition
			c.GlobalSection.VXLANPartition = "Common"
		} else {
			// Partition and name
			c.GlobalSection.VXLANPartition = cleanPath[:slashPos]
		}
	}

	subPidCh, err := c.startPythonDriver()
	if nil != err {
		log.Fatalf("Could not initialize subprocess configuration: %v", err)
	}
	c.subPid = <-subPidCh
	defer func(pid int) {
		if 0 != pid {
			var proc *os.Process
			proc, err = os.FindProcess(pid)
			if nil != err {
				log.Warningf("Failed to find sub-process on exit: %v", err)
			}
			err = proc.Signal(os.Interrupt)
			if nil != err {
				log.Warningf("Could not stop sub-process on exit: %d - %v", pid, err)
			}
		}
	}(c.subPid)

	intervalFactor := time.Duration(c.nodePollInterval)
	c.NodePoller = pollers.NewNodePoller(c.kubeClient, intervalFactor*time.Second, c.nodeLabelSelector)
	err = c.setupNodePolling()
	if nil != err {
		log.Fatalf("Required polling utility for node updates failed setup: %v", err)
		os.Exit(1)
	}
	c.NodePoller.Run()
}

func (c *CCCLManager) setupL4L7() {
	http.Handle("/metrics", promhttp.Handler())
	// Add health check e.g. is Python process still there?
	hc := &health.HealthChecker{
		SubPID: c.subPid,
	}
	http.Handle("/health", hc.HealthCheckHandler())
	bigIPPrometheus.RegisterMetrics()
	go func() {
		log.Fatal(http.ListenAndServe(c.httpAddress, nil).Error())
	}()
}

func (c *CCCLManager)setupNodePolling( ) error {
	// Register appMgr to watch for node updates to keep track of watched nodes
	err := c.NodePoller.RegisterListener(c.processNodeUpdate)
	if nil != err {
		return fmt.Errorf("error registering node update listener: %v",
			err)
	}

	if 0 != len(c.vxlanMode) {
		// If partition is part of vxlanName, extract just the tunnel name
		tunnelName := c.vxlanName
		cleanPath := strings.TrimLeft(c.vxlanName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos != -1 {
			tunnelName = cleanPath[slashPos+1:]
		}
		vxMgr, err := vxlan.NewVxlanMgr(
			c.vxlanMode,
			tunnelName,
			c.UseNodeInternal(),
			c.ConfigWriter(),
			c.eventChan,
		)
		if nil != err {
			return fmt.Errorf("error creating vxlan manager: %v", err)
		}

		// Register vxMgr to watch for node updates to process fdb records
		err = c.NodePoller.RegisterListener(vxMgr.ProcessNodeUpdate)
		if nil != err {
			return fmt.Errorf("error registering node update listener for vxlan mode: %v",
				err)
		}
		if c.eventChan != nil {
			vxMgr.ProcessAppmanagerEvents(c.kubeClient)
		}
	}

	return nil
}