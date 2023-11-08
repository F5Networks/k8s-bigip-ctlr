package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func (postMgr *PostManager) checkPrimaryClusterHealthStatus() bool {

	status := false
	for i := 1; i <= 2; i++ {
		switch postMgr.PrimaryClusterHealthProbeParams.EndPointType {
		case "http":
			status = postMgr.getPrimaryClusterHealthStatusFromHTTPEndPoint()
		case "tcp":
			status = postMgr.getPrimaryClusterHealthStatusFromTCPEndPoint()
		case "", "default":
			log.Debugf("[MultiCluster] unsupported primaryEndPoint specified under highAvailabilityCIS section: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
			return false
		}

		if status {
			return status
		}
		time.Sleep(time.Duration(postMgr.PrimaryClusterHealthProbeParams.retryInterval) * time.Second)
	}
	return false
}

// getPrimaryClusterHealthCheckEndPointType method determines type of probe to be done from CIS parameters
// http/tcp are the supported types
// when cis runs in primary mode this method should never be called
// should be called only when cis is running in secondary mode
func (postMgr *PostManager) setPrimaryClusterHealthCheckEndPointType() {
	if postMgr.PrimaryClusterHealthProbeParams.EndPoint != "" {
		if strings.HasPrefix(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "tcp://") {
			postMgr.PrimaryClusterHealthProbeParams.EndPointType = "tcp"
		} else if strings.HasPrefix(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "http://") {
			postMgr.PrimaryClusterHealthProbeParams.EndPointType = "http"
		} else {
			log.Debugf("[MultiCluster] unsupported primaryEndPoint protocol type configured under highAvailabilityCIS section. EndPoint: %v \n "+
				"supported protocols:[http, tcp] ", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
			os.Exit(1)
		}
	}
}

// getPrimaryClusterHealthStatusFromHTTPEndPoint check the primary cluster health using http endPoint
func (postMgr *PostManager) getPrimaryClusterHealthStatusFromHTTPEndPoint() bool {

	if postMgr.PrimaryClusterHealthProbeParams.EndPoint == "" {
		return false
	}
	if !strings.HasPrefix(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "http://") {
		log.Debugf("[MultiCluster] Error: invalid primaryEndPoint detected under highAvailabilityCIS section: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
		return false
	}

	req, err := http.NewRequest("GET", postMgr.PrimaryClusterHealthProbeParams.EndPoint, nil)
	if err != nil {
		log.Errorf("[MultiCluster] Creating new HTTP request error: %v ", err)
		return false
	}

	timeOut := postMgr.httpClient.Timeout
	defer func() {
		postMgr.httpClient.Timeout = timeOut
	}()
	if postMgr.PrimaryClusterHealthProbeParams.statusChanged {
		log.Debugf("[MultiCluster] posting GET Check primaryEndPoint Health request on %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
	}
	postMgr.httpClient.Timeout = 10 * time.Second

	httpResp := postMgr.httpGetReq(req)
	if httpResp == nil {
		return false
	}
	switch httpResp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusNotFound, http.StatusInternalServerError:
		log.Debugf("[MultiCluster] error fetching primaryEndPoint health status. endPoint:%v, statusCode: %v, error:%v",
			postMgr.PrimaryClusterHealthProbeParams.EndPoint, httpResp.StatusCode, httpResp.Request.Response)
	}
	return false
}

// getPrimaryClusterHealthStatusFromTCPEndPoint check the primary cluster health using tcp endPoint
func (postMgr *PostManager) getPrimaryClusterHealthStatusFromTCPEndPoint() bool {
	if postMgr.PrimaryClusterHealthProbeParams.EndPoint == "" {
		return false
	}
	if !strings.HasPrefix(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "tcp://") {
		log.Debugf("[MultiCluster] invalid primaryEndPoint health probe tcp endpoint: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
		return false
	}

	_, err := net.Dial("tcp", strings.TrimLeft(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "tcp://"))
	if err != nil {
		log.Debugf("[MultiCluster] error connecting to primaryEndPoint tcp health probe: %v, error: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint, err)
		return false
	}
	return true
}

func (postMgr *PostManager) httpGetReq(request *http.Request) *http.Response {
	httpResp, err := postMgr.httpClient.Do(request)

	if err != nil {
		if postMgr.PrimaryClusterHealthProbeParams.statusChanged {
			log.Debugf("[MultiCluster] REST call error: %v ", err)
		}
		return nil
	}

	return httpResp
}

/*
	* probePrimaryClusterHealthStatus runs as a thread
	* this method check the cluster health periodically
		* will start probing only after init state is processed
		* if cluster is up earlier and now its down then resource queue event will be triggered
		* if cluster is down earlier and now also its down then we will skip processing
		* if cluster is up and running there is no status change then we skip the processing

*/

func (ctlr *Controller) probePrimaryClusterHealthStatus() {
	for {
		if ctlr.initState {
			continue
		}
		ctlr.getPrimaryClusterHealthStatus()
	}
}

func (ctlr *Controller) getPrimaryClusterHealthStatus() {

	// only process when the cis is initialized
	status := ctlr.Agent.checkPrimaryClusterHealthStatus()
	// if status is changed i.e from up -> down / down -> up
	ctlr.Agent.PrimaryClusterHealthProbeParams.paramLock.Lock()
	if ctlr.Agent.PrimaryClusterHealthProbeParams.statusRunning != status {
		ctlr.Agent.PrimaryClusterHealthProbeParams.statusChanged = true
		// if primary cis id down then post the config
		if !status {
			ctlr.Agent.PrimaryClusterHealthProbeParams.statusRunning = false
			ctlr.enqueuePrimaryClusterProbeEvent()
		} else {
			ctlr.Agent.PrimaryClusterHealthProbeParams.statusRunning = true
		}
		//update cccl global section with primary cluster running status
		doneCh, errCh, err := ctlr.Agent.ConfigWriter.SendSection("primary-cluster-status", ctlr.Agent.PrimaryClusterHealthProbeParams.statusRunning)

		if nil != err {
			log.Warningf("[MultiCluster] Failed to write primary-cluster-status section: %v", err)
		} else {
			select {
			case <-doneCh:
				log.Debugf("[MultiCluster] Wrote primary-cluster-status as %v", ctlr.Agent.PrimaryClusterHealthProbeParams.statusRunning)
			case e := <-errCh:
				log.Warningf("[MultiCluster] Failed to write primary-cluster-status config section: %v", e)
			case <-time.After(time.Second):
				log.Warningf("[MultiCluster] Did not receive write response in 1s")
			}
		}
	} else {
		ctlr.Agent.PrimaryClusterHealthProbeParams.statusChanged = false
	}
	ctlr.Agent.PrimaryClusterHealthProbeParams.paramLock.Unlock()
	// wait for configured probeInterval
	time.Sleep(time.Duration(ctlr.Agent.PrimaryClusterHealthProbeParams.probeInterval) * time.Second)
}

func (ctlr *Controller) firstPollPrimaryClusterHealthStatus() {
	ctlr.Agent.PrimaryClusterHealthProbeParams.statusRunning = ctlr.Agent.checkPrimaryClusterHealthStatus()
	ctlr.Agent.PrimaryClusterHealthProbeParams.statusChanged = true
}
