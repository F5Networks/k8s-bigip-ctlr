package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net"
	"net/http"
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
			log.Debugf("unsupported primary cluster health probe endPoint  : %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
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
		}
	}
}

// getPrimaryClusterHealthStatusFromHTTPEndPoint check the primary cluster health using http endPoint
func (postMgr *PostManager) getPrimaryClusterHealthStatusFromHTTPEndPoint() bool {

	if postMgr.PrimaryClusterHealthProbeParams.EndPoint == "" {
		return false
	}
	if !strings.HasPrefix(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "http://") {
		log.Debugf("Error: invalid health probe http endpoint: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
		return false
	}

	req, err := http.NewRequest("GET", postMgr.PrimaryClusterHealthProbeParams.EndPoint, nil)
	if err != nil {
		log.Errorf("Creating new HTTP request error: %v ", err)
		return false
	}

	timeOut := postMgr.httpClient.Timeout
	defer func() {
		postMgr.httpClient.Timeout = timeOut
	}()
	log.Debugf("posting GET Check Primary Cluster Health request on %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
	postMgr.httpClient.Timeout = 10 * time.Second

	httpResp := postMgr.httpGetReq(req)
	if httpResp == nil {
		return false
	}
	switch httpResp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusNotFound, http.StatusInternalServerError:
		log.Debugf("error fetching primary cluster health status. endPoint:%v, statusCode: %v, error:%v",
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
		log.Debugf("invalid health probe tcp endpoint: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint)
		return false
	}

	_, err := net.Dial("tcp", strings.TrimLeft(postMgr.PrimaryClusterHealthProbeParams.EndPoint, "tcp://"))
	if err != nil {
		log.Debugf("error connecting to primary cluster tcp health probe endPoint: %v, error: %v", postMgr.PrimaryClusterHealthProbeParams.EndPoint, err)
		return false
	}
	return true
}

func (postMgr *PostManager) httpGetReq(request *http.Request) *http.Response {
	httpResp, err := postMgr.httpClient.Do(request)

	if err != nil {
		log.Errorf("REST call error: %v ", err)
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
		// only process when the cis is initialized
		status := ctlr.Agent.PostManager.checkPrimaryClusterHealthStatus()
		// if status is changed i.e from up -> down / down -> up
		if ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusRunning != status {
			ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusChanged = true
			// if primary cis id down then post the config
			if !status {
				ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusRunning = false
				ctlr.enqueuePrimaryClusterProbeEvent()
			} else {
				ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusRunning = true
			}
		} else {
			ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusChanged = false
		}
		// wait for configured probeInterval
		time.Sleep(time.Duration(ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.probeInterval) * time.Second)
	}
}

func (ctlr *Controller) firstPollPrimaryClusterHealthStatus() {
	ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusRunning = ctlr.Agent.PostManager.checkPrimaryClusterHealthStatus()
	ctlr.Agent.PostManager.PrimaryClusterHealthProbeParams.statusChanged = true
}
