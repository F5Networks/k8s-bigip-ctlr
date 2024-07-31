package controller

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func (ctlr *Controller) checkPrimaryClusterHealthStatus() bool {

	status := false
	for i := 1; i <= 2; i++ {
		switch ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPointType {
		case "http":
			status = ctlr.getPrimaryClusterHealthStatusFromHTTPEndPoint()
		case "tcp":
			status = ctlr.getPrimaryClusterHealthStatusFromTCPEndPoint()
		case "", "default":
			log.Debugf("[MultiCluster] unsupported primaryEndPoint specified under highAvailabilityCIS section: %v", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint)
			return false
		}

		if status {
			return status
		}
		time.Sleep(time.Duration(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval) * time.Second)
	}
	return false
}

// getPrimaryClusterHealthCheckEndPointType method determines type of probe to be done from CIS parameters
// http/tcp are the supported types
// when cis runs in primary mode this method should never be called
// should be called only when cis is running in secondary mode
func (ctlr *Controller) setPrimaryClusterHealthCheckEndPointType() {
	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint != "" {
		if strings.HasPrefix(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, "tcp://") {
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPointType = "tcp"
		} else if strings.HasPrefix(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, "http://") {
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPointType = "http"
		} else {
			log.Debugf("[MultiCluster] unsupported primaryEndPoint protocol type configured under highAvailabilityCIS section. EndPoint: %v \n "+
				"supported protocols:[http, tcp] ", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint)
			os.Exit(1)
		}
	}
}

// getPrimaryClusterHealthStatusFromHTTPEndPoint check the primary cluster health using http endPoint
func (ctlr *Controller) getPrimaryClusterHealthStatusFromHTTPEndPoint() bool {

	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint == "" {
		return false
	}
	if !strings.HasPrefix(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, "http://") {
		log.Debugf("[MultiCluster] Error: invalid primaryEndPoint detected under highAvailabilityCIS section: %v", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint)
		return false
	}

	req, err := http.NewRequest("GET", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, nil)
	if err != nil {
		log.Errorf("[MultiCluster] Creating new HTTP request error: %v ", err)
		return false
	}

	timeOut := ctlr.PostParams.httpClient.Timeout
	defer func() {
		ctlr.PostParams.httpClient.Timeout = timeOut
	}()
	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusChanged {
		log.Debugf("[MultiCluster] posting GET Check primaryEndPoint Health request on %v", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint)
	}
	ctlr.PostParams.httpClient.Timeout = 10 * time.Second

	httpResp := ctlr.httpGetReq(req)
	if httpResp == nil {
		return false
	}
	switch httpResp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusNotFound, http.StatusInternalServerError:
		log.Debugf("[MultiCluster] error fetching primaryEndPoint health status. endPoint:%v, statusCode: %v, error:%v",
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, httpResp.StatusCode, httpResp.Request.Response)
	}
	return false
}

// getPrimaryClusterHealthStatusFromTCPEndPoint check the primary cluster health using tcp endPoint
func (ctlr *Controller) getPrimaryClusterHealthStatusFromTCPEndPoint() bool {
	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint == "" {
		return false
	}
	if !strings.HasPrefix(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, "tcp://") {
		log.Debugf("[MultiCluster] invalid primaryEndPoint health probe tcp endpoint: %v", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint)
		return false
	}

	_, err := net.Dial("tcp", strings.TrimLeft(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, "tcp://"))
	if err != nil {
		log.Debugf("[MultiCluster] error connecting to primaryEndPoint tcp health probe: %v, error: %v", ctlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint, err)
		return false
	}
	return true
}

func (ctlr *Controller) httpGetReq(request *http.Request) *http.Response {
	httpResp, err := ctlr.PostParams.httpClient.Do(request)

	if err != nil {
		if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusChanged {
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

//coverage:ignore
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
	status := ctlr.checkPrimaryClusterHealthStatus()
	// if status is changed i.e from up -> down / down -> up
	ctlr.RequestHandler.PrimaryClusterHealthProbeParams.paramLock.Lock()
	if ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusRunning != status {
		ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusChanged = true
		// if primary cis id down then post the config
		if !status {
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusRunning = false
			ctlr.enqueuePrimaryClusterProbeEvent()
		} else {
			ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusRunning = true
		}
	} else {
		ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusChanged = false
	}
	ctlr.RequestHandler.PrimaryClusterHealthProbeParams.paramLock.Unlock()
	// wait for configured probeInterval
	time.Sleep(time.Duration(ctlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval) * time.Second)
}

func (ctlr *Controller) firstPollPrimaryClusterHealthStatus() {
	ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusRunning = ctlr.checkPrimaryClusterHealthStatus()
	ctlr.RequestHandler.PrimaryClusterHealthProbeParams.statusChanged = true
}
