package as3

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const Disable = "disable"

type PatchRequest struct {
	poolPath     string
	memberIP     string
	sessionState string
	ports        string
	gracePeriod  int64
}

// PatchDeployer patch deployer works on patch channel and patches the request
func (am *AS3Manager) PatchDeployer() {
	for patchReq := range am.PatchChan {
		go am.patchPoolMember(patchReq)
	}
}

func (am *AS3Manager) patchPoolMember(req PatchRequest) {
	ports := strings.Split(req.ports, ",")
	for _, p := range ports {
		port, _ := strconv.Atoi(p)
		port32 := int32(port)
		go func(graceTermination int64) {
			// Create a channel to receive a signal after the timeout
			timeout := time.Duration(graceTermination) * time.Second
			timeoutCh := time.After(timeout)
			count := 1
			// retry until the grace period
			for {
				// delete the pod from the cache after the timeout
				select {
				case <-timeoutCh:
					log.Debugf("[PatchRequest] grace period expired for the patch request. %v", req)
					return
				default:
					// Continue the loop until the timeout
					err := am.updatePoolMemberState(req.poolPath, req.memberIP, req.sessionState, port32)
					if err == nil {
						return
					} else {
						log.Errorf("[PatchRequest] Error patching pool member, Retrying in %v seconds: %v", count, err)
						time.Sleep(time.Duration(count) * time.Second)
						count = count * 2
					}
				}
			}
		}(req.gracePeriod)
	}
}

// function to updatePoolMemberState
func (am *AS3Manager) updatePoolMemberState(poolPath, ip, sessionState string, port int32) error {
	log.Debugf("[PatchRequest] Patching pool member %s:%d in pool %s", ip, port, poolPath)
	var state string
	switch sessionState {
	case Disable:
		state = "user-up"
	default:
		return fmt.Errorf("invalid session state: %s", sessionState)
	}
	action := map[string]interface{}{
		"state":   state,
		"session": "user-disabled",
	}
	body, err := json.Marshal(action)
	if err != nil {
		return err
	}
	// patch the pool member
	am.PostManager.PatchObject(am.PostManager.fetchPoolMemberURI(poolPath, ip, port), string(body))
	return nil
}

// function to fetchPoolMemberURI
func (postMgr *PostManager) fetchPoolMemberURI(poolPath, ip string, port int32) string {
	pfn := strings.Split(poolPath, "/")
	ipport := fmt.Sprintf("~%s~%s:%d", pfn[0], ip, port)
	if IsIpv6(ip) {
		ipport = fmt.Sprintf("~%s~%s.%d", pfn[1], ip, port)
	}
	link := fmt.Sprintf("/mgmt/tm/ltm/pool/%s/members/%s", Refname(pfn[0], pfn[1], pfn[2]), ipport)
	apiURL := postMgr.BIGIPURL + link
	return apiURL
}

func (postMgr *PostManager) PatchObject(url, data string) error {
	log.Debugf("[PatchRequest] Patching object: %s", url)
	httpReqBody := bytes.NewBuffer([]byte(data))
	req, err := http.NewRequest("PATCH", url, httpReqBody)
	if err != nil {
		log.Errorf("[PatchRequest] Creating new HTTP request error: %v ", err)
		return err
	}

	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil {
		log.Errorf("[PatchRequest] Received empty response: ", httpResp)
		return err
	}
	if responseMap == nil {
		log.Errorf("[PatchRequest] Received empty responseMap", responseMap)
		return err
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		log.Debugf("[PatchRequest] Patch request successful: %v", responseMap)
		return nil
	default:
		log.Errorf("[PatchRequest] Patch request failed: %v", responseMap)
		return err
	}
}

func Refname(partition, subfolder, name string) string {
	l := []string{}
	for _, x := range []string{partition, subfolder, name} {
		if x != "" {
			l = append(l, x)
		}
	}
	rn := strings.Join(l, "~")
	if rn != "" {
		rn = "~" + rn
	}
	escaped := url.QueryEscape(rn)
	return strings.ReplaceAll(escaped, "%2F", "/")
}

func IsIpv6(ipstr string) bool {
	ip := net.ParseIP(ipstr)
	return ip != nil && strings.Contains(ipstr, ":")
}
