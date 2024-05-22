package as3

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const Disabled = "disabled"
const Offline = "offline"

type PodIp string
type PoolPath string

type PoolMemberMap map[PodIp]PoolPath

// function to updatePoolMemberState
func (am *AS3Manager) updatePoolMemberState(poolPath, ip, sessionState string, port int) error {
	var state string
	switch sessionState {
	case Disabled:
		state = "user-up"
	case Offline:
		state = "user-down"
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
func (postMgr *PostManager) fetchPoolMemberURI(poolPath, ip string, port int) string {
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
	httpReqBody := bytes.NewBuffer([]byte(data))
	req, err := http.NewRequest("PATCH", url, httpReqBody)
	if err != nil {
		log.Errorf("[PoolMemberUpdate] Creating new HTTP request error: %v ", err)
		return err
	}

	req.SetBasicAuth(postMgr.BIGIPUsername, postMgr.BIGIPPassword)

	httpResp, responseMap := postMgr.httpReq(req)
	if httpResp == nil {
		log.Errorf("[PoolMemberUpdate] Received empty response: ", httpResp)
		return err
	}
	if responseMap == nil {
		log.Errorf("[PoolMemberUpdate] Received empty responseMap", responseMap)
		return err
	}

	switch httpResp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return nil
	default:
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
