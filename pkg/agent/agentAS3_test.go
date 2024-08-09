package agent

import (
	"bytes"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/as3"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"net/http"
)

type (
	mockPostManager struct {
		*as3.PostManager
		Responses []int
		RespIndex int
	}

	responceCtx struct {
		tenant string
		status float64
		body   string
	}
)

func newMockPostManager() *mockPostManager {
	mockPM := &mockPostManager{
		PostManager: &as3.PostManager{},
		Responses:   []int{},
		RespIndex:   0,
	}
	return mockPM
}

func (mockPM *mockPostManager) SetResponses(responces []responceCtx, method string) {
	var body string

	responseMap := make(mockhc.ResponseConfigMap)
	responseMap[method] = &mockhc.ResponseConfig{}

	for _, resp := range responces {
		if resp.body == "" {
			if resp.status == http.StatusOK {
				body = fmt.Sprintf(`{"results":[{"code":%f,"message":"none", "tenant": "%s"}]}`,
					resp.status, resp.tenant)
			} else {
				body = fmt.Sprintf(`{"results":[{"code":%f,"message":"none", "tenant": "%s"}],"error":{"code":%f}}`,
					resp.status, resp.tenant, resp.status)
			}
		} else {
			body = resp.body
		}

		responseMap[method].Responses = append(responseMap[method].Responses, &http.Response{
			StatusCode: int(resp.status),
			Header:     http.Header{},
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(body))),
		})
	}

	client, _ := mockhc.NewMockHTTPClient(responseMap)
	mockPM.HttpClient = client
}

var _ = Describe("Agent AS3 Tests", func() {
	Context("AS3 Agent functions", func() {

		It("AS3 Agent functions", func() {
			ag := agentAS3{AS3Manager: &as3.AS3Manager{}}
			ag.ReqChan = make(chan resource.MessageRequest, 1)
			ag.RspChan = make(chan interface{}, 1)
			mockPM := newMockPostManager()
			ag.PostManager = mockPM.PostManager
			Expect(ag.IsImplInAgent(resource.ResourceTypeCfgMap)).To(BeTrue())
			Expect(ag.IsImplInAgent("test")).To(BeFalse())
			_ = ag.Deploy(resource.MessageRequest{ReqID: 1, MsgType: "test"})
			_, ok := <-ag.ReqChan
			Expect(ok).To(BeTrue())
			// Test Get BIGIP Reg key
			tnt := "test"
			mockPM.SetResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusOK,
				body:   `{"registrationKey": "sfiifhanji"}`,
			}}, http.MethodGet)
			Expect(ag.GetBigipRegKey()).To(Equal("sfiifhanji"))
			// test clean function
			Expect(ag.Clean("test")).To(BeNil())
			// set invalid status
			mockPM.SetResponses([]responceCtx{{
				tenant: tnt,
				status: http.StatusServiceUnavailable,
				body:   `{"registrationKey": "sfiifhanji"}`,
			}}, http.MethodGet)
			Expect(ag.GetBigipRegKey()).To(BeEmpty())
			_ = ag.DeInit()
			_, ok = <-ag.ReqChan
			Expect(ok).To(BeFalse())
			_, ok = <-ag.RspChan
			Expect(ok).To(BeFalse())
		})
	})
})
