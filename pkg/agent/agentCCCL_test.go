package agent

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Agent CCCL Tests", func() {
	Context("CCCL Agent functions", func() {

		It("CCCL Agent functions", func() {
			mw := &test.MockWriter{
				FailStyle: test.ImmediateFail,
				Sections:  make(map[string]interface{}),
			}
			ag, _ := CreateAgent(CCCLAgent)
			ag.Init(&cccl.Params{ConfigWriter: mw})

			Expect(ag.IsImplInAgent("test")).To(BeFalse())
			ag.Deploy(resource.MessageRequest{ReqID: 1, MsgType: "test"})

			// Test Get BIGIP Reg key
			Expect(ag.Clean("test")).To(BeNil())

			Expect(ag.GetBigipRegKey()).To(BeEmpty())
			ag.DeInit()
		})
	})
})
