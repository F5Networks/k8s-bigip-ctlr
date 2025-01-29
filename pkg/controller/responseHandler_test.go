package controller

import (
	. "github.com/onsi/ginkgo/v2"
)

// TODO: Implement it once the dependant modules are completed
var _ = Describe("ResponseHandler Tests", func() {
	var mockCtlr *mockController
	var bigIpConfig BigIpConfig
	BeforeEach(func() {
		mockCtlr = newMockController()
	})
	Describe("Config failure handling", func() {
		//var agentCfg agentConfig
		BeforeEach(func() {
			bigIpConfig = BigIpConfig{
				BigIpAddress: "10.10.10.10",
			}
			mockCtlr.RequestHandler = &RequestHandler{}
			mockCtlr.RequestHandler.AgentWorker = make(map[BigIpConfig]*AgentWorker)
			mockCtlr.RequestHandler.AgentWorker[bigIpConfig] = &AgentWorker{
				PostChan:    make(chan AgentConfig),
				PostManager: PostManager{},
			}

			mockCtlr.requestMap = &requestMap{
				requestMap: make(map[BigIpConfig]requestMeta),
			}
		})

		It("Verify with old failed config", func() {
			//TODO
		})

		It("Verify with latest failed config", func() {
			//TODO
		})

		It("Verify requeue of latest failed config when Bigip is unavailable", func() {
			//TODO
		})

		It("Verify requeue of latest failed config when Bigip is available", func() {
			//TODO
		})
	})
})
