package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Backend Tests", func() {

	Describe("Prepare AS3 GTM PostManager", func() {
		BeforeEach(func() {
			DEFAULT_GTM_PARTITION = "test_gtm"
		})
		It("Test GTM on different server", func() {
			var agentParams AgentParams
			agentParams.CCCLGTMAgent = true
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(false), "GTM is not on a separate server")
			agentParams.CCCLGTMAgent = false
			agentParams.PrimaryParams.BIGIPURL = "https://192.168.1.1"
			agentParams.PrimaryParams.BIGIPPassword = "admin"
			agentParams.PrimaryParams.BIGIPUsername = "admin"
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(false), "GTM is not on a separate server")
			agentParams.GTMParams.BIGIPURL = "https://192.168.1.1"
			agentParams.GTMParams.BIGIPPassword = "admin"
			agentParams.GTMParams.BIGIPUsername = "admin"
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(false), "GTM is not on a separate server")
			agentParams.GTMParams.BIGIPURL = "https://172.16.1.1"
			Expect(isGTMOnSeparateServer(agentParams)).To(Equal(true), "GTM is on a separate server")
		})
	})
})
