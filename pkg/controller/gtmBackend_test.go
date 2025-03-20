package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"net/http"
	"time"
)

var _ = Describe("Backend Tests", func() {

	Describe("Prepare AS3 GTM PostManager", func() {
		var agent *Agent
		BeforeEach(func() {
			DEFAULT_GTM_PARTITION = "test_gtm"
			agent = newMockAgent(nil)
			//agent.GTMPostManager = NewGTMPostManager(AgentParams{GTMParams: PostParams{
			//	BIGIPURL: "192.168.1.1",
			//}},
			//agent.respChan)
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
		It("Test GTM Worker", func() {
			responces := []responceCtx{{
				tenant: DEFAULT_GTM_PARTITION,
				status: http.StatusOK,
				body:   "",
			}}
			mockHttpClient, _ := getMockHttpClient(responces, http.MethodPost)
			agent.GTMPostManager.httpClient = mockHttpClient
			go agent.gtmWorker()
			go agent.retryGTMWorker()
			monitors := []Monitor{
				{
					Name:     "pool1_monitor",
					Interval: 10,
					Timeout:  10,
					Type:     "http",
					Send:     "GET /health",
				},
			}
			gtmConfig := GTMConfig{
				DEFAULT_GTM_PARTITION: GTMPartitionConfig{
					WideIPs: map[string]WideIP{
						"test.com": {
							DomainName: "test.com",
							RecordType: "A",
							LBMethod:   "round-robin",
							Pools: []GSLBPool{
								{
									Name:       "pool1",
									RecordType: "A",
									LBMethod:   "round-robin",
									Members:    []string{"vs1", "vs2"},
									Monitors:   monitors,
								},
							},
						},
					},
				},
			}
			agent.GTMPostManager.PostGTMConfig(ResourceConfigRequest{gtmConfig: gtmConfig})
			time.Sleep(100 * time.Millisecond)
			// Expect(len(agent.GTMPostManager.cachedTenantDeclMap)).To(Equal(1), "Cached tenant declaration map should be updated")
			// Expect(len(agent.GTMPostManager.incomingTenantDeclMap)).To(Equal(1), "Incoming tenant declaration should be updated")
			// Expect(len(agent.GTMPostManager.retryTenantDeclMap)).To(Equal(0), "retry tenant declaration map should not be updated")
		})
		It("Test GTM retry Worker", func() {
			responces := []responceCtx{{
				tenant: DEFAULT_GTM_PARTITION,
				status: http.StatusUnprocessableEntity,
				body:   "",
			}}
			mockHttpClient, _ := getMockHttpClient(responces, http.MethodPost)
			agent.GTMPostManager.httpClient = mockHttpClient
			go agent.gtmWorker()
			go agent.retryGTMWorker()
			monitors := []Monitor{
				{
					Name:     "pool1_monitor",
					Interval: 10,
					Timeout:  10,
					Type:     "http",
					Send:     "GET /health",
				},
			}
			gtmConfig := GTMConfig{
				DEFAULT_GTM_PARTITION: GTMPartitionConfig{
					WideIPs: map[string]WideIP{
						"test.com": {
							DomainName: "test.com",
							RecordType: "A",
							LBMethod:   "round-robin",
							Pools: []GSLBPool{
								{
									Name:       "pool1",
									RecordType: "A",
									LBMethod:   "round-robin",
									Members:    []string{"vs1", "vs2"},
									Monitors:   monitors,
								},
							},
						},
					},
				},
			}
			// agent.GTMPostManager.PostGTMConfig(ResourceConfigRequest{gtmConfig: gtmConfig})
			time.Sleep(100 * time.Millisecond)
			// Expect(len(agent.GTMPostManager.cachedTenantDeclMap)).To(Equal(0), "Cached tenant declaration map should not be updated")
			// Expect(len(agent.GTMPostManager.incomingTenantDeclMap)).To(Equal(1), "Incoming tenant declaration should be updated")
			// Expect(len(agent.GTMPostManager.retryTenantDeclMap)).To(Equal(1), "retry tenant declaration map should be updated")
		})
	})
})
