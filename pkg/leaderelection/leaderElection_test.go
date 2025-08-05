package leaderelection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/httpclient"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/tokenmanager"
	"github.com/f5devcentral/go-bigip"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Leader Election Tests", func() {
	var (
		leaderElector  *LeaderElector
		mockServer     *httptest.Server
		config         LeaderElectorConfig
		mockResponses  map[string]interface{}
		requestHistory []string
	)

	BeforeEach(func() {
		// Reset request history
		requestHistory = []string{}
		mockResponses = make(map[string]interface{})

		// Create mock HTTP server
		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestHistory = append(requestHistory, r.Method+" "+r.URL.Path)

			switch r.URL.Path {
			case "/mgmt/shared/authn/login":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"token": {
						"token": "mock-token-12345",
						"expirationMicros": ` + fmt.Sprintf("%d", (time.Now().Add(1*time.Hour).UnixNano()/1000)) + `,
						"lastUse": ` + fmt.Sprintf("%d", time.Now().UnixNano()/1000) + `,
						"timeout": 3600,
						"userReference": {
							"link": "https://localhost/mgmt/shared/authz/users/admin"
						}
					}
				}`))

			case "/mgmt/tm/ltm/data-group/internal/test-leader-election":
				if r.Method == "GET" {
					if response, exists := mockResponses["datagroup_get"]; exists {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(response.(string)))
					} else {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"code": 404, "message": "Not found"}`))
					}
				} else if r.Method == "POST" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"name": "test-leader-election", "type": "string"}`))
				}

			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		// Setup configuration
		config = LeaderElectorConfig{
			CandidateID:       "test-candidate-123",
			DataGroupName:     "test-leader-election",
			HeartbeatTimeout:  5 * time.Second,
			HeartbeatInterval: 1 * time.Second,
			BigipHost:         mockServer.URL, // Use complete URL with http:// prefix
			Username:          "admin",
			Password:          "admin",
			TrustedCerts:      "",
			SslInsecure:       true,
			UserAgent:         "test-agent",
			Teem:              false,
		}
	})

	AfterEach(func() {
		if leaderElector != nil {
			leaderElector.Stop()
		}
		if mockServer != nil {
			mockServer.Close()
		}
	})

	Describe("NewLeaderElector", func() {
		Context("when creating a new leader elector", func() {
			It("should create a leader elector with shared token manager", func() {
				var err error
				leaderElector, err = NewLeaderElector(config)

				Expect(err).ToNot(HaveOccurred())
				Expect(leaderElector).ToNot(BeNil())
				Expect(leaderElector.config.CandidateID).To(Equal("test-candidate-123"))
				Expect(leaderElector.tokenManager).ToNot(BeNil())
				Expect(leaderElector.bigipHandler).ToNot(BeNil())
				Expect(leaderElector.httpClient).ToNot(BeNil())
			})

			It("should use shared token manager for same BigIP host", func() {
				// Create first leader elector
				le1, err1 := NewLeaderElector(config)
				Expect(err1).ToNot(HaveOccurred())

				// Create second leader elector with same host
				config2 := config
				config2.CandidateID = "test-candidate-456"
				le2, err2 := NewLeaderElector(config2)
				Expect(err2).ToNot(HaveOccurred())

				// Both should use the same token manager instance (same BigIP host)
				sharedTM := tokenmanager.GetSharedTokenManager()
				tm1 := sharedTM.GetTokenManager(config.BigipHost)
				tm2 := sharedTM.GetTokenManager(config2.BigipHost)
				Expect(tm1).To(Equal(tm2))

				le1.Stop()
				le2.Stop()
			})
		})

		Context("when BigIP host is invalid", func() {
			It("should handle connection errors gracefully", func() {
				invalidConfig := config
				invalidConfig.BigipHost = "invalid-host:9999"

				le, err := NewLeaderElector(invalidConfig)
				Expect(err).ToNot(HaveOccurred()) // Creation should succeed
				Expect(le).ToNot(BeNil())
				// Token synchronization errors are logged but don't fail creation
			})
		})
	})

	Describe("Leader Election Process", func() {
		BeforeEach(func() {
			var err error
			leaderElector, err = NewLeaderElector(config)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("when no leader exists", func() {
			BeforeEach(func() {
				// Mock empty datagroup response
				mockResponses["datagroup_get"] = `{
					"name": "test-leader-election",
					"type": "string",
					"records": []
				}`
			})

			It("should become leader when no active leader", func() {
				leaderElector.Start()
				// Wait for leader election process
				Eventually(func() bool {
					return leaderElector.IsLeader()
				}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())

				Expect(leaderElector.GetCandidateID()).To(Equal("test-candidate-123"))
			})
		})

		Context("when another leader exists", func() {
			BeforeEach(func() {
				// Mock datagroup with another active leader
				currentTime := time.Now().Unix()
				mockResponses["datagroup_get"] = fmt.Sprintf(`{
					"name": "test-leader-election",
					"type": "string",
					"records": [
						{
							"name": "leader",
							"data": "other-candidate %d"
						}
					]
				}`, currentTime)
			})

			It("should not become leader when another leader is active", func() {
				leaderElector.Start()

				// Wait and ensure it doesn't become leader
				Consistently(func() bool {
					return leaderElector.IsLeader()
				}, 2*time.Second, 100*time.Millisecond).Should(BeFalse())
			})
		})

		Context("when leader heartbeat expires", func() {
			BeforeEach(func() {
				// Mock datagroup with expired leader
				expiredTime := time.Now().Add(-10 * time.Second).Unix()
				mockResponses["datagroup_get"] = fmt.Sprintf(`{
					"name": "test-leader-election",
					"type": "string",
					"records": [
						{
							"name": "leader",
							"data": "expired-candidate %d"
						}
					]
				}`, expiredTime)
			})

			It("should become leader when current leader's heartbeat expires", func() {
				leaderElector.Start()

				Eventually(func() bool {
					return leaderElector.IsLeader()
				}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
			})
		})
	})

	Describe("Heartbeat Management", func() {
		BeforeEach(func() {
			var err error
			leaderElector, err = NewLeaderElector(config)
			Expect(err).ToNot(HaveOccurred())

			// Mock empty datagroup to become leader immediately
			mockResponses["datagroup_get"] = `{
				"name": "test-leader-election",
				"type": "string",
				"records": []
			}`
		})

		Context("when leader sends heartbeats", func() {
			It("should send periodic heartbeats when leader", func() {
				leaderElector.Start()

				Eventually(func() bool {
					return leaderElector.IsLeader()
				}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())

				// Count initial requests
				initialRequests := len(requestHistory)

				// Wait for heartbeat interval
				time.Sleep(config.HeartbeatInterval + 500*time.Millisecond)

				// Should have more requests (heartbeats)
				Expect(len(requestHistory)).To(BeNumerically(">", initialRequests))
			})
		})
	})

	Describe("Token Manager Integration", func() {
		BeforeEach(func() {
			var err error
			leaderElector, err = NewLeaderElector(config)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("when token refresh is needed", func() {
			It("should update BigIP session token from token manager", func() {
				// Test token update mechanism
				leaderElector.updateBigIPToken()

				// Verify token manager is called
				token := leaderElector.tokenManager.GetToken()
				Expect(token).ToNot(BeEmpty())

				// Verify BigIP client has updated token
				if bigipClient, ok := leaderElector.bigipHandler.Bigip.(*bigip.BigIP); ok {
					Expect(bigipClient.Token).To(Equal(token))
				}
			})
		})

		Context("when shared token manager is used", func() {
			It("should reuse token manager for same BigIP host", func() {
				sharedTM := tokenmanager.GetSharedTokenManager()
				hosts := sharedTM.GetActiveTokenManagers()

				// Should have at least one token manager for our test host
				Expect(len(hosts)).To(BeNumerically(">=", 1))

				// Should be able to get token manager for our host
				tm := sharedTM.GetTokenManager(config.BigipHost)
				Expect(tm).ToNot(BeNil())
			})
		})
	})

	Describe("HTTP Client Integration", func() {
		Context("when using HTTP client factory", func() {
			It("should create HTTP client through factory", func() {
				factory := httpclient.GetFactory()
				Expect(factory).ToNot(BeNil())

				// Create client configuration
				clientConfig := httpclient.ClientConfig{
					TrustedCerts: config.TrustedCerts,
					SSLInsecure:  config.SslInsecure,
					Timeout:      30 * time.Second,
				}

				// Get client from factory
				clientKey := fmt.Sprintf("leaderelection-%s", config.BigipHost)
				httpClient := factory.GetOrCreateClient(clientKey, clientConfig)
				Expect(httpClient).ToNot(BeNil())
			})
		})
	})

	Describe("Error Handling", func() {
		Context("when BigIP API calls fail", func() {
			BeforeEach(func() {
				var err error
				leaderElector, err = NewLeaderElector(config)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should handle datagroup read errors gracefully", func() {
				// Mock server error
				mockServer.Close()

				// Should not panic on read errors
				leader, modTime, err := leaderElector.readLeader()
				Expect(err).To(HaveOccurred())
				Expect(leader).To(BeEmpty())
				Expect(modTime.IsZero()).To(BeTrue())
			})

			It("should handle heartbeat write errors gracefully", func() {
				// Mock server error
				mockServer.Close()

				// Should not panic on write errors
				err := leaderElector.writeHeartbeat()
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Lifecycle Management", func() {
		Context("when starting and stopping leader election", func() {
			It("should start and stop cleanly", func() {
				var err error
				leaderElector, err = NewLeaderElector(config)
				Expect(err).ToNot(HaveOccurred())

				// Start leader election
				leaderElector.Start()

				// Should not be leader initially (until datagroup is checked)
				initialLeaderStatus := leaderElector.IsLeader()

				// Stop leader election
				leaderElector.Stop()

				// Should handle stop gracefully
				finalLeaderStatus := leaderElector.IsLeader()

				// Verify the process worked
				Expect(initialLeaderStatus).To(BeFalse()) // Initially false
				Expect(finalLeaderStatus).To(BeFalse())   // Should remain false after stop
			})
		})
	})

	Describe("Candidate ID Management", func() {
		Context("when using Pod UID and cluster name", func() {
			It("should use combined Pod UID and cluster name as candidate ID", func() {
				// Test with Pod UID format candidate ID
				podUID := "12345678-1234-1234-1234-123456789012"
				clusterName := "test-cluster"
				candidateID := fmt.Sprintf("%s-%s", podUID, clusterName)

				configWithPodUID := config
				configWithPodUID.CandidateID = candidateID

				le, err := NewLeaderElector(configWithPodUID)
				Expect(err).ToNot(HaveOccurred())
				Expect(le.GetCandidateID()).To(Equal(candidateID))

				le.Stop()
			})

			It("should handle unique candidate IDs for different pods", func() {
				// Create multiple leader electors with different candidate IDs
				configs := []LeaderElectorConfig{}
				electors := []*LeaderElector{}

				for i := 0; i < 3; i++ {
					cfg := config
					cfg.CandidateID = fmt.Sprintf("pod-%d-cluster-test", i)
					configs = append(configs, cfg)

					le, err := NewLeaderElector(cfg)
					Expect(err).ToNot(HaveOccurred())
					electors = append(electors, le)
				}

				// Verify all have unique candidate IDs
				for i, le := range electors {
					Expect(le.GetCandidateID()).To(Equal(configs[i].CandidateID))
					le.Stop()
				}
			})
		})
	})
})
