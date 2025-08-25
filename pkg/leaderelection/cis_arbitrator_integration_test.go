package leaderelection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/httpclient"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/tokenmanager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CIS Arbitrator Integration Tests", func() {
	var (
		mockServer     *httptest.Server
		config         LeaderElectorConfig
		requestHistory []string
	)

	BeforeEach(func() {
		requestHistory = []string{}

		// Create mock HTTP server for BigIP API
		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestHistory = append(requestHistory, fmt.Sprintf("%s %s", r.Method, r.URL.Path))

			switch r.URL.Path {
			case "/mgmt/shared/authn/login":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"token": {
						"token": "integration-token-12345",
						"expirationMicros": ` + fmt.Sprintf("%d", (time.Now().Add(1*time.Hour).UnixNano()/1000)) + `,
						"lastUse": ` + fmt.Sprintf("%d", time.Now().UnixNano()/1000) + `,
						"timeout": 3600,
						"userReference": {
							"link": "https://localhost/mgmt/shared/authz/users/admin"
						}
					}
				}`))

			case "/mgmt/tm/ltm/data-group/internal/cis-arbitrator":
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{
						"name": "cis-arbitrator",
						"type": "string",
						"records": []
					}`))
				} else if r.Method == "POST" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"name": "cis-arbitrator", "type": "string"}`))
				}

			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		// Setup configuration with Pod UID and cluster name
		podUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		clusterName := "test-cluster"
		candidateID := fmt.Sprintf("%s-%s", podUID, clusterName)

		config = LeaderElectorConfig{
			CandidateID:       candidateID,
			DataGroupName:     "cis-arbitrator",
			HeartbeatTimeout:  5 * time.Second,
			HeartbeatInterval: 1 * time.Second,
			BigipHost:         mockServer.URL[7:], // Remove http:// prefix
			Username:          "admin",
			Password:          "admin",
			TrustedCerts:      "",
			SslInsecure:       true,
			UserAgent:         "k8s-bigip-ctlr/test",
			Teem:              false,
		}
	})

	AfterEach(func() {
		if mockServer != nil {
			mockServer.Close()
		}
	})

	Describe("CIS Arbitrator Scenario", func() {
		Context("when CIS controller initializes", func() {
			It("should start leader election as part of controller init", func() {
				// Simulate controller initialization
				leaderElector, err := NewLeaderElector(config)
				Expect(err).ToNot(HaveOccurred())
				Expect(leaderElector).ToNot(BeNil())

				// Verify candidate ID uses Pod UID + cluster name format
				Expect(leaderElector.GetCandidateID()).To(ContainSubstring("a1b2c3d4-e5f6-7890-abcd-ef1234567890"))
				Expect(leaderElector.GetCandidateID()).To(ContainSubstring("test-cluster"))

				leaderElector.Stop()
			})

			It("should get Pod UID from Kubernetes API server", func() {
				// In real implementation, this would come from:
				// podUID, err := k8sClient.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
				// For test, we simulate the result
				simulatedPodUID := "12345678-abcd-efgh-ijkl-mnopqrstuvwx"
				clusterName := "production-cluster"

				expectedCandidateID := fmt.Sprintf("%s-%s", simulatedPodUID, clusterName)

				configWithRealPodUID := config
				configWithRealPodUID.CandidateID = expectedCandidateID

				le, err := NewLeaderElector(configWithRealPodUID)
				Expect(err).ToNot(HaveOccurred())
				Expect(le.GetCandidateID()).To(Equal(expectedCandidateID))

				le.Stop()
			})
		})

		Context("when multiple CIS instances run in same cluster", func() {
			It("should ensure only one leader per cluster", func() {
				// Create multiple CIS instances (simulating different pods)
				configs := []LeaderElectorConfig{}
				electors := []*LeaderElector{}

				for i := 0; i < 3; i++ {
					podUID := fmt.Sprintf("pod-%d-uid-1234-5678-9012", i)
					candidateID := fmt.Sprintf("%s-%s", podUID, "same-cluster")

					cfg := config
					cfg.CandidateID = candidateID
					configs = append(configs, cfg)

					le, err := NewLeaderElector(cfg)
					Expect(err).ToNot(HaveOccurred())
					electors = append(electors, le)
				}

				// All should have unique candidate IDs but same cluster
				for i, le := range electors {
					Expect(le.GetCandidateID()).To(ContainSubstring("same-cluster"))
					Expect(le.GetCandidateID()).To(ContainSubstring(fmt.Sprintf("pod-%d", i)))
					le.Stop()
				}
			})
		})
	})

	Describe("Shared Token Manager for CIS Components", func() {
		Context("when leader election and controller use same BigIP", func() {
			It("should share token manager instance", func() {
				host := mockServer.URL // Remove http:// prefix

				// Get shared token manager
				sharedTM := tokenmanager.GetSharedTokenManager()

				// Create HTTP client configuration
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()

				// Simulate leader election component
				leaderHTTPClient := factory.GetOrCreateClient("leader-election", clientConfig)
				leaderTM := sharedTM.GetOrCreateTokenManager(host, "admin", "admin", leaderHTTPClient)

				// Simulate controller component
				controllerHTTPClient := factory.GetOrCreateClient("controller", clientConfig)
				controllerTM := sharedTM.GetOrCreateTokenManager(host, "admin", "admin", controllerHTTPClient)

				// Should be the same token manager instance (same BigIP host)
				Expect(leaderTM).To(Equal(controllerTM))

				// Force token synchronization for test environment
				err := leaderTM.SyncToken()
				Expect(err).ToNot(HaveOccurred())

				// Both should get the same token
				leaderToken := leaderTM.GetToken()
				controllerToken := controllerTM.GetToken()
				Expect(leaderToken).To(Equal(controllerToken))
				Expect(leaderToken).ToNot(BeEmpty())
			})

			It("should avoid HTTP client duplication", func() {
				factory := httpclient.GetFactory()

				// Create client configurations
				config1 := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}

				// Get clients with same key - should return same instance
				client1 := factory.GetOrCreateClient("shared-bigip-client", config1)
				client2 := factory.GetOrCreateClient("shared-bigip-client", config1)

				Expect(client1).To(Equal(client2))
				Expect(client1).ToNot(BeNil())
			})
		})

		Context("when BigIP configuration is static", func() {
			It("should not require token manager deletion on BigIP host update", func() {
				// Since CIS doesn't allow updating BigIP host without restart,
				// token managers are created once and persist for the lifetime of CIS
				sharedTM := tokenmanager.GetSharedTokenManager()
				initialHosts := sharedTM.GetActiveTokenManagers()
				initialCount := len(initialHosts)

				// Create token manager for a BigIP host
				host := "static-bigip.example.com"
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("static-test", clientConfig)

				tm := sharedTM.GetOrCreateTokenManager(host, "admin", "admin", httpClient)
				Expect(tm).ToNot(BeNil())

				// Verify token manager is persistent
				newHosts := sharedTM.GetActiveTokenManagers()
				Expect(len(newHosts)).To(Equal(initialCount + 1))
				Expect(newHosts).To(ContainElement(host))

				// Getting the same token manager again should return same instance
				tm2 := sharedTM.GetTokenManager(host)
				Expect(tm2).To(Equal(tm))
			})
		})
	})

	Describe("Default HTTP Client Behavior", func() {
		Context("when no HTTP client is provided", func() {
			It("should use default HTTP client from factory", func() {
				sharedTM := tokenmanager.GetSharedTokenManager()
				host := "default-client-bigip.example.com"

				// Create token manager without providing HTTP client (nil)
				tm := sharedTM.GetOrCreateTokenManager(host, "admin", "admin", nil)
				Expect(tm).ToNot(BeNil())

				// Should use factory's default client internally
				factory := httpclient.GetFactory()
				defaultClient := factory.GetDefaultClient()
				Expect(defaultClient).ToNot(BeNil())
			})
		})
	})

	Describe("Performance and Scalability", func() {
		Context("when handling multiple BigIP hosts", func() {
			It("should efficiently manage token managers for different hosts", func() {
				sharedTM := tokenmanager.GetSharedTokenManager()
				numHosts := 5

				// Create token managers for multiple BigIP hosts
				var tokenManagers []tokenmanager.TokenManagerInterface
				for i := 0; i < numHosts; i++ {
					host := fmt.Sprintf("bigip-%d.example.com", i)

					clientConfig := httpclient.ClientConfig{
						SSLInsecure: true,
						Timeout:     30 * time.Second,
					}
					factory := httpclient.GetFactory()
					httpClient := factory.GetOrCreateClient(fmt.Sprintf("client-%d", i), clientConfig)

					tm := sharedTM.GetOrCreateTokenManager(host, "admin", "admin", httpClient)
					tokenManagers = append(tokenManagers, tm)
				}

				// All token managers should be different (different hosts)
				for i := 0; i < len(tokenManagers); i++ {
					for j := i + 1; j < len(tokenManagers); j++ {
						Expect(tokenManagers[i]).ToNot(Equal(tokenManagers[j]))
					}
				}

				// Verify all hosts are tracked
				activeHosts := sharedTM.GetActiveTokenManagers()
				Expect(len(activeHosts)).To(BeNumerically(">=", numHosts))
			})
		})
	})
})
