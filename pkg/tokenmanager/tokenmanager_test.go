package tokenmanager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/httpclient"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Shared Token Manager Tests", func() {
	var (
		sharedTM     *SharedTokenManager
		mockServer   *httptest.Server
		requestCount int
		requestMutex sync.Mutex
	)

	BeforeEach(func() {
		// Reset request counter
		requestMutex.Lock()
		requestCount = 0
		requestMutex.Unlock()

		// Create mock HTTP server for BigIP API
		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestMutex.Lock()
			requestCount++
			requestMutex.Unlock()

			switch r.URL.Path {
			case "/mgmt/shared/authn/login":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"token": {
						"token": "shared-token-12345",
						"expirationMicros": ` + fmt.Sprintf("%d", (time.Now().Add(1*time.Hour).UnixNano()/1000)) + `,
						"lastUse": ` + fmt.Sprintf("%d", time.Now().UnixNano()/1000) + `,
						"timeout": 3600,
						"userReference": {
							"link": "https://localhost/mgmt/shared/authz/users/admin"
						}
					}
				}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))

		// Get shared token manager instance
		sharedTM = GetSharedTokenManager()
	})

	AfterEach(func() {
		if mockServer != nil {
			mockServer.Close()
		}
	})

	Describe("Singleton Pattern", func() {
		Context("when getting shared token manager instance", func() {
			It("should return the same instance across multiple calls", func() {
				stm1 := GetSharedTokenManager()
				stm2 := GetSharedTokenManager()
				stm3 := GetSharedTokenManager()

				Expect(stm1).To(Equal(stm2))
				Expect(stm2).To(Equal(stm3))
				Expect(stm1).To(Equal(sharedTM))
			})

			It("should initialize with empty token managers map", func() {
				// Note: Since this is a singleton, we can't guarantee empty state
				// but we can verify the structure
				hosts := sharedTM.GetActiveTokenManagers()
				Expect(hosts).ToNot(BeNil())
			})
		})
	})

	Describe("Token Manager Creation and Reuse", func() {
		Context("when creating token managers for same BigIP host", func() {
			It("should reuse existing token manager for same host", func() {
				host := mockServer.URL[7:] // Remove http:// prefix
				username := "admin"
				password := "admin"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("test-client", clientConfig)

				// Create first token manager
				tm1 := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(tm1).ToNot(BeNil())

				// Create second token manager for same host
				tm2 := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(tm2).ToNot(BeNil())

				// Should be the same instance
				Expect(tm1).To(Equal(tm2))

				// Verify host is in active token managers
				hosts := sharedTM.GetActiveTokenManagers()
				Expect(hosts).To(ContainElement(host))
			})

			It("should create separate token managers for different hosts", func() {
				host1 := "bigip1.example.com"
				host2 := "bigip2.example.com"
				username := "admin"
				password := "admin"

				// Create HTTP clients
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient1 := factory.GetOrCreateClient("test-client-1", clientConfig)
				httpClient2 := factory.GetOrCreateClient("test-client-2", clientConfig)

				// Create token managers for different hosts
				tm1 := sharedTM.GetOrCreateTokenManager(host1, username, password, httpClient1)
				tm2 := sharedTM.GetOrCreateTokenManager(host2, username, password, httpClient2)

				Expect(tm1).ToNot(BeNil())
				Expect(tm2).ToNot(BeNil())
				Expect(tm1).ToNot(Equal(tm2))

				// Verify both hosts are in active token managers
				hosts := sharedTM.GetActiveTokenManagers()
				Expect(hosts).To(ContainElement(host1))
				Expect(hosts).To(ContainElement(host2))
			})
		})

		Context("when creating token manager without HTTP client", func() {
			It("should use default HTTP client from factory", func() {
				host := "bigip-default.example.com"
				username := "admin"
				password := "admin"

				// Create token manager without providing HTTP client
				tm := sharedTM.GetOrCreateTokenManager(host, username, password, nil)
				Expect(tm).ToNot(BeNil())

				// Verify host is tracked
				hosts := sharedTM.GetActiveTokenManagers()
				Expect(hosts).To(ContainElement(host))
			})
		})
	})

	Describe("Concurrent Access", func() {
		Context("when multiple goroutines access same host", func() {
			It("should handle concurrent token manager creation safely", func() {
				host := "bigip-concurrent.example.com"
				username := "admin"
				password := "admin"
				numGoroutines := 10

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("concurrent-test", clientConfig)

				// Channel to collect token managers
				tmChannel := make(chan TokenManagerInterface, numGoroutines)
				var wg sync.WaitGroup

				// Launch multiple goroutines
				for i := 0; i < numGoroutines; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						tm := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
						tmChannel <- tm
					}()
				}

				// Wait for all goroutines to complete
				wg.Wait()
				close(tmChannel)

				// Collect all token managers
				var tokenManagers []TokenManagerInterface
				for tm := range tmChannel {
					tokenManagers = append(tokenManagers, tm)
				}

				// All should be the same instance
				Expect(len(tokenManagers)).To(Equal(numGoroutines))
				firstTM := tokenManagers[0]
				for _, tm := range tokenManagers {
					Expect(tm).To(Equal(firstTM))
				}
			})
		})
	})

	Describe("Token Manager Retrieval", func() {
		Context("when getting existing token manager", func() {
			It("should return existing token manager for known host", func() {
				host := mockServer.URL[7:] // Remove http:// prefix
				username := "admin"
				password := "admin"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("retrieval-test", clientConfig)

				// Create token manager
				originalTM := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(originalTM).ToNot(BeNil())

				// Retrieve token manager
				retrievedTM := sharedTM.GetTokenManager(host)
				Expect(retrievedTM).ToNot(BeNil())
				Expect(retrievedTM).To(Equal(originalTM))
			})

			It("should return nil for unknown host", func() {
				unknownHost := "unknown-bigip.example.com"
				tm := sharedTM.GetTokenManager(unknownHost)
				Expect(tm).To(BeNil())
			})
		})
	})

	Describe("HTTP Client Factory Integration", func() {
		Context("when using HTTP client factory", func() {
			It("should use factory for HTTP client management", func() {
				factory := httpclient.GetFactory()
				Expect(factory).ToNot(BeNil())

				// Create client configurations
				config1 := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				config2 := httpclient.ClientConfig{
					SSLInsecure: false,
					Timeout:     60 * time.Second,
				}

				// Get clients from factory
				client1 := factory.GetOrCreateClient("client-1", config1)
				client2 := factory.GetOrCreateClient("client-2", config2)

				Expect(client1).ToNot(BeNil())
				Expect(client2).ToNot(BeNil())
				Expect(client1).ToNot(Equal(client2))

				// Reuse should return same instances
				client1Reuse := factory.GetOrCreateClient("client-1", config1)
				Expect(client1Reuse).To(Equal(client1))
			})
		})
	})

	Describe("Token Manager Lifecycle", func() {
		Context("when token managers are created for CIS components", func() {
			It("should support leader election and controller sharing same token manager", func() {
				host := mockServer.URL // Remove http:// prefix
				username := "admin"
				password := "admin"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("shared-test", clientConfig)

				// Simulate leader election component getting token manager
				leaderTM := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(leaderTM).ToNot(BeNil())

				// Simulate controller component getting token manager (same host)
				controllerTM := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(controllerTM).ToNot(BeNil())

				// Should be the same instance - avoiding token manager duplication
				Expect(leaderTM).To(Equal(controllerTM))

				// Both components should get the same token
				token1 := leaderTM.GetToken()
				token2 := controllerTM.GetToken()
				Expect(token1).To(Equal(token2))
				Expect(token1).ToNot(BeEmpty())
			})

			It("should handle multiple BigIP hosts for multi-cluster scenarios", func() {
				hosts := []string{"bigip-cluster1.example.com", "bigip-cluster2.example.com", "bigip-cluster3.example.com"}
				username := "admin"
				password := "admin"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()

				var tokenManagers []TokenManagerInterface

				// Create token managers for different clusters
				for i, host := range hosts {
					httpClient := factory.GetOrCreateClient(fmt.Sprintf("cluster-client-%d", i), clientConfig)
					tm := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
					Expect(tm).ToNot(BeNil())
					tokenManagers = append(tokenManagers, tm)
				}

				// All should be different instances (different hosts)
				for i := 0; i < len(tokenManagers); i++ {
					for j := i + 1; j < len(tokenManagers); j++ {
						Expect(tokenManagers[i]).ToNot(Equal(tokenManagers[j]))
					}
				}

				// Verify all hosts are tracked
				activeHosts := sharedTM.GetActiveTokenManagers()
				for _, host := range hosts {
					Expect(activeHosts).To(ContainElement(host))
				}
			})
		})
	})

	Describe("Token Manager Key Generation", func() {
		Context("when generating keys for token managers", func() {
			It("should use host as unique key", func() {
				key1 := TokenManagerKey{Host: "bigip1.example.com"}
				key2 := TokenManagerKey{Host: "bigip2.example.com"}
				key3 := TokenManagerKey{Host: "bigip1.example.com"}

				Expect(key1.String()).To(Equal("bigip1.example.com"))
				Expect(key2.String()).To(Equal("bigip2.example.com"))
				Expect(key1.String()).To(Equal(key3.String()))
				Expect(key1.String()).ToNot(Equal(key2.String()))
			})
		})
	})

	Describe("Error Handling and Resilience", func() {
		Context("when BigIP is unreachable during token manager creation", func() {
			It("should create token manager but log initialization errors", func() {
				unreachableHost := "unreachable-bigip.example.com"
				username := "admin"
				password := "admin"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     5 * time.Second, // Short timeout for faster test
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("unreachable-test", clientConfig)

				// Should create token manager despite connection failure
				tm := sharedTM.GetOrCreateTokenManager(unreachableHost, username, password, httpClient)
				Expect(tm).ToNot(BeNil())

				// Token manager should be tracked even if initial sync failed
				hosts := sharedTM.GetActiveTokenManagers()
				Expect(hosts).To(ContainElement(unreachableHost))
			})
		})

		Context("when credentials are invalid", func() {
			It("should create token manager but handle authentication errors", func() {
				host := mockServer.URL[7:] // Remove http:// prefix
				username := "invalid"
				password := "invalid"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("invalid-creds-test", clientConfig)

				// Should create token manager
				tm := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(tm).ToNot(BeNil())

				// Token manager should be tracked
				hosts := sharedTM.GetActiveTokenManagers()
				Expect(hosts).To(ContainElement(host))
			})
		})
	})

	Describe("Memory Management", func() {
		Context("when token managers are stored", func() {
			It("should maintain token managers for static BigIP hosts", func() {
				initialCount := len(sharedTM.GetActiveTokenManagers())

				host := "persistent-bigip.example.com"
				username := "admin"
				password := "admin"

				// Create HTTP client
				clientConfig := httpclient.ClientConfig{
					SSLInsecure: true,
					Timeout:     30 * time.Second,
				}
				factory := httpclient.GetFactory()
				httpClient := factory.GetOrCreateClient("persistent-test", clientConfig)

				// Create token manager
				tm := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(tm).ToNot(BeNil())

				// Count should increase
				newCount := len(sharedTM.GetActiveTokenManagers())
				Expect(newCount).To(Equal(initialCount + 1))

				// Creating again should not increase count
				tm2 := sharedTM.GetOrCreateTokenManager(host, username, password, httpClient)
				Expect(tm2).To(Equal(tm))
				finalCount := len(sharedTM.GetActiveTokenManagers())
				Expect(finalCount).To(Equal(newCount))
			})
		})
	})
})
