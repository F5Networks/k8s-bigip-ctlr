package networkmanager

import (
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager/mockmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"time"
)

func stringToJson(s string) map[string]interface{} {
	var es map[string]interface{}
	err := json.Unmarshal([]byte(s), &es)
	Expect(err).ToNot(HaveOccurred())
	return es
}

var _ = Describe("Network Manager Tests", func() {
	var tokenManager *tokenmanager.TokenManager
	var server *ghttp.Server
	var tokenResponse tokenmanager.AccessTokenResponse
	var networkManager *NetworkManager
	var inventoryResponse string
	var l3ForwardResponse string
	var routeAPISuccessResponse string
	var routeAPIFailureResponse string
	var routeTaskSuccessResponse string
	var routeTaskFailureResponse string
	var routeStore RouteStore
	var l3Forward L3Forward
	var staticRouteMap map[StaticRouteConfig]L3Forward
	var bigIPConfig []cisapiv1.BigIpConfig
	mockStatusManager := mockmanager.NewMockStatusManager()
	const (
		BigIPAddress       = "10.218.130.73"
		BigIpId            = "41073280-8f16-4b1f-9808-8908910e8fc2"
		TaskRef            = "/v1/tasks/9bb9a35e-83f0-4998-af41-95f3fcc4ac09"
		L3ForwardId        = "01c4d3e5-6754-4519-a449-33108427f9c9"
		statusCodeOk       = 200
		statusCodeAccepted = 202
		statusCodeNotFound = 404
	)

	Describe("TestNetworkManager", func() {
		Context("Create and delete success scenario", func() {
			BeforeEach(func() {
				routeStore = make(RouteStore)
				staticRouteMap = make(map[StaticRouteConfig]L3Forward)
				l3Forward = L3Forward{
					Config: StaticRouteConfig{
						Gateway:       "10.0.0.1",
						Destination:   "10.244.0.0/24",
						L3ForwardType: L3RouteGateway,
					},
					VRF:  DefaultL3Network,
					Name: "test",
				}
				// Mock the server
				server = ghttp.NewServer()
				tokenManager = tokenmanager.NewTokenManager(server.URL(), tokenmanager.Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true, mockStatusManager)

				tokenResponse = tokenmanager.AccessTokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCodeOk, tokenResponse),
					))
				tokenManager.SyncTokenWithoutRetry()
				inventoryResponse = fmt.Sprintf(`{
    "_embedded": {
        "devices": [
            {
                "address": "%s",
                "id": "%s"
            }
        ]
    }
}`, BigIPAddress, BigIpId)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", InventoryURI),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(inventoryResponse))),
				)
				// l3Forward response
				l3ForwardResponse = `{
    "_embedded": {
        "l3forwards": []
    }
}`
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", InstancesURI+BigIpId+L3Forwards),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(l3ForwardResponse))),
				)
				// Route delete success response
				networkManager = NewNetworkManager(tokenManager, "cluster-1")
				bigIPConfig = []cisapiv1.BigIpConfig{{
					BigIpAddress: BigIPAddress,
				}}
				networkManager.SetInstanceIds(bigIPConfig, "")
				go networkManager.NetworkConfigHandler()
			})
			AfterEach(func() {
				// Stop the mock token server
				server.Close()
				close(networkManager.NetworkChan)
			})

			It("Test the create l3Forward request success", func() {

				// Route post success response
				routeAPISuccessResponse = fmt.Sprintf(`
{
    "_links": {
        "task": {
            "href": "%s"
        }
    },
    "path": "/api/v1/spaces/default/instances/%s/l3forwards/%s"
}
`, TaskRef, BigIpId, L3ForwardId)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", InstancesURI+BigIpId+L3Forwards),
						ghttp.RespondWithJSONEncoded(statusCodeAccepted, stringToJson(routeAPISuccessResponse)),
					))
				// Task success response
				routeTaskSuccessResponse = fmt.Sprintf(`{
    "failure_reason": "",
    "status": "%s"
}`, Completed)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskSuccessResponse)),
					))

				staticRouteMap[l3Forward.Config] = l3Forward
				routeStore[BigIP{
					IPaddress:  BigIPAddress,
					InstanceId: BigIpId,
				}] = staticRouteMap
				networkManager.NetworkRequestHandler(routeStore)
				time.Sleep(3 * time.Second)
				networkManager.L3ForwardStore.RLock()
				isr, _ := networkManager.L3ForwardStore.InstanceStaticRoutes[BigIpId]
				networkManager.L3ForwardStore.RUnlock()
				_, ok := isr[l3Forward.Config]
				Expect(ok).To(BeTrue())
			})

			It("Test the delete l3Forward request success", func() {

				// Route success response
				routeAPISuccessResponse = fmt.Sprintf(`
{
    "_links": {
        "task": {
            "href": "%s"
        }
    },
    "path": "/api/v1/spaces/default/instances/33526123-105d-4d0c-bb22-dcaa70008dd8/l3forwards/%s"
}
`, TaskRef, L3ForwardId)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("DELETE", fmt.Sprintf("%s/%s", InstancesURI+BigIpId+L3Forwards, L3ForwardId)),
						ghttp.RespondWithJSONEncoded(statusCodeAccepted, stringToJson(routeAPISuccessResponse)),
					))
				// Task success response
				routeTaskSuccessResponse = fmt.Sprintf(`{
    "failure_reason": "",
    "status": "%s"
}`, Completed)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskSuccessResponse)),
					))
				routeStore[BigIP{
					IPaddress:  BigIPAddress,
					InstanceId: BigIpId,
				}] = staticRouteMap
				l3Forward.ID = L3ForwardId
				networkManager.L3ForwardStore.addL3ForwardEntry(BigIpId, l3Forward)
				networkManager.NetworkRequestHandler(routeStore)
				time.Sleep(3 * time.Second)
				Expect(networkManager.L3ForwardStore.getL3ForwardEntry(BigIpId, l3Forward)).To(BeFalse())
			})

		})
		Context("Create and delete failure scenario", func() {
			BeforeEach(func() {
				routeStore = make(RouteStore)
				staticRouteMap = make(map[StaticRouteConfig]L3Forward)
				l3Forward = L3Forward{
					Config: StaticRouteConfig{
						Gateway:       "10.0.0.1",
						Destination:   "10.244.0.0/24",
						L3ForwardType: L3RouteGateway,
					},
					VRF:  DefaultL3Network,
					Name: "test",
				}
				// Mock the server
				server = ghttp.NewServer()
				tokenManager = tokenmanager.NewTokenManager(server.URL(), tokenmanager.Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true, mockStatusManager)

				tokenResponse = tokenmanager.AccessTokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCodeOk, tokenResponse),
					))
				tokenManager.SyncTokenWithoutRetry()
				// Route delete success response
				networkManager = NewNetworkManager(tokenManager, "cluster-1")
			})
			AfterEach(func() {
				// Stop the mock token server
				server.Close()
				close(networkManager.NetworkChan)
			})
			It("Test the create l3Forward request task failure", func() {

				// Route post success response
				routeAPISuccessResponse = fmt.Sprintf(`
{
    "_links": {
        "task": {
            "href": "%s"
        }
    },
    "path": "/api/v1/spaces/default/instances/%s/l3forwards/%s"
}
`, TaskRef, BigIpId, L3ForwardId)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", InstancesURI+BigIpId+L3Forwards),
						ghttp.RespondWithJSONEncoded(statusCodeAccepted, stringToJson(routeAPISuccessResponse)),
					))

				// Task failure response
				routeTaskFailureResponse = fmt.Sprintf(`{
    "failure_reason": "Failed for xyz reason",
    "status": "%s"
}`, Failed)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskFailureResponse)),
					))

				networkConfigRequest := NetworkConfigRequest{
					NetworkConfig: l3Forward,
					BigIp: BigIP{
						IPaddress:  BigIPAddress,
						InstanceId: BigIpId,
					},
					Action: Create,
				}
				networkManager.HandleL3ForwardRequest(&networkConfigRequest, &l3Forward)
				Expect(len(networkManager.NetworkChan)).ToNot(BeZero())
				Expect(networkConfigRequest.retryTimeout).ToNot(BeZero())

			})
			It("Test the delete l3Forward request task failure", func() {

				// Route success response
				routeAPISuccessResponse = fmt.Sprintf(`
{
    "_links": {
        "task": {
            "href": "%s"
        }
    },
    "path": "/api/v1/spaces/default/instances/33526123-105d-4d0c-bb22-dcaa70008dd8/l3forwards/%s"
}
`, TaskRef, L3ForwardId)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("DELETE", fmt.Sprintf("%s/%s", InstancesURI+BigIpId+L3Forwards, L3ForwardId)),
						ghttp.RespondWithJSONEncoded(statusCodeAccepted, stringToJson(routeAPISuccessResponse)),
					))

				// Task failure response
				routeTaskFailureResponse = fmt.Sprintf(`{
    "failure_reason": "Failed for xyz reason",
    "status": "%s"
}`, Failed)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskFailureResponse)),
					))

				networkConfigRequest := NetworkConfigRequest{
					NetworkConfig: l3Forward,
					BigIp: BigIP{
						IPaddress:  BigIPAddress,
						InstanceId: BigIpId,
					},
					Action: Delete,
				}
				networkManager.L3ForwardStore.InstanceStaticRoutes[BigIpId] = staticRouteMap
				l3Forward.ID = L3ForwardId
				networkManager.L3ForwardStore.addL3ForwardEntry(BigIpId, l3Forward)
				networkManager.HandleL3ForwardRequest(&networkConfigRequest, &l3Forward)
				Expect(len(networkManager.NetworkChan)).ToNot(BeZero())
				Expect(networkConfigRequest.retryTimeout).ToNot(BeZero())

			})
			It("Test the create l3Forward request failure", func() {
				// Route post failure response
				routeAPIFailureResponse = `
{
    "status": 404,
    "message": "DEVICE-00004: Unable to find instance"
}`
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", InstancesURI+BigIpId+L3Forwards),
						ghttp.RespondWithJSONEncoded(statusCodeAccepted, stringToJson(routeAPIFailureResponse)),
					))

				networkConfigRequest := NetworkConfigRequest{
					NetworkConfig: l3Forward,
					BigIp: BigIP{
						IPaddress:  BigIPAddress,
						InstanceId: BigIpId,
					},
					Action: Create,
				}
				networkManager.HandleL3ForwardRequest(&networkConfigRequest, &l3Forward)
				Expect(len(networkManager.NetworkChan)).ToNot(BeZero())
				Expect(networkConfigRequest.retryTimeout).ToNot(BeZero())

			})
			It("Test the delete l3Forward request failure", func() {
				// Route failure response
				routeAPIFailureResponse = `
{
    "status": 404,
    "message": "DEVICE-00004: Unable to find instance"
}`
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("DELETE", fmt.Sprintf("%s/%s", InstancesURI+BigIpId+L3Forwards, L3ForwardId)),
						ghttp.RespondWithJSONEncoded(statusCodeAccepted, stringToJson(routeAPIFailureResponse)),
					))
				networkConfigRequest := NetworkConfigRequest{
					NetworkConfig: l3Forward,
					BigIp: BigIP{
						IPaddress:  BigIPAddress,
						InstanceId: BigIpId,
					},
					Action: Delete,
				}
				networkManager.L3ForwardStore.InstanceStaticRoutes[BigIpId] = staticRouteMap

				l3Forward.ID = L3ForwardId
				networkManager.L3ForwardStore.addL3ForwardEntry(BigIpId, l3Forward)
				networkManager.HandleL3ForwardRequest(&networkConfigRequest, &l3Forward)
				Expect(len(networkManager.NetworkChan)).ToNot(BeZero())
				Expect(networkConfigRequest.retryTimeout).ToNot(BeZero())
			})

		})

		Context("Network manager initialize scenario", func() {
			BeforeEach(func() {
				routeStore = make(RouteStore)
				staticRouteMap = make(map[StaticRouteConfig]L3Forward)
				l3Forward = L3Forward{
					Config: StaticRouteConfig{
						Gateway:       "10.0.0.1",
						Destination:   "10.244.0.0/24",
						L3ForwardType: L3RouteGateway,
					},
					VRF:  DefaultL3Network,
					Name: "test",
				}
				// Mock the server
				server = ghttp.NewServer()
				tokenManager = tokenmanager.NewTokenManager(server.URL(), tokenmanager.Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true, mockStatusManager)

				tokenResponse = tokenmanager.AccessTokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCodeOk, tokenResponse),
					))
				tokenManager.SyncTokenWithoutRetry()
				inventoryResponse = fmt.Sprintf(`{
    "_embedded": {
        "devices": [
            {
                "address": "%s",
                "id": "%s"
            }
        ]
    }
}`, BigIPAddress, BigIpId)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", InventoryURI),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(inventoryResponse))),
				)
				// l3Forward response
				l3ForwardResponse = fmt.Sprintf(`{
    "_embedded": {
        "l3forwards": [
{
                "id": "%s",
                "instance_id": "%s",
                "payload": {
                    "id": "8e241157-c680-4e27-a7da-2999d80f6e4d",
                    "name": "cluster-1/humane-airedale-master.novalocal/10.4.0.234",
                    "config": {
                        "gateway": "10.4.0.234",
                        "destination": "10.244.0.0/24",
                        "l3ForwardType": "L3RouteGateway"
                    },
					"vrf": "%s"
                }
            }
]
    }
}`, L3ForwardId, BigIpId, DefaultL3Network)
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", InstancesURI+BigIpId+L3Forwards),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(l3ForwardResponse))),
				)
				// Route delete success response
				networkManager = NewNetworkManager(tokenManager, "cluster-1")
				bigIPConfig = []cisapiv1.BigIpConfig{{
					BigIpAddress: BigIPAddress,
				}}
			})
			AfterEach(func() {
				// Stop the mock token server
				server.Close()
				close(networkManager.NetworkChan)
			})
			It("Initialize the network controller when l3forwards are present on server", func() {
				isr, _ := networkManager.L3ForwardStore.InstanceStaticRoutes[BigIpId]
				Expect(len(isr)).To(BeZero())
				networkManager.SetInstanceIds(bigIPConfig, "cluster-1")
				isr, _ = networkManager.L3ForwardStore.InstanceStaticRoutes[BigIpId]
				Expect(len(isr)).ToNot(BeZero())
				// test retry timeout increment
				Expect(getRetryTimeout(2)).To(Equal(4))
			})
		})
	})
})

var _ = Describe("getDefaultL3Network", func() {
	var (
		tokenManager *tokenmanager.TokenManager
	)

	BeforeEach(func() {
		tokenManager = &tokenmanager.TokenManager{}
	})

	Context("when CMVersion is empty", func() {
		It("should return DefaultL3Network", func() {
			tokenManager.CMVersion = ""
			Expect(getDefaultL3Network(tokenManager)).To(Equal(DefaultL3Network))
		})
	})

	Context("when CMVersion is in an invalid format", func() {
		It("should return DefaultL3Network for incorrect float parsing", func() {
			tokenManager.CMVersion = "invalid.version.1"
			Expect(getDefaultL3Network(tokenManager)).To(Equal(DefaultL3Network))
		})

		It("should return DefaultL3Network for incorrect int parsing", func() {
			tokenManager.CMVersion = "20.2.invalid"
			Expect(getDefaultL3Network(tokenManager)).To(Equal(DefaultL3Network))
		})
	})

	Context("when CMVersion is valid", func() {
		It("should return LegacyDefaultL3Network for versions less than 20.2.1", func() {
			tokenManager.CMVersion = "20.1.0"
			Expect(getDefaultL3Network(tokenManager)).To(Equal(LegacyDefaultL3Network))
		})

		It("should return LegacyDefaultL3Network for version 20.2.0", func() {
			tokenManager.CMVersion = "20.2.0"
			Expect(getDefaultL3Network(tokenManager)).To(Equal(LegacyDefaultL3Network))
		})

		It("should return DefaultL3Network for versions 20.2.1 and above", func() {
			tokenManager.CMVersion = "20.2.1"
			Expect(getDefaultL3Network(tokenManager)).To(Equal(DefaultL3Network))
		})

		It("should return DefaultL3Network for versions greater than 20.2.1", func() {
			tokenManager.CMVersion = "21.0.0"
			Expect(getDefaultL3Network(tokenManager)).To(Equal(DefaultL3Network))
		})
	})
})

var _ = Describe("getTaskApi", func() {
	var (
		tm *tokenmanager.TokenManager
	)

	BeforeEach(func() {
		tm = &tokenmanager.TokenManager{}
	})

	Context("when CMVersion is empty", func() {
		It("should return an empty string", func() {
			Expect(getTaskApi(tm)).To(Equal(""))
		})
	})

	Context("when CMVersion is not in valid format", func() {
		It("should return an empty string if version is incomplete", func() {
			tm.CMVersion = "20.2"
			Expect(getTaskApi(tm)).To(Equal(""))
		})

		It("should return an empty string if version has non-numeric parts", func() {
			tm.CMVersion = "20.2.a"
			Expect(getTaskApi(tm)).To(Equal(""))
		})
	})

	Context("when CMVersion is valid", func() {
		It("should return TaskBaseURI for versions less than 20.2.1", func() {
			tm.CMVersion = "20.1.5"
			Expect(getTaskApi(tm)).To(Equal(TaskBaseURI))

			tm.CMVersion = "20.2.0"
			Expect(getTaskApi(tm)).To(Equal(TaskBaseURI))
		})

		It("should return an empty string for versions 20.2.1 and above", func() {
			tm.CMVersion = "20.2.1"
			Expect(getTaskApi(tm)).To(Equal(""))

			tm.CMVersion = "21.0.0"
			Expect(getTaskApi(tm)).To(Equal(""))
		})
	})

	Context("when CMVersion has parsing errors", func() {
		It("should return an empty string if major.minor version parsing fails", func() {
			tm.CMVersion = "20.a.1"
			Expect(getTaskApi(tm)).To(Equal(""))
		})

		It("should return an empty string if patch version parsing fails", func() {
			tm.CMVersion = "20.2.a"
			Expect(getTaskApi(tm)).To(Equal(""))
		})
	})
})
