package networkmanager

import (
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	. "github.com/onsi/ginkgo"
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
	var tokenResponse tokenmanager.TokenResponse
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
					VLANs: []int{},
					Name:  "test",
				}
				// Mock the server
				server = ghttp.NewServer()
				tokenManager = tokenmanager.NewTokenManager(server.URL(), tokenmanager.Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true)

				tokenResponse = tokenmanager.TokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCodeOk, tokenResponse),
					))
				tokenManager.FetchToken()
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
						ghttp.VerifyRequest("GET", TaskBaseURI+TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskSuccessResponse)),
					))

				staticRouteMap[l3Forward.Config] = l3Forward
				routeStore[BigIpId] = staticRouteMap
				networkManager.NetworkRequestHandler(routeStore)
				time.Sleep(3 * time.Second)
				isr, _ := networkManager.L3ForwardStore.InstanceStaticRoutes[BigIpId]
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
						ghttp.VerifyRequest("GET", TaskBaseURI+TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskSuccessResponse)),
					))
				routeStore[BigIpId] = staticRouteMap
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
					VLANs: []int{},
					Name:  "test",
				}
				// Mock the server
				server = ghttp.NewServer()
				tokenManager = tokenmanager.NewTokenManager(server.URL(), tokenmanager.Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true)

				tokenResponse = tokenmanager.TokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCodeOk, tokenResponse),
					))
				tokenManager.FetchToken()
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
						ghttp.VerifyRequest("GET", TaskBaseURI+TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskFailureResponse)),
					))

				networkConfigRequest := NetworkConfigRequest{
					NetworkConfig:   l3Forward,
					BigIpInstanceId: BigIpId,
					Action:          Create,
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
						ghttp.VerifyRequest("GET", TaskBaseURI+TaskRef),
						ghttp.RespondWithJSONEncoded(statusCodeOk, stringToJson(routeTaskFailureResponse)),
					))

				networkConfigRequest := NetworkConfigRequest{
					NetworkConfig:   l3Forward,
					BigIpInstanceId: BigIpId,
					Action:          Delete,
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
					NetworkConfig:   l3Forward,
					BigIpInstanceId: BigIpId,
					Action:          Create,
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
					NetworkConfig:   l3Forward,
					BigIpInstanceId: BigIpId,
					Action:          Delete,
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
					VLANs: []int{},
					Name:  "test",
				}
				// Mock the server
				server = ghttp.NewServer()
				tokenManager = tokenmanager.NewTokenManager(server.URL(), tokenmanager.Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true)

				tokenResponse = tokenmanager.TokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCodeOk, tokenResponse),
					))
				tokenManager.FetchToken()
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
                    }
                }
            }
]
    }
}`, L3ForwardId, BigIpId)
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
