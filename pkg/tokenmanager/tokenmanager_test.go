package tokenmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager/mockmanager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"time"
)

var _ = Describe("Token Manager Tests", func() {
	var tokenManager *TokenManager
	var server *ghttp.Server
	var statusCode int
	var response AccessTokenResponse
	var refreshResponse RefreshTokenResponse
	Describe("GetAccessToken", func() {
		Context("when accessToken is fetched during login", func() {
			BeforeEach(func() {
				// Mock the accessToken server
				server = ghttp.NewServer()
				mockStatusManager := mockmanager.NewMockStatusManager()
				tokenManager = NewTokenManager(server.URL(), Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true, mockStatusManager)
			})
			AfterEach(func() {
				// Stop the mock accessToken server
				server.Close()
			})

			It("should return error while fetching accessToken", func() {
				statusCode = 500
				response = AccessTokenResponse{
					AccessToken: "test.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMRefreshTokenURL),
						ghttp.RespondWithJSONEncoded(statusCode, RefreshTokenResponse{
							AccessToken: "test.accessToken",
						}),
					))
				go tokenManager.SyncToken()
				time.Sleep(1 * time.Second)
				token := tokenManager.GetAccessToken()
				Expect(token).To(BeEmpty(), "Token should be empty")
			})

			It("should return a valid accessToken", func() {
				statusCode = 200
				response = AccessTokenResponse{
					AccessToken: "test.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				tokenManager.SyncTokenWithoutRetry()
				token := tokenManager.GetAccessToken()
				Expect(token).To(Equal(response.AccessToken), "Token should not be nil")
			})
			It("error code 401", func() {
				statusCode = 401
				response = AccessTokenResponse{
					AccessToken: "test.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err, _ := tokenManager.SyncTokenWithoutRetry()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unauthorized to fetch accessToken"))
			})
			It("error code 503", func() {
				statusCode = 503
				response = AccessTokenResponse{
					AccessToken: "test.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err, _ := tokenManager.SyncTokenWithoutRetry()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to get accessToken due to service unavailability"))
			})
			It("error code 404", func() {
				statusCode = 404
				response = AccessTokenResponse{
					AccessToken: "test.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err, _ := tokenManager.SyncTokenWithoutRetry()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("requested page/api not found"))
			})
		})
		Context("when accessToken is fetched during refresh", func() {
			BeforeEach(func() {
				// Mock the accessToken server
				server = ghttp.NewServer()
				mockStatusManager := mockmanager.NewMockStatusManager()
				tokenManager = NewTokenManager(server.URL(), Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true, mockStatusManager)
				tokenManager.accessToken = "test.accessToken"
				tokenManager.accessTokenExpiry = time.Now()
			})
			AfterEach(func() {
				// Stop the mock accessToken server
				server.Close()
			})

			It("should return a valid accessToken on refresh", func() {
				statusCode = 200
				refreshResponse = RefreshTokenResponse{
					AccessToken: "refreshed.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMRefreshTokenURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshAccessToken()
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenManager.accessToken).To(Equal(refreshResponse.AccessToken), "Token should not be nil")
			})
			It("error code 401 with refresh api", func() {
				statusCode = 401
				refreshResponse = RefreshTokenResponse{
					AccessToken: "refreshed.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMRefreshTokenURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshAccessToken()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unauthorized to fetch accessToken"))
			})
			It("error code 503 with token refresh api", func() {
				statusCode = 503
				refreshResponse = RefreshTokenResponse{
					AccessToken: "refreshed.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMRefreshTokenURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshAccessToken()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to get accessToken due to service unavailability"))
			})
			It("error code 404", func() {
				statusCode = 404
				refreshResponse = RefreshTokenResponse{
					AccessToken: "refreshed.accessToken",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", CMRefreshTokenURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshAccessToken()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("requested page/api not found"))
			})
		})
	})
})

var _ = Describe("GetCMVersion", func() {
	var (
		tm         *TokenManager
		server     *ghttp.Server
		statusCode int
	)

	BeforeEach(func() {
		server = ghttp.NewServer()
		mockStatusManager := mockmanager.NewMockStatusManager()
		tm = NewTokenManager(server.URL(), Credentials{
			Username: "admin",
			Password: "admin",
		}, "", true, mockStatusManager)
		tm.accessToken = "fake-accessToken"
		tm.accessTokenExpiry = time.Now().Add(5 * time.Minute)
	})

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("GetCMVersion", func() {
		It("should return the correct version when response is valid", func() {
			statusCode = 200
			response := map[string]interface{}{
				"version": "BIG-IP-Next-CentralManager-20.1.0-1",
			}
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", CMVersionURL),
					ghttp.RespondWithJSONEncoded(statusCode, response),
				))

			version, err := tm.GetCMVersion()
			Expect(err).NotTo(HaveOccurred())
			Expect(version).To(Equal("20.1.0"))
		})

		It("should return an error when the status code is not 200", func() {
			statusCode = 500
			response := map[string]interface{}{
				"version": "BIG-IP-Next-CentralManager-20.1.0-1",
			}
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", CMVersionURL),
					ghttp.RespondWithJSONEncoded(statusCode, response),
				))

			_, err := tm.GetCMVersion()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("API request failed with status code"))
		})

		It("should return an error when the response is not valid JSON", func() {
			statusCode = 200
			response := "invalid json"
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", CMVersionURL),
					ghttp.RespondWithJSONEncoded(statusCode, response),
				))

			_, err := tm.GetCMVersion()
			Expect(err).To(HaveOccurred())
		})

		It("should return an error when version format is incorrect", func() {
			statusCode = 200
			response := map[string]interface{}{
				"version": "invalidFormat",
			}
			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", CMVersionURL),
					ghttp.RespondWithJSONEncoded(statusCode, response),
				))

			_, err := tm.GetCMVersion()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("error fetching CM version"))
		})
	})
})
