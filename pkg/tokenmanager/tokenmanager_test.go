package tokenmanager

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"net/http"
	"time"
)

var _ = Describe("Token Manager Tests", func() {
	var tokenManager *TokenManager
	var server *ghttp.Server
	var statusCode int
	var response TokenResponse

	Describe("GetToken", func() {
		Context("when Token is fetched during login", func() {
			BeforeEach(func() {
				// Mock the Token server
				server = ghttp.NewServer()
				tokenManager = NewTokenManager(server.URL(), Credentials{
					Username:          "admin",
					Password:          "admin",
					LoginProviderName: "tmos",
				}, &http.Client{})
			})
			AfterEach(func() {
				// Stop the mock Token server
				server.Close()
			})

			It("should return error while fetching Token", func() {
				statusCode = 500
				response = TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "test.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("PATCH", BIGIPTokenURL+"test.Token"),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				tokenManager.SyncTokenWithoutRetry()
				Expect(tokenManager.Token).To(BeEmpty(), "Token should be empty")
			})

			It("should return a valid Token", func() {
				statusCode = 200
				response = TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "test.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				tokenManager.SyncTokenWithoutRetry()
				token := tokenManager.GetToken()
				Expect(token).To(Equal(response.Token.Token), "Token should not be nil")
			})

			It("error code 401", func() {
				statusCode = 401
				response = TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "test.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err, _ := tokenManager.SyncTokenWithoutRetry()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unauthorized to fetch Token"))
			})

			It("error code 503", func() {
				statusCode = 503
				response = TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "test.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err, _ := tokenManager.SyncTokenWithoutRetry()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to get Token due to service unavailability"))
			})

			It("error code 404", func() {
				statusCode = 404
				response = TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "test.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err, _ := tokenManager.SyncTokenWithoutRetry()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("requested page/api not found"))
			})
		})

		Context("when Token is refreshed", func() {
			BeforeEach(func() {
				// Mock the Token server
				server = ghttp.NewServer()
				tokenManager = NewTokenManager(server.URL(), Credentials{
					Username: "admin",
					Password: "admin",
				}, &http.Client{})
				tokenManager.Token = "test.Token"
				tokenManager.tokenExpiry = time.Now()
				tokenManager.tokenRefreshURL = BIGIPTokenURL + "test.Token"
			})

			AfterEach(func() {
				// Stop the mock Token server
				server.Close()
			})

			It("should return a valid Token on refresh", func() {
				statusCode = 200
				refreshResponse := TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "refreshed.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("PATCH", BIGIPTokenURL+"test.Token"),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshToken()
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenManager.Token).To(Equal(refreshResponse.Token.Token), "Token should not be nil")
			})

			It("error code 401 with refresh api", func() {
				statusCode = 401
				refreshResponse := TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "refreshed.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				// First for refresh attempt
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("PATCH", BIGIPTokenURL+"test.Token"),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				// Second for SyncToken attempt
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshToken()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unauthorized to fetch Token"))
			})

			It("error code 503 with Token refresh api", func() {
				statusCode = 503
				refreshResponse := TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "refreshed.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				// First for refresh attempt
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("PATCH", BIGIPTokenURL+"test.Token"),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				// Second for SyncToken attempt
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshToken()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to get Token due to service unavailability"))
			})

			It("error code 404", func() {
				statusCode = 404
				refreshResponse := TokenResponse{
					Token: struct {
						Token            string    `json:"Token"`
						ExpirationMicros int64     `json:"expirationMicros"`
						LastUse          int64     `json:"lastUse"`
						Timeout          int       `json:"timeout"`
						UserReference    Reference `json:"userReference"`
					}{
						Token:            "refreshed.Token",
						ExpirationMicros: time.Now().Add(1*time.Hour).UnixNano() / 1000,
					},
				}
				// First for refresh attempt
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("PATCH", BIGIPTokenURL+"test.Token"),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				// Second for SyncToken attempt
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", BIGIPLoginURL),
						ghttp.RespondWithJSONEncoded(statusCode, refreshResponse),
					))
				err := tokenManager.RefreshToken()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("requested page/api not found"))
			})
		})
	})
})
