package tokenmanager

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Token Manager Tests", func() {
	var tokenManager *TokenManager
	var server *ghttp.Server
	var statusCode int
	var response TokenResponse

	Describe("GetToken", func() {
		Context("when token fetch is successful", func() {
			BeforeEach(func() {
				// Mock the token server
				server = ghttp.NewServer()
				tokenManager = NewTokenManager(server.URL(), Credentials{
					Username: "admin",
					Password: "admin",
				}, "", true)
			})
			AfterEach(func() {
				// Stop the mock token server
				server.Close()
			})

			It("should return error while fetching token", func() {
				statusCode = 500
				response = TokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err := tokenManager.fetchToken()
				Expect(err).NotTo(BeNil(), "Error should not be nil")
				token := tokenManager.GetToken()
				Expect(token).To(BeEmpty(), "Token should be empty")
			})

			It("should return a valid token", func() {
				statusCode = 200
				response = TokenResponse{
					AccessToken: "test.token",
				}
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/api/login"),
						ghttp.RespondWithJSONEncoded(statusCode, response),
					))
				err := tokenManager.fetchToken()
				Expect(err).To(BeNil(), "Error should be nil")
				token := tokenManager.GetToken()
				Expect(token).To(Equal(response.AccessToken), "Token should not be nil")
			})
		})
	})
})
