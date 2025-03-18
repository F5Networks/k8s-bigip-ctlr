package controller

import (
	"errors"
	"io"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

var _ = Describe("NewPostManager", func() {
	var (
		params   AgentParams
		respChan chan *agentPostConfig
	)

	BeforeEach(func() {
		respChan = make(chan *agentPostConfig, 1)
		params = AgentParams{
			ApiType: AS3,
			PrimaryClusterHealthProbeParams: &PrimaryClusterHealthProbeParams{
				probeInterval: 5,
				retryInterval: 10,
			},
			GTMParams: PostParams{
				BIGIPURL: "https://gtm.example.com",
			},
			PrimaryParams: PostParams{
				BIGIPURL: "https://primary.example.com",
			},
			SecondaryParams: PostParams{
				BIGIPURL: "https://secondary.example.com",
			},
		}
	})

	Context("when creating a GTM BIG-IP post manager", func() {
		It("should initialize correctly", func() {
			pm := NewPostManager(params, GTMBigIP, respChan)

			Expect(pm).NotTo(BeNil())
			Expect(pm.firstPost).To(BeTrue())
			Expect(pm.PostParams).To(Equal(params.GTMParams))
			Expect(pm.postManagerPrefix).To(Equal(gtmPostmanagerPrefix))
			Expect(pm.apiType).To(Equal(AS3))
			Expect(pm.PrimaryClusterHealthProbeParams).To(Equal(params.PrimaryClusterHealthProbeParams))
		})
	})

	Context("when creating a Primary BIG-IP post manager", func() {
		It("should initialize correctly with Secondary BIG-IP configured", func() {
			pm := NewPostManager(params, PrimaryBigIP, respChan)

			Expect(pm).NotTo(BeNil())
			Expect(pm.firstPost).To(BeTrue())
			Expect(pm.PostParams).To(Equal(params.PrimaryParams))
			Expect(pm.postManagerPrefix).To(Equal(primaryPostmanagerPrefix))
		})

		It("should initialize correctly without Secondary BIG-IP", func() {
			params.SecondaryParams = PostParams{}
			pm := NewPostManager(params, PrimaryBigIP, respChan)

			Expect(pm).NotTo(BeNil())
			Expect(pm.PostParams).To(Equal(params.PrimaryParams))
			Expect(pm.postManagerPrefix).To(Equal(defaultPostmanagerPrefix))
		})
	})

	Context("when creating a Secondary BIG-IP post manager", func() {
		It("should initialize correctly", func() {
			pm := NewPostManager(params, SecondaryBigIP, respChan)

			Expect(pm).NotTo(BeNil())
			Expect(pm.firstPost).To(BeTrue())
			Expect(pm.PostParams).To(Equal(params.SecondaryParams))
			Expect(pm.postManagerPrefix).To(Equal(secondaryPostmanagerPrefix))
		})
	})

	It("should create a postChan", func() {
		pm := NewPostManager(params, GTMBigIP, respChan)
		Expect(pm.postChan).NotTo(BeNil())
	})

	It("should call setupBIGIPRESTClient", func() {
		pm := NewPostManager(params, GTMBigIP, respChan)
		Expect(pm.httpClient).NotTo(BeNil()) // Assuming setupBIGIPRESTClient initializes RESTClient
	})
})

var _ = Describe("setupBIGIPRESTClient", func() {
	var (
		postMgr *PostManager
	)

	BeforeEach(func() {
		postMgr = &PostManager{
			apiType:           AS3,
			postManagerPrefix: "TestPrefix",
			PostParams: PostParams{
				TrustedCerts:      "TestCerts",
				SSLInsecure:       false,
				HTTPClientMetrics: false,
			},
			httpClient: &http.Client{},
		}
	})

	Context("setupBIGIPRESTClient", func() {
		It("should create an HTTP client", func() {
			postMgr.setupBIGIPRESTClient()
			Expect(postMgr.httpClient).NotTo(BeNil())
		})

		It("should set SSL InsecureSkipVerify based on SSLInsecure flag", func() {
			postMgr.SSLInsecure = true
			postMgr.setupBIGIPRESTClient()
			transport := postMgr.httpClient.Transport.(*http.Transport)
			Expect(transport.TLSClientConfig.InsecureSkipVerify).To(BeTrue())
		})

		It("should append trusted certificates", func() {
			postMgr.TrustedCerts = "-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUJvfhXtLGVxNlZVLmhgXPQZgNPLwwDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTYxNDIxMTNaFw0yNDA1\nMTUxNDIxMTNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC8gTRWOLvE9hLlWWD6FvXXeGSlOZSBOgP0XpZoMXPP\nNFLBNrEQOvZOVZWzZgQo7tnqjvKvG0pXBJVp2ZsN9tIdpj1Oe1DhHBFrHzI8+8+m\nZVy8b/8W8U7FzMlCqoq3HUwOuiSc9+UpGRLMDqQXa5Pz0jiXcg/KMTKXlFqHClv0\n7I4zWg+ADnVYwVc1FW7T+aFzeyLWlc3RXZyCYHnqzWaZxsS1Vy+Cr+GWMNuBDvWg\nxK/Qj8nnpZWMTEQBrYyc9Nnj8BZmC1qSexceRhkMK3o0cNXrIi7tBwRcVwRdZZGT\nqHXqzgNbYprNh7gJU6jqt9wZdKJ/JXA1TAg+Qy6Xt+AxAgMBAAGjUzBRMB0GA1Ud\nDgQWBBRBZzFYthEsEPVjVZBDyBM3pUdtMzAfBgNVHSMEGDAWgBRBZzFYthEsEPVj\nVZBDyBM3pUdtMzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB7\nJ9IbfOdxHqLi1I8MhM1Z9KTWw/wqTWq0yMl0T2gWRBSG3H3Cy2BgGWo0aNbhePjO\nDLjGZJ9aONEWEasiPGcZWBOpkPIpS8mLKCPZI2iULZEUNrjZCBXpReBVZBXHBYQy\nXwUPKVo1+H5+ZHa7/UMeUGdPOVfh/TpJGH0+ocU0RcKW0kFubIvZF5HhSCVyJOdY\nULIzHFPLKQHXrkTCzEzLZqbJhR8cLOO6WpdN1ZuOXMehBgzaGX3eZ1xYtGXtOYO3\nLFVVZuHVOCX1Vnv3iBmk+TZMcI3+d1uW+rTzTGXLOdzXVuWZEcJcWKv8sCYV+l3I\nZtUNM/9FTHcNTUZXHCQf\n-----END CERTIFICATE-----"
			postMgr.setupBIGIPRESTClient()
			transport := postMgr.httpClient.Transport.(*http.Transport)
			Expect(transport.TLSClientConfig.RootCAs).NotTo(BeNil())
			Expect(transport.TLSClientConfig.RootCAs.Subjects()).To(HaveLen(1))
		})

		Context("when HTTPClientMetrics is true", func() {
			BeforeEach(func() {
				postMgr.HTTPClientMetrics = true
			})

			It("should create an instrumented HTTP client", func() {
				postMgr.setupBIGIPRESTClient()
				Expect(postMgr.httpClient).NotTo(BeNil())
				Expect(postMgr.httpClient.Transport).To(BeAssignableToTypeOf(promhttp.InstrumentRoundTripperInFlight(nil, nil)))
			})
		})

		Context("when HTTPClientMetrics is false", func() {
			BeforeEach(func() {
				postMgr.HTTPClientMetrics = false
			})

			It("should create a regular HTTP client", func() {
				postMgr.setupBIGIPRESTClient()
				Expect(postMgr.httpClient).NotTo(BeNil())
				Expect(postMgr.httpClient.Transport).To(BeAssignableToTypeOf(&http.Transport{}))
			})
		})
	})
})

var _ = Describe("PostManager", func() {
	var (
		server  *ghttp.Server
		cfg     *agentPostConfig
		mockPM  *mockPostManager
		request *http.Request
	)

	BeforeEach(func() {
		server = ghttp.NewServer()
		mockPM = newMockPostManger()
		mockPM.BIGIPURL = "bigip.com"
		mockPM.BIGIPUsername = "user"
		mockPM.BIGIPPassword = "pswd"
		cfg = &agentPostConfig{
			id:        1,
			as3APIURL: server.URL() + "/mgmt/shared/appsvcs/declare",
			data:      `{"class": "AS3"}`,
		}
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("postConfig", func() {
		Context("when the request is successful", func() {
			BeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyBasicAuth("testuser", "testpass"),
						ghttp.VerifyRequest("POST", "/mgmt/shared/appsvcs/declare"),
						ghttp.VerifyJSON(`{"class": "AS3"}`),
						ghttp.RespondWithJSONEncoded(200, map[string]interface{}{"status": "success"}),
					),
				)
			})

			It("should return a response and response map", func() {
				resp, respMap := mockPM.postConfig(cfg)
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(200))
				Expect(respMap).To(HaveKeyWithValue("status", "success"))
				Expect(mockPM.firstPost).To(BeFalse())
			})
		})

		Context("when creating the request fails", func() {
			BeforeEach(func() {
				cfg.as3APIURL = "://invalid-url"
			})

			It("should return nil response and nil map", func() {
				resp, respMap := mockPM.postConfig(cfg)
				Expect(resp).To(BeNil())
				Expect(respMap).To(BeNil())
			})
		})

		Context("when the HTTP POST fails", func() {
			BeforeEach(func() {
				mockPM.setResponses([]responceCtx{{
					tenant: "test",
					status: http.StatusNotFound,
					body:   io.NopCloser(strings.NewReader("")),
				}}, http.MethodPost)
			})

			It("should return nil response and nil map", func() {
				resp, respMap := mockPM.postConfig(cfg)
				Expect(resp).To(BeNil())
				Expect(respMap).To(BeNil())
			})
		})
	})
	Describe("httpPOST", func() {
		Context("when the response body cannot be read", func() {
			BeforeEach(func() {
				mockPM.setResponses([]responceCtx{{
					tenant: "test",
					status: http.StatusOK,
					body:   io.NopCloser(&errorReader{}),
				}}, http.MethodPost)
				request, _ = http.NewRequest("POST", "http://example.com", nil)
			})

			It("should return nil response and nil map", func() {
				resp, respMap := mockPM.httpPOST(request)
				Expect(resp).To(BeNil())
				Expect(respMap).To(BeNil())
			})
		})

		Context("when the response body is not valid JSON", func() {
			BeforeEach(func() {
				mockPM.setResponses([]responceCtx{{
					tenant: "test",
					status: http.StatusOK,
					body:   io.NopCloser(strings.NewReader("not json")),
				}}, http.MethodPost)
				request, _ = http.NewRequest("POST", "http://example.com", nil)
			})

			It("should return nil response and nil map", func() {
				resp, respMap := mockPM.httpPOST(request)
				Expect(resp).To(BeNil())
				Expect(respMap).To(BeNil())
			})
		})

		Context("when the response is Unauthorized", func() {
			BeforeEach(func() {
				mockPM.setResponses([]responceCtx{{
					tenant: "test",
					status: http.StatusUnauthorized,
					body:   io.NopCloser(strings.NewReader("Unauthorized")),
				}}, http.MethodPost)
				request, _ = http.NewRequest("POST", "http://example.com", nil)
			})

			It("should return nil response and nil map", func() {
				resp, respMap := mockPM.httpPOST(request)
				Expect(resp).To(BeNil())
				Expect(respMap).To(BeNil())
			})
		})
	})
})
