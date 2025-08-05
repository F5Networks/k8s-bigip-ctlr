package bigiphandler

import (
	"errors"
	"testing"

	"github.com/f5devcentral/go-bigip"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBigiphandler(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BigIPHandler Suite")
}

// MockBigIPClient implements BigIPClient interface for testing
type MockBigIPClient struct {
	shouldError bool
	errorMsg    string
}

func NewMockBigIPClient(shouldError bool, errorMsg string) *MockBigIPClient {
	return &MockBigIPClient{
		shouldError: shouldError,
		errorMsg:    errorMsg,
	}
}

// Mock methods implementing BigIPClient interface
func (m *MockBigIPClient) IRule(name string) (*bigip.IRule, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.IRule{Name: name}, nil
}

func (m *MockBigIPClient) GetClientSSLProfile(name string) (*bigip.ClientSSLProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.ClientSSLProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetServerSSLProfile(name string) (*bigip.ServerSSLProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.ServerSSLProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetWafPolicy(name string) (*bigip.WafPolicy, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.WafPolicy{Name: name}, nil
}

func (m *MockBigIPClient) GetBotDefenseProfile(name string) (*bigip.BotDefenseProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.BotDefenseProfile{Name: name}, nil
}

func (m *MockBigIPClient) Vlan(name string) (*bigip.Vlan, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Vlan{Name: name}, nil
}

func (m *MockBigIPClient) GetSnat(name string) (*bigip.Snat, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Snat{Name: name}, nil
}

func (m *MockBigIPClient) GetPool(name string) (*bigip.Pool, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Pool{Name: name}, nil
}

func (m *MockBigIPClient) GetTcp(name string) (*bigip.Tcp, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Tcp{Name: name}, nil
}

func (m *MockBigIPClient) GetHttp2(name string) (*bigip.Http2, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Http2{Name: name}, nil
}

func (m *MockBigIPClient) GetHttpProfile(name string) (*bigip.HttpProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.HttpProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetRewriteProfile(name string) (*bigip.RewriteProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.RewriteProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetFastl4(name string) (*bigip.Fastl4, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Fastl4{Name: name}, nil
}

func (m *MockBigIPClient) GetFtp(name string) (*bigip.Ftp, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Ftp{Name: name}, nil
}

func (m *MockBigIPClient) GetHttpCompressionProfile(name string) (*bigip.HttpCompressionProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.HttpCompressionProfile{Name: name}, nil
}

// Additional mock methods for missing interface implementations
func (m *MockBigIPClient) GetAccessProfile(name string) (*bigip.AccessProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	// Return a generic AccessProfile struct for testing
	return &bigip.AccessProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetOneconnect(name string) (*bigip.Oneconnect, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.Oneconnect{Name: name}, nil
}

func (m *MockBigIPClient) GetAccessPolicy(name string) (*bigip.AccessPolicy, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.AccessPolicy{Name: name}, nil
}

func (m *MockBigIPClient) GetRequestAdaptProfile(name string) (*bigip.RequestAdaptProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.RequestAdaptProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetResponseAdaptProfile(name string) (*bigip.ResponseAdaptProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.ResponseAdaptProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetDOSProfile(name string) (*bigip.DOSProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.DOSProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetFirewallPolicy(name string) (*bigip.FirewallPolicy, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.FirewallPolicy{Name: name}, nil
}

func (m *MockBigIPClient) GetIPIntelligencePolicy(name string) (*bigip.IPIntelligencePolicy, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.IPIntelligencePolicy{Name: name}, nil
}

func (m *MockBigIPClient) GetUDPProfile(name string) (*bigip.UdpProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.UdpProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetSecurityLogProfile(name string) (*bigip.SecurityLogProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.SecurityLogProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetWebsocketProfile(name string) (*bigip.WebsocketProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.WebsocketProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetHTMLProfile(name string) (*bigip.HTMLProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.HTMLProfile{Name: name}, nil
}

func (m *MockBigIPClient) GetCookiePersistenceProfile(name string) (*bigip.CookiePersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.CookiePersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetDestAddrPersistenceProfile(name string) (*bigip.DestAddrPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.DestAddrPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetHashPersistenceProfile(name string) (*bigip.HashPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.HashPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetHostPersistenceProfile(name string) (*bigip.HostPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.HostPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetMSRDPPersistenceProfile(name string) (*bigip.MSRDPPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.MSRDPPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetSIPPersistenceProfile(name string) (*bigip.SIPPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.SIPPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetSourceAddrPersistenceProfile(name string) (*bigip.SourceAddrPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.SourceAddrPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetUniversalPersistenceProfile(name string) (*bigip.UniversalPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.UniversalPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetSSLPersistenceProfile(name string) (*bigip.SSLPersistenceProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.SSLPersistenceProfile{}, nil
}

func (m *MockBigIPClient) GetAnalyticsProfile(name string) (*bigip.AnalyticsProfile, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	return &bigip.AnalyticsProfile{}, nil
}

// MockBigIPClientForPersistence is a specialized mock for testing persistence profile logic
type MockBigIPClientForPersistence struct {
	successfulProfile string // which profile type should succeed
	shouldError       bool
	errorMsg          string
}

func NewMockBigIPClientForPersistence(successfulProfile string, shouldError bool, errorMsg string) *MockBigIPClientForPersistence {
	return &MockBigIPClientForPersistence{
		successfulProfile: successfulProfile,
		shouldError:       shouldError,
		errorMsg:          errorMsg,
	}
}

// Implement all required methods for the persistence mock
func (m *MockBigIPClientForPersistence) IRule(name string) (*bigip.IRule, error) {
	return &bigip.IRule{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetClientSSLProfile(name string) (*bigip.ClientSSLProfile, error) {
	return &bigip.ClientSSLProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetServerSSLProfile(name string) (*bigip.ServerSSLProfile, error) {
	return &bigip.ServerSSLProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetWafPolicy(name string) (*bigip.WafPolicy, error) {
	return &bigip.WafPolicy{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetBotDefenseProfile(name string) (*bigip.BotDefenseProfile, error) {
	return &bigip.BotDefenseProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) Vlan(name string) (*bigip.Vlan, error) {
	return &bigip.Vlan{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetSnat(name string) (*bigip.Snat, error) {
	return &bigip.Snat{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetPool(name string) (*bigip.Pool, error) {
	return &bigip.Pool{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetTcp(name string) (*bigip.Tcp, error) {
	return &bigip.Tcp{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetHttp2(name string) (*bigip.Http2, error) {
	return &bigip.Http2{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetHttpProfile(name string) (*bigip.HttpProfile, error) {
	return &bigip.HttpProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetRewriteProfile(name string) (*bigip.RewriteProfile, error) {
	return &bigip.RewriteProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetFastl4(name string) (*bigip.Fastl4, error) {
	return &bigip.Fastl4{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetFtp(name string) (*bigip.Ftp, error) {
	return &bigip.Ftp{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetHttpCompressionProfile(name string) (*bigip.HttpCompressionProfile, error) {
	return &bigip.HttpCompressionProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetAccessProfile(name string) (*bigip.AccessProfile, error) {
	return &bigip.AccessProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetOneconnect(name string) (*bigip.Oneconnect, error) {
	return &bigip.Oneconnect{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetAccessPolicy(name string) (*bigip.AccessPolicy, error) {
	return &bigip.AccessPolicy{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetRequestAdaptProfile(name string) (*bigip.RequestAdaptProfile, error) {
	return &bigip.RequestAdaptProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetResponseAdaptProfile(name string) (*bigip.ResponseAdaptProfile, error) {
	return &bigip.ResponseAdaptProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetDOSProfile(name string) (*bigip.DOSProfile, error) {
	return &bigip.DOSProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetFirewallPolicy(name string) (*bigip.FirewallPolicy, error) {
	return &bigip.FirewallPolicy{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetIPIntelligencePolicy(name string) (*bigip.IPIntelligencePolicy, error) {
	return &bigip.IPIntelligencePolicy{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetUDPProfile(name string) (*bigip.UdpProfile, error) {
	return &bigip.UdpProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetSecurityLogProfile(name string) (*bigip.SecurityLogProfile, error) {
	return &bigip.SecurityLogProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetWebsocketProfile(name string) (*bigip.WebsocketProfile, error) {
	return &bigip.WebsocketProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetHTMLProfile(name string) (*bigip.HTMLProfile, error) {
	return &bigip.HTMLProfile{Name: name}, nil
}

func (m *MockBigIPClientForPersistence) GetAnalyticsProfile(name string) (*bigip.AnalyticsProfile, error) {
	return &bigip.AnalyticsProfile{Name: name}, nil
}

// Persistence profile methods that control the test behavior
func (m *MockBigIPClientForPersistence) GetCookiePersistenceProfile(name string) (*bigip.CookiePersistenceProfile, error) {
	if m.successfulProfile == "cookie" && !m.shouldError {
		return &bigip.CookiePersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetDestAddrPersistenceProfile(name string) (*bigip.DestAddrPersistenceProfile, error) {
	if m.successfulProfile == "dest-addr" && !m.shouldError {
		return &bigip.DestAddrPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetHashPersistenceProfile(name string) (*bigip.HashPersistenceProfile, error) {
	if m.successfulProfile == "hash" && !m.shouldError {
		return &bigip.HashPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetHostPersistenceProfile(name string) (*bigip.HostPersistenceProfile, error) {
	if m.successfulProfile == "host" && !m.shouldError {
		return &bigip.HostPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetMSRDPPersistenceProfile(name string) (*bigip.MSRDPPersistenceProfile, error) {
	if m.successfulProfile == "msrdp" && !m.shouldError {
		return &bigip.MSRDPPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetSIPPersistenceProfile(name string) (*bigip.SIPPersistenceProfile, error) {
	if m.successfulProfile == "sip" && !m.shouldError {
		return &bigip.SIPPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetSourceAddrPersistenceProfile(name string) (*bigip.SourceAddrPersistenceProfile, error) {
	if m.successfulProfile == "source-addr" && !m.shouldError {
		return &bigip.SourceAddrPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetUniversalPersistenceProfile(name string) (*bigip.UniversalPersistenceProfile, error) {
	if m.successfulProfile == "universal" && !m.shouldError {
		return &bigip.UniversalPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

func (m *MockBigIPClientForPersistence) GetSSLPersistenceProfile(name string) (*bigip.SSLPersistenceProfile, error) {
	if m.successfulProfile == "ssl" && !m.shouldError {
		return &bigip.SSLPersistenceProfile{
			PersistenceProfile: bigip.PersistenceProfile{
				Name: name,
			},
		}, nil
	}
	return nil, errors.New("profile not found")
}

var _ = Describe("BigIPHandler", func() {
	var (
		handler      *BigIPHandler
		mockClient   *MockBigIPClient
		testResource string
	)

	BeforeEach(func() {
		testResource = "test-resource"
	})

	Context("GetIRule", func() {
		It("should successfully retrieve an iRule", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetIRule(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.Name).To(Equal(testResource))
		})

		It("should return error when iRule retrieval fails", func() {
			errorMsg := "iRule not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetIRule(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetClientSSLProfile", func() {
		It("should successfully retrieve a Client SSL Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetClientSSLProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.Name).To(Equal(testResource))
		})

		It("should return error when Client SSL Profile retrieval fails", func() {
			errorMsg := "Client SSL Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetClientSSLProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetServerSSLProfile", func() {
		It("should successfully retrieve a Server SSL Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetServerSSLProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.Name).To(Equal(testResource))
		})

		It("should return error when Server SSL Profile retrieval fails", func() {
			errorMsg := "Server SSL Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetServerSSLProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetWAF", func() {
		It("should successfully retrieve a WAF Policy", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetWAF(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.Name).To(Equal(testResource))
		})

		It("should return error when WAF Policy retrieval fails", func() {
			errorMsg := "WAF Policy not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetWAF(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetProfileAccess", func() {
		It("should successfully retrieve an Access Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileAccess(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Access Profile retrieval fails", func() {
			errorMsg := "Access Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileAccess(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetPolicyPerRequestAccess", func() {
		It("should successfully retrieve a Per Request Access Policy", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPolicyPerRequestAccess(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Per Request Access Policy retrieval fails", func() {
			errorMsg := "Per Request Access Policy not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPolicyPerRequestAccess(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetProfileAdaptRequest", func() {
		It("should successfully retrieve a Request Adapt Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileAdaptRequest(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Request Adapt Profile retrieval fails", func() {
			errorMsg := "Request Adapt Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileAdaptRequest(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetProfileAdaptResponse", func() {
		It("should successfully retrieve a Response Adapt Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileAdaptResponse(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Response Adapt Profile retrieval fails", func() {
			errorMsg := "Response Adapt Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileAdaptResponse(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetDOSProfile", func() {
		It("should successfully retrieve a DOS Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetDOSProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when DOS Profile retrieval fails", func() {
			errorMsg := "DOS Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetDOSProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetBotDefenseProfile", func() {
		It("should successfully retrieve a Bot Defense Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetBotDefenseProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.BotDefenseProfile).Name).To(Equal(testResource))
		})

		It("should return error when Bot Defense Profile retrieval fails", func() {
			errorMsg := "Bot Defense Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetBotDefenseProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetFirewallPolicy", func() {
		It("should successfully retrieve a Firewall Policy", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetFirewallPolicy(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Firewall Policy retrieval fails", func() {
			errorMsg := "Firewall Policy not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetFirewallPolicy(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetVLAN", func() {
		It("should successfully retrieve a VLAN", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetVLAN(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Vlan).Name).To(Equal(testResource))
		})

		It("should return error when VLAN retrieval fails", func() {
			errorMsg := "VLAN not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetVLAN(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetIPIntelligencePolicy", func() {
		It("should successfully retrieve an IP Intelligence Policy", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetIPIntelligencePolicy(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when IP Intelligence Policy retrieval fails", func() {
			errorMsg := "IP Intelligence Policy not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetIPIntelligencePolicy(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetSNATPool", func() {
		It("should successfully retrieve a SNAT Pool", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetSNATPool(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Snat).Name).To(Equal(testResource))
		})

		It("should return error when SNAT Pool retrieval fails", func() {
			errorMsg := "SNAT Pool not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetSNATPool(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetLTMPool", func() {
		It("should successfully retrieve an LTM Pool", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetLTMPool(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Pool).Name).To(Equal(testResource))
		})

		It("should return error when LTM Pool retrieval fails", func() {
			errorMsg := "LTM Pool not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetLTMPool(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetTCPProfile", func() {
		It("should successfully retrieve a TCP Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetTCPProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Tcp).Name).To(Equal(testResource))
		})

		It("should return error when TCP Profile retrieval fails", func() {
			errorMsg := "TCP Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetTCPProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetUDPProfile", func() {
		It("should successfully retrieve a UDP Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetUDPProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when UDP Profile retrieval fails", func() {
			errorMsg := "UDP Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetUDPProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetHTTP2Profile", func() {
		It("should successfully retrieve an HTTP2 Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTTP2Profile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Http2).Name).To(Equal(testResource))
		})

		It("should return error when HTTP2 Profile retrieval fails", func() {
			errorMsg := "HTTP2 Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTTP2Profile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetHTTPProfile", func() {
		It("should successfully retrieve an HTTP Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTTPProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.HttpProfile).Name).To(Equal(testResource))
		})

		It("should return error when HTTP Profile retrieval fails", func() {
			errorMsg := "HTTP Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTTPProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetRewriteProfile", func() {
		It("should successfully retrieve a Rewrite Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetRewriteProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.RewriteProfile).Name).To(Equal(testResource))
		})

		It("should return error when Rewrite Profile retrieval fails", func() {
			errorMsg := "Rewrite Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetRewriteProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetPersistenceProfile", func() {
		It("should successfully retrieve a Cookie Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("cookie", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve a Dest-Addr Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("dest-addr", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve a Hash Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("hash", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve a Host Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("host", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve an MSRDP Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("msrdp", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve a SIP Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("sip", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve a Source-Addr Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("source-addr", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve a Universal Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("universal", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should successfully retrieve an SSL Persistence Profile", func() {
			mockClient := NewMockBigIPClientForPersistence("ssl", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when no persistence profile is found", func() {
			mockClient := NewMockBigIPClientForPersistence("none", false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetPersistenceProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(ContainSubstring("no persistence profile found"))
			Expect(result).To(BeNil())
		})
	})

	Context("GetLogProfile", func() {
		It("should successfully retrieve a Log Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetLogProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Log Profile retrieval fails", func() {
			errorMsg := "Log Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetLogProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetL4Profile", func() {
		It("should successfully retrieve an L4 Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetL4Profile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Fastl4).Name).To(Equal(testResource))
		})

		It("should return error when L4 Profile retrieval fails", func() {
			errorMsg := "L4 Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetL4Profile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetMultiplexProfile", func() {
		It("should successfully retrieve a Multiplex Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetMultiplexProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Multiplex Profile retrieval fails", func() {
			errorMsg := "Multiplex Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetMultiplexProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetAnalyticsProfile", func() {
		It("should successfully retrieve an Analytics Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetAnalyticsProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when Analytics Profile retrieval fails", func() {
			errorMsg := "Analytics Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetAnalyticsProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetProfileWebSocket", func() {
		It("should successfully retrieve a WebSocket Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileWebSocket(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when WebSocket Profile retrieval fails", func() {
			errorMsg := "WebSocket Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetProfileWebSocket(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetHTMLProfile", func() {
		It("should successfully retrieve an HTML Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTMLProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
		})

		It("should return error when HTML Profile retrieval fails", func() {
			errorMsg := "HTML Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTMLProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetFTPProfile", func() {
		It("should successfully retrieve an FTP Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetFTPProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.Ftp).Name).To(Equal(testResource))
		})

		It("should return error when FTP Profile retrieval fails", func() {
			errorMsg := "FTP Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetFTPProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	Context("GetHTTPCompressionProfile", func() {
		It("should successfully retrieve an HTTP Compression Profile", func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTTPCompressionProfile(testResource)

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.(*bigip.HttpCompressionProfile).Name).To(Equal(testResource))
		})

		It("should return error when HTTP Compression Profile retrieval fails", func() {
			errorMsg := "HTTP Compression Profile not found"
			mockClient = NewMockBigIPClient(true, errorMsg)
			handler = &BigIPHandler{Bigip: mockClient}

			result, err := handler.GetHTTPCompressionProfile(testResource)

			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(errorMsg))
			Expect(result).To(BeNil())
		})
	})

	// Edge cases and validation tests
	Context("Edge Cases", func() {
		BeforeEach(func() {
			mockClient = NewMockBigIPClient(false, "")
			handler = &BigIPHandler{Bigip: mockClient}
		})

		It("should handle empty resource name", func() {
			result, err := handler.GetIRule("")

			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result.Name).To(Equal(""))
		})

		It("should handle nil BigIP client", func() {
			handler = &BigIPHandler{Bigip: nil}

			// This should panic or handle gracefully depending on implementation
			// For now, we expect it to panic
			Expect(func() {
				handler.GetIRule(testResource)
			}).To(Panic())
		})
	})

	// Test CreateSession function
	Context("CreateSession", func() {
		It("should create a BigIP session with valid parameters", func() {
			host := "192.168.1.100"
			token := "test-token"
			userAgent := "test-agent"
			trustedCerts := ""
			insecure := true
			teem := false

			session := CreateSession(host, token, userAgent, trustedCerts, insecure, teem)

			Expect(session).ToNot(BeNil())
			Expect(session.Host).To(Equal(host))
			Expect(session.Token).To(Equal(token))
			Expect(session.UserAgent).To(Equal(userAgent))
			Expect(session.Teem).To(Equal(teem))
			Expect(session.ConfigOptions).ToNot(BeNil())
			Expect(session.Transport).ToNot(BeNil())
		})

		It("should create a BigIP session with trusted certificates", func() {
			host := "192.168.1.100"
			token := "test-token"
			userAgent := "test-agent"
			trustedCerts := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKS0F0D7ZR6VMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMDA1MTUwOTU2NThaFw0yMTA1MTUwOTU2NThaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC1SFI0kj12aJnB
-----END CERTIFICATE-----`
			insecure := false
			teem := true

			session := CreateSession(host, token, userAgent, trustedCerts, insecure, teem)

			Expect(session).ToNot(BeNil())
			Expect(session.Host).To(Equal(host))
			Expect(session.Token).To(Equal(token))
			Expect(session.UserAgent).To(Equal(userAgent))
			Expect(session.Teem).To(Equal(teem))
		})
	})
})
