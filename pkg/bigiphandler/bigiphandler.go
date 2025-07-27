package bigiphandler

import (
	"crypto/tls"
	"crypto/x509"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/f5devcentral/go-bigip"
	"net/http"
	"time"
)

// BigIPClient interface defines the methods needed from bigip.BigIP
type BigIPClient interface {
	IRule(name string) (*bigip.IRule, error)
	GetClientSSLProfile(name string) (*bigip.ClientSSLProfile, error)
	GetServerSSLProfile(name string) (*bigip.ServerSSLProfile, error)
	GetWafPolicy(name string) (*bigip.WafPolicy, error)
	GetBotDefenseProfile(name string) (*bigip.BotDefenseProfile, error)
	Vlan(name string) (*bigip.Vlan, error)
	GetSnat(name string) (*bigip.Snat, error)
	GetPool(name string) (*bigip.Pool, error)
	GetTcp(name string) (*bigip.Tcp, error)
	GetHttp2(name string) (*bigip.Http2, error)
	GetHttpProfile(name string) (*bigip.HttpProfile, error)
	GetRewriteProfile(name string) (*bigip.RewriteProfile, error)
	GetFastl4(name string) (*bigip.Fastl4, error)
	GetFtp(name string) (*bigip.Ftp, error)
	GetHttpCompressionProfile(name string) (*bigip.HttpCompressionProfile, error)
}

func CreateSession(host, token, userAgent, trustedCerts string, insecure, teem bool) *bigip.BigIP {
	// Connect to the BIG-IP system.
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// TODO: Make sure appMgr sets certificates in bigipInfo
	certs := []byte(trustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debugf("No certs appended, using only system certs with webhook")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
			RootCAs:            rootCAs,
		},
	}

	return &bigip.BigIP{
		Host: host,
		ConfigOptions: &bigip.ConfigOptions{
			APICallTimeout: 15 * time.Second,
			APICallRetries: 2,
		},
		Transport: tr,
		Token:     token,
		UserAgent: userAgent,
		Teem:      teem,
	}

}

// BigIPHandlerInterface defines the methods to interact with BIG-IP resources
type BigIPHandlerInterface interface {
	GetIRule(name string) (*bigip.IRule, error)
	GetClientSSLProfile(name string) (*bigip.ClientSSLProfile, error)
	GetServerSSLProfile(name string) (*bigip.ServerSSLProfile, error)
	GetWAF(name string) (*bigip.WafPolicy, error)
	GetProfileAccess(name string) (any, error)
	GetPolicyPerRequestAccess(name string) (any, error)
	GetProfileAdaptRequest(name string) (any, error)
	GetProfileAdaptResponse(name string) (any, error)
	GetDOSProfile(name string) (any, error)
	GetBotDefenseProfile(name string) (any, error)
	GetFirewallPolicy(name string) (any, error)
	GetVLAN(name string) (any, error)
	GetIPIntelligencePolicy(name string) (any, error)
	GetSNATPool(name string) (any, error)
	GetLTMPool(name string) (any, error)
	GetTCPProfile(name string) (any, error)
	GetUDPProfile(name string) (any, error)
	GetHTTP2Profile(name string) (any, error)
	GetHTTPProfile(name string) (any, error)
	GetRewriteProfile(name string) (any, error)
	GetPersistenceProfile(name string) (any, error)
	GetLogProfile(name string) (any, error)
	GetL4Profile(name string) (any, error)
	GetMultiplexProfile(name string) (any, error)
	GetAnalyticsProfile(name string) (any, error)
	GetProfileWebSocket(name string) (any, error)
	GetHTMLProfile(name string) (any, error)
	GetFTPProfile(name string) (any, error)
	GetHTTPCompressionProfile(name string) (any, error)
	// Add more methods as needed for other BIG-IP resources
}

type BigIPHandler struct {
	Bigip BigIPClient
}

func (handler *BigIPHandler) GetIRule(name string) (*bigip.IRule, error) {
	// Get the iRule by name and partition
	irule, err := handler.Bigip.IRule(name)
	if err != nil {
		return nil, err
	}
	return irule, nil
}

func (handler *BigIPHandler) GetClientSSLProfile(name string) (*bigip.ClientSSLProfile, error) {
	// Get the profile by name and partition
	profile, err := handler.Bigip.GetClientSSLProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func (handler *BigIPHandler) GetServerSSLProfile(name string) (*bigip.ServerSSLProfile, error) {
	// Get the profile by name and partition
	profile, err := handler.Bigip.GetServerSSLProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func (handler *BigIPHandler) GetWAF(name string) (*bigip.WafPolicy, error) {
	// Get the policy by name and partition
	policy, err := handler.Bigip.GetWafPolicy(name)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

// TODO: Implement GetProfileAccess method
func (handler *BigIPHandler) GetProfileAccess(name string) (any, error) {
	// Get the policy by name and partition
	//policy, err := handler.Bigip.getProfileAccess(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO: Implement GetPolicyPerRequestAccess method
func (handler *BigIPHandler) GetPolicyPerRequestAccess(name string) (any, error) {
	// Get the policy by name and partition
	//policy, err := handler.Bigip.getProfileAccess(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO: Implement GetProfileAdaptRequest method
func (handler *BigIPHandler) GetProfileAdaptRequest(name string) (any, error) {
	// Get the policy by name and partition
	//policy, err := handler.Bigip.getProfileAccess(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO: Implement GetProfileAdaptResponse method
func (handler *BigIPHandler) GetProfileAdaptResponse(name string) (any, error) {
	// Get the policy by name and partition
	//policy, err := handler.Bigip.getProfileAccess(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO: Implement GetDOSProfile method
func (handler *BigIPHandler) GetDOSProfile(name string) (any, error) {
	// Get the policy by name and partition
	//policy, err := handler.Bigip.getProfileAccess(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// GetBotDefenseProfile method get the Bot Defense profile by name
func (handler *BigIPHandler) GetBotDefenseProfile(name string) (any, error) {
	// Get the profile by name and partition
	profile, err := handler.Bigip.GetBotDefenseProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// TODO implement GetFirewallPolicy method get the firewall policy by name
func (handler *BigIPHandler) GetFirewallPolicy(name string) (any, error) {
	// Get the profile by name and partition
	//profile, err := handler.Bigip.GetBotDefenseProfile(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// GetVLAN method get the VLAN by name
func (handler *BigIPHandler) GetVLAN(name string) (any, error) {
	// Get the vlan by name and partition
	vlan, err := handler.Bigip.Vlan(name)
	if err != nil {
		return nil, err
	}
	return vlan, nil
}

// TODO implement GetIPIntelligencePolicy method get the VLAN by name
func (handler *BigIPHandler) GetIPIntelligencePolicy(name string) (any, error) {
	// Get the vlan by name and partition
	//policy, err := handler.Bigip.GetIPIntelligencePolicy(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// GetSNATPool method get the SNAT by name
func (handler *BigIPHandler) GetSNATPool(name string) (any, error) {
	// Get the snat by name
	snat, err := handler.Bigip.GetSnat(name)
	if err != nil {
		return nil, err
	}
	return snat, nil
}

// GetLTMPool method get the LTM Pool by name
func (handler *BigIPHandler) GetLTMPool(name string) (any, error) {
	// Get the pool by name
	pool, err := handler.Bigip.GetPool(name)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

// GetTCPProfile method get the TCP Profile by name
func (handler *BigIPHandler) GetTCPProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetTcp(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// TODO implement GetUDPProfile method get the UDP Profile by name
func (handler *BigIPHandler) GetUDPProfile(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetUdp(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// GetHTTP2Profile method get the HTTP2 profile by name
func (handler *BigIPHandler) GetHTTP2Profile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetHttp2(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetHTTPProfile method get the HTTP profile by name
func (handler *BigIPHandler) GetHTTPProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetHttpProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetRewriteProfile method get the rewrite profile by name
func (handler *BigIPHandler) GetRewriteProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetRewriteProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// TODO implement GetPersistenceProfile method get the persistence profile by name
func (handler *BigIPHandler) GetPersistenceProfile(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetPersistenceProfile(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO implement GetLogProfile method get the log profile by name
func (handler *BigIPHandler) GetLogProfile(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetLogProfile(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// GetL4Profile method get the L4 profile by name
func (handler *BigIPHandler) GetL4Profile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetFastl4(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// TODO implement GetMultiplexProfile method get the multiplex profile by name
func (handler *BigIPHandler) GetMultiplexProfile(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetMultiplexProfile(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO implement GetAnalyticsProfile method get the analytics profile by name
func (handler *BigIPHandler) GetAnalyticsProfile(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetAnalyticsProfile(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO implement GetProfileWebSocket method get the web socket profile by name
func (handler *BigIPHandler) GetProfileWebSocket(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetProfileWebSocket(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// TODO implement GetHTMLProfile method get the html profile by name
func (handler *BigIPHandler) GetHTMLProfile(name string) (any, error) {
	// Get the profile by name
	//profile, err := handler.Bigip.GetProfileWebSocket(name)
	//if err != nil {
	//	return nil, err
	//}
	return struct{}{}, nil
}

// GetFTPProfile method get the ftp profile by name
func (handler *BigIPHandler) GetFTPProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetFtp(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetHTTPCompressionProfile method get the http compression profile by name
func (handler *BigIPHandler) GetHTTPCompressionProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetHttpCompressionProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}
