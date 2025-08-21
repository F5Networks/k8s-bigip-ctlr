package bigiphandler

import (
	"context" //
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/f5devcentral/go-bigip"
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
	GetAccessProfile(name string) (*bigip.AccessProfile, error)
	GetOneconnect(name string) (*bigip.Oneconnect, error)
	GetAccessPolicy(name string) (*bigip.AccessPolicy, error)
	GetRequestAdaptProfile(name string) (*bigip.RequestAdaptProfile, error)
	GetResponseAdaptProfile(name string) (*bigip.ResponseAdaptProfile, error)
	GetDOSProfile(name string) (*bigip.DOSProfile, error)
	GetFirewallPolicy(name string) (*bigip.FirewallPolicy, error)
	GetIPIntelligencePolicy(name string) (*bigip.IPIntelligencePolicy, error)
	GetUDPProfile(name string) (*bigip.UdpProfile, error)
	GetSecurityLogProfile(name string) (*bigip.SecurityLogProfile, error)
	GetWebsocketProfile(name string) (*bigip.WebsocketProfile, error)
	GetHTMLProfile(name string) (*bigip.HTMLProfile, error)
	GetCookiePersistenceProfile(name string) (*bigip.CookiePersistenceProfile, error)
	GetDestAddrPersistenceProfile(name string) (*bigip.DestAddrPersistenceProfile, error)
	GetHashPersistenceProfile(name string) (*bigip.HashPersistenceProfile, error)
	GetHostPersistenceProfile(name string) (*bigip.HostPersistenceProfile, error)
	GetMSRDPPersistenceProfile(name string) (*bigip.MSRDPPersistenceProfile, error)
	GetSIPPersistenceProfile(name string) (*bigip.SIPPersistenceProfile, error)
	GetSourceAddrPersistenceProfile(name string) (*bigip.SourceAddrPersistenceProfile, error)
	GetUniversalPersistenceProfile(name string) (*bigip.UniversalPersistenceProfile, error)
	GetSSLPersistenceProfile(name string) (*bigip.SSLPersistenceProfile, error)
	GetAnalyticsProfile(name string) (*bigip.AnalyticsProfile, error)
	GetMonitor(name string, parent string) (*bigip.Monitor, error)
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
	GetMonitor(name string) (*bigip.Monitor, error)
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

// GetProfileAccess gets the access profile by name
func (handler *BigIPHandler) GetProfileAccess(name string) (any, error) {
	// Get the access profile by name
	profile, err := handler.Bigip.GetAccessProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetPolicyPerRequestAccess gets the policy per request access by name
func (handler *BigIPHandler) GetPolicyPerRequestAccess(name string) (any, error) {
	// Get the policy by name and partition
	policy, err := handler.Bigip.GetAccessPolicy(name)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

// GetProfileAdaptRequest gets the profile adapt request by name
func (handler *BigIPHandler) GetProfileAdaptRequest(name string) (any, error) {
	// Get the policy by name and partition
	profile, err := handler.Bigip.GetRequestAdaptProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetProfileAdaptResponse gets the profile adapt response by name
func (handler *BigIPHandler) GetProfileAdaptResponse(name string) (any, error) {
	// Get the policy by name and partition
	profile, err := handler.Bigip.GetResponseAdaptProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetDOSProfile method get the DOS profile by name
func (handler *BigIPHandler) GetDOSProfile(name string) (any, error) {
	// Get the policy by name and partition
	policy, err := handler.Bigip.GetDOSProfile(name)
	if err != nil {
		return nil, err
	}
	return policy, nil
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

// GetFirewallPolicy method get the firewall policy by name
func (handler *BigIPHandler) GetFirewallPolicy(name string) (any, error) {
	// Get the profile by name and partition
	profile, err := handler.Bigip.GetFirewallPolicy(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
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

// GetIPIntelligencePolicy method get the IP Intelligence policy by name
func (handler *BigIPHandler) GetIPIntelligencePolicy(name string) (any, error) {
	// Get the vlan by name and partition
	policy, err := handler.Bigip.GetIPIntelligencePolicy(name)
	if err != nil {
		return nil, err
	}
	return policy, nil
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

// GetUDPProfile method get the UDP Profile by name
func (handler *BigIPHandler) GetUDPProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetUDPProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
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

// GetPersistenceProfile method get the persistence profile by name
func (handler *BigIPHandler) GetPersistenceProfile(name string) (any, error) {
	// Get the profile by name
	// we have many types of persistence profiles, so we need to iterate through them to fetch each type and match with the given name
	// we will iterate in parallel to improve performance
	// supported persistence profiles include:cookie, dest-addr, hash, host, msrdp, sip, source-addr, universal, and ssl
	// make channel to collect results
	results := make(chan any, 9) // 9 types of persistence profiles
	waitGroup := &sync.WaitGroup{}

	// Add all goroutines to wait group before starting them
	waitGroup.Add(9)

	// cookie persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetCookiePersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// dest-addr persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetDestAddrPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// hash persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetHashPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// host persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetHostPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// msrdp persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetMSRDPPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// sip persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetSIPPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// source-addr persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetSourceAddrPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// universal persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetUniversalPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// ssl persistence profile
	go func() {
		defer waitGroup.Done()
		// Get the profile by name and type
		profile, err := handler.Bigip.GetSSLPersistenceProfile(name)
		if err == nil {
			results <- profile
		} else {
			log.Debugf("Failed to get persistence profile %s: %v", name, err)
		}
	}()
	// wait for all goroutines to finish
	waitGroup.Wait()
	// close the results channel
	close(results)

	// return the first result
	for result := range results {
		if result != nil {
			return result, nil
		}
	}
	return nil, fmt.Errorf("no persistence profile found with name: %s", name)
}

// GetLogProfile method get the log profile by name
func (handler *BigIPHandler) GetLogProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetSecurityLogProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
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

// GetMultiplexProfile method get the oneConnnect profile by name
func (handler *BigIPHandler) GetMultiplexProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetOneconnect(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// TODO implement GetAnalyticsProfile method get the analytics profile by name
func (handler *BigIPHandler) GetAnalyticsProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetAnalyticsProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetProfileWebSocket method get the web socket profile by name
func (handler *BigIPHandler) GetProfileWebSocket(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetWebsocketProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// GetHTMLProfile method get the html profile by name
func (handler *BigIPHandler) GetHTMLProfile(name string) (any, error) {
	// Get the profile by name
	profile, err := handler.Bigip.GetHTMLProfile(name)
	if err != nil {
		return nil, err
	}
	return profile, nil
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

func (handler *BigIPHandler) GetMonitor(name string) (*bigip.Monitor, error) {
	// monitorTypes := []string{"http", "tcp", "icmp", "https", "gateway icmp"}

	var f5MonitorParentTypes = []string{
		"http", "https", "tcp", "icmp", "gateway_icmp", "dns", "external", "ftp", "imap",
		"inband", "ldap", "mssql", "mysql", "oracle", "pop3", "postgresql", "radius",
		"radius_accounting", "real_server", "rpc", "sip", "smtp", "snmp_dca", "snmp_dca_base",
		"soap", "tcp_echo", "tcp_half_open", "udp", "virtual_location",
		"diameter", "firepass", "http2", "module_score", "mqtt", "nntp",
		"sasp", "scripted", "smb", "wap", "wmi",
	}

	type result struct {
		monitor *bigip.Monitor
		err     error
	}

	resultCh := make(chan result, len(f5MonitorParentTypes))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	for _, mType := range f5MonitorParentTypes {
		wg.Add(1)
		go func(mType string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				monitor, err := handler.Bigip.GetMonitor(name, mType)
				if err == nil {
					log.Debugf("Found monitor %s of type %s,monitor: %v", name, mType, monitor)
					// Found a valid monitor, send result and cancel others
					resultCh <- result{monitor, nil}
					cancel()
				}
			}
		}(mType)
	}

	// Close result channel once all goroutines are done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for res := range resultCh {
		// Return the first successful monitor
		if res.err == nil {
			return res.monitor, nil
		}
	}

	// If no monitor found
	return nil, fmt.Errorf("monitor %s not found", name)
}
