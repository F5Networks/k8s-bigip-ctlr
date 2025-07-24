package bigiphandler

import (
	"crypto/tls"
	"crypto/x509"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/f5devcentral/go-bigip"
	"net/http"
	"time"
)

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

type BigIPHandler struct {
	Bigip *bigip.BigIP
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
