package tokenmanager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	//CM login url
	CMLoginURL              = "/api/login"
	CMAccessTokenExpiration = 5 * time.Minute
)

// TokenManager is responsible for managing the authentication token.
type TokenManager struct {
	mu           sync.Mutex
	token        string
	serverURL    string
	credentials  Credentials
	sslInsecure  bool
	trustedCerts string
}

// Credentials represent the username and password used for authentication.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse represents the response received from the CM.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
}

// NewTokenManager creates a new instance of TokenManager.
func NewTokenManager(serverURL string, credentials Credentials, trustedCerts string, sslInsecure bool) *TokenManager {
	return &TokenManager{
		serverURL:    serverURL,
		credentials:  credentials,
		trustedCerts: trustedCerts,
		sslInsecure:  sslInsecure,
	}
}

// GetToken returns the current valid saved token.
func (tm *TokenManager) GetToken() string {
	tm.mu.Lock()
	token := tm.token
	tm.mu.Unlock()
	return token
}

// fetchToken retrieves a new token from the CM.
func (tm *TokenManager) fetchToken() error {
	// Prepare the request payload
	payload, err := json.Marshal(tm.credentials)
	if err != nil {
		return err
	}

	// Configure CA certificates
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs := []byte(tm.trustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debug("[Token Manager] No certs appended, using only system certs")
	}

	// Create an insecure/secure client based on the sslInsecure flag
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tm.sslInsecure,
			RootCAs:            rootCAs,
		},
	}

	client := &http.Client{Transport: tr}

	// Send POST request for token
	resp, err := client.Post(tm.serverURL+CMLoginURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Errorf("[Token Manager] Error fetching token from Central Manager: %s",
				fmt.Errorf("status code: %d, response: %s", resp.StatusCode, body))
			log.Errorf("[Token Manager] Unauthorized to fetch token from Central Manager. Please check the credentials")
			os.Exit(1)
		}

		return fmt.Errorf("failed to get token, status code: %d, response: %s", resp.StatusCode, body)
	}

	// Parse the token and its expiration time from the response
	tokenResponse := TokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return err
	}

	// Keep the token updated in the TokenManager
	tm.mu.Lock()
	tm.token = tokenResponse.AccessToken
	tm.mu.Unlock()

	return nil
}

// SyncToken maintains valid token. It fetches a new token before expiry.
func (tm *TokenManager) SyncToken(stopCh chan struct{}) {
	// retryInterval is the time to wait before retrying to fetch token on the event of failure
	retryInterval := time.Duration(10)
	// Immediately fetch token for the first time
	tm.syncTokenHelper(retryInterval)
	// Set ticker to 1 minute less than token expiry time to ensure token is refreshed on time
	tokenUpdateTicker := time.Tick(CMAccessTokenExpiration - 1*time.Minute)
	for {
		select {
		case <-tokenUpdateTicker:
			tm.syncTokenHelper(retryInterval)
		case <-stopCh:
			log.Debug("[Token Manager] Stopping synchronizing token")
			return
		}
	}
}

// syncTokenHelper is a helper function to fetch token and retry on failure
func (tm *TokenManager) syncTokenHelper(retryInterval time.Duration) {
	err := tm.fetchToken()
	if err != nil {
		log.Errorf("[Token Manager] Error fetching token from Central Manager: %s", err)
		log.Debugf("[Token Manager] Retrying to fetch token in %d seconds", retryInterval)
		for {
			time.Sleep(retryInterval * time.Second)
			err = tm.fetchToken()
			if err != nil {
				log.Errorf("[Token Manager] Error fetching token from Central Manager: %s", err)
				log.Debugf("[Token Manager] Retrying to fetch token in %d seconds", retryInterval)
			} else {
				log.Debugf("[Token Manager] Successfully fetched token from Central Manager")
				break
			}
		}
	}
}
