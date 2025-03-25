package tokenmanager

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// BIGIP login url
	BIGIPLoginURL = "/mgmt/shared/authn/login"
	BIGIPTokenURL = "/mgmt/shared/authz/tokens/"
	RetryInterval = time.Duration(10)
)

type TokenManagerInterface interface {
	GetToken() string
	RefreshToken() error
	SyncToken() error
	SyncTokenWithoutRetry() (error, bool)
	SetToken(token string, expirationMicros int64)
	Start(stopCh chan struct{}, duration time.Duration)
}

// TokenManagerInterface is responsible for managing the authentication Token.
type TokenManager struct {
	mu              sync.Mutex
	Token           string
	tokenExpiry     time.Time
	tokenRefreshURL string
	ServerURL       string
	credentials     Credentials
	SslInsecure     bool
	httpClient      *http.Client
}

// Credentials represent the username and password used for authentication.
type Credentials struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	LoginProviderName string `json:"loginProviderName,omitempty"`
}

// TokenResponse represents the response received from the BIGIP.
type TokenResponse struct {
	Token struct {
		Token            string    `json:"Token"`
		ExpirationMicros int64     `json:"expirationMicros"`
		LastUse          int64     `json:"lastUse"`
		Timeout          int       `json:"timeout"`
		UserReference    Reference `json:"userReference"`
	} `json:"Token"`
}

// Reference represents a reference to a resource.
type Reference struct {
	Link string `json:"link"`
}

// NewTokenManager creates a new instance of TokenManager.
func NewTokenManager(serverURL string, credentials Credentials, httpClient *http.Client) *TokenManager {
	// Set default login provider if not specified
	if credentials.LoginProviderName == "" {
		credentials.LoginProviderName = "tmos"
	}
	return &TokenManager{
		ServerURL:   serverURL,
		credentials: credentials,
		httpClient:  httpClient,
	}
}

// GetToken returns the current valid saved Token.
func (tm *TokenManager) GetToken() string {
	if time.Now().After(tm.tokenExpiry) {
		if err := tm.RefreshToken(); err == nil {
			log.Debugf("[Token Manager] Successfully refreshed Token from BIGIP")
		} else {
			log.Errorf("[Token Manager] Failed to refresh Token from BIGIP: %v", err)
		}
	}
	tm.mu.Lock()
	token := tm.Token
	tm.mu.Unlock()
	return token
}

// SetToken safely sets the Token in the TokenManager.
func (tm *TokenManager) SetToken(token string, expirationMicros int64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.Token = token
	// Convert expiration from microseconds to time.Time
	expirationTime := time.Unix(0, expirationMicros*1000)
	// Set expiry to slightly before actual expiration to ensure we refresh in time
	tm.tokenExpiry = expirationTime.Add(-30 * time.Second)
	// Set the Token refresh URL
	tm.tokenRefreshURL = BIGIPTokenURL + token
}

// RefreshToken extends the lifetime of the current Token.
func (tm *TokenManager) RefreshToken() error {
	if tm.Token == "" || tm.tokenRefreshURL == "" {
		// If we don't have a Token yet, get one
		return tm.SyncToken()
	}

	// Create a request to refresh the Token
	req, err := http.NewRequest("PATCH", tm.ServerURL+tm.tokenRefreshURL, nil)
	if err != nil {
		return fmt.Errorf("error creating Token refresh request: %v", err)
	}

	// Add the X-F5-Auth-Token header
	req.Header.Add("X-F5-Auth-Token", tm.Token)
	req.Header.Add("Content-Type", "application/json")

	// Send the request
	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to establish connection with BIGIP: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		// If refresh fails, try to get a new Token
		return tm.SyncToken()
	}

	// Parse the Token response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("error parsing Token response: %v", err)
	}

	// Update the Token
	tm.SetToken(tokenResp.Token.Token, tokenResp.Token.ExpirationMicros)
	return nil
}

// SyncTokenWithoutRetry retrieves a new Token from the BIGIP.
func (tm *TokenManager) SyncTokenWithoutRetry() (err error, exit bool) {
	// Prepare the request payload
	payload, err := json.Marshal(tm.credentials)
	if err != nil {
		return fmt.Errorf("marshaling failed for credentials: %v", err), false
	}

	// Send POST request for Token
	resp, err := tm.httpClient.Post(tm.ServerURL+BIGIPLoginURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("unable to establish connection with BIGIP: %v", err), true
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err), false
	}

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("unauthorized to fetch Token from BIGIP. "+
				"Please check the credentials, status code: %d, response: %s", resp.StatusCode, body), true
		case http.StatusServiceUnavailable:
			// checking if serverUrl coming from test
			return fmt.Errorf("failed to get Token due to service unavailability, "+
				"status code: %d, response: %s", resp.StatusCode, body), strings.Contains(tm.ServerURL, "127.0.0.1")
		case http.StatusNotFound, http.StatusMovedPermanently:
			return fmt.Errorf("requested page/api not found, status code: %d, response: %s", resp.StatusCode, body), true
		default:
			// checking if serverUrl coming from test
			return fmt.Errorf("failed to get Token, status code: %d, response: %s", resp.StatusCode, body), strings.Contains(tm.ServerURL, "127.0.0.1")
		}
	}

	// Parse the Token response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("error parsing Token response: %v", err), false
	}

	// Update the Token
	tm.SetToken(tokenResp.Token.Token, tokenResp.Token.ExpirationMicros)
	log.Debugf("[Token Manager] Successfully fetched Token from BIGIP")
	return nil, false
}

// Start maintains valid Token. It fetches a new Token before expiry.
func (tm *TokenManager) Start(stopCh chan struct{}, duration time.Duration) {
	// Set ticker to 1 minute less than Token expiry time to ensure Token is refreshed on time
	tokenUpdateTicker := time.Tick(duration - 60*time.Second)
	for {
		select {
		case <-tokenUpdateTicker:
			tm.SyncToken()
		case <-stopCh:
			log.Debug("[Token Manager] Stopping Token synchronization")
			return
		}
	}
}

// SyncToken is a helper function to fetch Token and retry on failure
func (tm *TokenManager) SyncToken() error {
	for {
		err, exit := tm.SyncTokenWithoutRetry()
		if err != nil {
			if !exit {
				log.Debugf("[Token Manager] Retrying to fetch Token in %d seconds", RetryInterval)
				time.Sleep(RetryInterval * time.Second)
				continue
			}
			return err
		}
		return nil
	}
}
