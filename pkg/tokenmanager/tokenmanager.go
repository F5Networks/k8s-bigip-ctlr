package tokenmanager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/statusmanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	//CM login url
	CMLoginURL               = "/api/login"
	CMVersionURL             = "/api/v1/system/infra/info"
	CMRefreshTokenURL        = "/api/token-refresh"
	CMRefreshTokenExpiration = 10 * time.Hour
	CMAccessTokenExpiration  = 5 * time.Minute
	TokenFetchFailed         = "Failed to fetch accessToken"
	Ok                       = "OK"
	RetryInterval            = time.Duration(10)
)

// TokenManager is responsible for managing the authentication accessToken.
type TokenManager struct {
	mu                sync.Mutex
	accessToken       string
	accessTokenExpiry time.Time
	refreshToken      string
	ServerURL         string
	credentials       Credentials
	SslInsecure       bool
	TrustedCerts      string
	httpClient        *http.Client
	CMVersion         string
	StatusManager     statusmanager.StatusManagerInterface
}

// Credentials represent the username and password used for authentication.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RefreshTokenResponse represents the response received from the CM.
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
}

// AccessTokenResponse represents the response received from the CM.
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
}

// NewTokenManager creates a new instance of TokenManager.
func NewTokenManager(serverURL string, credentials Credentials, trustedCerts string, sslInsecure bool, statusManager statusmanager.StatusManagerInterface) *TokenManager {
	return &TokenManager{
		ServerURL:     serverURL,
		credentials:   credentials,
		TrustedCerts:  trustedCerts,
		SslInsecure:   sslInsecure,
		StatusManager: statusManager,
		httpClient:    getHttpClient(trustedCerts, sslInsecure),
	}
}

// GetRefreshToken returns the current valid saved accessToken.
func (tm *TokenManager) GetRefreshToken() string {
	tm.mu.Lock()
	token := tm.refreshToken
	tm.mu.Unlock()
	return token
}

// SetRefreshToken safely sets the accessToken in the TokenManager.
func (tm *TokenManager) SetRefreshToken(token string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.refreshToken = token
}

// GetAccessToken returns the current valid saved accessToken.
func (tm *TokenManager) GetAccessToken() string {
	if time.Now().After(tm.accessTokenExpiry) {
		if err := tm.RefreshAccessToken(); err == nil {
			log.Debugf("[Token Manager] Successfully refreshed accessToken from Central Manager")
		} else {
			log.Errorf("[Token Manager] Failed to refresh accessToken from Central Manager: %v", err)
		}
	}
	tm.mu.Lock()
	token := tm.accessToken
	tm.mu.Unlock()
	return token
}

// SetAccessToken safely sets the accessToken in the TokenManager.
func (tm *TokenManager) SetAccessToken(token string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.accessToken = token
	tm.accessTokenExpiry = time.Now().Add(CMAccessTokenExpiration)
}

func getHttpClient(trustedCerts string, sslInsecure bool) *http.Client {
	// Configure CA certificates
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs := []byte(trustedCerts)

	// Append our certs to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Debug("[Token Manager] No certs appended, using only system certs")
	}

	// Create an insecure/secure client based on the SslInsecure flag
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: sslInsecure,
			RootCAs:            rootCAs,
		},
	}

	return &http.Client{Transport: tr}
}

// RefreshAccessToken retrieves a new accessToken from the CM.
func (tm *TokenManager) RefreshAccessToken() error {

	payload := []byte(`{"refresh_token":"` + tm.GetRefreshToken() + `"}`)
	// Send POST request for accessToken
	resp, err := tm.httpClient.Post(tm.ServerURL+CMRefreshTokenURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("unable to establish connection with Central Manager, Probable reasons might be: invalid custom-certs (or) custom-certs not provided using --trusted-certs-cfgmap flag")
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body %v. error: %v", resp.Body, err.Error())
	}

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("unauthorized to fetch accessToken from Central Manager. "+
				"Please check the credentials, status code: %d, response: %s", resp.StatusCode, body)
		case http.StatusServiceUnavailable:
			return fmt.Errorf("failed to get accessToken due to service unavailability, "+
				"status code: %d, response: %s", resp.StatusCode, body)
		case http.StatusNotFound, http.StatusMovedPermanently:
			return fmt.Errorf("requested page/api not found, status code: %d, response: %s", resp.StatusCode, body)
		default:
			return fmt.Errorf("failed to get accessToken, status code: %d, response: %s", resp.StatusCode, body)
		}
	}

	// Parse the accessToken and its expiration time from the response
	tokenResponse := RefreshTokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return fmt.Errorf("unmarshaling failed for refreshAccessToken response %v. error: %v", body, err.Error())
	}
	// Keep the accessToken updated in the TokenManager
	tm.SetAccessToken(tokenResponse.AccessToken)
	return nil
}

// SyncTokenWithoutRetry retrieves a new accessToken from the CM.
func (tm *TokenManager) SyncTokenWithoutRetry() (err error, exit bool) {
	var errMessage error
	// Prepare the request payload
	payload, err := json.Marshal(tm.credentials)
	if err != nil {
		errMessage = fmt.Errorf("marshaling failed for credentials %v. error: %v", tm.credentials, err.Error())
		return errMessage, false
	}

	// Send POST request for accessToken
	resp, err := tm.httpClient.Post(tm.ServerURL+CMLoginURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		errMessage = fmt.Errorf("unable to establish connection with Central Manager, Probable reasons might be: invalid custom-certs (or) custom-certs not provided using --trusted-certs-cfgmap flag")
		return errMessage, true
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMessage = fmt.Errorf("unable to read response body %v. error: %v", resp.Body, err.Error())
		return errMessage, false
	}

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			errMessage = fmt.Errorf("unauthorized to fetch accessToken from Central Manager. "+
				"Please check the credentials, status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, true
		case http.StatusServiceUnavailable:
			tm.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &cisapiv1.CMStatus{
				Message: TokenFetchFailed,
				Error: fmt.Sprintf("failed to get accessToken due to service unavailability, "+
					"status code: %d, response: %s", resp.StatusCode, body),
				LastUpdated: metav1.Now(),
			})
			errMessage = fmt.Errorf("failed to get accessToken due to service unavailability, "+
				"status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, false
		case http.StatusNotFound, http.StatusMovedPermanently:
			errMessage = fmt.Errorf("requested page/api not found, status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, true
		default:
			errMessage = fmt.Errorf("failed to get accessToken, status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, false
		}
	}

	// Parse the accessToken and its expiration time from the response
	tokenResponse := AccessTokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		errMessage = fmt.Errorf("unmarshaling failed for accessToken response %v. error: %v", body, err.Error())
		return errMessage, false
	}

	// Keep the accessToken updated in the TokenManager
	tm.SetAccessToken(tokenResponse.AccessToken)
	// Keep the refreshToken updated in the TokenManager
	tm.SetRefreshToken(tokenResponse.RefreshToken)
	log.Debugf("[Token Manager] Successfully fetched accessToken from Central Manager")
	return nil, false
}

// Start maintains valid accessToken. It fetches a new accessToken before expiry.
func (tm *TokenManager) Start(stopCh chan struct{}, duration time.Duration) {
	// Set ticker to 1 minute less than refreshToken expiry time to ensure accessToken is refreshed on time
	tokenUpdateTicker := time.Tick(duration - 60*time.Second)
	for {
		select {
		case <-tokenUpdateTicker:
			tm.SyncToken()
		case <-stopCh:
			log.Debug("[Token Manager] Stopping synchronizing refreshToken")
			close(stopCh)
			return
		}
	}
}

// SyncToken is a helper function to fetch refreshToken and retry on failure
func (tm *TokenManager) SyncToken() {
	for {
		err, exit := tm.SyncTokenWithoutRetry()
		if err != nil {
			tm.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", exit, &cisapiv1.CMStatus{
				Message:     TokenFetchFailed,
				Error:       fmt.Sprintf("%v", err.Error()),
				LastUpdated: metav1.Now(),
			})
			if !exit {
				log.Debugf("[Token Manager] Retrying to fetch refreshToken in %d seconds", RetryInterval)
				time.Sleep(RetryInterval * time.Second)
			}
		} else {
			// update the CM status
			tm.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &cisapiv1.CMStatus{
				Message:     Ok,
				LastUpdated: metav1.Now(),
			})
			break
		}
	}
}

func (tm *TokenManager) GetCMVersion() (string, error) {
	url := tm.ServerURL + CMVersionURL
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Creating new HTTP request error: %v ", err)
		return "", err
	}

	log.Debugf("posting GET CM version request on %v", url)
	// add authorization header to the req
	req.Header.Add("Authorization", "Bearer "+tm.GetAccessToken())

	httpResp, err := tm.httpClient.Do(req)

	if err != nil {
		return "", err
	}
	if httpResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code: %d", httpResp.StatusCode)
	}

	defer httpResp.Body.Close()

	// Decode JSON response
	var response map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&response); err != nil {
		return "", err
	}

	version := strings.Replace(response["version"].(string), "BIG-IP-Next-CentralManager-", "", -1)

	if len(strings.Split(version, "-")) > 1 {
		return strings.Split(version, "-")[0], nil
	} else {
		return "", fmt.Errorf("error fetching CM version")
	}
}
