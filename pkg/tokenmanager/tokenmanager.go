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
	CMLoginURL              = "/api/login"
	CMVersionURL            = "/api/v1/system/infra/info"
	CMAccessTokenExpiration = 5 * time.Minute
	TokenFetchFailed        = "Failed to fetch token"
	Ok                      = "OK"
	RetryInterval           = time.Duration(10)
)

// TokenManager is responsible for managing the authentication token.
type TokenManager struct {
	mu            sync.Mutex
	token         string
	ServerURL     string
	credentials   Credentials
	SslInsecure   bool
	TrustedCerts  string
	httpClient    *http.Client
	CMVersion     string
	StatusManager statusmanager.StatusManagerInterface
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

// GetToken returns the current valid saved token.
func (tm *TokenManager) GetToken() string {
	tm.mu.Lock()
	token := tm.token
	tm.mu.Unlock()
	return token
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

// SyncTokenWithoutRetry retrieves a new token from the CM.
func (tm *TokenManager) SyncTokenWithoutRetry() (err error, exit bool) {
	var errMessage error
	// Prepare the request payload
	payload, err := json.Marshal(tm.credentials)
	if err != nil {
		errMessage = fmt.Errorf("marshaling failed for credentials %v. error: %v", tm.credentials, err.Error())
		return errMessage, false
	}

	// Send POST request for token
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
			errMessage = fmt.Errorf("unauthorized to fetch token from Central Manager. "+
				"Please check the credentials, status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, true
		case http.StatusServiceUnavailable:
			tm.StatusManager.AddRequest(statusmanager.DeployConfig, "", "", false, &cisapiv1.CMStatus{
				Message: TokenFetchFailed,
				Error: fmt.Sprintf("failed to get token due to service unavailability, "+
					"status code: %d, response: %s", resp.StatusCode, body),
				LastUpdated: metav1.Now(),
			})
			errMessage = fmt.Errorf("failed to get token due to service unavailability, "+
				"status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, false
		case http.StatusNotFound, http.StatusMovedPermanently:
			errMessage = fmt.Errorf("requested page/api not found, status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, true
		default:
			errMessage = fmt.Errorf("failed to get token, status code: %d, response: %s", resp.StatusCode, body)
			return errMessage, false
		}
	}

	// Parse the token and its expiration time from the response
	tokenResponse := TokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		errMessage = fmt.Errorf("unmarshaling failed for token response %v. error: %v", body, err.Error())
		return errMessage, false
	}

	// Keep the token updated in the TokenManager
	tm.mu.Lock()
	tm.token = tokenResponse.AccessToken
	tm.mu.Unlock()
	log.Debugf("[Token Manager] Successfully fetched token from Central Manager")
	return nil, false
}

// Start maintains valid token. It fetches a new token before expiry.
func (tm *TokenManager) Start(stopCh chan struct{}) {
	// Set ticker to 1 minute less than token expiry time to ensure token is refreshed on time
	tokenUpdateTicker := time.Tick(CMAccessTokenExpiration - 1*time.Minute)
	for {
		select {
		case <-tokenUpdateTicker:
			tm.SyncToken()
		case <-stopCh:
			log.Debug("[Token Manager] Stopping synchronizing token")
			close(stopCh)
			return
		}
	}
}

// SyncToken is a helper function to fetch token and retry on failure
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
				log.Debugf("[Token Manager] Retrying to fetch token in %d seconds", RetryInterval)
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
	req.Header.Add("Authorization", "Bearer "+tm.GetToken())

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
