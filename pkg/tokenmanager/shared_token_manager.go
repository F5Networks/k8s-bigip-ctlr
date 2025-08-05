// Package tokenmanager provides shared token management for multiple CIS components
package tokenmanager

import (
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/httpclient"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SharedTokenManager manages tokens for multiple BIG-IP devices and shares them across CIS components
// Since BIG-IP hosts are static for the lifetime of CIS, token managers are never removed
type SharedTokenManager struct {
	mu                   sync.RWMutex
	tokenManagers        map[string]*TokenManager
	clientFactory        *httpclient.HTTPClientFactory
	refreshTokenInterval time.Duration
	stopChannels         map[string]chan struct{} // Track stop channels for each token manager
}

// TokenManagerKey represents a unique key for identifying token managers
// Since each BIG-IP host is unique, we only need the host as the key
type TokenManagerKey struct {
	Host string
}

// String returns a string representation of the key
func (k TokenManagerKey) String() string {
	return k.Host
}

// SharedTokenManagerInstance is the global instance
var (
	sharedInstance *SharedTokenManager
	once           sync.Once
)

// GetSharedTokenManager returns the singleton instance of SharedTokenManager
func GetSharedTokenManager() *SharedTokenManager {
	once.Do(func() {
		sharedInstance = &SharedTokenManager{
			tokenManagers:        make(map[string]*TokenManager),
			clientFactory:        httpclient.GetFactory(),
			refreshTokenInterval: 10 * time.Hour, // Default refresh interval
			stopChannels:         make(map[string]chan struct{}),
		}
	})
	return sharedInstance
}

// SetRefreshTokenInterval sets the token refresh interval for all token managers
func (stm *SharedTokenManager) SetRefreshTokenInterval(interval time.Duration) {
	stm.mu.Lock()
	defer stm.mu.Unlock()
	stm.refreshTokenInterval = interval
	log.Infof("[Shared Token Manager] Set refresh token interval to %v", interval)
}

// GetOrCreateTokenManager returns an existing token manager or creates a new one for the given BIG-IP host
// Since BIG-IP configuration is static, token managers are created once and reused
func (stm *SharedTokenManager) GetOrCreateTokenManager(host, username, password string, httpClient *http.Client) TokenManagerInterface {
	key := TokenManagerKey{Host: host}

	stm.mu.RLock()
	if tm, exists := stm.tokenManagers[key.String()]; exists {
		stm.mu.RUnlock()
		log.Debugf("[Shared Token Manager] Reusing existing token manager for %s", key.String())
		return tm
	}
	stm.mu.RUnlock()

	// Need to create a new token manager
	stm.mu.Lock()
	defer stm.mu.Unlock()

	// Double-check in case another goroutine created it while we were waiting for the lock
	if tm, exists := stm.tokenManagers[key.String()]; exists {
		log.Debugf("[Shared Token Manager] Token manager created by another goroutine for %s", key.String())
		return tm
	}

	// Use provided HTTP client or fall back to the factory's default
	client := httpClient
	if client == nil {
		client = stm.clientFactory.GetDefaultClient()
	}

	// Create new token manager
	credentials := Credentials{
		Username: username,
		Password: password,
		// LoginProviderName will default to "tmos" in NewTokenManager
	}

	tm := NewTokenManager(formatBigIPURL(host), credentials, client)

	// Initialize token synchronously
	if err := tm.SyncToken(); err != nil {
		log.Errorf("[Shared Token Manager] Failed to initialize token for %s: %v", key.String(), err)
		// Still store the token manager as it will retry token acquisition
	}

	// Start automatic token refresh with the configured interval
	stopCh := make(chan struct{})
	stm.stopChannels[key.String()] = stopCh
	go tm.Start(stopCh, stm.refreshTokenInterval)
	log.Infof("[Shared Token Manager] Started token refresh for %s with interval %v", key.String(), stm.refreshTokenInterval)

	stm.tokenManagers[key.String()] = tm
	log.Infof("[Shared Token Manager] Created new token manager for %s", key.String())

	return tm
}

// GetTokenManager returns an existing token manager for the given host
func (stm *SharedTokenManager) GetTokenManager(host string) TokenManagerInterface {
	key := TokenManagerKey{Host: host}

	stm.mu.RLock()
	defer stm.mu.RUnlock()

	if tm, exists := stm.tokenManagers[key.String()]; exists {
		return tm
	}

	return nil
}

// GetActiveTokenManagers returns a list of currently active BIG-IP hosts
func (stm *SharedTokenManager) GetActiveTokenManagers() []string {
	stm.mu.RLock()
	defer stm.mu.RUnlock()

	hosts := make([]string, 0, len(stm.tokenManagers))
	for host := range stm.tokenManagers {
		hosts = append(hosts, host)
	}
	return hosts
}

// StopTokenManager stops the token refresh for a specific host
func (stm *SharedTokenManager) StopTokenManager(host string) {
	key := TokenManagerKey{Host: host}

	stm.mu.Lock()
	defer stm.mu.Unlock()

	if stopCh, exists := stm.stopChannels[key.String()]; exists {
		close(stopCh)
		delete(stm.stopChannels, key.String())
		log.Infof("[Shared Token Manager] Stopped token refresh for %s", key.String())
	}
}

// StopAll stops all token managers (used during shutdown)
func (stm *SharedTokenManager) StopAll() {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	for host, stopCh := range stm.stopChannels {
		close(stopCh)
		log.Infof("[Shared Token Manager] Stopped token refresh for %s", host)
	}
	stm.stopChannels = make(map[string]chan struct{})
}

// formatBigIPURL ensures the host has a proper URL scheme prefix
// If the host already contains a scheme (http:// or https://), it returns the host as-is
// Otherwise, it defaults to https:// for production use
func formatBigIPURL(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	return fmt.Sprintf("https://%s", host)
}
