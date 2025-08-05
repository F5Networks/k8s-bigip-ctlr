package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ClientConfig holds configuration for HTTP client creation
type ClientConfig struct {
	TrustedCerts  string
	SSLInsecure   bool
	Timeout       time.Duration
	EnableMetrics bool
	MetricsConfig *MetricsConfig
}

// MetricsConfig holds Prometheus metrics configuration
type MetricsConfig struct {
	InFlightGauge   prometheus.Gauge
	RequestsCounter *prometheus.CounterVec
	Trace           *promhttp.InstrumentTrace
	HistogramVec    prometheus.ObserverVec
}

// HTTPClientFactory manages shared HTTP clients with different configurations
type HTTPClientFactory struct {
	mu      sync.RWMutex
	clients map[string]*http.Client
}

var (
	factory *HTTPClientFactory
	once    sync.Once
)

// GetFactory returns the singleton HTTP client factory
func GetFactory() *HTTPClientFactory {
	once.Do(func() {
		factory = &HTTPClientFactory{
			clients: make(map[string]*http.Client),
		}
	})
	return factory
}

// GetOrCreateClient returns an existing HTTP client or creates a new one based on the configuration
func (f *HTTPClientFactory) GetOrCreateClient(key string, config ClientConfig) *http.Client {
	f.mu.RLock()
	if client, exists := f.clients[key]; exists {
		f.mu.RUnlock()
		return client
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check in case another goroutine created it
	if client, exists := f.clients[key]; exists {
		return client
	}

	client := f.createHTTPClient(config)
	f.clients[key] = client
	log.Debugf("[HTTP Client Factory] Created new HTTP client for key: %s", key)

	return client
}

// createHTTPClient creates a new HTTP client with the given configuration
func (f *HTTPClientFactory) createHTTPClient(config ClientConfig) *http.Client {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Append trusted certificates if provided
	if config.TrustedCerts != "" {
		certs := []byte(config.TrustedCerts)
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			log.Debugf("[HTTP Client Factory] No certs appended, using only system certs")
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SSLInsecure,
			RootCAs:            rootCAs,
		},
	}

	// Set default timeout if not specified
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Apply metrics instrumentation if enabled
	if config.EnableMetrics && config.MetricsConfig != nil {
		log.Debug("[HTTP Client Factory] Creating HTTP client with metrics instrumentation")
		instrumentedRoundTripper := promhttp.InstrumentRoundTripperInFlight(config.MetricsConfig.InFlightGauge,
			promhttp.InstrumentRoundTripperCounter(config.MetricsConfig.RequestsCounter,
				promhttp.InstrumentRoundTripperTrace(config.MetricsConfig.Trace,
					promhttp.InstrumentRoundTripperDuration(config.MetricsConfig.HistogramVec, tr),
				),
			),
		)
		return &http.Client{
			Transport: instrumentedRoundTripper,
			Timeout:   timeout,
		}
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

// GetDefaultClient returns a basic HTTP client with secure defaults
func (f *HTTPClientFactory) GetDefaultClient() *http.Client {
	return f.GetOrCreateClient("default", ClientConfig{
		SSLInsecure: false,
		Timeout:     30 * time.Second,
	})
}

// generateClientKey creates a unique key for client configuration
func generateClientKey(config ClientConfig) string {
	// Create a deterministic key based on configuration
	key := ""
	if config.TrustedCerts != "" {
		key += "certs:"
	}
	if config.SSLInsecure {
		key += "insecure:"
	}
	if config.EnableMetrics {
		key += "metrics:"
	}
	key += config.Timeout.String()
	return key
}
