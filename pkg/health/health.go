package health

import (
	"context"
	"net/http"
	"os"
	"sync"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"k8s.io/client-go/kubernetes"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	clusterHealthPath = "/readyz"
	certFile          = "/tls/tls.crt"
	keyFile           = "/tls/tls.key"
)

var (
	healthCheckOnce sync.Once
)

type HealthChecker struct {
	SubPID                  int
	KubeClient              kubernetes.Interface
	ClusterConfigKubeClient kubernetes.Interface
	ApiVersionError         error
	HttpsAddress            string
	PythonDriverPID         int
	HttpClientMetrics       bool
	CustomResourceMode      bool
	PoolMode                string
	ControllerMode          string
	Agent                   string
}

func (hc HealthChecker) CISHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hc.KubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := hc.KubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				response = "kube-api server is not reachable."
			}
			if err == nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(response))
			}
		}
	})
}

func (hc HealthChecker) HealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hc.SubPID != 0 {
			_, err := os.FindProcess(hc.SubPID)
			if err == nil {
				// assume that Python process is still running
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
				return
			}

			log.Errorf(err.Error())
		}

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Python process is dead"))
	})
}

// health check: checks kube-api if SubPID==0, else checks process and kube-api
func (hc HealthChecker) HealthCheckHandlerSecured() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hc.SubPID != 0 {
			// Check process
			_, err := os.FindProcess(hc.SubPID)
			if err == nil {
				// Process exists, now check kube-api if KubeClient is set
				if hc.KubeClient != nil {
					_, kerr := hc.KubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
					if kerr == nil {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("Ok"))
						return
					} else {
						log.Errorf(kerr.Error())
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("kube-api server is not reachable."))
						return
					}
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Ok"))
					return
				}
			}
			log.Errorf(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Python process is dead"))
			return
		}
		// If SubPID is 0, only check kube-api
		if hc.KubeClient != nil {
			_, err := hc.KubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err == nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
				return
			} else {
				log.Errorf(err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("kube-api server is not reachable."))
				return
			}
		}
	})
}

// loadAndValidateTLSCertificate reads and validates the TLS certificate and key files.
func loadAndValidateTLSCertificate(certPath, keyPath string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read cert file: %w", err)
	}

	_, err = os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read key file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate PEM")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	if now.Before(parsedCert.NotBefore) {
		return tls.Certificate{}, fmt.Errorf("certificate is not valid yet (NotBefore: %v)", parsedCert.NotBefore)
	}
	if now.After(parsedCert.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("certificate is expired (NotAfter: %v)", parsedCert.NotAfter)
	}

	// If valid, load keypair as usual
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func (hc HealthChecker) CISHealthCheckSecured() {
	healthCheckOnce.Do(func() {
		// Initial cert load
		cert, err := loadAndValidateTLSCertificate(certFile, keyFile)
		if err != nil {
			log.Errorf("[Health server] TLS cert load failed: %v", err)
			return
		}

		// This will be updated when cert changes
		var currentCert atomic.Value
		currentCert.Store(cert)

		// Watch for changes
		go watchCertFiles(certFile, keyFile, func() {
			newCert, err := loadAndValidateTLSCertificate(certFile, keyFile)
			if err != nil {
				log.Errorf("[Health server] Failed to reload TLS cert: %v", err)
				return
			}
			currentCert.Store(newCert)
			log.Debugf("[Health server] TLS cert reloaded")
		})

		tlsCfg := &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				c := currentCert.Load().(tls.Certificate)
				return &c, nil
			},
		}
		healthMux := http.NewServeMux()
		if hc.CustomResourceMode || hc.ControllerMode != "" {
			healthMux.Handle("/ready", hc.CISHealthCheckHandlerSecured())
			healthMux.Handle("/health", hc.HealthCheckHandlerSecured())
		} else {
			if hc.PoolMode == "cluster" || hc.Agent == "as3" {
				healthMux.Handle("/health", hc.HealthCheckHandler())
			} else {
				healthMux.Handle("/health", hc.CISHealthCheckHandler())
			}
		}
		// Expose Prometheus metrics
		healthMux.Handle("/metrics", promhttp.Handler())
		healthServer := &http.Server{
			Addr:      hc.HttpsAddress,
			Handler:   healthMux,
			TLSConfig: tlsCfg,
		}
		healthShutdownCh := make(chan struct{})

		// Register HTTPClientMetrics for Prometheus
		bigIPPrometheus.RegisterMetrics(hc.HttpClientMetrics)

		// Graceful shutdown goroutine
		go func() {
			<-healthShutdownCh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := healthServer.Shutdown(ctx); err != nil {
				log.Errorf("Health server graceful shutdown failed: %v", err)
			} else {
				log.Infof("Health server gracefully stopped")
			}
		}()
		log.Infof("Starting health server on: %s", hc.HttpsAddress)
		if err := healthServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Errorf("Health server failed: %v", err)
		}
	})
}

func (hc HealthChecker) CISHealthCheckHandlerSecured() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hc.ClusterConfigKubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := hc.ClusterConfigKubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				response = "kube-api server is not reachable."
			}
			if hc.ApiVersionError != nil {
				response = response + "big-ip server is not reachable."
			}
			if hc.ApiVersionError == nil && err == nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(response))
			}
		}
	})
}

// watchCertFiles monitors the certificate and key files for changes and reloads them when modified.
func watchCertFiles(certPath, keyPath string, certsReload func()) {
	absCertPath, _ := filepath.Abs(certPath)
	absKeyPath, _ := filepath.Abs(keyPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Printf("[Health server] fsnotify init failed: %v\n", err)
		return
	}

	defer watcher.Close()

	certDir := filepath.Dir(absCertPath)
	keyDir := filepath.Dir(absKeyPath)
	_ = watcher.Add(certDir)

	if certDir != keyDir {
		_ = watcher.Add(keyDir)
	}

	log.Debugf("[Health Server] Watching certificate file: %s and key file: %s for changes...", certPath, keyPath)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
				certsReload()
			}
		case err, ok := <-watcher.Errors:
			if ok {
				log.Errorf("[Health server] fsnotify error: %v\n", err)
			}
		}
	}
}
