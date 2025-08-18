package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/health"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	webhookServerOnce sync.Once
	healthCheckOnce   sync.Once
)

type webHook struct {
	Server  *http.Server
	address string
}

func (ctlr *Controller) startWebhook() {
	webhookServerOnce.Do(func() {
		// Initial cert load
		cert, err := loadAndValidateTLSCertificate(certFile, keyFile)
		if err != nil {
			log.Errorf("[Webhook] TLS cert load failed: %v", err)
			return
		}

		// This will be updated when cert changes
		var currentCert atomic.Value
		currentCert.Store(cert)

		// Watch for changes
		go watchCertFiles(certFile, keyFile, func() {
			newCert, err := loadAndValidateTLSCertificate(certFile, keyFile)
			if err != nil {
				log.Errorf("[Webhook] Failed to reload webhook TLS cert: %v", err)
				return
			}
			currentCert.Store(newCert)
			log.Debugf("[Webhook] TLS cert reloaded")
		})

		tlsCfg := &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				c := currentCert.Load().(tls.Certificate)
				return &c, nil
			},
		}

		webhookMux := http.NewServeMux()
		webhookMux.HandleFunc("/mutate", ctlr.handleMutate)
		webhookMux.HandleFunc("/validate", ctlr.handleValidate)
		ctlr.webhookServer = webHook{
			Server: &http.Server{
				Addr:      ctlr.agentParams.HttpsAddress,
				Handler:   webhookMux,
				TLSConfig: tlsCfg,
			},
			address: ctlr.agentParams.HttpsAddress,
		}
		webhookShutdownCh := make(chan struct{})

		// Graceful shutdown goroutine
		go func() {
			<-webhookShutdownCh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := ctlr.webhookServer.GetWebhookServer().Shutdown(ctx); err != nil {
				log.Errorf("[Webhook] server graceful shutdown failed: %v", err)
			} else {
				log.Infof("[Webhook] server gracefully stopped")
			}
		}()
		log.Infof("[Webhook] starting webhook server on :%s", ctlr.agentParams.HttpsAddress)
		if err := ctlr.webhookServer.GetWebhookServer().ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Errorf("Webhook server failed: %v", err)
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

func (ctlr *Controller) CISHealthCheck() {
	healthCheckOnce.Do(func() {
		healthMux := http.NewServeMux()
		healthMux.Handle("/ready", ctlr.CISHealthCheckHandler())
		ctlr.healthServer = &http.Server{
			Addr:    ctlr.agentParams.HttpAddress,
			Handler: healthMux,
		}
		hc := &health.HealthChecker{
			KubeClient: ctlr.kubeClient,
		}
		// enable the health check endpoint only if the primary big-ip worker is running
		if ctlr.RequestHandler.PrimaryBigIPWorker.PythonDriverPID != 0 {
			// Add health check to track whether Python process still alive
			hc.SubPID = ctlr.RequestHandler.PrimaryBigIPWorker.PythonDriverPID
		}

		// add new health checker
		healthMux.Handle("/health", hc.HealthCheckHandler())
		// Expose Prometheus metrics
		healthMux.Handle("/metrics", promhttp.Handler())
		// Register HTTPClientMetrics for Prometheus
		bigIPPrometheus.RegisterMetrics(ctlr.agentParams.PrimaryParams.HTTPClientMetrics)
		healthShutdownCh := make(chan struct{})
		// Graceful shutdown goroutine
		go func() {
			<-healthShutdownCh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := ctlr.healthServer.Shutdown(ctx); err != nil {
				log.Errorf("Health server graceful shutdown failed: %v", err)
			} else {
				log.Infof("Health server gracefully stopped")
			}
		}()
		log.Infof("Starting health server on :%s", ctlr.agentParams.HttpAddress)
		if err := ctlr.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Health server failed: %v", err)
		}
	})
}

func (ctlr *Controller) CISHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		if clusterConfig.kubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := clusterConfig.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				response = "kube-api server is not reachable."
			}
			// Check if big-ip server is reachable
			_, _, _, err2 := ctlr.RequestHandler.PrimaryBigIPWorker.APIHandler.LTM.GetBigIPAPIVersion()
			if err2 != nil {
				response = response + "big-ip server is not reachable."
			}
			if err2 == nil && err == nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(response))
			}
		}
	})
}

// function to check if the webhook server is running
func (w webHook) IsWebhookServerRunning() bool {
	conn, err := tls.Dial("tcp", w.address, &tls.Config{
		InsecureSkipVerify: true, // Only for health check, skips cert validation
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// function to get the webhook server
func (w webHook) GetWebhookServer() *http.Server {
	return w.Server
}

// watchCertFiles monitors the certificate and key files for changes and reloads them when modified.
func watchCertFiles(certPath, keyPath string, certsReload func()) {
	absCertPath, _ := filepath.Abs(certPath)
	absKeyPath, _ := filepath.Abs(keyPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Printf("[Webhook] fsnotify init failed: %v\n", err)
		return
	}

	defer watcher.Close()

	certDir := filepath.Dir(absCertPath)
	keyDir := filepath.Dir(absKeyPath)
	_ = watcher.Add(certDir)

	if certDir != keyDir {
		_ = watcher.Add(keyDir)
	}

	log.Debugf("[Webhook] Watching certificate file: %s and key file: %s for changes...", certPath, keyPath)

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
				log.Errorf("[Webhook] fsnotify error: %v\n", err)
			}
		}
	}
}
