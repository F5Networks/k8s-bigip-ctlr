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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	webhookServerOnce sync.Once
	healthCheckOnce   sync.Once
)

func (ctlr *Controller) startWebhook() {
	webhookServerOnce.Do(func() {
		webhookMux := http.NewServeMux()
		webhookMux.HandleFunc("/mutate", ctlr.handleMutate)
		webhookMux.HandleFunc("/validate", ctlr.handleValidate)
		ctlr.webhookServer = &http.Server{
			Addr:    ctlr.agentParams.HttpsAddress,
			Handler: webhookMux,
		}
		webhookShutdownCh := make(chan struct{})

		// Check cert/key existence and validity before starting server
		if _, err := os.Stat(certFile); err != nil {
			log.Errorf("TLS certificate file not found: %s, error: %v", certFile, err)
			return
		}
		if _, err := os.Stat(keyFile); err != nil {
			log.Errorf("TLS key file not found: %s, error: %v", keyFile, err)
			return
		}
		if err := validateTLSCertificate(certFile, keyFile); err != nil {
			log.Errorf("Invalid TLS certificate or key: %v", err)
			return
		}

		// Graceful shutdown goroutine
		go func() {
			<-webhookShutdownCh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := ctlr.webhookServer.Shutdown(ctx); err != nil {
				log.Errorf("Webhook server graceful shutdown failed: %v", err)
			} else {
				log.Infof("Webhook server gracefully stopped")
			}
		}()
		log.Infof("Starting webhook server on :%s", ctlr.agentParams.HttpsAddress)
		if err := ctlr.webhookServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Errorf("Webhook server failed: %v", err)
		}
	})
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
		log.Infof("Starting health server server on :%s", ctlr.agentParams.HttpAddress)
		if err := ctlr.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Health server failed: %v", err)
		}
	})
}

// validateTLSCertificate checks if the cert/key files are valid and not expired
func validateTLSCertificate(certPath, keyPath string) error {
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("could not read cert file: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("could not read key file: %w", err)
	}
	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("invalid TLS key pair: %w", err)
	}
	// Check for expiration
	block, _ := pem.Decode(cert)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	if time.Now().After(parsedCert.NotAfter) {
		return fmt.Errorf("certificate is expired (NotAfter: %v)", parsedCert.NotAfter)
	}
	if time.Now().Before(parsedCert.NotBefore) {
		return fmt.Errorf("certificate is not valid yet (NotBefore: %v)", parsedCert.NotBefore)
	}
	return nil
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
