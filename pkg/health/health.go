package health

import (
	"context"
	"net/http"
	"os"
	"k8s.io/client-go/kubernetes"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

const (
	clusterHealthPath = "/readyz"
)

type HealthChecker struct {
	SubPID int
}

func (hc HealthChecker) CISHealthCheckHandler(kubeClient kubernetes.Interface) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
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
