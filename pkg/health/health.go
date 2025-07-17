package health

import (
	"context"
	"net/http"
	"os"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"k8s.io/client-go/kubernetes"
)

const (
	clusterHealthPath = "/readyz"
)

type HealthChecker struct {
	SubPID     int
	KubeClient kubernetes.Interface
}

// health check: checks kube-api if SubPID==0, else checks process and kube-api
func (hc HealthChecker) HealthCheckHandler() http.Handler {
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
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("No health check available"))
	})
}
