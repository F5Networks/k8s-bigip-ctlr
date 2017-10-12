package health

import (
	"net/http"
	"os"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
)

type HealthChecker struct {
	SubPID int
}

//TODO: Add additional health checks
func (hc HealthChecker) HealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hc.SubPID != 0 {
			_, err := os.FindProcess(hc.SubPID)
			if nil != err {
				// assume that Python process is still running
				log.Warningf("Failed to find sub-process on exit: %v", err)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
				return
			}
		}

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Python process is dead"))
	})
}
