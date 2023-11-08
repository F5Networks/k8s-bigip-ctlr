package health

import (
	"net/http"
	"os"

	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
)

type HealthChecker struct {
	SubPID int
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
