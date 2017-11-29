package health

import (
	"log"
	"net/http"
	"os"
)

type HealthChecker struct {
	SubPID int
}

//TODO: Add additional health checks
//TODO: add health check if Kubernetes API is still reachable
func (hc HealthChecker) HealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Health check called, checking for subprocess with ID: %d\n", hc.SubPID)
		if hc.SubPID != 0 {
			_, err := os.FindProcess(hc.SubPID)
			if nil != err {
				// assume that Python process is still running
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
				return
			}
			log.Println(err)
		}

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Python process is dead"))
	})
}
