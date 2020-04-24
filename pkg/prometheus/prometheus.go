package prometheus

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	"github.com/prometheus/client_golang/prometheus"
)

//TODO use as Counter not Gauge
var MonitoredNodes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_monitored_nodes",
		Help: "Total count of monitored nodes by the BigIP k8s CTLR",
	},
	[]string{"nodeselector"},
)

var MonitoredServices = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_monitored_services",
		Help: "Total count of monitored services by the BigIP k8s CTLR",
	},
	[]string{"namespace", "name", "status"},
)

var CurrentErrors = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_current_errors",
		Help: "Total count of errors occured parsing the configuration",
	},
	[]string{},
)

// further metrics? todo think about
// RegisterMetrics registers all Prometheus metrics defined above
func RegisterMetrics() {
	log.Info("[CORE] Registered BigIP Metrics")
	prometheus.MustRegister(MonitoredNodes)
	prometheus.MustRegister(MonitoredServices)
	prometheus.MustRegister(CurrentErrors)
}
