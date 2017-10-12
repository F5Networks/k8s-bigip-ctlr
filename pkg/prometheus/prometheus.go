package prometheus

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

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
	[]string{},
)

var CurrentErrors = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_current_errors",
		Help: "Total count of errors occured parsing the configuration",
	},
	[]string{},
)

// further metrics? todo think about

func RegisterMetrics() {
	log.Println("Registered BigIP Metrics")
	prometheus.MustRegister(MonitoredNodes)
	prometheus.MustRegister(MonitoredServices)
	prometheus.MustRegister(CurrentErrors)
	//prometheus.MustRegister(redisSlavesHealthyTotal)
}
