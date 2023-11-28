package prometheus

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TODO use as Counter not Gauge
var MonitoredNodes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_monitored_nodes",
		Help: "Total count of monitored nodes by the BigIP k8s CTLR.",
	},
	[]string{"nodeselector"},
)

var MonitoredServices = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_monitored_services",
		Help: "Total count of monitored services by the BigIP k8s CTLR.",
	},
	[]string{"namespace", "name", "status"},
)

var CurrentErrors = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_current_errors",
		Help: "Total count of errors occured parsing the configuration.",
	},
	[]string{},
)

var ClientInFlightGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "bigip_http_client_in_flight_requests",
	Help: "Total count of in-flight requests for the wrapped http client.",
})

var ClientAPIRequestsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "bigip_http_client_api_requests_total",
		Help: "A counter for requests from the wrapped http client.",
	},
	[]string{"code", "method"},
)

var ClientDNSLatencyVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "bigip_http_client_dns_duration_seconds",
		Help:    "Trace dns latency histogram.",
		Buckets: []float64{.005, .01, .025, .05},
	},
	[]string{"event"},
)

var ClientTLSLatencyVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "bigip_http_client_tls_duration_seconds",
		Help:    "Trace tls latency histogram.",
		Buckets: []float64{.05, .1, .25, .5},
	},
	[]string{"event"},
)

var ClientHistVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "bigip_http_client_request_duration_seconds",
		Help:    "Trace http request latencies histogram.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{},
)

var ClientTrace = &promhttp.InstrumentTrace{
	DNSStart: func(t float64) {
		ClientDNSLatencyVec.WithLabelValues("dns_start").Observe(t)
	},
	DNSDone: func(t float64) {
		ClientDNSLatencyVec.WithLabelValues("dns_done").Observe(t)
	},
	TLSHandshakeStart: func(t float64) {
		ClientTLSLatencyVec.WithLabelValues("tls_handshake_start").Observe(t)
	},
	TLSHandshakeDone: func(t float64) {
		ClientTLSLatencyVec.WithLabelValues("tls_handshake_done").Observe(t)
	},
}

// further metrics? todo think about
// RegisterMetrics registers all Prometheus metrics defined above
func RegisterMetrics(httpClientMetrics bool) {
	log.Info("Registered BigIP Metrics")
	if httpClientMetrics {
		prometheus.MustRegister(
			MonitoredNodes,
			MonitoredServices,
			CurrentErrors,
			ClientInFlightGauge,
			ClientAPIRequestsCounter,
			ClientDNSLatencyVec,
			ClientTLSLatencyVec,
			ClientHistVec,
		)
	} else {
		prometheus.MustRegister(
			MonitoredNodes,
			MonitoredServices,
			CurrentErrors,
		)
	}
}
