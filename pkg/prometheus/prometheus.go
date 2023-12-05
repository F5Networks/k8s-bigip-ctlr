package prometheus

import (
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ManagedServices = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "k8s_bigip_ctlr_managed_services",
	Help: "The total number of managed services by the CIS Controller.",
})

var ManagedTransportServers = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "k8s_bigip_ctlr_managed_transport_servers",
	Help: "The total number of managed transport servers by the CIS Controller.",
})

var ConfigurationWarnings = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "k8s_bigip_ctlr_configuration_warnings",
		Help: "The total number of configuration warnings by the CIS Controller.",
	},
	[]string{"kind", "namespace", "name", "warning"},
)

var AgentCount = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "k8s_bigip_ctlr_managed_bigips",
	Help: "The total number of bigips where the CIS Controller posts the declaration.",
})

var MonitoredNodes = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "k8s_bigip_ctlr_monitored_nodes",
		Help: "The total number of monitored nodes by the CIS Controller",
	},
	[]string{"nodeselector"},
)

var ClientInFlightGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "k8s_bigip_ctlr_http_client_in_flight_requests",
	Help: "Total count of in-flight requests for the wrapped http client.",
})

var ClientAPIRequestsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "k8s_bigip_ctlr_http_client_api_requests_total",
		Help: "A counter for requests from the wrapped http client.",
	},
	[]string{"code", "method"},
)

var ClientDNSLatencyVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "k8s_bigip_ctlr_http_client_dns_duration_seconds",
		Help:    "Trace dns latency histogram.",
		Buckets: []float64{.005, .01, .025, .05},
	},
	[]string{"event"},
)

var ClientTLSLatencyVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "k8s_bigip_ctlr_http_client_tls_duration_seconds",
		Help:    "Trace tls latency histogram.",
		Buckets: []float64{.05, .1, .25, .5},
	},
	[]string{"event"},
)

var ClientHistVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "k8s_bigip_ctlr_http_client_request_duration_seconds",
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
func RegisterMetrics(httpClientMetrics bool, bigip string) {
	log.Infof("Registered BigIP Metrics for BigIP %v", bigip)
	if httpClientMetrics {
		prometheus.MustRegister(
			ManagedServices,
			ManagedTransportServers,
			ConfigurationWarnings,
			AgentCount,
			MonitoredNodes,
			ClientInFlightGauge,
			ClientAPIRequestsCounter,
			ClientDNSLatencyVec,
			ClientTLSLatencyVec,
			ClientHistVec,
		)
	} else {
		prometheus.MustRegister(
			ManagedServices,
			ManagedTransportServers,
			ConfigurationWarnings,
			AgentCount,
			MonitoredNodes,
		)
	}
}
