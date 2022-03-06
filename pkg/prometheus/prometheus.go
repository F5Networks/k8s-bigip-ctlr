package prometheus

import (
	"sync"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

	"github.com/prometheus/client_golang/prometheus"
)

type recordEntity struct {
	Operation string
	Kind      string
	Namespace string
	Name      string
}

var AS3Times int = 0
var AS3CostTotal int64 = 0

func AddRESTAS3Cost(cost int64) {
	AS3Times += 1
	AS3CostTotal += cost
	MonitoredWorkingListengths.WithLabelValues("as3.total").Set(float64(AS3CostTotal))
	MonitoredWorkingListengths.WithLabelValues("as3.times").Set(float64(AS3Times))
}

var ResourcesRecorder = map[recordEntity][]int64{}
var ResourcesRecorderLock = sync.Mutex{}

func RecStartTime(opr, kind, ns, name string) {

	re := recordEntity{
		Operation: opr,
		Kind:      kind,
		Namespace: ns,
		Name:      name,
	}

	ResourcesRecorderLock.Lock()
	if _, ok := ResourcesRecorder[re]; !ok {
		ResourcesRecorder[re] = []int64{}
	}
	ResourcesRecorder[re] = append(ResourcesRecorder[re], time.Now().UnixMilli())
	ResourcesRecorderLock.Unlock()
}

func CalcWaitTime(opr, kind, ns, name string) {

	re := recordEntity{
		Operation: opr,
		Kind:      kind,
		Namespace: ns,
		Name:      name,
	}

	ResourcesRecorderLock.Lock()
	tn := time.Now().UnixMilli()
	if len(ResourcesRecorder[re]) >= 1 {
		MonitoredResourcesTimeCost.WithLabelValues(
			re.Kind, re.Namespace, re.Namespace+"_"+re.Name, re.Operation, "wait").Set(
			float64(tn - ResourcesRecorder[re][0]))
		ResourcesRecorder[re] = ResourcesRecorder[re][1:]
		if len(ResourcesRecorder[re]) == 0 {
			delete(ResourcesRecorder, re)
		}
	}
	ResourcesRecorderLock.Unlock()
}

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

var MonitoredResourcesTimeCost = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_monitored_resources_timecost",
		Help: "Status of monitored resources by the BigIP k8s CTLR",
	},
	[]string{"kind", "namespace", "name", "operation", "stage"},
)

var MonitoredWorkingListengths = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bigip_working_list_length",
		Help: "The current length of Queues/Working-list",
	},
	[]string{"name"},
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
	prometheus.MustRegister(MonitoredResourcesTimeCost)
	prometheus.MustRegister(MonitoredWorkingListengths)
	prometheus.MustRegister(CurrentErrors)
}
