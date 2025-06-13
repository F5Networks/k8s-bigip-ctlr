/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package appmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vxlan"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"

	netv1 "k8s.io/api/networking/v1"

	cisAgent "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	. "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	routeapi "github.com/openshift/api/route/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	listersroutev1 "github.com/openshift/client-go/route/listers/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type ResourceMap map[int32][]*ResourceConfig

// RoutesMap consists of List of route names indexed by namespace
type RoutesMap map[string][]string

type PodSvcCache struct {
	podDetails  *sync.Map
	svcPodCache *sync.Map
}

type PodDetails struct {
	podIp       string
	gracePeriod int64
	epKey       string
	podPorts    string
	status      string
}

type Manager struct {
	resources           *Resources
	customProfiles      *CustomProfileStore
	irulesMap           IRulesMap
	intDgMap            InternalDataGroupMap
	agentCfgMap         map[string]*AgentCfgMap
	agentCfgMapSvcCache map[string]*SvcEndPointsCache
	podSvcCache         PodSvcCache
	kubeClient          kubernetes.Interface
	restClientv1        rest.Interface
	restClientv1beta1   rest.Interface
	netClientv1         rest.Interface
	routeClientV1       routeclient.RouteV1Interface
	steadyState         bool
	queueLen            int
	processedItems      int
	processedResources  map[string]bool
	// Mutex to control access to processedResources map
	processedResourcesMutex sync.Mutex
	processedHostPath       ProcessedHostPath
	// Use internal node IPs
	useNodeInternal bool
	// Running in nodeport (or cluster) mode
	isNodePort bool
	// Mutex to control access to node data
	// FIXME: Simple synchronization for now, it remains to be determined if we'll
	// need something more complicated (channels, etc?)
	oldNodesMutex sync.Mutex
	// Nodes from previous iteration of node polling
	oldNodes []Node
	// Mutex for all informers (for informer CRUD)
	informersMutex sync.Mutex
	// Mutex for intDgMap
	intDgMutex sync.Mutex
	// App informer support
	vsQueue      workqueue.RateLimitingInterface
	appInformers map[string]*appInformer
	nodeInformer *nodeInformer
	// Namespace informer support (namespace labels)
	nsQueue    workqueue.RateLimitingInterface
	nsInformer cache.SharedIndexInformer
	DynamicNS  bool
	// Event notifier
	eventNotifier *EventNotifier
	// Route configurations
	routeConfig RouteConfig
	// Currently configured node label selector
	nodeLabelSelector string
	// Strategy for resolving Ingress Hosts into IP addresses (LOOKUP or custom DNS)
	resolveIng string
	// Default IP for any Ingress with the 'controller-default' ip annotation
	defaultIngIP string
	// Optional SNAT pool name to be referenced by virtual servers
	vsSnatPoolName string
	// Use Secrets for SSL Profiles
	useSecrets bool
	// Channel for emitting events
	eventChan chan interface{}
	// Where the schemas reside locally
	schemaLocal string
	// map of rules that have been merged
	mergedRulesMap map[string]map[string]MergedRuleEntry
	// Whether to watch ConfigMap resources or not
	manageConfigMaps       bool
	configMapLabel         string
	hubMode                bool
	manageIngress          bool
	manageIngressClassOnly bool
	ingressClass           string
	// Ingress SSL security Context
	rsrcSSLCtxt map[string]*v1.Secret
	WatchedNS   WatchedNamespaces
	// AS3 Specific features that can be applied to a Route/Ingress
	trustedCertsCfgmap string
	intF5Res           InternalF5ResourcesGroup
	dgPath             string
	AgentCIS           cisAgent.CISAgentInterface
	// Processed routes for updating Admit Status
	agRspChan          chan interface{}
	processAgentLabels func(map[string]string, string, string) bool
	TeemData           *teem.TeemsData
	defaultRouteDomain int
	poolMemberType     string
	// key is namespace/pod. stores list of npl annotation on pod
	nplStore map[string]NPLAnnoations
	// Mutex to control access to nplStore map
	nplStoreMutex sync.Mutex
	AgentName     string
	BigIPURL      string
	//vxlan
	vxlanName           string
	ciliumTunnelName    string
	vxlanMode           string
	configWriter        writer.Writer
	staticRoutingMode   bool
	orchestrationCNI    string
	staticRouteNodeCIDR string
	membersToDisable    map[string]map[string]struct{}
}

// Store of processed host-Path map
type ProcessedHostPath struct {
	sync.Mutex
	processedHostPathMap map[string]metav1.Time
}

// Watched Namespaces for global availability.
type WatchedNamespaces struct {
	Namespaces     []string
	NamespaceLabel string
}

// NPL information from pod annotation
type NPLAnnotation struct {
	PodPort  int32  `json:"podPort"`
	NodeIP   string `json:"nodeIP"`
	NodePort int32  `json:"nodePort"`
}

// List of NPL annotations
type NPLAnnoations []NPLAnnotation

// static route config section
type routeSection struct {
	CISIdentifier string        `json:"cis-identifier,omitempty"`
	Entries       []routeConfig `json:"routes"`
}

type routeConfig struct {
	Name        string `json:"name"`
	Network     string `json:"network"`
	Gateway     string `json:"gw"`
	Description string `json:"description,omitempty"`
}

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	KubeClient        kubernetes.Interface
	RouteClientV1     routeclient.RouteV1Interface
	UseNodeInternal   bool
	IsNodePort        bool
	RouteConfig       RouteConfig
	ResolveIngress    string
	DefaultIngIP      string
	VsSnatPoolName    string
	NodeLabelSelector string
	UseSecrets        bool
	SchemaLocal       string
	EventChan         chan interface{}
	ConfigWriter      writer.Writer
	// Package local for untesting only
	restClient             rest.Interface
	steadyState            bool
	broadcasterFunc        NewBroadcasterFunc
	ManageConfigMaps       bool
	ManageIngress          bool
	ManageIngressClassOnly bool
	HubMode                bool
	PodGracefulShutdown    bool
	IngressClass           string
	Agent                  string
	SchemaLocalPath        string
	TrustedCertsCfgmap     string
	// Data group path
	DgPath             string
	AgRspChan          chan interface{}
	ProcessAgentLabels func(map[string]string, string, string) bool
	UserAgent          string
	DefaultRouteDomain int
	PoolMemberType     string
	//vxlan
	VXLANName           string
	VXLANMode           string
	CiliumTunnelName    string
	StaticRoutingMode   bool
	OrchestrationCNI    string
	StaticRouteNodeCIDR string
	BigIPURL            string
}

type SvcEndPointsCache struct {
	members     []Member
	labelString string
}

// Configuration options for Routes in OpenShift
type RouteConfig struct {
	RouteVSAddr string
	RouteLabel  string
	HttpVs      string
	HttpsVs     string
	ClientSSL   string
	ServerSSL   string
}

var K8SCoreServices = map[string]bool{
	"kube-dns":                      true,
	"kube-scheduler":                true,
	"kube-controller-manager":       true,
	"kube-apiserver":                true,
	"docker-registry":               true,
	"kubernetes":                    true,
	"registry-console":              true,
	"router":                        true,
	"kubelet":                       true,
	"console":                       true,
	"alertmanager-main":             true,
	"alertmanager-operated":         true,
	"cluster-monitoring-operator":   true,
	"kube-state-metrics":            true,
	"node-exporter":                 true,
	"prometheus-k8s":                true,
	"prometheus-operated":           true,
	"prometheus-operatorwebconsole": true,
	"kube-proxy":                    true,
	"flannel":                       true,
	"etcd":                          true,
	"antrea":                        true,
}

var OSCPCoreServices = map[string]bool{
	"openshift":                          true,
	"metrics":                            true,
	"api":                                true,
	"check-endpoints":                    true,
	"oauth-openshift":                    true,
	"cco-metrics":                        true,
	"machine-approver":                   true,
	"node-tuning-operator":               true,
	"performance-addon-operator-service": true,
	"cluster-storage-operator-metrics":   true,
	"csi-snapshot-controller-operator-metrics": true,
	"csi-snapshot-webhook":                     true,
	"cluster-version-operator":                 true,
	"downloads":                                true,
	"controller-manager":                       true,
	"dns-default":                              true,
	"image-registry-operator":                  true,
	"router-internal-default":                  true,
	"apiserver":                                true,
	"scheduler":                                true,
	"cluster-autoscaler-operator":              true,
	"cluster-baremetal-operator-service":       true,
	"cluster-baremetal-webhook-service":        true,
	"machine-api-controllers":                  true,
	"machine-api-operator":                     true,
	"machine-api-operator-webhook":             true,
	"machine-config-controller":                true,
	"machine-config-daemon":                    true,
	"certified-operators":                      true,
	"community-operators":                      true,
	"marketplace-operator-metrics":             true,
	"redhat-marketplace":                       true,
	"redhat-operators":                         true,
	"openshift-state-metrics":                  true,
	"telemeter-client":                         true,
	"thanos-querier":                           true,
	"multus-admission-controller":              true,
	"network-metrics-service":                  true,
	"network-check-source":                     true,
	"network-check-target":                     true,
	"catalog-operator-metrics":                 true,
	"olm-operator-metrics":                     true,
	"packageserver-service":                    true,
	"sdn":                                      true,
	"sdn-controller":                           true,
}

const (

	// Kinds of Resources
	Namespaces     = "namespaces"
	Services       = "services"
	Endpoints      = "endpoints"
	Pod            = "pod"
	Nodes          = "nodes"
	Configmaps     = "configmaps"
	Ingresses      = "ingresses"
	Routes         = "routes"
	Secrets        = "secrets"
	IngressClasses = "ingressclasses"

	NPLPodAnnotation = "nodeportlocal.antrea.io"
	NPLSvcAnnotation = "nodeportlocal.antrea.io/enabled"
	// CNI
	OVN_K8S                    = "ovn-k8s"
	OVNK8sNodeSubnetAnnotation = "k8s.ovn.org/node-subnets"
	OVNK8sNodeIPAnnotation     = "k8s.ovn.org/node-primary-ifaddr"
	// k8s.ovn.org/host-addresses is changed to k8s.ovn.org/host-cidrs in openshift 4.14
	OVNK8sNodeIPAnnotation2 = "k8s.ovn.org/host-addresses"
	OVNK8sNodeIPAnnotation3 = "k8s.ovn.org/host-cidrs"

	CILIUM_K8S                      = "cilium-k8s"
	CiliumK8sNodeSubnetAnnotation12 = "io.cilium.network.ipv4-pod-cidr"
	CiliumK8sNodeSubnetAnnotation13 = "network.cilium.io/ipv4-pod-cidr"
)

// Create and return a new app manager that meets the Manager interface
func NewManager(params *Params) *Manager {
	vsQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "virtual-server-controller")
	nsQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "namespace-controller")
	manager := Manager{
		resources:              NewResources(),
		customProfiles:         NewCustomProfiles(),
		irulesMap:              make(IRulesMap),
		intDgMap:               make(InternalDataGroupMap),
		kubeClient:             params.KubeClient,
		restClientv1:           params.restClient,
		restClientv1beta1:      params.restClient,
		routeClientV1:          params.RouteClientV1,
		useNodeInternal:        params.UseNodeInternal,
		isNodePort:             params.IsNodePort,
		steadyState:            params.steadyState,
		queueLen:               0,
		processedItems:         0,
		routeConfig:            params.RouteConfig,
		nodeLabelSelector:      params.NodeLabelSelector,
		resolveIng:             params.ResolveIngress,
		defaultIngIP:           params.DefaultIngIP,
		vsSnatPoolName:         params.VsSnatPoolName,
		schemaLocal:            params.SchemaLocal,
		useSecrets:             params.UseSecrets,
		vsQueue:                vsQueue,
		nsQueue:                nsQueue,
		appInformers:           make(map[string]*appInformer),
		eventNotifier:          NewEventNotifier(params.broadcasterFunc),
		mergedRulesMap:         make(map[string]map[string]MergedRuleEntry),
		manageConfigMaps:       params.ManageConfigMaps,
		hubMode:                params.HubMode,
		manageIngress:          params.ManageIngress,
		manageIngressClassOnly: params.ManageIngressClassOnly,
		ingressClass:           params.IngressClass,
		rsrcSSLCtxt:            make(map[string]*v1.Secret),
		trustedCertsCfgmap:     params.TrustedCertsCfgmap,
		intF5Res:               make(map[string]InternalF5Resources),
		dgPath:                 params.DgPath,
		agRspChan:              params.AgRspChan,
		processAgentLabels:     params.ProcessAgentLabels,
		agentCfgMap:            make(map[string]*AgentCfgMap),
		agentCfgMapSvcCache:    make(map[string]*SvcEndPointsCache),
		defaultRouteDomain:     params.DefaultRouteDomain,
		poolMemberType:         params.PoolMemberType,
		AgentName:              params.Agent,
		vxlanName:              params.VXLANName,
		vxlanMode:              params.VXLANMode,
		ciliumTunnelName:       params.CiliumTunnelName,
		eventChan:              params.EventChan,
		configWriter:           params.ConfigWriter,
		staticRoutingMode:      params.StaticRoutingMode,
		orchestrationCNI:       params.OrchestrationCNI,
		staticRouteNodeCIDR:    params.StaticRouteNodeCIDR,
		membersToDisable:       make(map[string]map[string]struct{}),
		BigIPURL:               params.BigIPURL,
	}
	if params.PodGracefulShutdown {
		manager.podSvcCache = PodSvcCache{
			podDetails:  &sync.Map{},
			svcPodCache: &sync.Map{},
		}
	}
	manager.processedResources = make(map[string]bool)
	manager.processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
	manager.nplStore = make(map[string]NPLAnnoations)
	// Initialize agent response worker
	go manager.agentResponseWorker()

	if nil != manager.kubeClient && nil == manager.restClientv1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.restClientv1 = manager.kubeClient.CoreV1().RESTClient()
	}
	if nil != manager.kubeClient && nil == manager.restClientv1beta1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.restClientv1beta1 = manager.kubeClient.ExtensionsV1beta1().RESTClient()
	}
	if nil != manager.kubeClient && nil == manager.netClientv1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.netClientv1 = manager.kubeClient.NetworkingV1().RESTClient()
	}
	return &manager
}

func (appMgr *Manager) watchingAllNamespacesLocked() bool {
	if 0 == len(appMgr.appInformers) {
		// Not watching any namespaces.
		return false
	}
	_, watchingAll := appMgr.appInformers[""]
	return watchingAll
}

func (appMgr *Manager) AddNamespace(
	namespace string,
	cfgMapSelector labels.Selector,
	resyncPeriod time.Duration,
) error {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	_, err := appMgr.addNamespaceLocked(namespace, cfgMapSelector, resyncPeriod)
	return err
}

func (appMgr *Manager) addNamespaceLocked(
	namespace string,
	cfgMapSelector labels.Selector,
	resyncPeriod time.Duration,
) (*appInformer, error) {
	// Check if watching all namespaces by checking all appInformers is created for "" namespace
	if appMgr.watchingAllNamespacesLocked() {
		return nil, fmt.Errorf(
			"Cannot add additional namespaces when already watching all.")
	}
	if len(appMgr.appInformers) > 0 && "" == namespace {
		return nil, fmt.Errorf(
			"Cannot watch all namespaces when already watching specific ones.")
	}
	var appInf *appInformer
	var found bool
	if appInf, found = appMgr.appInformers[namespace]; found {
		return appInf, nil
	}
	appInf = appMgr.newAppInformer(namespace, cfgMapSelector, resyncPeriod)
	appMgr.appInformers[namespace] = appInf
	return appInf, nil
}

func (appMgr *Manager) removeNamespace(namespace string) error {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	err := appMgr.removeNamespaceLocked(namespace)
	return err
}

func (appMgr *Manager) removeNamespaceLocked(namespace string) error {
	if _, found := appMgr.appInformers[namespace]; !found {
		return fmt.Errorf("No informers exist for namespace %v\n", namespace)
	}
	delete(appMgr.appInformers, namespace)
	return nil
}

// AddNodeInformer to watch the node udpates
func (appMgr *Manager) AddNodeInformer(resyncPeriod time.Duration) error {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()

	nodeOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = appMgr.nodeLabelSelector
	}
	appMgr.nodeInformer = &nodeInformer{
		stopCh: make(chan struct{}),
		nodeInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				"nodes",
				"",
				nodeOptions,
			),
			&v1.Node{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}
	appMgr.nodeInformer.nodeInformer.AddEventHandler(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.setupNodeProcessing() },
			UpdateFunc: func(obj, cur interface{}) { appMgr.setupNodeProcessing() },
			DeleteFunc: func(obj interface{}) { appMgr.setupNodeProcessing() },
		},
	)
	return nil
}

// AddNamespaceLabelInformer spins an informer to watch all namespaces with matching label
func (appMgr *Manager) AddNamespaceLabelInformer(
	labelSelector labels.Selector,
	resyncPeriod time.Duration,
) error {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	if nil != appMgr.nsInformer {
		return fmt.Errorf("Already have a namespace label informer added.")
	}
	if 0 != len(appMgr.appInformers) {
		return fmt.Errorf("Cannot set a namespace label informer when informers " +
			"have been setup for one or more namespaces.")
	}
	optionsModifier := func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
	appMgr.nsInformer = cache.NewSharedIndexInformer(
		cache.NewFilteredListWatchFromClient(
			appMgr.restClientv1,
			Namespaces,
			"",
			optionsModifier,
		),
		&v1.Namespace{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	appMgr.nsInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueNamespace(obj) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueNamespace(cur) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueNamespace(obj) },
		},
		resyncPeriod,
	)

	return nil
}

func (appMgr *Manager) enqueueNamespace(obj interface{}) {
	ns := obj.(*v1.Namespace)
	if !appMgr.DynamicNS && !appMgr.watchingAllNamespacesLocked() {
		if _, ok := appMgr.getNamespaceInformer(ns.Name); !ok {
			return
		}
	}

	appMgr.nsQueue.Add(ns.ObjectMeta.Name)
}

func (appMgr *Manager) namespaceWorker() {
	for appMgr.processNextNamespace() {
	}
}

func (appMgr *Manager) processNextNamespace() bool {
	key, quit := appMgr.nsQueue.Get()
	if quit {
		return false
	}
	defer appMgr.nsQueue.Done(key)

	err := appMgr.syncNamespace(key.(string))
	if err == nil {
		appMgr.nsQueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
	appMgr.nsQueue.AddRateLimited(key)

	return true
}

func (appMgr *Manager) triggerSyncResources(ns string, inf *appInformer) {
	enqueueSvcFromNamespace := func(namespace string, appInf *appInformer) {
		objs, err := appInf.svcInformer.GetIndexer().ByIndex("namespace", namespace)
		if err != nil {
			log.Errorf("[CORE] Unable to fetch services from namespace: %v for periodic resync", namespace)
			return
		}
		if objs != nil && len(objs) > 0 {
			svc := objs[0].(*v1.Service)
			svcKey := serviceQueueKey{
				Namespace:    namespace,
				ServiceName:  svc.Name,
				ResourceKind: Services,
				ResourceName: svc.Name,
				Operation:    OprTypeUpdate,
			}
			log.Debugf("[CORE] Periodic enqueue of Service from Namespace: %v, svc: %s", namespace, svc.Name)
			appMgr.vsQueue.Add(svcKey)
		}
	}

	if appMgr.watchingAllNamespacesLocked() {
		namespaces := appMgr.GetWatchedNamespacesLockless()

		if len(namespaces) == 1 && namespaces[0] == "" {
			if appMgr.nsInformer == nil {
				return
			}
			nsps := appMgr.nsInformer.GetIndexer().List()
			namespaces = []string{}
			for _, ns := range nsps {
				namespaces = append(namespaces, ns.(*v1.Namespace).Name)
			}
		}

		for _, ns := range namespaces {
			if inf, ok := appMgr.getNamespaceInformerLocked(ns); ok {
				enqueueSvcFromNamespace(ns, inf)
			}
		}
	} else {
		enqueueSvcFromNamespace(ns, inf)
	}
}

func (appMgr *Manager) syncNamespace(nsName string) error {
	startTime := time.Now()
	var err error
	defer func() {
		endTime := time.Now()
		log.Debugf("[CORE] Finished syncing namespace %+v (%v)",
			nsName, endTime.Sub(startTime))
	}()
	_, exists, err := appMgr.nsInformer.GetIndexer().GetByKey(nsName)
	if nil != err {
		log.Warningf("[CORE] Error looking up namespace '%v': %v\n", nsName, err)
		return err
	}

	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	appInf, found := appMgr.getNamespaceInformerLocked(nsName)
	if exists && found {
		appMgr.triggerSyncResources(nsName, appInf)
		return nil
	}
	// Skip deleting informers if watching specific namespaces
	if !appMgr.DynamicNS {
		return nil
	}
	if exists {
		// exists but not found in informers map, add
		cfgMapSelector, err := labels.Parse(DefaultConfigMapLabel)
		if err != nil {
			return fmt.Errorf("Failed to parse Label Selector string: %v", err)
		}
		appInf, err = appMgr.addNamespaceLocked(nsName, cfgMapSelector, 0)
		if err != nil {
			return fmt.Errorf("Failed to add informers for namespace %v: %v",
				nsName, err)
		}
		appInf.start()
		appInf.waitForCacheSync()
	} else {
		// does not exist but found in informers map, delete
		// Clean up all resources that reference a removed namespace
		appInf.stopInformers()
		appMgr.removeNamespaceLocked(nsName)
		appMgr.eventNotifier.DeleteNotifierForNamespace(nsName)
		appMgr.resources.Lock()
		rsDeleted := 0
		appMgr.resources.ForEach(func(key ServiceKey, cfg *ResourceConfig) {
			if key.Namespace == nsName {
				if appMgr.resources.Delete(key, NameRef{}) {
					rsDeleted += 1
				}
			}
		})
		appMgr.resources.Unlock()
		// Handle Agent Specific ConfigMaps
		if appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap) {
			for _, cm := range appMgr.agentCfgMap {
				if cm.Namespace == nsName {
					cm.Operation = OprTypeDelete
					rsDeleted += 1
				}
			}
		}
		if rsDeleted > 0 {
			log.Warningf("[CORE] Error looking up namespace '%v': %v\n", nsName, err)
			appMgr.deployResource()
		}
	}

	return nil
}

func (appMgr *Manager) GetWatchedNamespaces() []string {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	return appMgr.GetWatchedNamespacesLockless()
}

func (appMgr *Manager) GetWatchedNamespacesLockless() []string {
	var namespaces []string
	for k, _ := range appMgr.appInformers {
		namespaces = append(namespaces, k)
	}
	return namespaces
}
func (appMgr *Manager) GetNamespaceLabelInformer() cache.SharedIndexInformer {
	return appMgr.nsInformer
}

type serviceQueueKey struct {
	Namespace    string
	ServiceName  string
	ResourceKind string
	ResourceName string
	Operation    string
	Object       interface{}
}

type nodeInformer struct {
	nodeInformer cache.SharedIndexInformer
	stopCh       chan struct{}
}

type appInformer struct {
	namespace                 string
	cfgMapInformer            cache.SharedIndexInformer
	svcInformer               cache.SharedIndexInformer
	endptInformer             cache.SharedIndexInformer
	ingInformer               cache.SharedIndexInformer
	routeInformer             cache.SharedIndexInformer
	secretInformer            cache.SharedIndexInformer
	ingClassInformer          cache.SharedIndexInformer
	podInformer               cache.SharedIndexInformer
	deploymentInformer        cache.SharedIndexInformer
	stopCh                    chan struct{}
	stopChDisableMemInformers chan struct{}
}

func (appMgr *Manager) newAppInformer(
	namespace string,
	cfgMapSelector labels.Selector,
	resyncPeriod time.Duration,
) *appInformer {
	log.Debugf("[CORE] Creating new app informer")
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	appInf := appInformer{
		namespace:                 namespace,
		stopCh:                    make(chan struct{}),
		stopChDisableMemInformers: make(chan struct{}),
		svcInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				Services,
				namespace,
				everything,
			),
			&v1.Service{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		secretInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				Secrets,
				namespace,
				everything,
			),
			&v1.Secret{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}
	//enable podinformer for nodeport local and pod graceful shutdown
	if appMgr.poolMemberType == NodePortLocal || (appMgr.podSvcCache.svcPodCache != nil && appMgr.podSvcCache.podDetails != nil) {
		appInf.podInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				"pods",
				namespace,
				everything,
			),
			&v1.Pod{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}

	//For nodeport mode, disable ep informer
	if appMgr.poolMemberType != NodePort {
		appInf.endptInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				Endpoints,
				namespace,
				everything,
			),
			&v1.Endpoints{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}
	if true == appMgr.manageIngress {
		log.Infof("[CORE] Watching Ingress resources.")
		appInf.ingInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.netClientv1,
				Ingresses,
				namespace,
				everything,
			),
			&netv1.Ingress{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
		appInf.ingClassInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.netClientv1,
				IngressClasses,
				"",
				everything,
			),
			&netv1.IngressClass{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)

	} else {
		log.Infof("[CORE] Not watching Ingress resources.")
	}

	if false != appMgr.manageConfigMaps {
		appMgr.configMapLabel = cfgMapSelector.String()
		cfgMapOptions := func(options *metav1.ListOptions) {
			options.LabelSelector = appMgr.configMapLabel
		}
		log.Infof("[CORE] Watching ConfigMap resources.")
		appInf.cfgMapInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				Configmaps,
				namespace,
				cfgMapOptions,
			),
			&v1.ConfigMap{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	} else {
		log.Infof("[CORE] Not watching ConfigMap resources.")
	}

	if nil != appMgr.routeClientV1 {
		// Ensure the default server cert is loaded
		appMgr.loadDefaultCert()
		appInf.routeInformer = cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					options.LabelSelector = appMgr.routeConfig.RouteLabel
					return appMgr.routeClientV1.Routes(namespace).List(context.TODO(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					options.LabelSelector = appMgr.routeConfig.RouteLabel
					return appMgr.routeClientV1.Routes(namespace).Watch(context.TODO(), options)
				},
			},
			&routeapi.Route{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}

	if false != appMgr.manageConfigMaps {
		log.Infof("[CORE] Handling ConfigMap resource events.")
		appInf.cfgMapInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) { appMgr.enqueueConfigMap(obj, OprTypeCreate) },
				UpdateFunc: func(old, cur interface{}) {
					if appMgr.hubMode || !reflect.DeepEqual(old, cur) {
						appMgr.enqueueConfigMap(cur, OprTypeUpdate)
					}
				},
				DeleteFunc: func(obj interface{}) { appMgr.enqueueConfigMap(obj, OprTypeDelete) },
			},
			resyncPeriod,
		)
	} else {
		log.Infof("[CORE] Not handling ConfigMap resource events.")
	}

	appInf.svcInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueService(obj, OprTypeCreate) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueService(cur, OprTypeUpdate) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueService(obj, OprTypeDelete) },
		},
		resyncPeriod,
	)
	if appInf.endptInformer != nil {
		appInf.endptInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { appMgr.enqueueEndpoints(obj, OprTypeCreate) },
				UpdateFunc: func(old, cur interface{}) { appMgr.enqueueEndpointsUpdate(old, cur, OprTypeUpdate) },
				DeleteFunc: func(obj interface{}) { appMgr.enqueueEndpoints(obj, OprTypeDelete) },
			},
			resyncPeriod,
		)
	}
	appInf.secretInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			// Making all operation types as update because each change in secret will update the ingress/configmap
			AddFunc:    func(obj interface{}) { appMgr.enqueueSecrets(obj, OprTypeUpdate) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueSecrets(cur, OprTypeUpdate) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueSecrets(obj, OprTypeUpdate) },
		},
		resyncPeriod,
	)
	if appInf.podInformer != nil {
		appInf.podInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { appMgr.enqueuePod(obj, OprTypeCreate) },
				UpdateFunc: func(obj, cur interface{}) { appMgr.enqueuePod(cur, OprTypeUpdate) },
				DeleteFunc: func(obj interface{}) { appMgr.enqueuePod(obj, OprTypeDelete) },
			},
		)
	}

	if true == appMgr.manageIngress {
		log.Infof("[CORE] Handling Ingress resource events.")
		appInf.ingInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeCreate) },
				UpdateFunc: func(old, cur interface{}) { appMgr.enqueueIngressUpdate(cur, old, OprTypeUpdate) },
				DeleteFunc: func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeDelete) },
			},
			resyncPeriod,
		)
		appInf.ingClassInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				//AddFunc:    func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeCreate) },
				//UpdateFunc: func(old, cur interface{}) { appMgr.enqueueIngress(cur, OprTypeUpdate) },
				//DeleteFunc: func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeDelete) },
			},
			resyncPeriod,
		)
	} else {
		log.Infof("[CORE] Not handling Ingress resource events.")
	}

	if nil != appMgr.routeClientV1 {
		appInf.routeInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) { appMgr.enqueueRoute(obj, OprTypeCreate) },
				UpdateFunc: func(old, cur interface{}) {
					oldrt := old.(*routeapi.Route)
					newrt := cur.(*routeapi.Route)

					if reflect.DeepEqual(oldrt.Spec, newrt.Spec) {
						return
					}
					appMgr.enqueueRoute(cur, OprTypeUpdate)
				},
				DeleteFunc: func(obj interface{}) { appMgr.enqueueRoute(obj, OprTypeDelete) },
			},
			resyncPeriod,
		)
	}

	return &appInf
}

func (appMgr *Manager) enqueueConfigMap(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidConfigMap(obj, operation); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueueService(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidService(obj); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}
}

// enqueue endpoint wil be called in three cases
// 1. When endpoint is created
// 2. When endpoints are scaled down, in case of pod-graceful-shutdown is enabled
// 3 When endpoint is deleted
func (appMgr *Manager) enqueueEndpoints(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidEndpoints(obj, operation); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}
}

// enqueueEndpointsUpdate will be called when endpoints are updated
// 1. When endpoints are scaled up, it will just enqueue to the queue
// 2. When pod-graceful-shutdown is enabled, it will check if the endpoints are scaled down
func (appMgr *Manager) enqueueEndpointsUpdate(old, cur interface{}, operation string) {
	oldep := old.(*v1.Endpoints)
	newep := cur.(*v1.Endpoints)
	if reflect.DeepEqual(oldep.Subsets, newep.Subsets) {
		return
	}
	if appMgr.podSvcCache.svcPodCache != nil && appMgr.podSvcCache.podDetails != nil {
		if len(oldep.Subsets) == 0 || len(newep.Subsets) == 0 {
			operation = OprTypeDisable
		} else if len(oldep.Subsets[0].Addresses) > len(newep.Subsets[0].Addresses) {
			// we are considering index 0 by assuming all the endpoints will have same addresses even though the ports are different
			operation = OprTypeDisable
		}
	}

	if ok, keys := appMgr.checkValidEndpoints(newep, operation); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueuePod(obj interface{}, operation string) {
	// only enqueue pod for nodeport local
	// don't enqueue pod for pod-graceful-shutdown as it will be handled by endpoints
	if appMgr.poolMemberType == NodePortLocal {
		if ok, keys := appMgr.checkValidPod(obj, operation); ok {
			for _, key := range keys {
				key.Operation = operation
				appMgr.vsQueue.Add(*key)
			}
		}
	}
}

func (appMgr *Manager) enqueueSecrets(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidSecrets(obj); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}

}

func (appMgr *Manager) enqueueIngress(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidIngress(obj); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) handleIngressUpdate(
	cur, old interface{},
) (bool, []*serviceQueueKey) {
	var validIngress bool
	var keys []*serviceQueueKey
	oldIngress := old.(*netv1.Ingress)
	curIngress := cur.(*netv1.Ingress)
	if fetchVSDeletionStatus(curIngress.ObjectMeta.Annotations, oldIngress.ObjectMeta.Annotations) {
		appMgr.removeOldVIngressObjects(oldIngress)
	}
	validIngress, keys = appMgr.checkV1Ingress(curIngress)
	return validIngress, keys
}

func (appMgr *Manager) enqueueIngressUpdate(cur, old interface{}, operation string) {
	if ok, keys := appMgr.handleIngressUpdate(cur, old); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueueRoute(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidRoute(obj); ok {
		for _, key := range keys {
			key.Operation = operation
			if operation == OprTypeDelete {
				key.Object = obj
			}
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) getNamespaceInformer(
	ns string,
) (*appInformer, bool) {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	appInf, found := appMgr.getNamespaceInformerLocked(ns)
	return appInf, found
}

func (appMgr *Manager) getNamespaceInformerLocked(
	ns string,
) (*appInformer, bool) {
	toFind := ns
	if appMgr.watchingAllNamespacesLocked() {
		toFind = ""
	}
	appInf, found := appMgr.appInformers[toFind]
	return appInf, found
}

func (appInf *appInformer) start() {
	if nil != appInf.svcInformer {
		go appInf.svcInformer.Run(appInf.stopCh)
	}
	if nil != appInf.endptInformer {
		go appInf.endptInformer.Run(appInf.stopCh)
	}
	if nil != appInf.secretInformer {
		go appInf.secretInformer.Run(appInf.stopCh)
	}
	if nil != appInf.ingInformer {
		go appInf.ingInformer.Run(appInf.stopCh)
	}
	if nil != appInf.routeInformer {
		go appInf.routeInformer.Run(appInf.stopCh)
	}
	if nil != appInf.cfgMapInformer {
		go appInf.cfgMapInformer.Run(appInf.stopCh)
	}
	if nil != appInf.ingClassInformer {
		go appInf.ingClassInformer.Run(appInf.stopCh)
	}
	if nil != appInf.podInformer {
		go appInf.podInformer.Run(appInf.stopCh)
	}
}

func (appInf *appInformer) waitForCacheSync() {
	cacheSyncs := []cache.InformerSynced{}

	if nil != appInf.svcInformer {
		cacheSyncs = append(cacheSyncs, appInf.svcInformer.HasSynced)
	}
	if nil != appInf.endptInformer {
		cacheSyncs = append(cacheSyncs, appInf.endptInformer.HasSynced)
	}
	if nil != appInf.secretInformer {
		cacheSyncs = append(cacheSyncs, appInf.secretInformer.HasSynced)
	}
	if nil != appInf.ingInformer {
		cacheSyncs = append(cacheSyncs, appInf.ingInformer.HasSynced)
	}
	if nil != appInf.routeInformer {
		cacheSyncs = append(cacheSyncs, appInf.routeInformer.HasSynced)
	}
	if nil != appInf.cfgMapInformer {
		cacheSyncs = append(cacheSyncs, appInf.cfgMapInformer.HasSynced)
	}
	if nil != appInf.ingClassInformer {
		cacheSyncs = append(cacheSyncs, appInf.ingClassInformer.HasSynced)
	}
	if nil != appInf.podInformer {
		cacheSyncs = append(cacheSyncs, appInf.podInformer.HasSynced)
	}
	cache.WaitForCacheSync(
		appInf.stopCh,
		cacheSyncs...,
	)
}

func (appInf *appInformer) stopInformers() {
	close(appInf.stopCh)
	// Deployment and pod(not always) informers are created separated so they need to be stoped as well
	close(appInf.stopChDisableMemInformers)
}

func (appMgr *Manager) IsNodePort() bool {
	return appMgr.isNodePort
}

func (appMgr *Manager) UseNodeInternal() bool {
	return appMgr.useNodeInternal
}

func (appMgr *Manager) Run(stopCh <-chan struct{}) {
	go appMgr.runImpl(stopCh)
	go appMgr.setOtherSDNType()
}

func (appMgr *Manager) runImpl(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer appMgr.vsQueue.ShutDown()
	defer appMgr.nsQueue.ShutDown()
	// start and sync node informer.
	appMgr.startAndSyncNodeInformer()
	if nil != appMgr.nsInformer {
		// Using one worker for namespace label changes.
		appMgr.startAndSyncNamespaceInformer(stopCh)
		go wait.Until(appMgr.namespaceWorker, time.Second, stopCh)
	}
	// start and sync App informer
	appMgr.startAndSyncAppInformers()

	// Using only one virtual server worker currently.
	go wait.Until(appMgr.virtualServerWorker, time.Second, stopCh)

	<-stopCh
	appMgr.stopAppInformers()
	close(appMgr.nodeInformer.stopCh)
}

func (appMgr *Manager) startAndSyncNodeInformer() {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	go appMgr.nodeInformer.nodeInformer.Run(appMgr.nodeInformer.stopCh)
	cache.WaitForCacheSync(appMgr.nodeInformer.stopCh, appMgr.nodeInformer.nodeInformer.HasSynced)
}

func (appMgr *Manager) startAndSyncNamespaceInformer(stopCh <-chan struct{}) {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	go appMgr.nsInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, appMgr.nsInformer.HasSynced)
}

func (appMgr *Manager) startAndSyncAppInformers() {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	appMgr.startAppInformersLocked()
	appMgr.waitForCacheSyncLocked()
}

func (appMgr *Manager) startAppInformersLocked() {
	for _, appInf := range appMgr.appInformers {
		appInf.start()
	}
}

func (appMgr *Manager) waitForCacheSync() {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	appMgr.waitForCacheSyncLocked()
}

func (appMgr *Manager) waitForCacheSyncLocked() {
	for _, appInf := range appMgr.appInformers {
		appInf.waitForCacheSync()
	}
}

func (appMgr *Manager) stopAppInformers() {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	for _, appInf := range appMgr.appInformers {
		appInf.stopInformers()
	}
}

func (appMgr *Manager) virtualServerWorker() {
	for appMgr.processNextVirtualServer() {
	}
}

// Get all Namespaces being watched based on Namespaces provided, Namespace Label or all
func (appMgr *Manager) GetAllWatchedNamespaces() []string {
	var namespaces []string
	switch {
	case len(appMgr.WatchedNS.Namespaces) != 0:
		namespaces = appMgr.WatchedNS.Namespaces
	case len(appMgr.WatchedNS.NamespaceLabel) != 0:
		NsLabel, _ := createLabel(appMgr.WatchedNS.NamespaceLabel)
		nsL, err := listerscorev1.NewNamespaceLister(appMgr.nsInformer.GetIndexer()).List(NsLabel)
		if err != nil {
			log.Errorf("[CORE] Error getting Namespaces with Namespace label - %v.", err)
		}
		for _, v := range nsL {
			namespaces = append(namespaces, v.Name)
		}
	default:
		namespaces = append(namespaces, "")
	}
	return namespaces
}

// Get the length of queue
func (appMgr *Manager) getQueueLength() int {
	qLen := 0
	for _, ns := range appMgr.GetAllWatchedNamespaces() {
		var services []interface{}
		var err error
		var appInf *appInformer
		var found bool
		if appInf, found = appMgr.getNamespaceInformer(ns); !found {
			continue
		}
		if ns == "" {
			services = appInf.svcInformer.GetIndexer().List()
		} else {
			services, err = appInf.svcInformer.GetIndexer().ByIndex("namespace", ns)
		}
		if err != nil {
			continue
		}
		for _, obj := range services {
			svc := obj.(*v1.Service)
			if ok, _ := appMgr.checkValidService(svc); ok {
				qLen++
			}
		}
		if false != appMgr.manageConfigMaps {
			//Get cms using informers*/
			cmLister := listerscorev1.NewConfigMapLister(appInf.cfgMapInformer.GetIndexer())
			ls, _ := createLabel(appMgr.configMapLabel)
			cms, err := cmLister.ConfigMaps(ns).List(ls)
			if err != nil {
				continue
			}
			for _, cm := range cms {
				if ok, _ := appMgr.checkValidConfigMap(cm, OprTypeCreate); ok {
					qLen++
				}
			}
		}
		if nil != appMgr.routeClientV1 {
			//get routes from informers
			rs, _ := createLabel(appMgr.routeConfig.RouteLabel)
			rts, err := listersroutev1.NewRouteLister(appInf.routeInformer.GetIndexer()).Routes(ns).List(rs)
			if err != nil {
				continue
			}
			for _, rt := range rts {
				if ok, _ := appMgr.checkValidRoute(rt); ok {
					qLen++
				}
			}
		}
	}
	return qLen
}

// isNonPerfResource returns true if the resource gets processed according to old low performing algorithm
func isNonPerfResource(resKind string) bool {

	switch resKind {
	case Services, Configmaps, Routes:
		// Configmaps and Routes get processed according to low performing algorithm
		// But, Service must be processed everytime
		return true
	case Ingresses, Endpoints:
		// Ingresses get processed according to new high performance algorithm
		// Endpoints are out of equation, during initial state never gets processed
		return false
	}

	// Unknown resources are to be considered as non-performing
	return true
}

func (appMgr *Manager) processNextVirtualServer() bool {
	key, quit := appMgr.vsQueue.Get()
	if !appMgr.steadyState && appMgr.processedItems == 0 {
		if len(appMgr.oldNodes) == 0 {
			// update node cache on init
			nodesList, _ := appMgr.kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: appMgr.nodeLabelSelector})
			nodes, _ := appMgr.getNodes(nodesList.Items)
			appMgr.oldNodes = nodes
		}
		appMgr.queueLen = appMgr.getQueueLength()
	}
	if quit {
		// The controller is shutting down.
		return false
	}

	defer appMgr.vsQueue.Done(key)
	skey := key.(serviceQueueKey)
	if !appMgr.steadyState && !isNonPerfResource(skey.ResourceKind) {
		if skey.Operation != OprTypeCreate {
			appMgr.vsQueue.AddRateLimited(key)
		}
		appMgr.vsQueue.Forget(key)
		return true
	}

	if !appMgr.steadyState && skey.Operation != OprTypeCreate {
		appMgr.vsQueue.AddRateLimited(key)
		appMgr.vsQueue.Forget(key)
		return true
	}

	err := appMgr.syncVirtualServer(skey)
	if err == nil {
		if !appMgr.steadyState {
			appMgr.processedItems++
		}
		appMgr.vsQueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
	appMgr.vsQueue.AddRateLimited(key)

	return true
}

func (s *vsSyncStats) isStatsAvailable() bool {
	switch {
	case s.vsUpdated > 0,
		s.vsDeleted > 0,
		s.cpUpdated > 0,
		s.dgUpdated > 0,
		s.poolsUpdated > 0:
		return true
	}

	return false
}

type vsSyncStats struct {
	vsFound      int
	vsUpdated    int
	vsDeleted    int
	cpUpdated    int
	dgUpdated    int
	poolsUpdated int
}

func (appMgr *Manager) syncVirtualServer(sKey serviceQueueKey) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		// processedItems with +1 because that is the actual number of items processed
		// and it gets incremented just after this function returns
		log.Debugf("[CORE] Finished syncing virtual servers with service %+v in namespace %+v (%v), processed VS %v out of %v",
			sKey.ServiceName, sKey.Namespace, endTime.Sub(startTime), appMgr.processedItems+1, appMgr.queueLen)
	}()
	// Get the informers for the namespace. This will tell us if we care about
	// this item.
	appInf, haveNamespace := appMgr.getNamespaceInformer(sKey.Namespace)
	if !haveNamespace {
		// This shouldn't happen as the namespace is checked for every item before
		// it is added to the queue, but issue a warning if it does.
		log.Warningf(
			"Received an update for an item from an un-watched namespace %v",
			sKey.Namespace)
		return nil
	}

	// Lookup the service
	svcKey := sKey.Namespace + "/" + sKey.ServiceName
	obj, svcFound, err := appInf.svcInformer.GetIndexer().GetByKey(svcKey)
	if nil != err {
		// Returning non-nil err will re-queue this item with rate-limiting.
		log.Warningf("[CORE] Error looking up service '%v': %v\n", svcKey, err)
		return err
	}

	// Processing just one service from a namespace processes all the resources in that namespace
	switch sKey.ResourceKind {
	case Services:
		rkey := Services + "_" + sKey.Namespace
		if !appMgr.steadyState && sKey.Operation == OprTypeCreate {
			if _, ok := appMgr.processedResources[rkey]; ok {
				if !appMgr.steadyState && appMgr.processedItems >= appMgr.queueLen-1 {
					appMgr.deployResource()
					appMgr.steadyState = true
				}
				return nil
			}
			appMgr.processedResourcesMutex.Lock()
			appMgr.processedResources[rkey] = true
			appMgr.processedResourcesMutex.Unlock()
		}
	case Endpoints:
		if appMgr.IsNodePort() {
			return nil
		}
	case Configmaps:
		resKey := prepareResourceKey(sKey.ResourceKind, sKey.Namespace, sKey.ResourceName)
		switch sKey.Operation {
		case OprTypeCreate:
			if _, ok := appMgr.processedResources[resKey]; ok {
				if !appMgr.steadyState && appMgr.processedItems >= appMgr.queueLen-1 {
					appMgr.deployResource()
					appMgr.steadyState = true
				}
				return nil
			}
		case OprTypeDelete:
			appMgr.processedResourcesMutex.Lock()
			delete(appMgr.processedResources, resKey)
			appMgr.processedResourcesMutex.Unlock()
		}

	default:
		// Resources other than Services will be tracked if they are processed earlier
		resKey := prepareResourceKey(sKey.ResourceKind, sKey.Namespace, sKey.ResourceName)
		switch sKey.Operation {
		// If a resource is processed earlier and still sKey gives us CREATE event,
		// then it was handled earlier when associated service processed
		// otherwise just mark it as processed and continue
		case OprTypeCreate:
			if processed, ok := appMgr.processedResources[resKey]; ok {
				if processed {
					if !appMgr.steadyState && appMgr.processedItems >= appMgr.queueLen-1 {
						appMgr.deployResource()
						appMgr.steadyState = true
					}
					return nil
				}
			}
			appMgr.processedResourcesMutex.Lock()
			appMgr.processedResources[resKey] = true
			appMgr.processedResourcesMutex.Unlock()
		case OprTypeDelete:
			appMgr.processedResourcesMutex.Lock()
			delete(appMgr.processedResources, resKey)
			appMgr.processedResourcesMutex.Unlock()
		}

	}

	// Use a map to allow ports in the service to be looked up quickly while
	// looping through the ConfigMaps. The value is not currently used.
	svcPortMap := make(map[int32]bool)
	var svc *v1.Service
	if svcFound {
		svc = obj.(*v1.Service)
		for _, portSpec := range svc.Spec.Ports {
			svcPortMap[portSpec.Port] = false
		}
	}

	// rsMap stores all resources currently in Resources matching sKey, indexed by port.
	// At the end of processing, rsMap should only contain configs we want to delete.
	// If we have a valid config, then we remove it from rsMap.
	rsMap := appMgr.getResourcesForKey(sKey)
	dgMap := make(InternalDataGroupMap)

	var stats vsSyncStats
	appMgr.rsrcSSLCtxt = make(map[string]*v1.Secret)
	if nil != appInf.ingInformer {
		err = appMgr.syncIngresses(&stats, sKey, rsMap, svcPortMap, svc, appInf, dgMap)
		if nil != err {
			return err
		}
	}
	if nil != appInf.routeInformer {
		err = appMgr.syncRoutes(&stats, sKey, rsMap, svcPortMap, svc, appInf, dgMap)
		if nil != err {
			return err
		}
	}
	if nil != appInf.cfgMapInformer {
		err = appMgr.syncConfigMaps(&stats, sKey, rsMap, svcPortMap, svc, appInf)
		if nil != err {
			return err
		}
	}
	// Update internal data groups if changed
	appMgr.syncDataGroups(&stats, dgMap, sKey.Namespace)
	// Delete IRules if necessary
	appMgr.syncIRules()

	if len(rsMap) > 0 {
		// We get here when there are ports defined in the service that don't
		// have a corresponding config map.
		stats.vsDeleted += appMgr.deleteUnusedConfigs(sKey, rsMap)
		stats.vsUpdated += appMgr.deleteUnusedResources(sKey, svcFound)

	} else if !svcFound {
		stats.vsUpdated += appMgr.deleteUnusedResources(sKey, svcFound)
	}

	log.Debugf("[CORE] Updated %v of %v virtual server configs, deleted %v",
		stats.vsUpdated, stats.vsFound, stats.vsDeleted)

	// delete any custom profiles that are no longer referenced
	appMgr.deleteUnusedProfiles(appInf, sKey.Namespace, &stats)

	switch {
	case stats.isStatsAvailable(),
		!appMgr.steadyState && appMgr.processedItems >= appMgr.queueLen-1:
		{
			if appMgr.processedItems >= appMgr.queueLen-1 || appMgr.steadyState {
				appMgr.deployResource()
				appMgr.steadyState = true
			}
		}
	}

	return nil
}

func (appMgr *Manager) syncConfigMaps(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
) error {

	// Handle delete cfgMap Operation for Agent
	if appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap) {
		key := sKey.Namespace + "/" + sKey.ResourceName
		if sKey.Operation == OprTypeDelete && sKey.ResourceKind == Configmaps {
			if _, ok := appMgr.agentCfgMap[key]; ok {
				appMgr.agentCfgMap[key].Operation = OprTypeDelete
				stats.vsDeleted += 1
			}
			return nil

		}
		if nil != svc {
			tntLabel, tntOk := svc.ObjectMeta.Labels["cis.f5.com/as3-tenant"]
			appLabel, appOk := svc.ObjectMeta.Labels["cis.f5.com/as3-app"]
			poolLabel, poolOk := svc.ObjectMeta.Labels["cis.f5.com/as3-pool"]

			selector := "cis.f5.com/as3-tenant=" + tntLabel + "," +
				"cis.f5.com/as3-app=" + appLabel + "," +
				"cis.f5.com/as3-pool=" + poolLabel

			key := sKey.Namespace + "/" + sKey.ServiceName

			// A service can be considered as an as3 configmap associated service only when it has these 3 labels
			if tntOk && appOk && poolOk {
				members, _, err := appMgr.getEndpoints(selector, sKey.Namespace, make([]interface{}, 0), false)
				if err != nil {
					return err
				}
				if _, ok := appMgr.agentCfgMapSvcCache[key]; !ok {
					if len(members) != 0 {
						appMgr.agentCfgMapSvcCache[key] = &SvcEndPointsCache{
							members:     members,
							labelString: selector,
						}
						stats.poolsUpdated += 1
					}
				} else {
					sc := &SvcEndPointsCache{
						members:     members,
						labelString: selector,
					}
					if len(sc.members) != len(appMgr.agentCfgMapSvcCache[key].members) || !reflect.DeepEqual(sc, appMgr.agentCfgMapSvcCache[key]) {
						stats.poolsUpdated += 1
						appMgr.agentCfgMapSvcCache[key] = sc
					}
				}
			} else {
				if _, ok := appMgr.agentCfgMapSvcCache[key]; ok {
					stats.poolsUpdated += 1
					delete(appMgr.agentCfgMapSvcCache, key)
				}
			}
		}
	}

	cfgMapsByIndex, err := appInf.cfgMapInformer.GetIndexer().ByIndex(
		"namespace", sKey.Namespace)
	if nil != err {
		log.Warningf("[CORE] Unable to list config maps for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}
	appMgr.TeemData.Lock()
	appMgr.TeemData.ResourceType.Configmaps[sKey.Namespace] = len(cfgMapsByIndex)
	appMgr.TeemData.Unlock()
	// Cleanup the membersToDisable map to make sure old disable members are removed and fresh data is updated
	// Do this only in case of AS3configmap
	if appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap) {
		delete(appMgr.membersToDisable, sKey.Namespace)
	}
	cmWithDisableMembersAnnotn := false // Tracks if any configmap has Disable Members annotation
	for _, obj := range cfgMapsByIndex {
		// We need to look at all config maps in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		cm := obj.(*v1.ConfigMap)

		if cm.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}

		if appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap) {
			//ignore invalid as3 configmaps if found.
			if sKey.Operation != OprTypeDelete {
				err := validateConfigJson(cm.Data["template"])
				if err != nil {
					continue
				}
			}
			// Handle ConfigMap with disableMembers annotation
			var disableMembersAnnotation string // Stores the value of the disable members annotation
			if disableMembers, ok := cm.Annotations[DisableMemberAnnotation]; ok {
				cmWithDisableMembersAnnotn = appMgr.handleDisableMembersAnnotation(disableMembers, cm, sKey)
				disableMembersAnnotation = disableMembers
			}
			if ok := appMgr.processAgentLabels(cm.Labels, cm.Name, cm.Namespace); ok {
				agntCfgMap := new(AgentCfgMap)
				agntCfgMap.Init(cm.Name, cm.Namespace, cm.Data["template"], cm.Labels, disableMembersAnnotation, appMgr.getEndpoints)
				key := cm.Namespace + "/" + cm.Name
				if cfgMap, ok := appMgr.agentCfgMap[key]; ok {
					if appMgr.hubMode || cfgMap.Data != cm.Data["template"] || cm.Labels["as3"] != cfgMap.Label["as3"] || cm.Labels["overrideAS3"] != cfgMap.Label["overrideAS3"] || disableMembersAnnotation != cfgMap.Annotation {
						appMgr.agentCfgMap[key] = agntCfgMap
						stats.vsUpdated += 1
					}

				} else {
					appMgr.agentCfgMap[key] = agntCfgMap
					stats.vsUpdated += 1
				}
				// Mark each resource as it is already processed
				// So that later the create event of the same resource will not processed, unnecessarily
				appMgr.processedResourcesMutex.Lock()
				appMgr.processedResources[prepareResourceKey(Configmaps, sKey.Namespace, cm.Name)] = true
				appMgr.processedResourcesMutex.Unlock()
			}
			continue
		}

		rsCfg, err := ParseConfigMap(cm, appMgr.schemaLocal, appMgr.vsSnatPoolName)
		if nil != err {
			bigIPPrometheus.MonitoredServices.WithLabelValues(cm.ObjectMeta.Namespace, cm.ObjectMeta.Name, "parse-error").Set(1)
			// Ignore this config map for the time being. When the user updates it
			// so that it is valid it will be requeued.
			log.Errorf("[CORE] Error parsing ConfigMap %v_%v",
				cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
			continue
		}

		bigIPPrometheus.MonitoredServices.WithLabelValues(cm.ObjectMeta.Namespace, cm.ObjectMeta.Name, "parse-error").Set(0)

		// Check if SSLProfile(s) are contained in Secrets
		if appMgr.useSecrets {
			for _, profile := range rsCfg.Virtual.Profiles {
				if profile.Context != CustomProfileClient {
					continue
				}
				// Check if profile is contained in a Secret
				appInf, found := appMgr.getNamespaceInformer(cm.ObjectMeta.Namespace)
				if !found {
					log.Debugf("[CORE] No Informer found while fetching secret with name '%s' in namespace '%s'",
						profile.Name, sKey.Namespace)
					return fmt.Errorf("[CORE] No Informer found while fetching secret with name '%s' in namespace '%s'",
						profile.Name, sKey.Namespace)
				}
				obj, found, err := appInf.secretInformer.GetIndexer().GetByKey(
					fmt.Sprintf("%s/%s", cm.ObjectMeta.Namespace, profile.Name))
				if err != nil || !found {
					// No secret, so we assume the profile is a BIG-IP default
					log.Debugf("[CORE] No Secret with name '%s' in namespace '%s', "+
						"parsing secretName as path instead.", profile.Name, sKey.Namespace)
					continue
				}
				secret := obj.(*v1.Secret)
				appMgr.rsrcSSLCtxt[profile.Name] = secret
				err, updated := appMgr.createSecretSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("[CORE] %v", err)
					continue
				}
				if updated {
					stats.cpUpdated += 1
				}
			}
		}

		rsName := rsCfg.GetNameRef()
		ok, found, updated, err := appMgr.handleConfigForType(
			rsCfg, sKey, rsMap, rsName, svcPortMap,
			svc, appInf, []string{}, nil)
		if err != nil {
			return err
		}
		if !ok {
			stats.vsUpdated += updated
			continue
		} else {
			// Mark each resource as it is already processed
			// So that later the create event of the same resource will not be processed, unnecessarily
			appMgr.processedResourcesMutex.Lock()
			appMgr.processedResources[prepareResourceKey(Configmaps, sKey.Namespace, cm.Name)] = true
			appMgr.processedResourcesMutex.Unlock()
			bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, sKey.ServiceName, "parse-error").Set(0)
			stats.vsFound += found
			stats.vsUpdated += updated
		}

		// Set a status annotation to contain the virtualAddress bindAddr
		if rsCfg.MetaData.ResourceType != "iapp" &&
			rsCfg.Virtual.VirtualAddress != nil &&
			rsCfg.Virtual.VirtualAddress.BindAddr != "" {
			appMgr.setBindAddrAnnotation(cm, sKey, rsCfg)
		}
	}
	// Stop that informers those were started to facilitate disable members annotation for Configmap to reduce the overhead if:
	// 1. It's AS3Configmap has disableMembers annotation
	// 2. Current CIS controller in handling the AS3Configmap
	// 3. No AS3Configmap in the namespace has the disable members annotation
	// 4. CIS is running in cluster mode
	if appMgr.AgentCIS.IsImplInAgent(ResourceTypeCfgMap) && sKey.ResourceKind == Configmaps && !cmWithDisableMembersAnnotn &&
		appMgr.poolMemberType == Cluster {
		appInf, ok := appMgr.getNamespaceInformer(sKey.Namespace)
		if ok {
			if appInf.deploymentInformer != nil {
				close(appInf.stopChDisableMemInformers)
				appInf.deploymentInformer = nil
				// stop pod informer only in case it's created to support disableMembers feature
				if appInf.podInformer != nil &&
					(appMgr.podSvcCache.svcPodCache == nil && appMgr.podSvcCache.podDetails == nil) {
					{
						appInf.podInformer = nil
					}
				}
			}
		}
		log.Debug("[CORE] Stopped the additional informers as no Disable Member annotation is provided")
	}
	return nil
}

// handleDisableMembersAnnotation handles the disable memebers annotation specified in the configmap
// 1. Starts the Deployment and Pod informers if not already started
// 2. Parses and Stores the DisableMembers values for further processing
// 3. Returns true if the annotations were handled successfully, else false
func (appMgr *Manager) handleDisableMembersAnnotation(disableMembers string, cm *v1.ConfigMap, sKey serviceQueueKey) bool {
	if cm == nil {
		return false
	}
	appInf, ok := appMgr.getNamespaceInformer(sKey.Namespace)
	if ok {
		// Start pod informer only if it is not started and poolMemberType is Cluster
		if appMgr.poolMemberType == Cluster && appInf.podInformer == nil {
			appInf.podInformer = cache.NewSharedIndexInformer(
				cache.NewFilteredListWatchFromClient(
					appMgr.restClientv1,
					"pods",
					sKey.Namespace,
					func(options *metav1.ListOptions) {
						options.LabelSelector = ""
					},
				),
				&v1.Pod{},
				0,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			)
			appInf.stopChDisableMemInformers = make(chan struct{})
			go appInf.podInformer.Run(appInf.stopChDisableMemInformers)
			if !cache.WaitForCacheSync(appInf.stopChDisableMemInformers, appInf.podInformer.HasSynced) {
				log.Warningf("[CORE] Timed out waiting for Pod informer caches to sync for namespace: %s\n", sKey.Namespace)
			}
			log.Debugf("[CORE] Started Pod informers to facilitate handling of disable pool members for AS3 Configmaps.")
		}

		// Start Deployment informer only if it is not started and poolMemberType is Cluster
		if appMgr.poolMemberType == Cluster && appInf.deploymentInformer == nil {
			appInf.deploymentInformer = cache.NewSharedIndexInformer(
				cache.NewFilteredListWatchFromClient(
					appMgr.kubeClient.AppsV1().RESTClient(),
					"deployments",
					sKey.Namespace,
					func(options *metav1.ListOptions) {
						options.LabelSelector = ""
					},
				),
				&appsv1.Deployment{},
				0,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			)
			appInf.stopChDisableMemInformers = make(chan struct{})
			go appInf.deploymentInformer.Run(appInf.stopChDisableMemInformers)
			if !cache.WaitForCacheSync(appInf.stopChDisableMemInformers, appInf.deploymentInformer.HasSynced) {
				log.Warningf("Timed out waiting for Deployment informer caches to sync for namespace: %s\n", sKey.Namespace)
			}
			log.Debugf("[CORE] Started Deployment informers to facilitate handling of disable pool members for AS3 Configmaps.")
		}
	} else {
		log.Errorf("[CORE] Failed handling Disable member annotations as AppInformers not initialised.")
		return false
	}
	membersToDisable := strings.Split(disableMembers, ",")
	if len(membersToDisable) > 0 && membersToDisable[0] != "" {
		log.Debugf("[CORE] Disable Members: %v read for Configmap: %s/%s", membersToDisable, cm.Namespace, cm.Name)
		for _, deploymentsName := range membersToDisable {
			if _, ok := appMgr.membersToDisable[cm.Namespace]; !ok {
				appMgr.membersToDisable[cm.Namespace] = make(map[string]struct{})
			}
			appMgr.membersToDisable[cm.Namespace][deploymentsName] = struct{}{}
		}
		return true
	} else {
		log.Errorf("[CORE] Error handling disableMembers member annotation for Configmap %s", cm.Name)
	}
	return false
}

func (appMgr *Manager) syncIngresses(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
	dgMap InternalDataGroupMap,
) error {
	ingByIndex, err := appInf.getOrderedIngress(sKey.Namespace)
	if nil != err {
		log.Warningf("[CORE] Unable to list ingresses for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}
	appMgr.TeemData.Lock()
	appMgr.TeemData.ResourceType.Ingresses[sKey.Namespace] = len(ingByIndex)
	appMgr.TeemData.Unlock()
	for _, ing := range ingByIndex {
		// We need to look at all ingresses in the store, parse the data blob,
		// and process ingresses that has changed.
		var partition string
		svcFwdRulesMap := NewServiceFwdRuleMap()
		// TODO: Each ingress resource must be processed for its associated service
		//  only, existing implementation processes all services available in k8s
		//  and this approach degrades the performance of processing Ingress resources
		if ing.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}

		if ok := appMgr.checkV1SingleServivceIngress(ing); !ok {
			continue
		}
		if len(ing.Spec.TLS) > 0 || len(ing.ObjectMeta.Annotations[F5ClientSslProfileAnnotation]) > 0 {
			prepareV1IngressSSLContext(appMgr, ing)
		}
		// Resolve first Ingress Host name (if required)
		_, exists := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]
		if !exists && appMgr.resolveIng != "" {
			appMgr.resolveV1IngressHost(ing, sKey.Namespace)
		}
		// Get partition for ingress
		if p, ok := ing.ObjectMeta.Annotations[F5VsPartitionAnnotation]; ok == true {
			partition = p
		} else {
			partition = DEFAULT_PARTITION
		}
		// Get a list of dependencies removed so their pools can be removed.
		objKey, objDeps := NewObjectDependencies(ing)
		ingressLookupFunc := func(key ObjectDependency) bool {
			if key.Kind != "Ingress" {
				return false
			}
			ingKey := key.Namespace + "/" + key.Name
			_, ingFound, _ := appInf.ingInformer.GetIndexer().GetByKey(ingKey)
			return !ingFound
		}

		depsAdded, depsRemoved := appMgr.resources.UpdateDependencies(
			objKey, objDeps, ingressLookupFunc)
		portStructs := appMgr.v1VirtualPorts(ing)
		for i, portStruct := range portStructs {
			rsCfg, _ := appMgr.createRSConfigFromV1Ingress(
				ing,
				appMgr.resources,
				sKey.Namespace,
				appInf,
				portStruct,
				appMgr.defaultIngIP,
				appMgr.vsSnatPoolName,
			)
			if rsCfg == nil {
				// Currently, an error is returned only if the Ingress is one we
				// do not care about
				continue
			}

			// Handle TLS configuration
			updated := appMgr.handleV1IngressTls(rsCfg, ing, svcFwdRulesMap)
			if updated {
				stats.cpUpdated += 1
			}

			// Handle Ingress health monitors
			rsName := rsCfg.GetNameRef()
			hmStr, found := ing.ObjectMeta.Annotations[HealthMonitorAnnotation]
			if found {
				var monitors AnnotationHealthMonitors
				err := json.Unmarshal([]byte(hmStr), &monitors)
				if err != nil {
					msg := "Unable to parse health monitor JSON array " + hmStr + ": " + err.Error()
					log.Errorf("[CORE] %s", msg)
					appMgr.recordV1IngressEvent(ing, "InvalidData", msg)
				} else {
					if nil != ing.Spec.DefaultBackend {
						var poolPortString string
						if ing.Spec.DefaultBackend.Service.Port.Number != 0 {
							poolPortString = fmt.Sprintf("%d", ing.Spec.DefaultBackend.Service.Port.Number)
						} else if ing.Spec.DefaultBackend.Service.Port.Name != "" {
							poolPortString = ing.Spec.DefaultBackend.Service.Port.Name
						}
						fullPoolName := fmt.Sprintf("/%s/%s", rsCfg.Virtual.Partition,
							FormatIngressPoolName(sKey.Namespace, sKey.ServiceName, ing.ObjectMeta.Name, poolPortString))
						RemoveUnReferredHealthMonitors(rsCfg, fullPoolName, monitors)
						appMgr.handleSingleServiceV1IngressHealthMonitors(fullPoolName, rsCfg, ing, monitors)
					} else {
						appMgr.handleMultiServiceV1IngressHealthMonitors(rsCfg, ing, monitors)
					}
				}
				RemoveUnusedHealthMonitors(rsCfg)
				rsCfg.SortMonitors()
			}
			// Collect all service names on this Ingress.
			// Used in handleConfigForType.
			svcs := getIngressV1Backend(ing)
			// Remove any dependencies no longer used by this Ingress
			for _, dep := range depsRemoved {
				if dep.Kind == ServiceDep {
					cfgChanged, svcKey := rsCfg.RemovePool(
						dep.Namespace, dep.PoolName, appMgr.mergedRulesMap)
					if cfgChanged {
						stats.poolsUpdated++
					}
					if nil != svcKey {
						appMgr.resources.DeleteKeyRef(*svcKey, rsName)
					}
				}
				if dep.Kind == RuleDep {
					for _, pol := range rsCfg.Policies {
						for _, rl := range pol.Rules {
							if rl.FullURI == dep.Name {
								rsCfg.DeleteRuleFromPolicy(pol.Name, rl, appMgr.mergedRulesMap)
							}
						}
					}
				}
				if dep.Kind == URLDep || dep.Kind == AppRootDep {
					var addedRules string
					for _, add := range depsAdded {
						if add.Kind == URLDep || add.Kind == AppRootDep {
							addedRules = add.Name
						}
					}
					removedRules := strings.Split(dep.Name, ",")
					for _, remv := range removedRules {
						if !strings.Contains(addedRules, remv) {
							// Rule has been removed from annotation, delete it
							var found bool
							for _, pol := range rsCfg.Policies {
								for _, rl := range pol.Rules {
									if rl.Name == remv {
										found = true
										rsCfg.DeleteRuleFromPolicy(pol.Name, rl, appMgr.mergedRulesMap)
										break
									}
								}
							}
							if !found { // likely a merged rule
								rsCfg.UnmergeRule(remv, appMgr.mergedRulesMap)
							}
						}
					}
				}
			}
			if ok, found, updated := appMgr.handleConfigForTypeIngress(
				rsCfg, sKey, rsMap, rsName, appInf, svcs, ing); !ok {
				stats.vsUpdated += updated
				continue
			} else {
				stats.vsFound += found
				stats.vsUpdated += updated
				if updated > 0 {
					msg := "Created a ResourceConfig " + rsCfg.GetName() + " for the Ingress."
					appMgr.recordV1IngressEvent(ing, "ResourceConfigured", msg)
				}
			}
			if i < len(portStructs)-1 {
				//ingress ip is same for rscfg even for different port structs.
				//Process only once.
				continue
			}
			// Set the Ingress Status IP address
			appMgr.setV1IngressStatus(ing, rsCfg, appInf)
		}
		// Mark each resource as it is already processed
		// So that later the create event of the same resource will not processed, unnecessarily
		appMgr.processedResourcesMutex.Lock()
		appMgr.processedResources[prepareResourceKey(Ingresses, sKey.Namespace, ing.Name)] = true
		appMgr.processedResourcesMutex.Unlock()

		if len(svcFwdRulesMap) > 0 {
			httpsRedirectDg := NameRef{
				Name:      HttpsRedirectDgName,
				Partition: partition,
			}
			if _, found := dgMap[httpsRedirectDg]; !found {
				dgMap[httpsRedirectDg] = make(DataGroupNamespaceMap)
			}
			svcFwdRulesMap.AddToDataGroup(dgMap[httpsRedirectDg], partition)
		}
	}
	appMgr.HandleTranslateAddress(sKey, stats)

	return nil
}

// HandleTranslateAddress - Sets Address Translate flag for Virtual Server
func (appMgr *Manager) HandleTranslateAddress(sKey serviceQueueKey, stats *vsSyncStats) {
	// Process for all ingress in a namespace
	// Multiple ingress sharing same VS will have below logic applied
	// default is enable. Enable if anyone ingress is having annotation true / no annotation defined across all ingress
	if appMgr.resources.TranslateAddress == nil {
		return
	}
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if vsMap, ok := appMgr.resources.TranslateAddress[sKey.Namespace]; ok {
		for vs, _ := range vsMap {
			if _, ok := appMgr.resources.RsMap[vs]; ok {
				if appMgr.resources.RsMap[vs].Virtual.TranslateServerAddress == "" {
					appMgr.resources.RsMap[vs].Virtual.TranslateServerAddress = "enabled"
				}
				// if set false explicitly
				if !CheckFlag(appMgr.resources.TranslateAddress[sKey.Namespace][vs], "true") &&
					CheckFlag(appMgr.resources.TranslateAddress[sKey.Namespace][vs], "false") {
					if appMgr.resources.RsMap[vs].Virtual.TranslateServerAddress != "disabled" {
						appMgr.resources.RsMap[vs].Virtual.TranslateServerAddress = "disabled"
						stats.vsUpdated += 1
					}
				} else if appMgr.resources.RsMap[vs].Virtual.TranslateServerAddress != "enabled" {
					appMgr.resources.RsMap[vs].Virtual.TranslateServerAddress = "enabled"
					stats.vsUpdated += 1
				}
			}
		}
		// Reset
		delete(appMgr.resources.TranslateAddress, sKey.Namespace)
	}
}

func CheckFlag(list []string, searchString string) bool {
	for _, item := range list {
		if item == searchString {
			return true
		}
	}
	return false
}

func (appMgr *Manager) syncRoutes(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
	dgMap InternalDataGroupMap,
) error {
	if sKey.Operation == OprTypeDelete && sKey.ResourceKind == Routes {
		appMgr.deleteHostPathMapEntry(sKey.Object)
	}
	routeByIndex, err := appInf.getOrderedRoutes(sKey.Namespace)
	if nil != err {
		log.Warningf("[CORE] Unable to list routes for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}
	appMgr.TeemData.Lock()
	appMgr.TeemData.ResourceType.Routes[sKey.Namespace] = len(routeByIndex)
	appMgr.TeemData.Unlock()
	// Rebuild all internal data groups for routes as we process each
	svcFwdRulesMap := NewServiceFwdRuleMap()

	// buffer to hold F5Resources till all routes are processed
	bufferF5Res := InternalF5Resources{}

	for _, route := range routeByIndex {
		if route.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}
		var key string
		if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
			key = route.Spec.Host + "/"
		} else {
			key = route.Spec.Host + route.Spec.Path
		}
		if processedRouteTimestamp, ok := appMgr.processedHostPath.processedHostPathMap[key]; ok {
			rsKey := prepareResourceKey(Routes, route.Namespace, route.Name)
			if processedRouteTimestamp.Before(&route.ObjectMeta.CreationTimestamp) {
				if _, ok := appMgr.processedResources[rsKey]; !ok {
					// Adding the entry for resource so logs does not print repeatedly
					log.Warningf("[CORE]  Route exist with same host: %v and path: %v", route.Spec.Host, route.Spec.Path)
				}
				// Putting the value as false so that route status gets updated
				appMgr.processedResourcesMutex.Lock()
				appMgr.processedResources[rsKey] = false
				appMgr.processedResourcesMutex.Unlock()
				appMgr.resources.RemoveDependency(ObjectDependency{Kind: "Route", Namespace: route.Namespace, Name: route.Name})
				rules := GetRouteAssociatedRuleNames(route)
				for _, ruleName := range rules {
					appMgr.resources.UpdatePolicy(NameRef{Name: appMgr.routeConfig.HttpsVs, Partition: DEFAULT_PARTITION}, SecurePolicyName, ruleName)
					appMgr.resources.UpdatePolicy(NameRef{Name: appMgr.routeConfig.HttpVs, Partition: DEFAULT_PARTITION}, InsecurePolicyName, ruleName)
				}

				message := fmt.Sprintf("Discarding route %v as other route already exposes URI %v%v and is older ", route.Name, route.Spec.Host, route.Spec.Path)
				log.Errorf(message)
				go appMgr.updateRouteAdmitStatus(fmt.Sprintf("%v/%v", route.Namespace, route.Name), "HostAlreadyClaimed", message, v1.ConditionFalse)
				continue
			}
		}
		// Updating the hostPath if route Path is changed
		appMgr.updateHostPathMap(route.ObjectMeta.CreationTimestamp, key)

		//FIXME(kenr): why do we process services that aren't associated
		//             with a route?
		svcName := GetRouteCanonicalServiceName(route)
		if ExistsRouteServiceName(route, sKey.ServiceName) {
			svcName = sKey.ServiceName
		}

		// Collect all service names for this Route.
		svcNames := GetRouteServiceNames(route)

		// Get a list of dependencies removed so their pools can be removed.
		objKey, objDeps := NewObjectDependencies(route)
		routeLookupFunc := func(key ObjectDependency) bool {
			if key.Kind != "Route" {
				return false
			}
			routeKey := key.Namespace + "/" + key.Name
			_, routeFound, _ := appInf.routeInformer.GetIndexer().GetByKey(routeKey)
			return !routeFound
		}
		_, depsRemoved := appMgr.resources.UpdateDependencies(
			objKey, objDeps, routeLookupFunc)

		pStructs := []portStruct{{protocol: "http", port: DEFAULT_HTTP_PORT},
			{protocol: "https", port: DEFAULT_HTTPS_PORT}}
		for _, ps := range pStructs {
			rsCfg, err, pool := appMgr.createRSConfigFromRoute(
				route, svcName, appMgr.resources, appMgr.routeConfig, ps,
				appInf.svcInformer.GetIndexer(), svcFwdRulesMap, appMgr.vsSnatPoolName)
			if err != nil {
				log.Warningf("[CORE] %v", err)
				continue
			}
			rsName := rsCfg.GetNameRef()
			// Handle Route health monitors
			hmStr, exists := route.ObjectMeta.Annotations[HealthMonitorAnnotation]
			if exists {
				var monitors AnnotationHealthMonitors
				err := json.Unmarshal([]byte(hmStr), &monitors)
				if err != nil {
					log.Errorf("[CORE] Unable to parse health monitor JSON array '%v': %v",
						hmStr, err)
				} else {
					appMgr.handleRouteHealthMonitors(pool, rsCfg, monitors, stats)
				}
				rsCfg.SortMonitors()
			}

			// TLS Cert/Key
			if nil != route.Spec.TLS &&
				rsCfg.Virtual.VirtualAddress.Port == DEFAULT_HTTPS_PORT {
				switch route.Spec.TLS.Termination {
				case routeapi.TLSTerminationEdge:
					appMgr.setClientSslProfile(stats, sKey, rsCfg, route)
					serverSsl := "false"
					// Combination of hostName and path are used as key in edge Datagroup.
					// Servername and path from the ssl::payload of clientssl_data Irule event is
					// used as value in edge Datagroup.
					hostName := route.Spec.Host
					path := route.Spec.Path
					sslPath := hostName + path
					sslPath = strings.TrimSuffix(sslPath, "/")
					updateDataGroup(dgMap, EdgeServerSslDgName,
						DEFAULT_PARTITION, sKey.Namespace, sslPath, serverSsl)

				case routeapi.TLSTerminationReencrypt:
					appMgr.setClientSslProfile(stats, sKey, rsCfg, route)
					serverSsl := appMgr.setServerSslProfile(stats, sKey, rsCfg, route)
					// Combination of hostName and path are used as key in reencrypt Datagroup.
					// Servername and path from the ssl::payload of clientssl_data Irule event is
					// used as value in reencrypt Datagroup.
					hostName := route.Spec.Host
					path := route.Spec.Path
					sslPath := hostName + path
					sslPath = strings.TrimSuffix(sslPath, "/")
					if "" != serverSsl {
						updateDataGroup(dgMap, ReencryptServerSslDgName,
							DEFAULT_PARTITION, sKey.Namespace, sslPath, serverSsl)
					}
				}
			}

			// Remove any left over pools/rules from configs no longer used by this Route
			for _, dep := range depsRemoved {
				if dep.Kind == ServiceDep {
					cfgChanged, svcKey := rsCfg.RemovePool(
						dep.Namespace, FormatRoutePoolName(dep.Namespace, dep.Name), appMgr.mergedRulesMap)
					if cfgChanged {
						stats.poolsUpdated++
					}
					if nil != svcKey {
						appMgr.resources.DeleteKeyRef(*svcKey, rsName)
					}
				}
				if dep.Kind == RuleDep {
					for _, pol := range rsCfg.Policies {
						var toRemove []*Rule
						for _, rl := range pol.Rules {
							if rl.FullURI == dep.Name {
								toRemove = append(toRemove, rl)
								// Delete profile (route only)
								if rsCfg.MetaData.ResourceType == "route" {
									resourceName := strings.Split(rl.Name, "_")[3]
									rsCfg.DeleteRouteProfile(dep.Namespace, resourceName)
								}
							}
						}
						for _, rl := range toRemove {
							rsCfg.DeleteRuleFromPolicy(pol.Name, rl, appMgr.mergedRulesMap)
						}
					}
				}
				if dep.Kind == URLDep || dep.Kind == AppRootDep {
					for _, pol := range rsCfg.Policies {
						var toRemove []*Rule
						for _, rl := range pol.Rules {
							if strings.Contains(dep.Name, rl.Name) {
								toRemove = append(toRemove, rl)
							}
						}
						for _, rl := range toRemove {
							rsCfg.DeleteRuleFromPolicy(pol.Name, rl, appMgr.mergedRulesMap)
						}
					}
				}
				if dep.Kind == WhitelistDep {
					rsCfg.DeleteWhitelistCondition()
				}
			}
			// Sort the rules
			for _, pol := range rsCfg.Policies {
				sort.Sort(sort.Reverse(&pol.Rules))
				rsCfg.SetPolicy(pol)
			}

			ok, found, updated, _ := appMgr.handleConfigForType(
				rsCfg, sKey, rsMap, rsName, svcPortMap,
				svc, appInf, svcNames, nil)
			if ok {
				// pool found && service matched we can confirm endpoints are also processed for route
				// Mark each resource  as it is already processed during init Time
				// So that later the create event of the same resource will not processed, unnecessarily
				appMgr.processedResourcesMutex.Lock()
				appMgr.processedResources[prepareResourceKey(Routes, sKey.Namespace, route.Name)] = true
				appMgr.processedResourcesMutex.Unlock()
			}
			stats.vsFound += found
			stats.vsUpdated += updated
		}
		if nil != route.Spec.TLS {
			// We need this even for A/B so the irule can determine if we are
			// doing passthrough or reencrypt (otherwise we need to add more
			// info to the A/B data group).
			switch route.Spec.TLS.Termination {
			case routeapi.TLSTerminationPassthrough:
				updateDataGroupForPassthroughRoute(route, DEFAULT_PARTITION,
					sKey.Namespace, dgMap)
			case routeapi.TLSTerminationReencrypt:
				updateDataGroupForReencryptRoute(route, DEFAULT_PARTITION,
					sKey.Namespace, dgMap)
			case routeapi.TLSTerminationEdge:
				updateDataGroupForEdgeRoute(route, DEFAULT_PARTITION,
					sKey.Namespace, dgMap)
			}
		}
		updateDataGroupForABRoute(route, svcName, DEFAULT_PARTITION, sKey.Namespace, dgMap)

		appMgr.processAS3SpecificFeatures(route, bufferF5Res)
	}

	// if buffer is updated then update the appMgr and stats
	if (len(appMgr.intF5Res[sKey.Namespace]) != 0 || len(bufferF5Res) != 0) &&
		(!reflect.DeepEqual(appMgr.intF5Res[sKey.Namespace], bufferF5Res)) {

		appMgr.intF5Res[sKey.Namespace] = bufferF5Res
		stats.vsUpdated++
	}

	if len(svcFwdRulesMap) > 0 {
		httpsRedirectDg := NameRef{
			Name:      HttpsRedirectDgName,
			Partition: DEFAULT_PARTITION,
		}
		if _, found := dgMap[httpsRedirectDg]; !found {
			dgMap[httpsRedirectDg] = make(DataGroupNamespaceMap)
		}
		svcFwdRulesMap.AddToDataGroup(dgMap[httpsRedirectDg], DEFAULT_PARTITION)
	}

	return nil
}

// Process AS3 Specific features
func (appMgr *Manager) processAS3SpecificFeatures(route *routeapi.Route, buffer map[Record]F5Resources) {
	idf := Record{
		Host: route.Spec.Host,
		Path: route.Spec.Path,
	}

	// Check for WAF Annotation
	if wafPolicyName, exists := route.Annotations[F5VsWAFPolicy]; exists {
		buffer[idf] = F5Resources{
			Virtual:   appMgr.affectedVirtuals(route),
			WAFPolicy: wafPolicyName,
		}
	}
}

// Identify which virtuals needs update
func (appMgr *Manager) affectedVirtuals(route *routeapi.Route) ConstVirtuals {
	var v ConstVirtuals = HTTP
	if route.Spec.TLS != nil {
		v = HTTPS

		if route.Spec.TLS.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyAllow ||
			route.Spec.TLS.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyRedirect {
			v = HTTPANDS
		}
	}
	return v
}

func getBooleanAnnotation(
	annotations map[string]string,
	key string,
	defaultValue bool,
) bool {
	val, found := annotations[key]
	if !found {
		return defaultValue
	}
	bVal, err := strconv.ParseBool(val)
	if nil != err {
		log.Errorf("[CORE] Unable to parse boolean value '%v': %v", val, err)
		return defaultValue
	}
	return bVal
}

type portStruct struct {
	protocol string
	port     int32
}

func poolInNamespace(cfg *ResourceConfig, name, namespace string) bool {
	split := strings.Split(name, "_")
	if cfg.MetaData.ResourceType == "iapp" {
		if split[0] == namespace {
			return true
		}
	} else if split[1] == namespace {
		return true
	}
	return false
}

func serviceMatch(svcs []string, sKey serviceQueueKey) bool {
	// ConfigMap case (svc will always match sKey)
	if len(svcs) == 0 {
		return true
	}
	// Ingress/Route case
	for _, svc := range svcs {
		if svc == sKey.ServiceName {
			return true
		}
	}
	return false
}

// handling function for Ingresses
func (appMgr *Manager) handleConfigForTypeIngress(
	rsCfg *ResourceConfig,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	rsName NameRef,
	appInf *appInformer,
	currResourceSvcs []string, // Used for Ingress/Routes
	obj interface{}, // Used for writing events
) (bool, int, int) {
	vsFound := 0
	vsUpdated := 0
	deactivated := false
	poolUpdated := 0
	for _, backendSvc := range currResourceSvcs {
		//get current resource skey and port
		svcBackend := sKey.Namespace + "/" + backendSvc
		//backend svc key of ingress
		CurrsvcKey := serviceQueueKey{
			ServiceName: backendSvc,
			Namespace:   sKey.Namespace,
		}
		backend, _, _ := appInf.svcInformer.GetIndexer().GetByKey(svcBackend)

		// Get the pool that matches the sKey we are processing
		for i, pl := range rsCfg.Pools {
			if pl.ServiceName == CurrsvcKey.ServiceName &&
				poolInNamespace(rsCfg, pl.Name, sKey.Namespace) {
				poolUpdated += 1
				// Make sure pool members from the old config are applied to the new
				// config pools.
				appMgr.syncPoolMembers(rsName, rsCfg, i)

				svcKey := ServiceKey{
					Namespace:   sKey.Namespace,
					ServiceName: pl.ServiceName,
					ServicePort: pl.ServicePort,
				}
				if nil != backend {
					svc := backend.(*v1.Service)
					svcPortMap := make(map[int32]bool)
					for _, portSpec := range svc.Spec.Ports {
						svcPortMap[portSpec.Port] = false
					}
					// Match, remove config from rsMap so we don't delete it at the end.
					// (rsMap contains configs we want to delete).
					// In the case of Ingress/Routes: If the svc(s) of the currently processed ingress/route
					// doesn't match the svc in our ServiceKey, then we don't want to remove the config from the map.
					// Multiple Ingress/Routes can share a config, so if one Ingress/Route is deleted, then just
					// the pools for that resource should be deleted from our config. By keeping the config in the map,
					// we delete the necessary pools later on, while leaving everything else intact.
					cfgList := rsMap[pl.ServicePort]
					if serviceMatch(currResourceSvcs, sKey) {
						if len(cfgList) == 1 && cfgList[0].GetNameRef() == rsName {
							delete(rsMap, pl.ServicePort)
						} else if len(cfgList) > 1 {
							for index, val := range cfgList {
								if val.GetNameRef() == rsName {
									cfgList = append(cfgList[:index], cfgList[index+1:]...)
								}
							}
							rsMap[pl.ServicePort] = cfgList
						}
					}

					bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "port-not-found").Set(0)
					if _, ok := svcPortMap[pl.ServicePort]; !ok {
						log.Debugf("[CORE] Process Service delete - name: %v namespace: %v",
							pl.ServiceName, svcKey.Namespace)
						log.Infof("[CORE] Port '%v' for service '%v' was not found.",
							pl.ServicePort, pl.ServiceName)
						bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "port-not-found").Set(1)
						bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "success").Set(0)
						if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, i) {
							deactivated = true
							vsUpdated += 1
						}
					}

					bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "service-not-found").Set(0)

					// Update pool members.
					vsFound += 1
					correctBackend := true
					var reason string
					var msg string

					if svc.ObjectMeta.Labels["component"] == "apiserver" && svc.ObjectMeta.Labels["provider"] == "kubernetes" {
						appMgr.exposeKubernetesService(svc, svcKey, rsCfg, appInf, i)
					} else {
						if appMgr.IsNodePort() {
							//Pool members update required in Nodeport only in below scenarios
							//1.If it's create event
							//2.There's node update/update from ProcessNodeUpdate
							//3.Backend serviceport is updated or service is deleted.
							if sKey.Operation == OprTypeCreate || (sKey.ResourceKind == Nodes && sKey.Operation == OprTypeUpdate) || sKey.ResourceKind == Services {
								correctBackend, reason, msg =
									appMgr.updatePoolMembersForNodePort(svc, svcKey, rsCfg, i)
							} else {
								//No node updates are observed.
								correctBackend, reason, msg = true, "", ""
							}
						} else if appMgr.poolMemberType == NodePortLocal {
							correctBackend, reason, msg, _ =
								appMgr.updatePoolMembersForNPL(svc, svcKey, rsCfg, i)
						} else {
							correctBackend, reason, msg =
								appMgr.updatePoolMembersForCluster(svc, svcKey, rsCfg, appInf, i)
						}
					}
					// This will only update the config if the vs actually changed.
					if appMgr.saveVirtualServer(svcKey, rsName, rsCfg) {
						vsUpdated += 1

						// If this is an Ingress resource, add an event if there was a backend error
						if !correctBackend {
							if obj != nil {
								appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), reason, msg)
							}
						}
					}

					if !deactivated {
						bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "success").Set(1)
					}
				} else {
					// The service is gone, de-activate it in the config.
					log.Infof("[CORE] Service '%v' has not been found.", pl.ServiceName)
					bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "service-not-found").Set(1)
					bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "success").Set(0)
					if !deactivated {
						if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, i) {
							deactivated = true
							vsUpdated += 1
						}
					}
					// If this is an Ingress resource, add an event that the service wasn't found
					if obj != nil {
						msg := "Service " + pl.ServiceName + " has not been found."
						appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), "ServiceNotFound", msg)
					}

				}
			}
		}

		if vsUpdated > 0 && !appMgr.processAllMultiSvc(len(rsCfg.Pools),
			rsCfg.GetNameRef()) {
			vsUpdated -= 1
			vsFound -= 1
		}

	}

	if poolUpdated == 0 {
		return false, 0, 0
	}

	if deactivated {
		return false, vsFound, vsUpdated
	}

	return true, vsFound, vsUpdated
}

// Common handling function for ConfigMaps and Routes
func (appMgr *Manager) handleConfigForType(
	rsCfg *ResourceConfig,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	rsName NameRef,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
	currResourceSvcs []string, // Used for Ingress/Routes
	obj interface{}, // Used for writing events
) (bool, int, int, error) {
	vsFound := 0
	vsUpdated := 0

	// Get the pool that matches the sKey we are processing
	var pool Pool
	found := false
	plIdx := 0
	for i, pl := range rsCfg.Pools {
		if pl.ServiceName == sKey.ServiceName &&
			poolInNamespace(rsCfg, pl.Name, sKey.Namespace) {
			found = true
			pool = pl
			plIdx = i
			break
		}
	}
	if !found {
		return false, vsFound, vsUpdated, nil
	}

	// Make sure pool members from the old config are applied to the new
	// config pools.
	appMgr.syncPoolMembers(rsName, rsCfg, plIdx)

	svcKey := ServiceKey{
		Namespace:   sKey.Namespace,
		ServiceName: pool.ServiceName,
		ServicePort: pool.ServicePort,
	}

	// Match, remove config from rsMap so we don't delete it at the end.
	// (rsMap contains configs we want to delete).
	// In the case of Ingress/Routes: If the svc(s) of the currently processed ingress/route
	// doesn't match the svc in our ServiceKey, then we don't want to remove the config from the map.
	// Multiple Ingress/Routes can share a config, so if one Ingress/Route is deleted, then just
	// the pools for that resource should be deleted from our config. By keeping the config in the map,
	// we delete the necessary pools later on, while leaving everything else intact.
	cfgList := rsMap[pool.ServicePort]
	if serviceMatch(currResourceSvcs, sKey) {
		if len(cfgList) == 1 && cfgList[0].GetNameRef() == rsName {
			delete(rsMap, pool.ServicePort)
		} else if len(cfgList) > 1 {
			for index, val := range cfgList {
				if val.GetNameRef() == rsName {
					cfgList = append(cfgList[:index], cfgList[index+1:]...)
				}
			}
			rsMap[pool.ServicePort] = cfgList
		}
	}

	deactivated := false
	bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "port-not-found").Set(0)
	if _, ok := svcPortMap[pool.ServicePort]; !ok {
		log.Debugf("[CORE] Process Service delete - name: %v namespace: %v",
			pool.ServiceName, svcKey.Namespace)
		log.Infof("[CORE] Port '%v' for service '%v' was not found.",
			pool.ServicePort, pool.ServiceName)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "port-not-found").Set(1)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "success").Set(0)
		if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
			vsUpdated += 1
		}
		deactivated = true
	}

	bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "service-not-found").Set(0)
	if nil == svc {
		// The service is gone, de-activate it in the config.
		log.Infof("[CORE] Service '%v' has not been found.", pool.ServiceName)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "service-not-found").Set(1)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "success").Set(0)

		if !deactivated {
			deactivated = true
			if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
				vsUpdated += 1
			}
		}

		// If this is an Ingress resource, add an event that the service wasn't found
		if obj != nil {
			msg := "Service " + pool.ServiceName + " has not been found."
			appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), "ServiceNotFound", msg)
		}
		return false, vsFound, vsUpdated, nil
	}

	// Update pool members.
	vsFound += 1
	correctBackend := true
	var reason string
	var msg string

	if svc.ObjectMeta.Labels["component"] == "apiserver" && svc.ObjectMeta.Labels["provider"] == "kubernetes" {
		appMgr.exposeKubernetesService(svc, svcKey, rsCfg, appInf, plIdx)
	} else {
		if appMgr.IsNodePort() {
			//Pool members update required in Nodeport only in below scenarios
			//1.If it's create event
			//2.There's node update/update from ProcessNodeUpdate
			//3.Backend serviceport is updated or service is deleted.
			if sKey.Operation == OprTypeCreate || (sKey.ResourceKind == Nodes && sKey.Operation == OprTypeUpdate) || sKey.ResourceKind == Services {
				correctBackend, reason, msg =
					appMgr.updatePoolMembersForNodePort(svc, svcKey, rsCfg, plIdx)
			} else {
				//No node updates.
				correctBackend, reason, msg = true, "", ""
			}
		} else if appMgr.poolMemberType == NodePortLocal {
			var err error
			correctBackend, reason, msg, err =
				appMgr.updatePoolMembersForNPL(svc, svcKey, rsCfg, plIdx)
			if err != nil {
				return false, 0, 0, err
			}
		} else {
			correctBackend, reason, msg =
				appMgr.updatePoolMembersForCluster(svc, svcKey, rsCfg, appInf, plIdx)
		}
	}

	// This will only update the config if the vs actually changed.
	if appMgr.saveVirtualServer(svcKey, rsName, rsCfg) {
		vsUpdated += 1

		// If this is an Ingress resource, add an event if there was a backend error
		if !correctBackend {
			if obj != nil {
				appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), reason, msg)
			}
		}
	}

	if !deactivated {
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName.Name, "success").Set(1)
	}
	if len(currResourceSvcs) > 0 {
		if !serviceMatch(currResourceSvcs, sKey) {
			//pool found but service not matched with current resource backend. So endpoints are not updated for correct pool
			//So keep the resource as not processed.
			return false, vsFound, vsUpdated, nil
		}
	}
	return true, vsFound, vsUpdated, nil
}

func (appMgr *Manager) syncPoolMembers(rsName NameRef, rsCfg *ResourceConfig, plIdx int) {
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
		//for i, newPool := range rsCfg.Pools {
		for _, oldPool := range oldCfg.Pools {
			if oldPool.Name == rsCfg.Pools[plIdx].Name {
				rsCfg.Pools[plIdx].Members = oldPool.Members
			}
		}
		//}
		//for iApp resource update IAppPoolMemberTable with members found for pool.
		if rsCfg.MetaData.ResourceType == "iapp" {
			for _, p := range rsCfg.Pools {
				if rsCfg.IApp.Name == p.Name {
					rsCfg.IApp.IAppPoolMemberTable.Members = p.Members
				}
			}
		}
	}
}

func (appMgr *Manager) updatePoolMembersForNodePort(
	svc *v1.Service,
	svcKey ServiceKey,
	rsCfg *ResourceConfig,
	index int,
) (bool, string, string) {
	log.Debugf("Updating poolmembers for nodeport mode with service %v/%v", svcKey.ServiceName, svcKey.Namespace)
	if svc.Spec.Type == v1.ServiceTypeNodePort || svc.Spec.Type == v1.ServiceTypeLoadBalancer {
		for _, portSpec := range svc.Spec.Ports {
			if portSpec.Port == svcKey.ServicePort {
				log.Debugf("[CORE] Service backend matched %+v: using node port %v",
					svcKey, portSpec.NodePort)
				rsCfg.MetaData.Active = true
				rsCfg.Pools[index].Members =
					appMgr.getEndpointsForNodePort(portSpec.NodePort, portSpec.Port)
			}
		}
		//check if endpoints are found
		if rsCfg.Pools[index].Members == nil {
			log.Debugf("[CORE]Endpoints could not be fetched for service %v with port %v", svcKey.ServiceName, svcKey.ServicePort)
		}
		return true, "", ""
	} else {
		msg := "[CORE] Requested service backend " + svcKey.ServiceName + " not of NodePort or LoadBalancer type"
		log.Debug(msg)
		return false, "IncorrectBackendServiceType", msg
	}
}

func (appMgr *Manager) updatePoolMembersForNPL(
	svc *v1.Service,
	svcKey ServiceKey,
	rsCfg *ResourceConfig,
	index int,
) (bool, string, string, error) {
	//get pods for service
	if svc.Spec.Type == v1.ServiceTypeClusterIP || svc.Spec.Type == v1.ServiceTypeLoadBalancer {
		pods, err := appMgr.GetPodsForService(svcKey.Namespace, svcKey.ServiceName)
		if err != nil {
			return false, "", "", err
		}
		if pods != nil {
			for _, portSpec := range svc.Spec.Ports {
				if portSpec.Port == svcKey.ServicePort {
					podPort := portSpec.TargetPort
					ipPorts := appMgr.getEndpointsForNPL(podPort, pods)
					log.Debugf("[CORE] Found endpoints for backend %+v: %v", svcKey, ipPorts)
					rsCfg.MetaData.Active = true
					rsCfg.Pools[index].Members = ipPorts
				}
			}
		}
		//check if endpoints are found
		if rsCfg.Pools[index].Members == nil {
			log.Debugf("[CORE]Endpoints could not be fetched for service %v with port %v", svcKey.ServiceName, svcKey.ServicePort)
		}
		return true, "", "", nil
	} else {
		msg := "[CORE] Requested service backend " + svcKey.ServiceName + " not of ClusterIP or LoadBalancer type supported for NPL"
		log.Debug(msg)
		return false, "IncorrectBackendServiceType", msg, nil
	}
}

func (appMgr *Manager) updatePoolMembersForCluster(
	svc *v1.Service,
	sKey ServiceKey,
	rsCfg *ResourceConfig,
	appInf *appInformer,
	index int,
) (bool, string, string) {
	svcKey := sKey.Namespace + "/" + sKey.ServiceName
	item, found, _ := appInf.endptInformer.GetStore().GetByKey(svcKey)
	if !found {
		msg := "Endpoints for service " + svcKey + " not found!"
		log.Debug(msg)
		return false, "EndpointsNotFound", msg
	}
	eps, _ := item.(*v1.Endpoints)
	for _, portSpec := range svc.Spec.Ports {
		if portSpec.Port == sKey.ServicePort {
			ipPorts := appMgr.getEndpointsForCluster(portSpec.Name, eps, svc.Spec.ClusterIP)
			log.Debugf("[CORE] Found endpoints for backend %+v: %v", sKey, ipPorts)
			rsCfg.MetaData.Active = true
			rsCfg.Pools[index].Members = ipPorts
		}
	}
	//check if endpoints are found
	if rsCfg.Pools[index].Members == nil {
		log.Debugf("[CORE]Endpoints could not be fetched for service %v with port %v", sKey.ServiceName, sKey.ServicePort)
	}
	return true, "", ""
}

func (appMgr *Manager) deactivateVirtualServer(
	sKey ServiceKey,
	rsName NameRef,
	rsCfg *ResourceConfig,
	index int,
) bool {
	updateConfig := false
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if rs, ok := appMgr.resources.Get(sKey, rsName); ok {
		if len(rsCfg.Pools) > 1 {
			// Only deactivate if all other pools for this config are nil as well
			var valid bool
			for i, pool := range rsCfg.Pools {
				if i != index && pool.Members != nil {
					valid = true
					break
				}
			}
			if !valid {
				rsCfg.MetaData.Active = false
				rsCfg.Pools[index].Members = nil
			}
		} else {
			rsCfg.MetaData.Active = false
			rsCfg.Pools[index].Members = nil
		}

		if !rsCfg.MetaData.Active {
			log.Debugf("[CORE] Service delete matching backend '%v', deactivating config '%v'",
				sKey, rsName)
		}

		if !reflect.DeepEqual(rs, rsCfg) {
			updateConfig = true
		}
	} else {
		// We have a config map but not a server. Put in the virtual server from
		// the config map.
		updateConfig = true
	}
	if updateConfig {
		appMgr.resources.Assign(sKey, rsName, rsCfg)
	}
	return updateConfig
}

func (appMgr *Manager) saveVirtualServer(
	sKey ServiceKey,
	rsName NameRef,
	newRsCfg *ResourceConfig,
) bool {
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if oldRsCfg, ok := appMgr.resources.Get(sKey, rsName); ok {
		if reflect.DeepEqual(oldRsCfg, newRsCfg) {
			// not changed, don't trigger a config write
			return false
		}
		log.Debugf("[CORE] Overwriting existing entry for backend %+v and resource %+v", sKey, rsName)
	}
	appMgr.resources.Assign(sKey, rsName, newRsCfg)
	return true
}

func (appMgr *Manager) getResourcesForKey(sKey serviceQueueKey) ResourceMap {
	// Return a copy of what is stored in resources
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	rsMap := make(ResourceMap)
	appMgr.resources.ForEach(func(key ServiceKey, cfg *ResourceConfig) {
		if key.Namespace == sKey.Namespace &&
			key.ServiceName == sKey.ServiceName {
			rsMap[key.ServicePort] =
				append(rsMap[key.ServicePort], cfg)
		}
	})
	return rsMap
}

func (appMgr *Manager) processAllMultiSvc(numPools int, rsName NameRef) bool {
	// If multi-service and we haven't yet configured keys/cfgs for each service,
	// then we don't want to update
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if appMgr.resources.GetPoolCount(rsName) != numPools {
		return false
	}
	return true
}

func (appMgr *Manager) deleteUnusedConfigs(
	sKey serviceQueueKey,
	rsMap ResourceMap,
) int {
	rsDeleted := 0
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	// First delete any configs that we have left over from processing
	// (Configs that are still valid aren't left over)
	for port, cfgList := range rsMap {
		tmpKey := ServiceKey{
			Namespace:   sKey.Namespace,
			ServiceName: sKey.ServiceName,
			ServicePort: port,
		}
		for _, cfg := range cfgList {
			rsName := cfg.GetNameRef()
			if appMgr.resources.Delete(tmpKey, rsName) {
				rsDeleted += 1
			}
		}
	}
	return rsDeleted
}

// Delete any pools/rules/profileRefs that no longer exist
// for a deleted Ingress/Route or associated Service
func (appMgr *Manager) deleteUnusedResources(
	sKey serviceQueueKey,
	svcFound bool,
) int {
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	rsUpdated := 0
	namespace := sKey.Namespace
	svcName := sKey.ServiceName
	for _, cfg := range appMgr.resources.RsMap {
		if cfg.MetaData.ResourceType == "configmap" ||
			cfg.MetaData.ResourceType == "iapp" {
			continue
		}
		for _, pool := range cfg.Pools {
			// Make sure we aren't processing empty pool
			if pool.Name != "" {
				key := ServiceKey{
					ServiceName: pool.ServiceName,
					ServicePort: pool.ServicePort,
					Namespace:   namespace,
				}
				poolNS := strings.Split(pool.Name, "_")[1]
				_, ok := appMgr.resources.Get(key, cfg.GetNameRef())
				if pool.ServiceName == svcName && poolNS == namespace && (!ok || !svcFound) {
					if updated, svcKey := cfg.RemovePool(namespace, pool.Name, appMgr.mergedRulesMap); updated {
						appMgr.resources.DeleteKeyRefLocked(*svcKey, cfg.GetNameRef())
						rsUpdated += 1
					}
				}
			}
		}
	}
	return rsUpdated
}

func (appMgr *Manager) setBindAddrAnnotation(
	cm *v1.ConfigMap,
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
) {
	var doUpdate bool
	if cm.ObjectMeta.Annotations == nil {
		cm.ObjectMeta.Annotations = make(map[string]string)
		doUpdate = true
	} else if cm.ObjectMeta.Annotations[VsStatusBindAddrAnnotation] !=
		rsCfg.Virtual.VirtualAddress.BindAddr {
		doUpdate = true
	}
	if doUpdate {
		cm.ObjectMeta.Annotations[VsStatusBindAddrAnnotation] =
			rsCfg.Virtual.VirtualAddress.BindAddr
		_, err := appMgr.kubeClient.CoreV1().ConfigMaps(sKey.Namespace).Update(context.TODO(), cm, metav1.UpdateOptions{})
		if nil != err {
			log.Warningf("[CORE] Error when creating status IP annotation: %s", err)
		} else {
			log.Debugf("[CORE] Updating ConfigMap %+v annotation - %v: %v",
				sKey, VsStatusBindAddrAnnotation,
				rsCfg.Virtual.VirtualAddress.BindAddr)
		}
	}
}

func (appMgr *Manager) getEndpointsForCluster(
	portName string,
	eps *v1.Endpoints,
	clusterIP string,
) []Member {
	nodes := appMgr.getNodesFromCache()
	var members []Member

	if eps == nil {
		return members
	}

	// Mark each resource as it is already processed
	// So that later the create event of the same resource will not processed, unnecessarily
	appMgr.processedResourcesMutex.Lock()
	appMgr.processedResources[prepareResourceKey(Endpoints, eps.Namespace, eps.Name)] = true
	appMgr.processedResourcesMutex.Unlock()
	for _, subset := range eps.Subsets {
		for _, p := range subset.Ports {
			if portName == p.Name {
				for _, addr := range subset.Addresses {
					// Checking for headless service
					if containsNode(nodes, *addr.NodeName) || clusterIP == "None" {
						member := Member{
							Address: addr.IP,
							Port:    p.Port,
							SvcPort: p.Port,
							Session: "user-enabled",
						}
						members = append(members, member)
					}
				}
			}
		}
	}
	return members
}

func (appMgr *Manager) getServicePortFromTargetPort(svcPorts map[int32]int32, targetPort int32) int32 {
	if svcPorts == nil {
		return targetPort
	}
	svcPort, ok := svcPorts[targetPort]
	if ok {
		return svcPort
	} else {
		return targetPort
	}
}

func (appMgr *Manager) getServicePorts(svc *v1.Service) map[int32]int32 {
	if svc == nil {
		return nil
	}
	svcPorts := make(map[int32]int32)
	var targetPort int32
	for _, portSpec := range svc.Spec.Ports {
		targetPort = portSpec.TargetPort.IntVal
		if targetPort == 0 {
			targetPort = portSpec.Port
		}
		svcPorts[targetPort] = portSpec.Port
	}
	return svcPorts
}

func (appMgr *Manager) getEndpointsForNodePort(
	nodePort, port int32,
) []Member {
	nodes := appMgr.getNodesFromCache()
	var members []Member
	uniqueMembersMap := make(map[Member]struct{})
	for _, v := range nodes {
		member := Member{
			Address: v.Addr,
			Port:    nodePort,
			SvcPort: port,
			Session: "user-enabled",
		}
		if _, ok := uniqueMembersMap[member]; !ok {
			uniqueMembersMap[member] = struct{}{}
			members = append(members, member)
		}
	}

	return members
}

func handleConfigMapParseFailure(
	appMgr *Manager,
	cm *v1.ConfigMap,
	cfg *ResourceConfig,
	err error,
) bool {
	log.Warningf("[CORE] Could not get config for ConfigMap: %v - %v",
		cm.ObjectMeta.Name, err)
	// If virtual server exists for invalid configmap, delete it
	var serviceName string
	var servicePort int32
	if nil != cfg {
		if len(cfg.Pools) == 0 {
			serviceName = ""
			servicePort = 0
		} else {
			serviceName = cfg.Pools[0].ServiceName
			servicePort = cfg.Pools[0].ServicePort
		}
		sKey := ServiceKey{ServiceName: serviceName, ServicePort: servicePort, Namespace: cm.ObjectMeta.Namespace}
		rsName := NameRef{
			Name:      FormatConfigMapVSName(cm),
			Partition: cfg.GetPartition(),
		}
		appMgr.resources.Lock()
		defer appMgr.resources.Unlock()
		if _, ok := appMgr.resources.Get(sKey, rsName); ok {
			appMgr.resources.Delete(sKey, rsName)
			delete(cm.ObjectMeta.Annotations, VsStatusBindAddrAnnotation)
			appMgr.kubeClient.CoreV1().ConfigMaps(cm.ObjectMeta.Namespace).Update(context.TODO(), cm, metav1.UpdateOptions{})
			log.Warningf("[CORE] Deleted virtual server associated with ConfigMap: %v",
				cm.ObjectMeta.Name)
			return true
		}
	}
	return false
}

type Node struct {
	Name string
	Addr string
}

// Check for a change in Node state
func (appMgr *Manager) ProcessNodeUpdate(
	obj interface{},
) {
	newNodes, err := appMgr.getNodes(obj)
	if nil != err {
		log.Warningf("[CORE] Unable to get list of nodes, err=%+v", err)
		return
	}

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()

	// Only check for updates once we are in our initial state
	if appMgr.steadyState {
		// Compare last set of nodes with new one
		if !reflect.DeepEqual(newNodes, appMgr.oldNodes) {
			log.Infof("[CORE] ProcessNodeUpdate: Change in Node state detected")
			// ServiceKey contains a service port in addition to namespace service
			// name, while the work queue does not use service port. Create a list
			// of unique work queue keys using a map.
			items := make(map[serviceQueueKey]int)
			appMgr.resources.ForEach(func(key ServiceKey, cfg *ResourceConfig) {
				queueKey := serviceQueueKey{
					Namespace:    key.Namespace,
					ServiceName:  key.ServiceName,
					ResourceKind: Nodes,
					Operation:    OprTypeUpdate,
				}
				items[queueKey]++
			})
			for queueKey := range items {
				appMgr.vsQueue.Add(queueKey)
			}

			// Update node cache
			appMgr.oldNodes = newNodes
		}
	} else {
		// Initialize appMgr nodes on our first pass through
		appMgr.oldNodes = newNodes
	}
}

// Return a copy of the node cache
func (appMgr *Manager) getNodesFromCache() []Node {
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()
	nodes := make([]Node, len(appMgr.oldNodes))
	copy(nodes, appMgr.oldNodes)

	return nodes
}

// Get a list of Node addresses
func (appMgr *Manager) getNodes(
	obj interface{},
) ([]Node, error) {
	nodes, ok := obj.([]v1.Node)
	if false == ok {
		return nil,
			fmt.Errorf("poll update unexpected type, interface is not []v1.Node")
	}

	watchedNodes := []Node{}

	var addrType v1.NodeAddressType
	if appMgr.UseNodeInternal() {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	// Append list of nodes to watchedNodes
	for _, node := range nodes {
		// Ignore the Nodes with status NotReady
		var notExecutable bool
		for _, nodeCondition := range node.Status.Conditions {
			if nodeCondition.Type == v1.NodeReady && nodeCondition.Status != v1.ConditionTrue {
				notExecutable = true
				break
			}
		}
		if notExecutable == true {
			continue
		}
		nodeAddrs := node.Status.Addresses
		for _, addr := range nodeAddrs {
			if addr.Type == addrType {
				n := Node{
					Name: node.ObjectMeta.Name,
					Addr: addr.Address,
				}
				watchedNodes = append(watchedNodes, n)
			}
		}
	}
	return watchedNodes, nil
}

func containsNode(nodes []Node, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}

type byTimestamp []v1.Service
type NodeList []v1.Node
type PodList []*v1.Pod

// sort services by timestamp
func (slice byTimestamp) Len() int {
	return len(slice)
}

func (slice byTimestamp) Less(i, j int) bool {
	d1 := slice[i].GetCreationTimestamp()
	d2 := slice[j].GetCreationTimestamp()
	return d1.Before(&d2)
}

func (slice byTimestamp) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// sort nodes by Name
func (nodes NodeList) Len() int {
	return len(nodes)
}

func (nodes NodeList) Less(i, j int) bool {
	return nodes[i].Name < nodes[j].Name
}

func (nodes NodeList) Swap(i, j int) {
	nodes[i], nodes[j] = nodes[j], nodes[i]
}

// sort pods by Name
func (pods PodList) Len() int {
	return len(pods)
}

func (pods PodList) Less(i, j int) bool {
	return pods[i].Name < pods[j].Name
}

func (pods PodList) Swap(i, j int) {
	pods[i], pods[j] = pods[j], pods[i]
}

func createLabel(label string) (labels.Selector, error) {
	var l labels.Selector
	var err error
	if label == "" {
		l = labels.Everything()
	} else {
		l, err = labels.Parse(label)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Label Selector string: %v", err)
		}
	}
	return l, nil
}

// get the service list in case of hub mode
func (appMgr *Manager) getServicesForHubMode(selector, namespace string, isTenantNameServiceNamespace bool) ([]v1.Service, error) {
	var svcItems []v1.Service
	if isTenantNameServiceNamespace {
		if appInf, infFound := appMgr.getNamespaceInformer(namespace); infFound {
			svcInformer := appInf.svcInformer
			svcLister := listerscorev1.NewServiceLister(svcInformer.GetIndexer())
			ls, _ := createLabel(selector)
			svcListed, _ := svcLister.Services(namespace).List(ls)

			for n, _ := range svcListed {
				svcItems = append(svcItems, *svcListed[n])
			}
			log.Debugf("[CORE] Extract service via watch-list informer '%s'", namespace)
			return svcItems, nil
		}
	}
	// Leaving the old way for hubMode for now.
	svcListOptions := metav1.ListOptions{
		LabelSelector: selector,
	}
	services, err := appMgr.kubeClient.CoreV1().Services(v1.NamespaceAll).List(context.TODO(), svcListOptions)

	if err != nil {
		log.Errorf("[CORE] Error getting service list. %v", err)
		return nil, err
	}
	svcItems = services.Items
	log.Debugf("[CORE] Query service via '%v'", selector)
	return svcItems, nil
}

// get the endpoints for the hub mode
func (appMgr *Manager) getEndpointsForHubMode(svcName, svcNamespace string, isTenantNameServiceNamespace bool) (*v1.Endpoints, error) {
	var eps *v1.Endpoints
	if isTenantNameServiceNamespace {
		if appInf, infFound := appMgr.getNamespaceInformer(svcNamespace); infFound {
			if item, found, _ := appInf.endptInformer.GetStore().GetByKey(svcNamespace + "/" + svcName); found {
				eps, _ = item.(*v1.Endpoints)
			}
			return eps, nil
		}
	}
	// Leaving the old way for hubMode for now.
	endpointsList, err := appMgr.kubeClient.CoreV1().Endpoints(svcNamespace).List(context.TODO(),
		metav1.ListOptions{
			FieldSelector: "metadata.name=" + svcName,
		},
	)
	if err != nil {
		return nil, err
	}
	if len(endpointsList.Items) == 0 {
		return eps, nil
	}
	eps = &endpointsList.Items[0]
	return eps, nil
}

// Performs Service discovery for the given AS3 Pool and returns a pool.
// Service discovery is loosely coupled with Kubernetes Service labels. A Kubernetes Service is treated as a match for
// an AS3 Pool, if the Kubernetes Service have the following labels and their values matches corresponding AS3
// Object.
// cis.f5.com/as3-tenant=<Tenant Name>
// cis.f5.com/as3-app=<Application Name>
// cis.f5.com/as3-pool=<Pool Name>
// When controller is in NodePort mode, returns a list of Node IP Address and NodePort.
// When controller is in ClusterIP mode, returns a list of Cluster IP Address and Service Port. Also, it accumulates
// members for static ARP entry population.

func (appMgr *Manager) getEndpoints(selector, namespace string, poolMemberConfig []interface{}, isTenantNameServiceNamespace bool) ([]Member, []map[string]interface{}, error) {
	var members []Member
	uniqueMembersMap := make(map[Member]struct{})
	filteredPoolMemConfig := make([]map[string]interface{}, 0)
	appInf, _ := appMgr.getNamespaceInformer(namespace)

	var svcItems []v1.Service
	var err error
	if appMgr.hubMode {
		svcItems, err = appMgr.getServicesForHubMode(selector, namespace, isTenantNameServiceNamespace)
		if err != nil {
			filteredPoolMemConfig := make([]map[string]interface{}, 0)
			return nil, filteredPoolMemConfig, err
		}
	} else {
		svcInformer := appInf.svcInformer
		svcLister := listerscorev1.NewServiceLister(svcInformer.GetIndexer())
		ls, _ := createLabel(selector)
		svcListed, _ := svcLister.Services(namespace).List(ls)

		for n, _ := range svcListed {
			svcItems = append(svcItems, *svcListed[n])
		}
		log.Debugf("[CORE] Extract service via watch-list informer '%s'", namespace)
	}

	if len(svcItems) > 1 {
		var svcList []v1.Service
		processedSvc := make(map[string]bool)
		sort.Sort(byTimestamp(svcItems))
		for _, service := range svcItems {
			poolMemberPriorityGroupLabel, poolMemberPriorityGroupOk := service.ObjectMeta.Labels["cis.f5.com/as3-pool-member-priorityGroup"]
			svcSelector := selector
			if poolMemberPriorityGroupOk {
				svcSelector += "_" + poolMemberPriorityGroupLabel
			}
			if _, ok := processedSvc[svcSelector]; !ok {
				processedSvc[svcSelector] = true
				svcList = append(svcList, service)
			} else {
				svcName := fmt.Sprintf("Service: %v, Namespace: %v,Timestamp: %v\n", service.Name, service.Namespace, service.GetCreationTimestamp())
				log.Warningf("[CORE] Multiple Services are tagged for this pool. Using oldest service endpoints.\n%v", svcName)
			}
		}
		svcItems = svcList
	}

	for _, service := range svcItems {
		var replicaSets map[string]struct{}
		var targetDeployments []string
		poolMemberPriorityGroupLabel, poolMemberPriorityGroupOk := service.ObjectMeta.Labels["cis.f5.com/as3-pool-member-priorityGroup"]
		if len(appMgr.membersToDisable) > 0 {
			targetDeployments, replicaSets = appMgr.getDeploysAndRsMatchingSvcLabel(&service)
		}
		if appMgr.isNodePort == false && appMgr.poolMemberType != NodePortLocal {
			svcPorts := appMgr.getServicePorts(&service) // Controller is in ClusterIP Mode
			svcKey := service.Namespace + "/" + service.Name
			// try to get the endpoints from the pod cache if graceful shutdown is enabled
			if appMgr.podSvcCache.svcPodCache != nil && appMgr.podSvcCache.podDetails != nil {
				// return if pod graceful shut down event is handled,
				// it will add the endpoint event again after pod completes the graceful shutdown
				if pods, ok := appMgr.podSvcCache.svcPodCache.Load(svcKey); ok {
					for k := range *(pods.(*map[string]struct{})) {
						if podDetailInt, ok := appMgr.podSvcCache.podDetails.Load(k); ok {
							podDetails := podDetailInt.(PodDetails)
							for _, p := range strings.Split(podDetails.podPorts, ",") {
								port, _ := strconv.Atoi(p)
								member := Member{
									Address:    k,
									Port:       int32(port),
									SvcPort:    appMgr.getServicePortFromTargetPort(svcPorts, int32(port)),
									AdminState: podDetails.status,
								}
								if poolMemberPriorityGroupOk {
									member.PriorityGroup, err = strconv.Atoi(poolMemberPriorityGroupLabel)
									if err != nil {
										log.Warningf("Invalid pool member priority group %s for service: %v/%v", poolMemberPriorityGroupLabel, service.Name, service.Namespace)
									}
								}
								if _, ok := uniqueMembersMap[member]; !ok {
									uniqueMembersMap[member] = struct{}{}
									for _, mem := range poolMemberConfig {
										poolMemPriorityGroup, ok := mem.(map[string]interface{})["priorityGroup"]
										if !ok {
											poolMemPriorityGroup = float64(0)
										}
										if int(member.SvcPort) == int(mem.(map[string]interface{})["servicePort"].(float64)) && member.PriorityGroup == int(poolMemPriorityGroup.(float64)) {
											filteredPoolMemConfig = append(filteredPoolMemConfig, mem.(map[string]interface{}))
											break
										}
									}
									members = append(members, member)
								}
							}
						}
					}
				}
				// continue to work with all services
				continue
			}
			var eps *v1.Endpoints
			if appMgr.hubMode {
				eps, err = appMgr.getEndpointsForHubMode(service.Name, service.Namespace, isTenantNameServiceNamespace)
				if err != nil {
					log.Debugf("[CORE] Error getting endpoints for service %v/%v", service.Namespace, service.Name)
					return nil, filteredPoolMemConfig, err
				}
				if eps == nil {
					log.Debugf("[CORE] Endpoints for service %v/%v not found", service.Namespace, service.Name)
					continue
				}
			} else {
				item, found, _ := appInf.endptInformer.GetStore().GetByKey(svcKey)
				if !found {
					msg := "Endpoints for service " + svcKey + " not found!"
					log.Debug(msg)
					continue
				} else {
					eps, _ = item.(*v1.Endpoints)
				}
			}

			for _, subset := range eps.Subsets {
				for _, port := range subset.Ports {
					for _, addr := range subset.Addresses {
						adminState := "enable"
						if len(replicaSets) > 0 && addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" &&
							doesPodNameMatchWithDeployments(addr.TargetRef.Name, targetDeployments) &&
							appMgr.checkIfPodIsOwnedByTargetReplicaSet(addr.TargetRef.Name, addr.TargetRef.Namespace, replicaSets) {
							adminState = "disable"
						}
						member := Member{
							Address:    addr.IP,
							Port:       port.Port,
							SvcPort:    appMgr.getServicePortFromTargetPort(svcPorts, port.Port),
							AdminState: adminState,
						}
						if poolMemberPriorityGroupOk {
							member.PriorityGroup, err = strconv.Atoi(poolMemberPriorityGroupLabel)
							if err != nil {
								log.Warningf("Invalid pool member priority group %s for service: %v/%v", poolMemberPriorityGroupLabel, service.Name, service.Namespace)
							}
						}
						if _, ok := uniqueMembersMap[member]; !ok {
							uniqueMembersMap[member] = struct{}{}
							for _, mem := range poolMemberConfig {
								poolMemPriorityGroup, ok := mem.(map[string]interface{})["priorityGroup"]
								if !ok {
									poolMemPriorityGroup = float64(0)
								}
								if int(member.SvcPort) == int(mem.(map[string]interface{})["servicePort"].(float64)) && member.PriorityGroup == int(poolMemPriorityGroup.(float64)) {
									filteredPoolMemConfig = append(filteredPoolMemConfig, mem.(map[string]interface{}))
									break
								}
							}
							members = append(members, member)
						}
					}
				}
			}
		} else if appMgr.poolMemberType == NodePortLocal { // Controller is in NodePortLocal Mode
			pods, err := appMgr.GetPodsForService(service.Namespace, service.Name)
			if err != nil {
				return nil, filteredPoolMemConfig, err
			}
			if pods != nil {
				for _, portSpec := range service.Spec.Ports {
					podPort := portSpec.TargetPort
					for _, newMember := range appMgr.getEndpointsForNPL(podPort, pods) {
						if poolMemberPriorityGroupOk {
							newMember.PriorityGroup, err = strconv.Atoi(poolMemberPriorityGroupLabel)
							if err != nil {
								log.Warningf("Invalid pool member priority group %s for service: %v/%v", poolMemberPriorityGroupLabel, service.Name, service.Namespace)
							}
						}
						if _, ok := uniqueMembersMap[newMember]; !ok {
							uniqueMembersMap[newMember] = struct{}{}
							for _, mem := range poolMemberConfig {
								poolMemPriorityGroup, ok := mem.(map[string]interface{})["priorityGroup"]
								if !ok {
									poolMemPriorityGroup = float64(0)
								}
								if int(newMember.SvcPort) == int(mem.(map[string]interface{})["servicePort"].(float64)) && newMember.PriorityGroup == int(poolMemPriorityGroup.(float64)) {
									filteredPoolMemConfig = append(filteredPoolMemConfig, mem.(map[string]interface{}))
									break
								}
							}
							members = append(members, newMember)
						}
					}
				}
			}
		} else { // Controller is in NodePort mode.
			if service.Spec.Type == v1.ServiceTypeNodePort {
				for _, port := range service.Spec.Ports {
					endpointMembers := appMgr.getEndpointsForNodePort(port.NodePort, port.Port)
					for _, newMember := range endpointMembers {
						if poolMemberPriorityGroupOk {
							newMember.PriorityGroup, err = strconv.Atoi(poolMemberPriorityGroupLabel)
							if err != nil {
								log.Warningf("Invalid pool member priority group %s for service: %v/%v", poolMemberPriorityGroupLabel, service.Name, service.Namespace)
							}
						}
						if _, ok := uniqueMembersMap[newMember]; !ok {
							uniqueMembersMap[newMember] = struct{}{}
							for _, mem := range poolMemberConfig {
								poolMemPriorityGroup, ok := mem.(map[string]interface{})["priorityGroup"]
								if !ok {
									poolMemPriorityGroup = float64(0)
								}
								if int(newMember.SvcPort) == int(mem.(map[string]interface{})["servicePort"].(float64)) && newMember.PriorityGroup == int(poolMemPriorityGroup.(float64)) {
									filteredPoolMemConfig = append(filteredPoolMemConfig, mem.(map[string]interface{}))
									break
								}
							}
							members = append(members, newMember)
						}
					}
				}
			} /* else {
				msg := fmt.Sprintf("[CORE] Requested service backend '%+v' not of NodePort type", service.Name)
				log.Debug(msg)
			}*/
		}
		log.Debugf("[CORE] Discovered members for service %v/%v is %v", service.Namespace, service.Name, members)
	}
	// Let's sort the members to make sure the order is consistent
	sort.Slice(members, func(i, j int) bool {
		if members[i].Address == members[j].Address {
			return members[i].Port < members[j].Port
		}
		return members[i].Address < members[j].Address
	})
	return members, filteredPoolMemConfig, nil
}

// getDeploysAndRsMatchingSvcLabel returns the name of the deployments and replicasets which are associated with the provided service
func (appMgr *Manager) getDeploysAndRsMatchingSvcLabel(service *v1.Service) ([]string, map[string]struct{}) {
	var targetDeployments []string
	replicaSets := make(map[string]struct{})
	if service == nil {
		return targetDeployments, replicaSets
	}
	appInf, ok := appMgr.getNamespaceInformer(service.Namespace)
	if !ok {
		log.Errorf("Informers not found for namespace: %v", service.Namespace)
		return targetDeployments, replicaSets
	}
	if appInf.deploymentInformer == nil {
		log.Errorf("Deployment Informer not found for namespace: %v", service.Namespace)
		return targetDeployments, replicaSets
	}
	selector := labels.SelectorFromSet(service.Spec.Selector)
	if deployments, ok := appMgr.membersToDisable[service.Namespace]; ok {
		for deploymentName, _ := range deployments {
			obj, found, err := appInf.deploymentInformer.GetStore().GetByKey(service.Namespace + "/" + deploymentName)
			// if err is not nil it means pod is not found
			if !found {
				log.Errorf("[CORE] Deployment %s in namespace %s, not found", deploymentName, service.Namespace)
				continue
			}
			if err != nil {
				log.Errorf("[CORE] Failed fetching the Deployment %s in namespace %s, Error: %v", deploymentName, service.Namespace, err.Error())
				continue
			}
			if found {
				deployment, _ := obj.(*appsv1.Deployment)
				if selector.Matches(labels.Set(deployment.Spec.Selector.MatchLabels)) {
					targetDeployments = append(targetDeployments, deploymentName)
					// TODO: Update the replicasets as well
					rs := appMgr.getReplicaSetFromDeployment(deployment)
					if rs != "" {
						replicaSets[rs] = struct{}{}
					}
				}
			}
		}
	}
	return targetDeployments, replicaSets
}

// getReplicaSetFromDeployment returns the replicaSet name that the provided deployment created
func (appMgr *Manager) getReplicaSetFromDeployment(deployment *appsv1.Deployment) string {
	if deployment == nil {
		return ""
	}

	// Find the replicaset from the deployment's status conditions
	var replicasetName string
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == "Progressing" && condition.Reason == "NewReplicaSetAvailable" {
			// Extract the replicaset name from the condition message
			fmt.Sscanf(condition.Message, "ReplicaSet \"%s\" has successfully progressed.", &replicasetName)
			if replicasetName != "" {
				replicasetName = replicasetName[:len(replicasetName)-1] // Remove the trailing double quote
				break
			}
		}
	}
	if replicasetName == "" {
		log.Errorf("Failed to find replicaset for deployment %s", deployment.Name)
	}
	return replicasetName
}

// doesPodNameMatchWithDeployments checks if pod name matches with deployment name,
// In case it matches then this makes it a good candidate for further processing
// This is a good check to do to improve efficiency as the no. of deployments for disable members is very less
func doesPodNameMatchWithDeployments(podName string, deployments []string) bool {
	if podName == "" || len(deployments) == 0 {
		return false
	}
	for _, deploymentName := range deployments {
		if strings.HasPrefix(podName, deploymentName+"-") {
			return true
		}
	}
	return false
}

// checkIfPodIsOwnedByTargetReplicaSet checks if the provided pod is owned by any of the provided replicaSets
func (appMgr *Manager) checkIfPodIsOwnedByTargetReplicaSet(podName, namespace string, replicaSetMap map[string]struct{}) bool {
	appInf, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		log.Debugf("[CORE] Failed checking pod ownership for Pod %s as AppInfomer not initialised for namespace %s", podName, namespace)
		return false
	}
	obj, found, err := appInf.podInformer.GetStore().GetByKey(namespace + "/" + podName)
	// if err is not nil it means pod is not found
	if !found {
		log.Errorf("[CORE] Pod %s in namespace %s not found", podName, namespace)
		return false
	} else if err != nil {
		log.Errorf("[Core] Failed fetching the Pod %s in namespace %s, Error: %v", podName, namespace, err.Error())
		return false
	}
	if found {
		pod, _ := obj.(*v1.Pod)
		if pod.OwnerReferences != nil {
			for _, owner := range pod.OwnerReferences {
				if owner.Kind == "ReplicaSet" {
					if _, ok := replicaSetMap[owner.Name]; ok {
						log.Debugf("[CORE] Confirmed Pod ownership as replicaset matched for pod %s/%s", namespace, podName)
						return true
					}
				}
			}
		}
	}
	log.Debugf("[CORE] Replicaset does not matched for pod %s/%s", namespace, podName)
	return false
}

func (appMgr *Manager) exposeKubernetesService(
	svc *v1.Service,
	sKey ServiceKey,
	rsCfg *ResourceConfig,
	appInf *appInformer,
	index int,
) (bool, string, string) {
	svcKey := sKey.Namespace + "/" + sKey.ServiceName
	item, found, _ := appInf.endptInformer.GetStore().GetByKey(svcKey)
	if !found {
		msg := "Endpoints for service " + svcKey + " not found!"
		log.Debug(msg)
		return false, "EndpointsNotFound", msg
	}
	eps, _ := item.(*v1.Endpoints)
	for _, portSpec := range svc.Spec.Ports {
		if portSpec.Port == sKey.ServicePort {
			var members []Member
			for _, subset := range eps.Subsets {
				for _, p := range subset.Ports {
					if portSpec.Name == p.Name {
						for _, addr := range subset.Addresses {
							member := Member{
								Address: addr.IP,
								Port:    p.Port,
							}
							members = append(members, member)
						}
					}
				}
			}
			log.Debugf("[CORE] Found endpoints for backend %+v: %v", sKey, members)
			rsCfg.MetaData.Active = true
			rsCfg.Pools[index].Members = members
		}
	}
	return true, "", ""
}

func prepareResourceKey(kind, namespace, name string) string {
	return kind + "_" + namespace + "/" + name
}

func getIngressV1Backend(ing *netv1.Ingress) []string {
	services := make(map[string]bool)
	if nil != ing.Spec.Rules { // multi-service
		for _, rl := range ing.Spec.Rules {
			if nil != rl.IngressRuleValue.HTTP {
				for _, pth := range rl.IngressRuleValue.HTTP.Paths {
					services[pth.Backend.Service.Name] = true
				}
			}
		}
	} else { // single-service
		services[ing.Spec.DefaultBackend.Service.Name] = true
	}
	//unique svc list
	svcs := []string{}
	for key, _ := range services {
		svcs = append(svcs, key)
	}
	return svcs
}

func (appMgr *Manager) matchSvcSelectorPodLabels(svcSelector, podLabel map[string]string) bool {
	if len(svcSelector) == 0 {
		return false
	}

	for selectorKey, selectorVal := range svcSelector {
		if labelVal, ok := podLabel[selectorKey]; !ok || selectorVal != labelVal {
			return false
		}
	}
	return true
}

func (appMgr *Manager) GetServicesForPod(pod *v1.Pod) []*v1.Service {
	var svcList []*v1.Service
	appInf, ok := appMgr.getNamespaceInformer(pod.Namespace)
	if !ok {
		log.Errorf("Informer not found for namespace: %v", pod.Namespace)
		return svcList
	}
	services := appInf.svcInformer.GetIndexer().List()
	for _, obj := range services {
		svc := obj.(*v1.Service)
		if svc.Spec.Type != v1.ServiceTypeNodePort {
			if appMgr.matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
				svcList = append(svcList, svc)
			}
		}
	}
	return svcList
}

func (appMgr *Manager) GetPodsForService(namespace, serviceName string) ([]*v1.Pod, error) {
	svcKey := namespace + "/" + serviceName
	crInf, ok := appMgr.getNamespaceInformer(namespace)
	if !ok && !appMgr.hubMode {
		log.Errorf("Informer not found for namespace: %v", namespace)
		return nil, nil
	}
	var svc interface{}
	var err error
	var found bool
	if appMgr.hubMode {
		svc, err = appMgr.kubeClient.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	} else {
		svc, found, err = crInf.svcInformer.GetIndexer().GetByKey(svcKey)
		if !found {
			log.Errorf("Error: Service %v not found", svcKey)
			return nil, nil
		}
	}
	if err != nil {
		log.Infof("Error fetching service %v from the store: %v", svcKey, err)
		// Keep processing in case of service not found error
		if !errors.IsNotFound(err) {
			return nil, err
		}
	}
	annotations := svc.(*v1.Service).Annotations
	if _, ok := annotations[NPLSvcAnnotation]; !ok {
		log.Errorf("NPL annotation %v not set on service %v", NPLSvcAnnotation, serviceName)
		return nil, nil
	}

	selector := svc.(*v1.Service).Spec.Selector
	if len(selector) == 0 {
		log.Errorf("selector not set on service %v", serviceName)
		return nil, nil
	}
	labelSelector, err := metav1.ParseToLabelSelector(labels.Set(selector).AsSelectorPreValidated().String())
	labelmap, err := metav1.LabelSelectorAsMap(labelSelector)
	if err != nil {
		return nil, nil
	}
	pl, _ := createLabel(labels.SelectorFromSet(labelmap).String())
	var podList []*v1.Pod
	if appMgr.hubMode {
		var pods *v1.PodList
		pods, err = appMgr.kubeClient.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: labels.SelectorFromSet(labelmap).String(),
		})
		for _, obj := range pods.Items {
			pod := obj
			podList = append(podList, &pod)
		}
	} else {
		podList, err = listerscorev1.NewPodLister(crInf.podInformer.GetIndexer()).Pods(namespace).List(pl)
	}
	if err != nil {
		log.Debugf("Got error while listing Pods with selector %v: %v", selector, err)
		return nil, err
	}
	sort.Sort(PodList(podList))
	return podList, nil
}

// getEndpointsForNPL returns members.
func (appMgr *Manager) getEndpointsForNPL(
	targetPort intstr.IntOrString,
	pods []*v1.Pod,
) []Member {
	var members []Member
	for _, pod := range pods {
		anns, found := appMgr.nplStore[pod.Namespace+"/"+pod.Name]
		if !found {
			if appMgr.hubMode {
				ann := pod.GetAnnotations()
				var annotations []NPLAnnotation
				if val, ok := ann[NPLPodAnnotation]; ok {
					if err := json.Unmarshal([]byte(val), &annotations); err != nil {
						log.Errorf("key: %s, got error while unmarshaling NPL annotations: %v", err)
						continue
					}
					anns = annotations
				} else {
					log.Debugf("key: %s, NPL annotation not found for Pod", pod.Name)
					continue
				}
			} else {
				continue
			}
		}
		var podPort int32
		//Support for named targetPort
		if targetPort.StrVal != "" {
			targetPortStr := targetPort.StrVal
			//Get the containerPort matching targetPort from pod spec.
			for _, container := range pod.Spec.Containers {
				for _, port := range container.Ports {
					portStr := port.Name
					if targetPortStr == portStr {
						podPort = port.ContainerPort
					}
				}
			}
		} else {
			// targetPort with int value
			podPort = targetPort.IntVal
		}
		for _, annotation := range anns {
			if annotation.PodPort == podPort {
				member := Member{
					Address: annotation.NodeIP,
					Port:    annotation.NodePort,
					SvcPort: annotation.PodPort,
					Session: "user-enabled",
				}
				members = append(members, member)
			}
		}
	}
	return members
}

func (appMgr *Manager) checkCoreserviceLabels(labels map[string]string) bool {
	for _, v := range labels {
		if _, ok := K8SCoreServices[v]; ok {
			return true
		}
		if nil != appMgr.routeClientV1 {
			if _, ok := OSCPCoreServices[v]; ok {
				return true
			}
		}
	}
	return false
}

func (appMgr *Manager) updateHostPathMap(timestamp metav1.Time, key string) {
	// This function updates the processedHostPath
	appMgr.processedHostPath.Lock()
	defer appMgr.processedHostPath.Unlock()
	for hostPath, routeTimestamp := range appMgr.processedHostPath.processedHostPathMap {
		if routeTimestamp == timestamp && hostPath != key {
			// Deleting the ProcessedHostPath map if route's path is changed
			delete(appMgr.processedHostPath.processedHostPathMap, hostPath)
		}
	}
	// adding the ProcessedHostPath map entry
	appMgr.processedHostPath.processedHostPathMap[key] = timestamp
}

func (appMgr *Manager) deleteHostPathMapEntry(obj interface{}) {
	// This function deletes the route entry from processedHostPath
	route := obj.(*routeapi.Route)
	var key string
	if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
		key = route.Spec.Host + "/"
	} else {
		key = route.Spec.Host + route.Spec.Path
	}
	appMgr.processedHostPath.Lock()
	defer appMgr.processedHostPath.Unlock()
	if routeTimestamp, ok := appMgr.processedHostPath.processedHostPathMap[key]; ok {
		if routeTimestamp == route.CreationTimestamp {
			delete(appMgr.processedHostPath.processedHostPathMap, key)
		}
	}
}

// Set Other SDNType
func (appMgr *Manager) setOtherSDNType() {
	appMgr.TeemData.Lock()
	defer appMgr.TeemData.Unlock()
	if appMgr.orchestrationCNI == "" && (appMgr.TeemData.SDNType == "other" || appMgr.TeemData.SDNType == "flannel") {
		kubePods, err := appMgr.kubeClient.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if nil != err {
			log.Errorf("Could not list Kubernetes Pods for CNI Check: %v", err)
			return
		}
		for _, kPod := range kubePods.Items {
			if strings.Contains(kPod.Name, "cilium") && kPod.Status.Phase == "Running" {
				appMgr.TeemData.SDNType = "cilium"
				return
			}
			if strings.Contains(kPod.Name, "calico") && kPod.Status.Phase == "Running" {
				appMgr.TeemData.SDNType = "calico"
				return
			}
		}
	}
}

func (appMgr *Manager) setupNodeProcessing() error {
	// Register appMgr to watch for node updates to keep track of watched nodes
	//when there is update from node informer get list of nodes from nodeinformer cache
	nodes := appMgr.nodeInformer.nodeInformer.GetIndexer().List()
	var nodeslist []v1.Node
	for _, obj := range nodes {
		node := obj.(*v1.Node)
		nodeslist = append(nodeslist, *node)
	}
	sort.Sort(NodeList(nodeslist))
	appMgr.ProcessNodeUpdate(nodeslist)
	// adding the bigip_monitored_nodes	metrics
	bigIPPrometheus.MonitoredNodes.WithLabelValues(appMgr.nodeLabelSelector).Set(float64(len(appMgr.oldNodes)))
	if appMgr.staticRoutingMode {
		appMgr.processStaticRouteUpdate(nodes)
	} else if 0 != len(appMgr.vxlanMode) {
		// If partition is part of vxlanName, extract just the tunnel name
		tunnelName := appMgr.vxlanName
		cleanPath := strings.TrimLeft(appMgr.vxlanName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos != -1 {
			tunnelName = cleanPath[slashPos+1:]
		}
		vxMgr, err := vxlan.NewVxlanMgr(
			appMgr.vxlanMode,
			tunnelName,
			appMgr.ciliumTunnelName,
			appMgr.UseNodeInternal(),
			appMgr.configWriter,
			appMgr.eventChan,
		)
		if nil != err {
			return fmt.Errorf("error creating vxlan manager: %v", err)
		}

		// Register vxMgr to watch for node updates to process fdb records
		vxMgr.ProcessNodeUpdate(nodeslist)

		if appMgr.eventChan != nil {
			vxMgr.ProcessAppmanagerEvents(appMgr.kubeClient)
		}
	}

	return nil
}

func ciliumPodCidr(annotation map[string]string) string {
	if subnet, ok := annotation[CiliumK8sNodeSubnetAnnotation13]; ok {
		return subnet
	} else if subnet, ok := annotation[CiliumK8sNodeSubnetAnnotation12]; ok {
		return subnet
	}
	return ""
}

func (appMgr *Manager) processStaticRouteUpdate(
	nodes []interface{},
) {
	//if static-routing-mode process static routes
	var addrType v1.NodeAddressType
	if appMgr.useNodeInternal {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	routes := routeSection{}
	routes.CISIdentifier = DEFAULT_PARTITION + "_" + strings.TrimPrefix(appMgr.BigIPURL, "https://")
	for _, obj := range nodes {
		node := obj.(*v1.Node)
		// Ignore the Nodes with status NotReady
		var notExecutable bool
		for _, nodeCondition := range node.Status.Conditions {
			if nodeCondition.Type == v1.NodeReady && nodeCondition.Status != v1.ConditionTrue {
				notExecutable = true
				break
			}
		}
		if notExecutable == true {
			continue
		}
		route := routeConfig{}
		route.Description = routes.CISIdentifier
		// For ovn-k8s get pod subnet and node ip from annotation
		if appMgr.orchestrationCNI == OVN_K8S {
			annotations := node.Annotations
			if nodeSubnetAnn, ok := annotations[OVNK8sNodeSubnetAnnotation]; !ok {
				log.Warningf("Node subnet annotation %v not found on node %v static route not added", OVNK8sNodeSubnetAnnotation, node.Name)
				continue
			} else {
				nodesubnet, err := parseNodeSubnet(nodeSubnetAnn, node.Name)
				if err != nil {
					log.Warningf("Node subnet annotation %v not properly configured for node %v:%v", OVNK8sNodeSubnetAnnotation, node.Name, err)
					continue
				}
				route.Network = nodesubnet
			}
			if appMgr.staticRouteNodeCIDR != "" {
				_, nodenetwork, err := net.ParseCIDR(appMgr.staticRouteNodeCIDR)
				if err != nil {
					log.Errorf("Unable to parse cidr %v with error %v", appMgr.staticRouteNodeCIDR, err)
					continue
				} else {
					var hostaddresses string
					var ok bool
					var nodeIP string
					var err error
					if hostaddresses, ok = annotations[OVNK8sNodeIPAnnotation2]; !ok {
						//For ocp 4.14 and above check for new annotation
						if hostaddresses, ok = annotations[OVNK8sNodeIPAnnotation3]; !ok {
							log.Warningf("Host addresses annotation %v not found on node %v static route not added", OVNK8sNodeIPAnnotation2, node.Name)
							continue
						} else {
							nodeIP, err = parseHostCIDRS(hostaddresses, nodenetwork)
							if err != nil {
								log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OVNK8sNodeIPAnnotation3, node.Name, err)
								continue
							}
							route.Gateway = nodeIP
							route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
						}
					} else {
						nodeIP, err = parseHostAddresses(hostaddresses, nodenetwork)
						if err != nil {
							log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OVNK8sNodeIPAnnotation2, node.Name, err)
							continue
						}
						route.Gateway = nodeIP
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
					}

				}
			} else {
				if nodeIPAnn, ok := annotations[OVNK8sNodeIPAnnotation]; !ok {
					log.Warningf("Node IP annotation %v not found on node %v static route not added", OVNK8sNodeIPAnnotation, node.Name)
					continue
				} else {
					nodeIP, err := parseNodeIP(nodeIPAnn, node.Name)
					if err != nil {
						log.Warningf("Node IP annotation %v not properly configured for node %v:%v", OVNK8sNodeIPAnnotation, node.Name, err)
						continue
					}
					route.Gateway = nodeIP
					route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, nodeIP)
				}
			}

		} else if appMgr.orchestrationCNI == CILIUM_K8S {
			nodesubnet := ciliumPodCidr(node.ObjectMeta.Annotations)
			if nodesubnet == "" {
				log.Warningf("Cilium node podCIDR annotation not found on node %v, node has spec.podCIDR ?", node.Name)
				continue
			} else {
				route.Network = nodesubnet
				nodeAddrs := node.Status.Addresses
				for _, addr := range nodeAddrs {
					if addr.Type == addrType {
						route.Gateway = addr.Address
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, addr.Address)
					}
				}

			}

		} else {
			podCIDR := node.Spec.PodCIDR
			if podCIDR != "" {
				route.Network = podCIDR
				nodeAddrs := node.Status.Addresses
				for _, addr := range nodeAddrs {
					if addr.Type == addrType {
						route.Gateway = addr.Address
						route.Name = fmt.Sprintf("k8s-%v-%v", node.Name, addr.Address)
					}
				}
			} else {
				log.Debugf("podCIDR is not found on node %v so not adding the static route for node", node.Name)
				continue
			}
		}
		routes.Entries = append(routes.Entries, route)
	}
	doneCh, errCh, err := appMgr.configWriter.SendSection("static-routes", routes)

	if nil != err {
		log.Warningf("Failed to write static routes config section: %v", err)
	} else {
		select {
		case <-doneCh:
			log.Debugf("Wrote static route config section: %v", routes)
		case e := <-errCh:
			log.Warningf("Failed to write static route config section: %v", e)
		case <-time.After(time.Second):
			log.Warningf("Did not receive write response in 1s")
		}
	}
}

func (appMgr *Manager) udpatePodCacheForGracefulShutDown(eps *v1.Endpoints, inf *appInformer, operation string) bool {
	var forgetEvent bool
	epKey := fmt.Sprintf("%s/%s", eps.Namespace, eps.Name)
	if operation == OprTypeDisable || operation == OprTypeDelete {
		var deletedItems []string
		if operation == OprTypeDisable {
			// fetch the deleted pod from the cache and delete it
			elementMap := make(map[string]bool)
			for _, item := range eps.Subsets[0].Addresses {
				elementMap[item.IP] = true
			}
			appMgr.podSvcCache.podDetails.Range(func(key, value interface{}) bool {
				ip := key.(string)
				podDetails := value.(PodDetails)
				if !elementMap[ip] && podDetails.epKey == epKey {
					deletedItems = append(deletedItems, ip)
				}
				return true
			})
		}
		if operation == OprTypeDelete {
			// if endpoint object is deleted then we need to handle all the pods
			for _, item := range eps.Subsets[0].Addresses {
				deletedItems = append(deletedItems, item.IP)
			}
		}

		// we are considering index 0 by assuming all the endpoints will have same addresses even though the ports are different
		for _, addr := range deletedItems {
			if value, ok := appMgr.podSvcCache.podDetails.Load(addr); ok {
				if podDetails, ok := value.(PodDetails); ok {
					if podDetails.epKey == epKey {
						// udpate the pod status to disabled
						podDetails.status = PodStatusDisable
						appMgr.podSvcCache.podDetails.Store(addr, podDetails)
						// disable the endpoint to disable new connections
						log.Debugf("[PodGracefulShutdown] Updated the pod status to disable for ip address %v", addr)
						appMgr.enqueueEndpointDisable(eps, podDetails)
						forgetEvent = true
						go func(graceTermination int64, address string, ep string, eps *v1.Endpoints) {
							// Create a channel to receive a signal after the timeout
							timeout := time.Duration(graceTermination) * time.Second
							timeoutCh := time.After(timeout)
							for {
								// delete the pod from the cache after the timeout
								select {
								case <-timeoutCh:
									appMgr.podSvcCache.podDetails.Delete(address)
									// delete the entry from svc pod cache
									if ips, ok := appMgr.podSvcCache.svcPodCache.Load(ep); ok {
										podMap := ips.(*map[string]struct{})
										delete(*podMap, address)
										appMgr.podSvcCache.svcPodCache.Store(ep, podMap)
										log.Debugf("[CORE] Deleted the %v from pod cache", address)
									}
									// disable the endpoint to disable new connections
									log.Debugf("[PodGracefulShutdown] Enqueue the pod with ip address %v to remove as pool member", address)
									appMgr.enqueueEndpoints(eps, OprTypeUpdate)
									return
								default:
									// Continue the loop until the timeout
								}
							}
						}(podDetails.gracePeriod, addr, epKey, eps)
					}
				}
			}
		}
		if operation == OprTypeDelete {
			// delete the entry from the cache
			log.Debugf("[PodGracefulShutdown] Deleting the pod and service mapping for %v", epKey)
			appMgr.podSvcCache.svcPodCache.Delete(epKey)
		}
	} else {
		// we are considering index 0 by assuming all the endpoints will have same addresses even though the ports are different
		for _, addr := range eps.Subsets[0].Addresses {
			if addr.TargetRef == nil {
				continue
			}
			obj, found, err := inf.podInformer.GetStore().GetByKey(addr.TargetRef.Namespace + "/" + addr.TargetRef.Name)
			// if err is not nil it means pod is not found
			if err != nil || !found {
				continue
			}

			if found {
				pod, _ := obj.(*v1.Pod)
				var ports []string
				for _, port := range eps.Subsets[0].Ports {
					ports = append(ports, strconv.Itoa(int(port.Port)))
				}
				// udpate the pod cache for graceful shutdown
				appMgr.podSvcCache.podDetails.Store(addr.IP,
					PodDetails{
						podIp:       addr.IP,
						gracePeriod: *pod.Spec.TerminationGracePeriodSeconds,
						epKey:       epKey,
						podPorts:    strings.Join(ports, ","),
						status:      PodStatusEnable,
					})
				// update the svc pod cache
				if ips, ok := appMgr.podSvcCache.svcPodCache.Load(epKey); ok {
					podMap := ips.(*map[string]struct{})
					(*podMap)[addr.IP] = struct{}{}
					appMgr.podSvcCache.svcPodCache.Store(epKey, podMap)
				} else {
					podMap := make(map[string]struct{})
					podMap[addr.IP] = struct{}{}
					appMgr.podSvcCache.svcPodCache.Store(epKey, &podMap)
				}
				log.Debugf("[CORE] Updated the cache endpoint %v event for pod ip %v", operation, addr.IP)
			}
		}
	}
	return forgetEvent
}

// EnqueueEndpointDisable enqueues the endpoint disable event
func (appMgr *Manager) enqueueEndpointDisable(eps *v1.Endpoints, obj interface{}) {
	log.Debugf("[PodGracefulShutdown] enqueueing pod ip for disable %v", obj)
	key := &serviceQueueKey{
		ServiceName:  eps.ObjectMeta.Name,
		Namespace:    eps.ObjectMeta.Namespace,
		ResourceKind: Endpoints,
		ResourceName: eps.Name,
		Operation:    OprTypeDisable,
		Object:       obj,
	}
	appMgr.vsQueue.Add(*key)
}

func parseNodeSubnet(ann, nodeName string) (string, error) {
	var subnetDict map[string]interface{}
	json.Unmarshal([]byte(ann), &subnetDict)
	if nodeSubnet, ok := subnetDict["default"]; ok {
		switch nodeSubnetObj := nodeSubnet.(type) {
		case string:
			return nodeSubnet.(string), nil
		case []interface{}:
			for _, subnet := range nodeSubnetObj {
				ip, _, err := net.ParseCIDR(subnet.(string))
				if err != nil {
					log.Errorf("Unable to parse cidr for subnet %v with err %v", subnet, err)
				} else {
					//check for ipv4 address
					if nil != ip.To4() {
						return subnet.(string), nil
					}
				}
			}
		default:
			return "", fmt.Errorf("Unsupported annotation format")
		}
	}
	err := fmt.Errorf("%s annotation for "+
		"node '%s' has invalid format; cannot validate node subnet. "+
		"Should be of the form: '{\"default\":\"<node-subnet>\"}'", OVNK8sNodeSubnetAnnotation, nodeName)
	return "", err
}

func parseNodeIP(ann, nodeName string) (string, error) {
	var IPDict map[string]interface{}
	json.Unmarshal([]byte(ann), &IPDict)
	if IP, ok := IPDict["ipv4"]; ok {
		ipmask := IP.(string)
		nodeip := strings.Split(ipmask, "/")[0]
		return nodeip, nil
	}
	err := fmt.Errorf("%s annotation for "+
		"node '%s' has invalid format; cannot validate node IP. "+
		"Should be of the form: '{\"ipv4\":\"<node-ip>\"}'", OVNK8sNodeIPAnnotation, nodeName)
	return "", err
}

func parseHostAddresses(ann string, nodenetwork *net.IPNet) (string, error) {
	var hostaddresses []string
	json.Unmarshal([]byte(ann), &hostaddresses)
	for _, IP := range hostaddresses {
		ip := net.ParseIP(IP)
		if nodenetwork.Contains(ip) {
			return ip.String(), nil
		}
	}
	err := fmt.Errorf("Cannot get nodeip from %s within nodenetwork %v", OVNK8sNodeIPAnnotation2, nodenetwork)
	return "", err
}

func parseHostCIDRS(ann string, nodenetwork *net.IPNet) (string, error) {
	var hostcidrs []string
	json.Unmarshal([]byte(ann), &hostcidrs)
	for _, cidr := range hostcidrs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("Unable to parse cidr %v with error %v", cidr, err)
		} else {
			if nodenetwork.Contains(ip) {
				return ip.String(), nil
			}
		}
	}
	err := fmt.Errorf("Cannot get nodeip from %s within nodenetwork %v", OVNK8sNodeIPAnnotation3, nodenetwork)
	return "", err
}
