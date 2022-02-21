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

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/teem"

	netv1 "k8s.io/api/networking/v1"

	cisAgent "github.com/F5Networks/k8s-bigip-ctlr/pkg/agent"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/pkg/prometheus"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"github.com/miekg/dns"
	routeapi "github.com/openshift/api/route/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"golang.org/x/mod/semver"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type ResourceMap map[int32][]*ResourceConfig

// RoutesMap consists of List of route names indexed by namespace
type RoutesMap map[string][]string

type Manager struct {
	resources           *Resources
	customProfiles      *CustomProfileStore
	IRulesStore         IRulesStore
	intDgMap            InternalDataGroupMap
	agentCfgMap         map[string]*AgentCfgMap
	agentCfgMapSvcCache map[string]*SvcEndPointsCache
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
	as3Informer  *appInformer
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
	K8sVersion         string
	TeemData           *teem.TeemsData
	defaultRouteDomain int
}

// Watched Namespaces for global availability.
type WatchedNamespaces struct {
	Namespaces     []string
	NamespaceLabel string
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
	// Package local for untesting only
	restClient             rest.Interface
	steadyState            bool
	broadcasterFunc        NewBroadcasterFunc
	ManageConfigMaps       bool
	ManageIngress          bool
	ManageIngressClassOnly bool
	HubMode                bool
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

type SvcEndPointsCache struct {
	members     []Member
	labelString string
}

const (

	// Kinds of Resources
	Namespaces     = "namespaces"
	Services       = "services"
	Endpoints      = "endpoints"
	Configmaps     = "configmaps"
	Ingresses      = "ingresses"
	Routes         = "routes"
	Secrets        = "secrets"
	IngressClasses = "ingressclasses"

	hubModeInterval = 30 * time.Second //Hubmode ConfigMap resync interval
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
		IRulesStore:            IRulesStore{},
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
		eventChan:              params.EventChan,
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
	}
	manager.processedResources = make(map[string]bool)
	manager.IRulesStore.IRulesMap = make(map[NameRef]*IRule)
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
			log.Debugf("[CORE] Periodic enqueue of Service from Namespace: %v", namespace)
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
				if appMgr.resources.Delete(key, "") {
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
}

type appInformer struct {
	namespace        string
	cfgMapInformer   cache.SharedIndexInformer
	svcInformer      cache.SharedIndexInformer
	endptInformer    cache.SharedIndexInformer
	ingInformer      cache.SharedIndexInformer
	routeInformer    cache.SharedIndexInformer
	nodeInformer     cache.SharedIndexInformer
	secretInformer   cache.SharedIndexInformer
	ingClassInformer cache.SharedIndexInformer
	stopCh           chan struct{}
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
		namespace: namespace,
		stopCh:    make(chan struct{}),
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
		endptInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				Endpoints,
				namespace,
				everything,
			),
			&v1.Endpoints{},
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

	if true == appMgr.manageIngress {
		log.Infof("[CORE] Watching Ingress resources.")
		// TODO Remove the version comparison once v1beta1.Ingress is deprecated in k8s 1.22
		out := semver.Compare(appMgr.K8sVersion, "v1.19.0")
		if out >= 0 {
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
			appInf.ingInformer = cache.NewSharedIndexInformer(
				cache.NewFilteredListWatchFromClient(
					appMgr.restClientv1beta1,
					Ingresses,
					namespace,
					everything,
				),
				&v1beta1.Ingress{},
				resyncPeriod,
				cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			)
		}

	} else {
		log.Infof("[CORE] Not watching Ingress resources.")
	}

	if false != appMgr.manageConfigMaps {
		appMgr.configMapLabel = cfgMapSelector.String()
		cfgMapOptions := func(options *metav1.ListOptions) {
			options.LabelSelector = appMgr.configMapLabel
		}
		log.Infof("[CORE] Watching ConfigMap resources.")
		//If Hubmode is enabled, process configmaps every 30 seconds to process unwatched namespace deployments
		syncInterval := resyncPeriod
		if appMgr.hubMode {
			syncInterval = hubModeInterval
		}
		appInf.cfgMapInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				appMgr.restClientv1,
				Configmaps,
				namespace,
				cfgMapOptions,
			),
			&v1.ConfigMap{},
			syncInterval,
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
		// If Hubmode is enabled, process configmaps every 30 seconds to process unwatched namespace deployments
		syncInterval := resyncPeriod
		if appMgr.hubMode {
			syncInterval = hubModeInterval
		}
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
			syncInterval,
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

	appInf.endptInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueEndpoints(obj, OprTypeCreate) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueEndpoints(cur, OprTypeUpdate) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueEndpoints(obj, OprTypeDelete) },
		},
		resyncPeriod,
	)
	appInf.secretInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			// Making all operation types as update because each change in secret will update the ingress/configmap
			AddFunc:    func(obj interface{}) { appMgr.enqueueSecrets(obj, OprTypeUpdate) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueSecrets(cur, OprTypeUpdate) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueSecrets(obj, OprTypeUpdate) },
		},
		resyncPeriod,
	)

	if true == appMgr.manageIngress {
		log.Infof("[CORE] Handling Ingress resource events.")
		appInf.ingInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeCreate) },
				UpdateFunc: func(old, cur interface{}) { appMgr.enqueueIngress(cur, OprTypeUpdate) },
				DeleteFunc: func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeDelete) },
			},
			resyncPeriod,
		)
		// TODO Remove the version comparison once v1beta1.Ingress is deprecated in k8s 1.22
		out := semver.Compare(appMgr.K8sVersion, "v1.19.0")
		if out >= 0 {
			appInf.ingClassInformer.AddEventHandlerWithResyncPeriod(
				&cache.ResourceEventHandlerFuncs{
					//AddFunc:    func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeCreate) },
					//UpdateFunc: func(old, cur interface{}) { appMgr.enqueueIngress(cur, OprTypeUpdate) },
					//DeleteFunc: func(obj interface{}) { appMgr.enqueueIngress(obj, OprTypeDelete) },
				},
				resyncPeriod,
			)
		}
	} else {
		log.Infof("[CORE] Not handling Ingress resource events.")
	}

	if nil != appMgr.routeClientV1 {
		appInf.routeInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { appMgr.enqueueRoute(obj, OprTypeCreate) },
				UpdateFunc: func(old, cur interface{}) { appMgr.enqueueRoute(cur, OprTypeUpdate) },
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

func (appMgr *Manager) enqueueEndpoints(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidEndpoints(obj); ok {
		for _, key := range keys {
			key.Operation = operation
			appMgr.vsQueue.Add(*key)
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

func (appMgr *Manager) enqueueRoute(obj interface{}, operation string) {
	if ok, keys := appMgr.checkValidRoute(obj); ok {
		for _, key := range keys {
			key.Operation = operation
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
	if nil != appInf.nodeInformer {
		go appInf.nodeInformer.Run(appInf.stopCh)
	}
	if nil != appInf.ingClassInformer {
		go appInf.ingClassInformer.Run(appInf.stopCh)
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
	if nil != appInf.nodeInformer {
		cacheSyncs = append(cacheSyncs, appInf.nodeInformer.HasSynced)
	}
	if nil != appInf.ingClassInformer {
		cacheSyncs = append(cacheSyncs, appInf.ingClassInformer.HasSynced)
	}
	cache.WaitForCacheSync(
		appInf.stopCh,
		cacheSyncs...,
	)
}

func (appInf *appInformer) stopInformers() {
	close(appInf.stopCh)
}

func (appMgr *Manager) IsNodePort() bool {
	return appMgr.isNodePort
}

func (appMgr *Manager) UseNodeInternal() bool {
	return appMgr.useNodeInternal
}

func (appMgr *Manager) Run(stopCh <-chan struct{}) {
	go appMgr.runImpl(stopCh)
}

func (appMgr *Manager) runImpl(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer appMgr.vsQueue.ShutDown()
	defer appMgr.nsQueue.ShutDown()

	if nil != appMgr.nsInformer {
		// Using one worker for namespace label changes.
		appMgr.startAndSyncNamespaceInformer(stopCh)
		go wait.Until(appMgr.namespaceWorker, time.Second, stopCh)
	}

	appMgr.startAndSyncAppInformers()

	// Using only one virtual server worker currently.
	go wait.Until(appMgr.virtualServerWorker, time.Second, stopCh)

	<-stopCh
	appMgr.stopAppInformers()
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
	if nil != appMgr.as3Informer {
		appMgr.as3Informer.start()
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
	if nil != appMgr.as3Informer {
		appMgr.as3Informer.waitForCacheSync()
	}
}

func (appMgr *Manager) stopAppInformers() {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	for _, appInf := range appMgr.appInformers {
		appInf.stopInformers()
	}
	if nil != appMgr.as3Informer {
		appMgr.as3Informer.stopInformers()
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
		NsListOptions := metav1.ListOptions{
			LabelSelector: appMgr.WatchedNS.NamespaceLabel,
		}
		nsL, err := appMgr.kubeClient.CoreV1().Namespaces().List(context.TODO(), NsListOptions)
		if err != nil {
			log.Errorf("[CORE] Error getting Namespaces with Namespace label - %v.", err)
		}
		for _, v := range nsL.Items {
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

	cmOptions := metav1.ListOptions{
		LabelSelector: appMgr.configMapLabel,
	}

	rtOptions := metav1.ListOptions{
		LabelSelector: appMgr.routeConfig.RouteLabel,
	}

	for _, ns := range appMgr.GetAllWatchedNamespaces() {
		services, err := appMgr.kubeClient.CoreV1().Services(ns).List(context.TODO(), metav1.ListOptions{})
		for _, svc := range services.Items {
			if ok, _ := appMgr.checkValidService(&svc); ok {
				qLen++
			}
		}
		if err != nil {
			log.Errorf("[CORE] Failed getting Services from watched namespace : %v.", err)
			return appMgr.vsQueue.Len()
		}

		if false != appMgr.manageConfigMaps {
			cms, err := appMgr.kubeClient.CoreV1().ConfigMaps(ns).List(context.TODO(), cmOptions)
			for _, cm := range cms.Items {
				if ok, _ := appMgr.checkValidConfigMap(&cm, OprTypeCreate); ok {
					qLen++
				}
			}
			if err != nil {
				log.Errorf("[CORE] Failed getting Configmaps from watched namespace : %v.", err)
				return appMgr.vsQueue.Len()
			}
		}

		if nil != appMgr.routeClientV1 {
			rts, err := appMgr.routeClientV1.Routes(ns).List(context.TODO(), rtOptions)
			for _, rt := range rts.Items {
				if ok, _ := appMgr.checkValidRoute(&rt); ok {
					qLen++
				}
			}
			if err != nil {
				log.Errorf("[CORE] Failed getting Routes from watched namespace : %v.", err)
				return appMgr.vsQueue.Len()
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
		log.Debugf("[CORE] Finished syncing virtual servers %+v in namespace %+v (%v), %v/%v",
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
			if _, ok := appMgr.processedResources[resKey]; ok {
				if !appMgr.steadyState && appMgr.processedItems >= appMgr.queueLen-1 {
					appMgr.deployResource()
					appMgr.steadyState = true
				}
				return nil
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
			appMgr.agentCfgMap[key].Operation = OprTypeDelete
			stats.vsDeleted += 1
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
				//TODO: Sorting endpoints members
				members := appMgr.getEndpoints(selector, sKey.Namespace)

				if _, ok := appMgr.agentCfgMapSvcCache[key]; !ok {
					if len(members) != 0 {
						appMgr.agentCfgMapSvcCache[key] = &SvcEndPointsCache{
							members:     members,
							labelString: selector,
						}
						stats.poolsUpdated += 1
						log.Debugf("[CORE] Discovered members for service %v is %v", key, members)
					}
				} else {
					sc := &SvcEndPointsCache{
						members:     members,
						labelString: selector,
					}
					if len(sc.members) != len(appMgr.agentCfgMapSvcCache[key].members) || !reflect.DeepEqual(sc, appMgr.agentCfgMapSvcCache[key]) {
						stats.poolsUpdated += 1
						appMgr.agentCfgMapSvcCache[key] = sc
						log.Debugf("[CORE] Discovered members for service %v is %v", key, members)
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
			if ok := appMgr.processAgentLabels(cm.Labels, cm.Name, cm.Namespace); ok {
				agntCfgMap := new(AgentCfgMap)
				agntCfgMap.Init(cm.Name, cm.Namespace, cm.Data["template"], cm.Labels, appMgr.getEndpoints)
				key := cm.Namespace + "/" + cm.Name
				if cfgMap, ok := appMgr.agentCfgMap[key]; ok {
					if appMgr.hubMode || cfgMap.Data != cm.Data["template"] || cm.Labels["as3"] != cfgMap.Label["as3"] || cm.Labels["overrideAS3"] != cfgMap.Label["overrideAS3"] {
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
				secret, err := appMgr.kubeClient.CoreV1().Secrets(cm.ObjectMeta.Namespace).
					Get(context.TODO(), profile.Name, metav1.GetOptions{})
				if err != nil {
					// No secret, so we assume the profile is a BIG-IP default
					log.Debugf("[CORE] No Secret with name '%s' in namespace '%s', "+
						"parsing secretName as path instead.", profile.Name, sKey.Namespace)
					continue
				}

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

		rsName := rsCfg.GetName()
		ok, found, updated := appMgr.handleConfigForType(
			rsCfg, sKey, rsMap, rsName, svcPortMap,
			svc, appInf, []string{}, nil)
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

	return nil
}

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func prepareIngressSSLContext(appMgr *Manager, ing *v1beta1.Ingress) {
	// Prepare Ingress SSL Transient Context
	for _, tls := range ing.Spec.TLS {
		// Check if TLS Secret already exists
		if _, ok := appMgr.rsrcSSLCtxt[tls.SecretName]; ok {
			continue
		}
		// Check if profile is contained in a Secret
		secret, err := appMgr.kubeClient.CoreV1().Secrets(ing.ObjectMeta.Namespace).
			Get(context.TODO(), tls.SecretName, metav1.GetOptions{})
		if err != nil {
			appMgr.rsrcSSLCtxt[tls.SecretName] = nil
			continue
		}
		appMgr.rsrcSSLCtxt[tls.SecretName] = secret
	}
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
	ingByIndex, err := appInf.ingInformer.GetIndexer().ByIndex(
		"namespace", sKey.Namespace)
	if nil != err {
		log.Warningf("[CORE] Unable to list ingresses for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}
	appMgr.TeemData.Lock()
	appMgr.TeemData.ResourceType.Ingresses[sKey.Namespace] = len(ingByIndex)
	appMgr.TeemData.Unlock()
	svcFwdRulesMap := NewServiceFwdRuleMap()
	for _, obj := range ingByIndex {
		// We need to look at all ingresses in the store, parse the data blob,
		// and process ingresses that has changed.
		//TODO remove the switch case and checkV1beta1Ingress function
		switch obj.(type) {
		case *v1beta1.Ingress:
			ing := obj.(*v1beta1.Ingress)
			// TODO: Each ingress resource must be processed for its associated service
			//  only, existing implementation processes all services available in k8s
			//  and this approach degrades the performance of processing Ingress resources
			if ing.ObjectMeta.Namespace != sKey.Namespace {
				continue
			}
			if ok := appMgr.checkV1Beta1SingleServivceIngress(ing); !ok {
				continue
			}
			if appMgr.useSecrets {
				prepareIngressSSLContext(appMgr, ing)
			}
			// Resolve first Ingress Host name (if required)
			_, exists := ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation]
			if !exists && appMgr.resolveIng != "" {
				appMgr.resolveIngressHost(ing, sKey.Namespace)
			}
			// Get a list of dependencies removed so their pools can be removed.
			objKey, objDeps := NewObjectDependencies(ing)
			svcDepKey := ObjectDependency{
				Kind:      ServiceDep,
				Namespace: sKey.Namespace,
				Name:      sKey.ServiceName,
			}
			ingressLookupFunc := func(key ObjectDependency) bool {
				if key.Kind != "Ingress" {
					return false
				}
				ingKey := key.Namespace + "/" + key.Name
				_, ingFound, _ := appInf.ingInformer.GetIndexer().GetByKey(ingKey)
				return !ingFound
			}
			// So that later the create event of the same resource will not processed, unnecessarily
			appMgr.processedResourcesMutex.Lock()
			appMgr.processedResources[prepareResourceKey(Ingresses, sKey.Namespace, ing.Name)] = true
			appMgr.processedResourcesMutex.Unlock()
			depsAdded, depsRemoved := appMgr.resources.UpdateDependencies(
				objKey, objDeps, svcDepKey, ingressLookupFunc)
			portStructs := appMgr.virtualPorts(ing)
			for i, portStruct := range portStructs {
				rsCfg := appMgr.createRSConfigFromIngress(
					ing,
					appMgr.resources,
					sKey.Namespace,
					appInf.svcInformer.GetIndexer(),
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
				updated := appMgr.handleIngressTls(rsCfg, ing, svcFwdRulesMap)
				if updated {
					stats.cpUpdated += 1
				}

				// Handle Ingress health monitors
				rsName := rsCfg.GetName()
				hmStr, found := ing.ObjectMeta.Annotations[HealthMonitorAnnotation]
				if found {
					var monitors AnnotationHealthMonitors
					err := json.Unmarshal([]byte(hmStr), &monitors)
					if err != nil {
						msg := "Unable to parse health monitor JSON array " + hmStr + " : " + err.Error()
						log.Errorf("[CORE] %s", msg)
						appMgr.recordIngressEvent(ing, "InvalidData", msg)
					} else {
						if nil != ing.Spec.Backend {
							fullPoolName := fmt.Sprintf("/%s/%s", rsCfg.Virtual.Partition,
								FormatIngressPoolName(sKey.Namespace, sKey.ServiceName))
							appMgr.handleSingleServiceHealthMonitors(
								rsName, fullPoolName, rsCfg, ing, monitors)
						} else {
							appMgr.handleMultiServiceHealthMonitors(
								rsName, rsCfg, ing, monitors)
						}
					}
					rsCfg.SortMonitors()
				}
				// Collect all service names on this Ingress.
				// Used in handleConfigForType.
				svcs := getIngressBackend(ing)
				// Remove any dependencies no longer used by this Ingress
				for _, dep := range depsRemoved {
					if dep.Kind == ServiceDep {
						cfgChanged, svcKey := rsCfg.RemovePool(
							dep.Namespace, FormatIngressPoolName(dep.Namespace, dep.Name), appMgr.mergedRulesMap)
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
					rsCfg, sKey, rsMap, rsName, svcPortMap,
					svc, appInf, svcs, obj); !ok {
					stats.vsUpdated += updated
					continue
				} else {
					stats.vsFound += found
					stats.vsUpdated += updated
					if updated > 0 {
						msg := "Created a ResourceConfig " + rsCfg.GetName() + " for the Ingress."
						appMgr.recordIngressEvent(ing, "ResourceConfigured", msg)
					}
				}
				if i < len(portStructs)-1 {
					//ingress ip is same for rscfg even for different port structs.
					//Process only once.
					continue
				}
				// Set the Ingress Status IP address
				appMgr.setIngressStatus(ing, rsCfg, appInf)
			}
		default:
			ing := obj.(*netv1.Ingress)
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
			// Get a list of dependencies removed so their pools can be removed.
			objKey, objDeps := NewObjectDependencies(ing)
			svcDepKey := ObjectDependency{
				Kind:      ServiceDep,
				Namespace: sKey.Namespace,
				Name:      sKey.ServiceName,
			}
			ingressLookupFunc := func(key ObjectDependency) bool {
				if key.Kind != "Ingress" {
					return false
				}
				ingKey := key.Namespace + "/" + key.Name
				_, ingFound, _ := appInf.ingInformer.GetIndexer().GetByKey(ingKey)
				return !ingFound
			}
			// Mark each resource as it is already processed
			// So that later the create event of the same resource will not processed, unnecessarily
			appMgr.processedResourcesMutex.Lock()
			appMgr.processedResources[prepareResourceKey(Ingresses, sKey.Namespace, ing.Name)] = true
			appMgr.processedResourcesMutex.Unlock()
			depsAdded, depsRemoved := appMgr.resources.UpdateDependencies(
				objKey, objDeps, svcDepKey, ingressLookupFunc)
			portStructs := appMgr.v1VirtualPorts(ing)
			for i, portStruct := range portStructs {
				rsCfg := appMgr.createRSConfigFromV1Ingress(
					ing,
					appMgr.resources,
					sKey.Namespace,
					appInf.svcInformer.GetIndexer(),
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
				rsName := rsCfg.GetName()
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
							fullPoolName := fmt.Sprintf("/%s/%s", rsCfg.Virtual.Partition,
								FormatIngressPoolName(sKey.Namespace, sKey.ServiceName))
							appMgr.handleSingleServiceV1IngressHealthMonitors(
								rsName, fullPoolName, rsCfg, ing, monitors)
						} else {
							appMgr.handleMultiServiceV1IngressHealthMonitors(
								rsName, rsCfg, ing, monitors)
						}
					}
					rsCfg.SortMonitors()
				}
				// Collect all service names on this Ingress.
				// Used in handleConfigForType.
				svcs := getIngressV1Backend(ing)
				// Remove any dependencies no longer used by this Ingress
				for _, dep := range depsRemoved {
					if dep.Kind == ServiceDep {
						cfgChanged, svcKey := rsCfg.RemovePool(
							dep.Namespace, FormatIngressPoolName(dep.Namespace, dep.Name), appMgr.mergedRulesMap)
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
					rsCfg, sKey, rsMap, rsName, svcPortMap,
					svc, appInf, svcs, obj); !ok {
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

		}

	}
	if len(svcFwdRulesMap) > 0 {
		httpsRedirectDg := NameRef{
			Name:      HttpsRedirectDgName,
			Partition: DEFAULT_PARTITION,
		}
		if _, found := dgMap[httpsRedirectDg]; !found {
			dgMap[httpsRedirectDg] = make(DataGroupNamespaceMap)
		}
		svcFwdRulesMap.AddToDataGroup(dgMap[httpsRedirectDg])
	}

	return nil
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

	routePathMap := make(map[string]string)
	for _, route := range routeByIndex {
		if route.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}

		var key string
		if route.Spec.Path == "/" || len(route.Spec.Path) == 0 {
			key = route.Spec.Host
		} else {
			key = route.Spec.Host + route.Spec.Path
		}
		if _, ok := routePathMap[key]; ok {
			if _, ok := appMgr.processedResources[prepareResourceKey(Routes, sKey.Namespace, route.Name)]; !ok {
				// Adding the entry for resource so logs does not print repeatedly
				log.Warningf("[CORE]  Route exist with same host: %v and path: %v", route.Spec.Host, route.Spec.Path)
			}
			// Putting the value as false so that route status gets updated
			appMgr.processedResourcesMutex.Lock()
			appMgr.processedResources[prepareResourceKey(Routes, sKey.Namespace, route.Name)] = false
			appMgr.processedResourcesMutex.Unlock()
			// Removing the route related object from appMgr.resources

			appMgr.resources.RemoveDependency(ObjectDependency{Kind: "Route", Namespace: route.Namespace, Name: route.Name})
			rules := GetRouteAssociatedRuleNames(route)
			for _, ruleName := range rules {
				appMgr.resources.UpdatePolicy(appMgr.routeConfig.HttpsVs, SecurePolicyName, ruleName)
				appMgr.resources.UpdatePolicy(appMgr.routeConfig.HttpVs, InsecurePolicyName, ruleName)
			}
			continue
		} else {
			routePathMap[key] = route.Spec.Host
		}
		// Mark each resource  as it is already processed during init Time
		// So that later the create event of the same resource will not processed, unnecessarily
		appMgr.processedResourcesMutex.Lock()
		appMgr.processedResources[prepareResourceKey(Routes, sKey.Namespace, route.Name)] = true
		appMgr.processedResourcesMutex.Unlock()

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
		svcDepKey := ObjectDependency{
			Kind:      ServiceDep,
			Namespace: sKey.Namespace,
			Name:      sKey.ServiceName,
		}
		routeLookupFunc := func(key ObjectDependency) bool {
			if key.Kind != "Route" {
				return false
			}
			routeKey := key.Namespace + "/" + key.Name
			_, routeFound, _ := appInf.routeInformer.GetIndexer().GetByKey(routeKey)
			return !routeFound
		}
		_, depsRemoved := appMgr.resources.UpdateDependencies(
			objKey, objDeps, svcDepKey, routeLookupFunc)

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

			rsName := rsCfg.GetName()

			// Handle Route health monitors
			hmStr, exists := route.ObjectMeta.Annotations[HealthMonitorAnnotation]
			if exists {
				var monitors AnnotationHealthMonitors
				err := json.Unmarshal([]byte(hmStr), &monitors)
				if err != nil {
					log.Errorf("[CORE] Unable to parse health monitor JSON array '%v': %v",
						hmStr, err)
				} else {
					appMgr.handleRouteHealthMonitors(rsName, pool, rsCfg, monitors, stats)
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

			_, found, updated := appMgr.handleConfigForType(
				rsCfg, sKey, rsMap, rsName, svcPortMap,
				svc, appInf, svcNames, nil)
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
		svcFwdRulesMap.AddToDataGroup(dgMap[httpsRedirectDg])
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

// Return the required ports for Ingress VS (depending on sslRedirect/allowHttp vals)
// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) virtualPorts(ing *v1beta1.Ingress) []portStruct {
	var httpPort int32
	var httpsPort int32
	if port, ok := ing.ObjectMeta.Annotations[F5VsHttpPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpPort = int32(p)
	} else {
		httpPort = DEFAULT_HTTP_PORT
	}
	if port, ok := ing.ObjectMeta.Annotations[F5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		IngressAllowHttp, false)

	http := portStruct{
		protocol: "http",
		port:     httpPort,
	}
	https := portStruct{
		protocol: "https",
		port:     httpsPort,
	}
	var ports []portStruct
	if len(ing.Spec.TLS) > 0 {
		if sslRedirect || allowHttp {
			// States 2,3; both HTTP and HTTPS
			// 2 virtual servers needed
			ports = append(ports, http)
			ports = append(ports, https)
		} else {
			// State 1; HTTPS only
			ports = append(ports, https)
		}
	} else {
		// HTTP only, no TLS
		ports = append(ports, http)
	}
	return ports
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

// Common handling function for ConfigMaps, Ingresses, and Routes
func (appMgr *Manager) handleConfigForTypeIngress(
	rsCfg *ResourceConfig,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	rsName string,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
	currResourceSvcs []string, // Used for Ingress/Routes
	obj interface{}, // Used for writing events
) (bool, int, int) {
	vsFound := 0
	vsUpdated := 0
	var pool Pool
	plIdx := 0
	for j, backendSvc := range currResourceSvcs {
		//get current resource skey and port
		svcBackend := sKey.Namespace + "/" + backendSvc
		//backend svc key of ingress
		CurrsvcKey := serviceQueueKey{
			ServiceName: backendSvc,
			Namespace:   sKey.Namespace,
		}
		backend, _, _ := appInf.svcInformer.GetIndexer().GetByKey(svcBackend)
		deactivated := false
		found := false
		// Get the pool that matches the sKey we are processing
		for i, pl := range rsCfg.Pools {
			if pl.ServiceName == CurrsvcKey.ServiceName &&
				poolInNamespace(rsCfg, pl.Name, sKey.Namespace) {
				pool = pl
				plIdx = i
				found = true
				break
			}
		}
		if !found {
			//For multi-service continue processing remaining services.
			if j < len(currResourceSvcs)-1 {
				continue
			}
			return false, vsFound, vsUpdated
		}
		// Make sure pool members from the old config are applied to the new
		// config pools.
		appMgr.syncPoolMembers(rsName, rsCfg)

		svcKey := ServiceKey{
			Namespace:   sKey.Namespace,
			ServiceName: pool.ServiceName,
			ServicePort: pool.ServicePort,
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
			cfgList := rsMap[pool.ServicePort]
			if serviceMatch(currResourceSvcs, sKey) {
				if len(cfgList) == 1 && cfgList[0].GetName() == rsName {
					delete(rsMap, pool.ServicePort)
				} else if len(cfgList) > 1 {
					for index, val := range cfgList {
						if val.GetName() == rsName {
							cfgList = append(cfgList[:index], cfgList[index+1:]...)
						}
					}
					rsMap[pool.ServicePort] = cfgList
				}
			}

			bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "port-not-found").Set(0)
			if _, ok := svcPortMap[pool.ServicePort]; !ok {
				log.Debugf("[CORE] Process Service delete - name: %v namespace: %v",
					pool.ServiceName, svcKey.Namespace)
				log.Infof("[CORE] Port '%v' for service '%v' was not found.",
					pool.ServicePort, pool.ServiceName)
				bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "port-not-found").Set(1)
				bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(0)
				if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
					vsUpdated += 1
				}
				deactivated = true
			}

			bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "service-not-found").Set(0)

			// Update pool members.
			vsFound += 1
			correctBackend := true
			var reason string
			var msg string

			if svc.ObjectMeta.Labels["component"] == "apiserver" && svc.ObjectMeta.Labels["provider"] == "kubernetes" {
				appMgr.exposeKubernetesService(svc, svcKey, rsCfg, appInf, plIdx)
			} else {
				if appMgr.IsNodePort() {
					correctBackend, reason, msg =
						appMgr.updatePoolMembersForNodePort(svc, svcKey, rsCfg, plIdx)
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
						switch obj.(type) {
						case *v1beta1.Ingress:
							appMgr.recordIngressEvent(obj.(*v1beta1.Ingress), reason, msg)
						default:
							appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), reason, msg)

						}
					}
				}
			}

			if !deactivated {
				bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(1)
			}
		} else {
			// The service is gone, de-activate it in the config.
			log.Infof("[CORE] Service '%v' has not been found.", pool.ServiceName)
			bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "service-not-found").Set(1)
			bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(0)
			if !deactivated {
				deactivated = true
				if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
					vsUpdated += 1
				}
			}
			// If this is an Ingress resource, add an event that the service wasn't found
			if obj != nil {
				msg := "Service " + pool.ServiceName + " has not been found."
				switch obj.(type) {
				case *v1beta1.Ingress:
					appMgr.recordIngressEvent(obj.(*v1beta1.Ingress), "ServiceNotFound", msg)
				default:
					appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), "ServiceNotFound", msg)

				}
			}
			//Continue processing other services for multi-svc backend
			if j < len(currResourceSvcs)-1 {
				continue
			}
			return false, vsFound, vsUpdated
		}
		if vsUpdated > 0 && !appMgr.processAllMultiSvc(len(rsCfg.Pools),
			rsCfg.GetName()) {
			vsUpdated -= 1
			vsFound -= 1
		}
	}

	return true, vsFound, vsUpdated
}

// Common handling function for ConfigMaps, Ingresses, and Routes
func (appMgr *Manager) handleConfigForType(
	rsCfg *ResourceConfig,
	sKey serviceQueueKey,
	rsMap ResourceMap,
	rsName string,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
	currResourceSvcs []string, // Used for Ingress/Routes
	obj interface{}, // Used for writing events
) (bool, int, int) {
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
		return false, vsFound, vsUpdated
	}

	// Make sure pool members from the old config are applied to the new
	// config pools.
	appMgr.syncPoolMembers(rsName, rsCfg)

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
		if len(cfgList) == 1 && cfgList[0].GetName() == rsName {
			delete(rsMap, pool.ServicePort)
		} else if len(cfgList) > 1 {
			for index, val := range cfgList {
				if val.GetName() == rsName {
					cfgList = append(cfgList[:index], cfgList[index+1:]...)
				}
			}
			rsMap[pool.ServicePort] = cfgList
		}
	}

	deactivated := false
	bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "port-not-found").Set(0)
	if _, ok := svcPortMap[pool.ServicePort]; !ok {
		log.Debugf("[CORE] Process Service delete - name: %v namespace: %v",
			pool.ServiceName, svcKey.Namespace)
		log.Infof("[CORE] Port '%v' for service '%v' was not found.",
			pool.ServicePort, pool.ServiceName)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "port-not-found").Set(1)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(0)
		if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
			vsUpdated += 1
		}
		deactivated = true
	}

	bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "service-not-found").Set(0)
	if nil == svc {
		// The service is gone, de-activate it in the config.
		log.Infof("[CORE] Service '%v' has not been found.", pool.ServiceName)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "service-not-found").Set(1)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(0)

		if !deactivated {
			deactivated = true
			if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
				vsUpdated += 1
			}
		}

		// If this is an Ingress resource, add an event that the service wasn't found
		if obj != nil {
			msg := "Service " + pool.ServiceName + " has not been found."
			switch obj.(type) {
			case *v1beta1.Ingress:
				appMgr.recordIngressEvent(obj.(*v1beta1.Ingress), "ServiceNotFound", msg)
			default:
				appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), "ServiceNotFound", msg)

			}
		}
		return false, vsFound, vsUpdated
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
			correctBackend, reason, msg =
				appMgr.updatePoolMembersForNodePort(svc, svcKey, rsCfg, plIdx)
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
				switch obj.(type) {
				case *v1beta1.Ingress:
					appMgr.recordIngressEvent(obj.(*v1beta1.Ingress), reason, msg)
				default:
					appMgr.recordV1IngressEvent(obj.(*netv1.Ingress), reason, msg)

				}
			}
		}
	}

	if !deactivated {
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(1)
	}

	return true, vsFound, vsUpdated
}

func (appMgr *Manager) syncPoolMembers(rsName string, rsCfg *ResourceConfig) {
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if oldCfg, exists := appMgr.resources.GetByName(rsName); exists {
		for i, newPool := range rsCfg.Pools {
			for _, oldPool := range oldCfg.Pools {
				if oldPool.Name == newPool.Name {
					rsCfg.Pools[i].Members = oldPool.Members
				}
			}
		}
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
	rsName string,
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
	rsName string,
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

func (appMgr *Manager) processAllMultiSvc(numPools int, rsName string) bool {
	// If multi-service and we haven't yet configured keys/cfgs for each service,
	// then we don't want to update
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	_, keys := appMgr.resources.GetAllWithName(rsName)
	if len(keys) != numPools {
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
			rsName := cfg.GetName()
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
	for _, cfg := range appMgr.resources.GetAllResources() {
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
				_, ok := appMgr.resources.Get(key, cfg.GetName())
				if pool.ServiceName == svcName && poolNS == namespace && (!ok || !svcFound) {
					if updated, svcKey := cfg.RemovePool(namespace, pool.Name, appMgr.mergedRulesMap); updated {
						appMgr.resources.DeleteKeyRefLocked(*svcKey, cfg.GetName())
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

// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) setIngressStatus(
	ing *v1beta1.Ingress,
	rsCfg *ResourceConfig,
	appInf *appInformer,
) {
	// Set the ingress status to include the virtual IP
	ip, _ := Split_ip_with_route_domain(rsCfg.Virtual.VirtualAddress.BindAddr)
	lbIngress := v1.LoadBalancerIngress{IP: ip}
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, lbIngress)
	} else if ing.Status.LoadBalancer.Ingress[0].IP != ip {
		ing.Status.LoadBalancer.Ingress[0] = lbIngress
	} else {
		return
	}
	go appMgr.updateIngressStatus(ing, rsCfg, appInf)
}
func (appMgr *Manager) updateIngressStatus(ing *v1beta1.Ingress, rsCfg *ResourceConfig, appInf *appInformer) {
	ingKey := ing.Namespace + "/" + ing.Name
	_, ingFound, _ := appInf.ingInformer.GetIndexer().GetByKey(ingKey)
	if ingFound {
		_, updateErr := appMgr.kubeClient.ExtensionsV1beta1().
			Ingresses(ing.ObjectMeta.Namespace).UpdateStatus(context.TODO(), ing, metav1.UpdateOptions{})
		if nil != updateErr {
			// Multi-service causes the controller to try to update the status multiple times
			// at once. Ignore this error.
			if strings.Contains(updateErr.Error(), "object has been modified") {
				return
			}
			warning := "Error when setting Ingress status IP for virtual server " + rsCfg.GetName() + ": " + updateErr.Error()
			log.Warning(warning)
			appMgr.recordIngressEvent(ing, "StatusIPError", warning)
		}
	}
}

// Resolve the first host name in an Ingress and use the IP address as the VS address
// TODO remove the function once v1beta1.Ingress is deprecated in k8s 1.22
func (appMgr *Manager) resolveIngressHost(ing *v1beta1.Ingress, namespace string) {
	var host, ipAddress string
	var err error
	var netIPs []net.IP
	logDNSError := func(msg string) {
		log.Warning(msg)
		appMgr.recordIngressEvent(ing, "DNSResolutionError", msg)
	}

	if nil != ing.Spec.Rules {
		// Use the host from the first rule
		host = ing.Spec.Rules[0].Host
		if host == "" {
			// Host field is empty
			logDNSError("First host is empty on Ingress " + ing.ObjectMeta.Name + "; cannot resolve.")
			return
		}
	} else {
		logDNSError("No host found for DNS resolution on Ingress " + ing.ObjectMeta.Name)
		return
	}

	if appMgr.resolveIng == "LOOKUP" {
		// Use local DNS
		netIPs, err = net.LookupIP(host)
		if nil != err {
			logDNSError("Error while resolving host " + host + ": " + err.Error())
			return
		} else {
			if len(netIPs) > 1 {
				log.Warningf(
					"Resolved multiple IP addresses for host '%s', "+
						"choosing first resolved address.", host)
			}
			ipAddress = netIPs[0].String()
		}
	} else {
		// Use custom DNS server
		port := "53"
		customDNS := appMgr.resolveIng
		// Grab the port if it exists
		slice := strings.Split(customDNS, ":")
		if _, err = strconv.Atoi(slice[len(slice)-1]); err == nil {
			port = slice[len(slice)-1]
		}
		isIP := net.ParseIP(customDNS)
		if isIP == nil {
			// customDNS is not an IPAddress, it is a hostname that we need to resolve first
			netIPs, err = net.LookupIP(customDNS)
			if nil != err {
				logDNSError("Error while resolving host " + appMgr.resolveIng + ": " + err.Error())
				return
			}
			customDNS = netIPs[0].String()
		}
		client := dns.Client{}
		msg := dns.Msg{}
		msg.SetQuestion(host+".", dns.TypeA)
		var res *dns.Msg
		res, _, err = client.Exchange(&msg, customDNS+":"+port)
		if nil != err {
			logDNSError("Error while resolving host " + host + " using DNS server " + appMgr.resolveIng + ": " + err.Error())
			return
		} else if len(res.Answer) == 0 {
			logDNSError("No results for host " + host + " using DNS server " + appMgr.resolveIng)
			return
		}
		Arecord := res.Answer[0].(*dns.A)
		ipAddress = Arecord.A.String()
	}

	// Update the virtual-server annotation with the resolved IP Address
	if ing.ObjectMeta.Annotations == nil {
		ing.ObjectMeta.Annotations = make(map[string]string)
	}
	ing.ObjectMeta.Annotations[F5VsBindAddrAnnotation] = ipAddress
	_, err = appMgr.kubeClient.ExtensionsV1beta1().Ingresses(namespace).Update(context.TODO(), ing, metav1.UpdateOptions{})
	if nil != err {
		msg := "Error while setting virtual-server IP for Ingress " + ing.ObjectMeta.Name + ": " + err.Error()
		log.Warning(msg)
		appMgr.recordIngressEvent(ing, "IPAnnotationError", msg)
	} else {
		msg := "Resolved host " + host + " as " + ipAddress + "; set " + F5VsBindAddrAnnotation + " annotation with address."
		log.Info(msg)
		appMgr.recordIngressEvent(ing, "HostResolvedSuccessfully", msg)
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

func (appMgr *Manager) getEndpointsForNodePort(
	nodePort, port int32,
) []Member {
	nodes := appMgr.getNodesFromCache()
	var members []Member
	for _, v := range nodes {
		member := Member{
			Address: v.Addr,
			Port:    nodePort,
			SvcPort: port,
			Session: "user-enabled",
		}
		members = append(members, member)
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
		rsName := FormatConfigMapVSName(cm)
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
	obj interface{}, err error,
) {
	if nil != err {
		log.Warningf("[CORE] Unable to get list of nodes, err=%+v", err)
		return
	}

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
					Namespace:   key.Namespace,
					ServiceName: key.ServiceName,
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

//sort services by timestamp
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

func (appMgr *Manager) getEndpoints(selector, namespace string) []Member {
	var members []Member

	svcListOptions := metav1.ListOptions{
		LabelSelector: selector,
	}

	// Identify services that matches the given label
	var services *v1.ServiceList
	var err error
	if appMgr.hubMode {
		services, err = appMgr.kubeClient.CoreV1().Services(v1.NamespaceAll).List(context.TODO(), svcListOptions)
	} else {
		services, err = appMgr.kubeClient.CoreV1().Services(namespace).List(context.TODO(), svcListOptions)
	}

	if err != nil {
		log.Errorf("[CORE] Error getting service list. %v", err)
		return nil
	}

	if len(services.Items) > 1 {
		svcName := ""
		sort.Sort(byTimestamp(services.Items))
		//picking up the oldest service
		services.Items = services.Items[:1]

		for _, service := range services.Items {
			svcName += fmt.Sprintf("Service: %v, Namespace: %v,Timestamp: %v\n", service.Name, service.Namespace, service.GetCreationTimestamp())
		}

		log.Warningf("[CORE] Multiple Services are tagged for this pool. Using oldest service endpoints.\n%v", svcName)
	}

	for _, service := range services.Items {
		if appMgr.isNodePort == false { // Controller is in ClusterIP Mode
			endpointsList, err := appMgr.kubeClient.CoreV1().Endpoints(service.Namespace).List(context.TODO(),
				metav1.ListOptions{
					FieldSelector: "metadata.name=" + service.Name,
				},
			)
			if err != nil {
				log.Debugf("[CORE] Error getting endpoints for service %v", service.Name)
				continue
			}

			for _, endpoints := range endpointsList.Items {
				for _, subset := range endpoints.Subsets {
					for _, address := range subset.Addresses {
						for _, port := range subset.Ports {
							member := Member{
								Address: address.IP,
								Port:    port.Port,
								SvcPort: port.Port,
							}
							members = append(members, member)
						}

					}
				}
			}
		} else { // Controller is in NodePort mode.
			if service.Spec.Type == v1.ServiceTypeNodePort {
				for _, port := range service.Spec.Ports {
					members = append(members, appMgr.getEndpointsForNodePort(port.NodePort, port.Port)...)
				}
			} /* else {
				msg := fmt.Sprintf("[CORE] Requested service backend '%+v' not of NodePort type", service.Name)
				log.Debug(msg)
			}*/
		}
	}
	return members
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

func getIngressBackend(ing *v1beta1.Ingress) []string {
	// Collect all service names on this Ingress.
	// Used in handleConfigForType.
	services := make(map[string]bool)
	if nil != ing.Spec.Rules { // multi-service
		for _, rl := range ing.Spec.Rules {
			if nil != rl.IngressRuleValue.HTTP {
				for _, pth := range rl.IngressRuleValue.HTTP.Paths {
					services[pth.Backend.ServiceName] = true
				}
			}
		}
	} else { // single-service
		services[ing.Spec.Backend.ServiceName] = true
	}
	//unique svc list
	svcs := []string{}
	for key, _ := range services {
		svcs = append(svcs, key)
	}
	return svcs
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
