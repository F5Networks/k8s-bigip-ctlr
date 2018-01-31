/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
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
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/miekg/dns"
	routeapi "github.com/openshift/origin/pkg/route/api"
)

const DefaultConfigMapLabel = "f5type in (virtual-server)"
const vsStatusBindAddrAnnotation = "status.virtual-server.f5.com/ip"
const ingressSslRedirect = "ingress.kubernetes.io/ssl-redirect"
const ingressAllowHttp = "ingress.kubernetes.io/allow-http"
const healthMonitorAnnotation = "virtual-server.f5.com/health"
const k8sIngressClass = "kubernetes.io/ingress.class"
const f5VsBindAddrAnnotation = "virtual-server.f5.com/ip"
const f5VsHttpPortAnnotation = "virtual-server.f5.com/http-port"
const f5VsHttpsPortAnnotation = "virtual-server.f5.com/https-port"
const f5VsBalanceAnnotation = "virtual-server.f5.com/balance"
const f5VsPartitionAnnotation = "virtual-server.f5.com/partition"
const f5ClientSslProfileAnnotation = "virtual-server.f5.com/clientssl"
const f5ServerSslProfileAnnotation = "virtual-server.f5.com/serverssl"
const f5ServerSslSecureAnnotation = "virtual-server.f5.com/secure-serverssl"
const defaultSslServerCAName = "openshift_route_cluster_default-ca"

type ResourceMap map[int32][]*ResourceConfig

type Manager struct {
	resources         *Resources
	customProfiles    *CustomProfileStore
	irulesMap         IRulesMap
	intDgMap          InternalDataGroupMap
	kubeClient        kubernetes.Interface
	restClientv1      rest.Interface
	restClientv1beta1 rest.Interface
	routeClientV1     rest.Interface
	configWriter      writer.Writer
	initialState      bool
	// Use internal node IPs
	useNodeInternal bool
	// Running in nodeport (or cluster) mode
	isNodePort bool
	// Mutex to control access to node data
	// FIXME: Simple synchronization for now, it remains to be determined if we'll
	// need something more complicated (channels, etc?)
	oldNodesMutex sync.Mutex
	// Nodes from previous iteration of node polling
	oldNodes []string
	// Mutex for all informers (for informer CRUD)
	informersMutex sync.Mutex
	// Mutex for irulesMap
	irulesMutex sync.Mutex
	// Mutex for intDgMap
	intDgMutex sync.Mutex
	// App informer support
	vsQueue      workqueue.RateLimitingInterface
	appInformers map[string]*appInformer
	// Namespace informer support (namespace labels)
	nsQueue    workqueue.RateLimitingInterface
	nsInformer cache.SharedIndexInformer
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
	// Use Secrets for SSL Profiles
	useSecrets bool
	// Channel for emitting events
	eventChan chan interface{}
	// Where the schemas reside locally
	schemaLocal string
}

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	KubeClient        kubernetes.Interface
	RouteClientV1     rest.Interface
	ConfigWriter      writer.Writer
	UseNodeInternal   bool
	IsNodePort        bool
	RouteConfig       RouteConfig
	ResolveIngress    string
	DefaultIngIP      string
	NodeLabelSelector string
	UseSecrets        bool
	EventChan         chan interface{}
	// Package local for unit testing only
	restClient      rest.Interface
	initialState    bool
	broadcasterFunc NewBroadcasterFunc
	SchemaLocal     string
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

// Create and return a new app manager that meets the Manager interface
func NewManager(params *Params) *Manager {
	vsQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "virtual-server-controller")
	nsQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "namespace-controller")
	manager := Manager{
		resources:         NewResources(),
		customProfiles:    NewCustomProfiles(),
		irulesMap:         make(IRulesMap),
		intDgMap:          make(InternalDataGroupMap),
		kubeClient:        params.KubeClient,
		restClientv1:      params.restClient,
		restClientv1beta1: params.restClient,
		routeClientV1:     params.RouteClientV1,
		configWriter:      params.ConfigWriter,
		useNodeInternal:   params.UseNodeInternal,
		isNodePort:        params.IsNodePort,
		initialState:      params.initialState,
		routeConfig:       params.RouteConfig,
		nodeLabelSelector: params.NodeLabelSelector,
		resolveIng:        params.ResolveIngress,
		defaultIngIP:      params.DefaultIngIP,
		useSecrets:        params.UseSecrets,
		eventChan:         params.EventChan,
		vsQueue:           vsQueue,
		nsQueue:           nsQueue,
		appInformers:      make(map[string]*appInformer),
		eventNotifier:     NewEventNotifier(params.broadcasterFunc),
		schemaLocal:       params.SchemaLocal,
	}
	if nil != manager.kubeClient && nil == manager.restClientv1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.restClientv1 = manager.kubeClient.Core().RESTClient()
	}
	if nil != manager.kubeClient && nil == manager.restClientv1beta1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.restClientv1beta1 = manager.kubeClient.Extensions().RESTClient()
	}

	return &manager
}

func (appMgr *Manager) addIRule(name, partition, rule string) {
	appMgr.irulesMutex.Lock()
	defer appMgr.irulesMutex.Unlock()

	key := nameRef{
		Name:      name,
		Partition: partition,
	}
	appMgr.irulesMap[key] = NewIRule(name, partition, rule)
}

func (appMgr *Manager) addInternalDataGroup(name, partition string) {
	appMgr.intDgMutex.Lock()
	defer appMgr.intDgMutex.Unlock()

	key := nameRef{
		Name:      name,
		Partition: partition,
	}
	appMgr.intDgMap[key] = make(DataGroupNamespaceMap)
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
	appMgr.nsInformer = cache.NewSharedIndexInformer(
		newListWatchWithLabelSelector(
			appMgr.restClientv1,
			"namespaces",
			"",
			labelSelector,
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

func (appMgr *Manager) syncNamespace(nsName string) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing namespace %+v (%v)",
			nsName, endTime.Sub(startTime))
	}()
	_, exists, err := appMgr.nsInformer.GetIndexer().GetByKey(nsName)
	if nil != err {
		log.Warningf("Error looking up namespace '%v': %v\n", nsName, err)
		return err
	}

	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
	appInf, found := appMgr.getNamespaceInformerLocked(nsName)
	if exists && found {
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
		appMgr.eventNotifier.deleteNotifierForNamespace(nsName)
		appMgr.resources.Lock()
		defer appMgr.resources.Unlock()
		rsDeleted := 0
		appMgr.resources.ForEach(func(key serviceKey, cfg *ResourceConfig) {
			if key.Namespace == nsName {
				if appMgr.resources.Delete(key, "") {
					rsDeleted += 1
				}
			}
		})
		if rsDeleted > 0 {
			appMgr.outputConfigLocked()
		}
	}

	return nil
}

func (appMgr *Manager) GetWatchedNamespaces() []string {
	appMgr.informersMutex.Lock()
	defer appMgr.informersMutex.Unlock()
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
	Namespace   string
	ServiceName string
}

type appInformer struct {
	namespace      string
	cfgMapInformer cache.SharedIndexInformer
	svcInformer    cache.SharedIndexInformer
	endptInformer  cache.SharedIndexInformer
	ingInformer    cache.SharedIndexInformer
	routeInformer  cache.SharedIndexInformer
	stopCh         chan struct{}
}

func (appMgr *Manager) newAppInformer(
	namespace string,
	cfgMapSelector labels.Selector,
	resyncPeriod time.Duration,
) *appInformer {
	appInf := appInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
		cfgMapInformer: cache.NewSharedIndexInformer(
			newListWatchWithLabelSelector(
				appMgr.restClientv1,
				"configmaps",
				namespace,
				cfgMapSelector,
			),
			&v1.ConfigMap{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		svcInformer: cache.NewSharedIndexInformer(
			newListWatchWithLabelSelector(
				appMgr.restClientv1,
				"services",
				namespace,
				labels.Everything(),
			),
			&v1.Service{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		endptInformer: cache.NewSharedIndexInformer(
			newListWatchWithLabelSelector(
				appMgr.restClientv1,
				"endpoints",
				namespace,
				labels.Everything(),
			),
			&v1.Endpoints{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		ingInformer: cache.NewSharedIndexInformer(
			newListWatchWithLabelSelector(
				appMgr.restClientv1beta1,
				"ingresses",
				namespace,
				labels.Everything(),
			),
			&v1beta1.Ingress{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}
	if nil != appMgr.routeClientV1 {
		// Ensure the default server cert is loaded
		appMgr.loadDefaultCert()

		var label labels.Selector
		var err error
		if len(appMgr.routeConfig.RouteLabel) == 0 {
			label = labels.Everything()
		} else {
			label, err = labels.Parse(appMgr.routeConfig.RouteLabel)
			if err != nil {
				log.Errorf("Failed to parse Label Selector string: %v", err)
			}
		}
		appInf.routeInformer = cache.NewSharedIndexInformer(
			newListWatchWithLabelSelector(
				appMgr.routeClientV1,
				"routes",
				namespace,
				label,
			),
			&routeapi.Route{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}

	appInf.cfgMapInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueConfigMap(obj) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueConfigMap(cur) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueConfigMap(obj) },
		},
		resyncPeriod,
	)

	appInf.svcInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueService(obj) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueService(cur) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueService(obj) },
		},
		resyncPeriod,
	)

	appInf.endptInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueEndpoints(obj) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueEndpoints(cur) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueEndpoints(obj) },
		},
		resyncPeriod,
	)

	appInf.ingInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { appMgr.enqueueIngress(obj) },
			UpdateFunc: func(old, cur interface{}) { appMgr.enqueueIngress(cur) },
			DeleteFunc: func(obj interface{}) { appMgr.enqueueIngress(obj) },
		},
		resyncPeriod,
	)

	if nil != appMgr.routeClientV1 {
		appInf.routeInformer.AddEventHandlerWithResyncPeriod(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { appMgr.enqueueRoute(obj) },
				UpdateFunc: func(old, cur interface{}) { appMgr.enqueueRoute(cur) },
				DeleteFunc: func(obj interface{}) { appMgr.enqueueRoute(obj) },
			},
			resyncPeriod,
		)
	}

	return &appInf
}

func newListWatchWithLabelSelector(
	c cache.Getter,
	resource string,
	namespace string,
	labelSelector labels.Selector,
) cache.ListerWatcher {
	listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
		return c.Get().
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			LabelsSelectorParam(labelSelector).
			Do().
			Get()
	}
	watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {
		return c.Get().
			Prefix("watch").
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			LabelsSelectorParam(labelSelector).
			Watch()
	}
	return &cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc}
}

func (appMgr *Manager) enqueueConfigMap(obj interface{}) {
	if ok, keys := appMgr.checkValidConfigMap(obj); ok {
		for _, key := range keys {
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueueService(obj interface{}) {
	if ok, keys := appMgr.checkValidService(obj); ok {
		for _, key := range keys {
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueueEndpoints(obj interface{}) {
	if ok, keys := appMgr.checkValidEndpoints(obj); ok {
		for _, key := range keys {
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueueIngress(obj interface{}) {
	if ok, keys := appMgr.checkValidIngress(obj); ok {
		for _, key := range keys {
			appMgr.vsQueue.Add(*key)
		}
	}
}

func (appMgr *Manager) enqueueRoute(obj interface{}) {
	if ok, keys := appMgr.checkValidRoute(obj); ok {
		for _, key := range keys {
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
	go appInf.cfgMapInformer.Run(appInf.stopCh)
	go appInf.svcInformer.Run(appInf.stopCh)
	go appInf.endptInformer.Run(appInf.stopCh)
	go appInf.ingInformer.Run(appInf.stopCh)
	if nil != appInf.routeInformer {
		go appInf.routeInformer.Run(appInf.stopCh)
	}
}

func (appInf *appInformer) waitForCacheSync() {
	if nil != appInf.routeInformer {
		cache.WaitForCacheSync(
			appInf.stopCh,
			appInf.cfgMapInformer.HasSynced,
			appInf.svcInformer.HasSynced,
			appInf.endptInformer.HasSynced,
			appInf.ingInformer.HasSynced,
			appInf.routeInformer.HasSynced,
		)
	} else {
		cache.WaitForCacheSync(
			appInf.stopCh,
			appInf.cfgMapInformer.HasSynced,
			appInf.svcInformer.HasSynced,
			appInf.endptInformer.HasSynced,
			appInf.ingInformer.HasSynced,
		)
	}
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

func (appMgr *Manager) ConfigWriter() writer.Writer {
	return appMgr.configWriter
}

func (appMgr *Manager) Run(stopCh <-chan struct{}) {
	go appMgr.runImpl(stopCh)
}

func (appMgr *Manager) runImpl(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer appMgr.vsQueue.ShutDown()
	defer appMgr.nsQueue.ShutDown()

	appMgr.addIRule(httpRedirectIRuleName, DEFAULT_PARTITION,
		httpRedirectIRule(DEFAULT_HTTPS_PORT))
	appMgr.addInternalDataGroup(httpsRedirectDgName, DEFAULT_PARTITION)

	if nil != appMgr.routeClientV1 {
		appMgr.addIRule(
			sslPassthroughIRuleName, DEFAULT_PARTITION, sslPassthroughIRule())
		appMgr.addInternalDataGroup(passthroughHostsDgName, DEFAULT_PARTITION)
		appMgr.addInternalDataGroup(reencryptHostsDgName, DEFAULT_PARTITION)
		appMgr.addInternalDataGroup(reencryptServerSslDgName, DEFAULT_PARTITION)
		appMgr.addIRule(
			abDeploymentPathIRuleName, DEFAULT_PARTITION, abDeploymentPathIRule())
		appMgr.addInternalDataGroup(abDeploymentDgName, DEFAULT_PARTITION)
	}

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

func (appMgr *Manager) processNextVirtualServer() bool {
	key, quit := appMgr.vsQueue.Get()
	if quit {
		// The controller is shutting down.
		return false
	}
	defer appMgr.vsQueue.Done(key)

	err := appMgr.syncVirtualServer(key.(serviceQueueKey))
	if err == nil {
		appMgr.vsQueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
	appMgr.vsQueue.AddRateLimited(key)

	return true
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
		log.Debugf("Finished syncing virtual servers %+v (%v)",
			sKey, endTime.Sub(startTime))
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
		log.Warningf("Error looking up service '%v': %v\n", svcKey, err)
		return err
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

	// rsMap stores all resources currently in Resources matching sKey, indexed by port
	rsMap := appMgr.getResourcesForKey(sKey)
	dgMap := make(InternalDataGroupMap)

	var stats vsSyncStats
	err = appMgr.syncConfigMaps(&stats, sKey, rsMap, svcPortMap, svc, appInf)
	if nil != err {
		return err
	}

	err = appMgr.syncIngresses(&stats, sKey, rsMap, svcPortMap, svc, appInf, dgMap)
	if nil != err {
		return err
	}
	if nil != appInf.routeInformer {
		err = appMgr.syncRoutes(&stats, sKey, rsMap, svcPortMap, svc, appInf, dgMap)
		if nil != err {
			return err
		}
	}

	// Update internal data groups if changed
	appMgr.updateRouteDataGroups(&stats, dgMap, sKey.Namespace)

	if len(rsMap) > 0 {
		// We get here when there are ports defined in the service that don't
		// have a corresponding config map.
		stats.vsDeleted += appMgr.deleteUnusedConfigs(sKey, rsMap)
		stats.vsUpdated += appMgr.deleteUnusedResources(sKey, svcFound)
	} else if !svcFound {
		stats.vsUpdated += appMgr.deleteUnusedResources(sKey, svcFound)
	}

	log.Debugf("Updated %v of %v virtual server configs, deleted %v",
		stats.vsUpdated, stats.vsFound, stats.vsDeleted)

	// delete any custom profiles that are no longer referenced
	appMgr.deleteUnusedProfiles(appInf, sKey.Namespace, &stats)

	if stats.vsUpdated > 0 || stats.vsDeleted > 0 || stats.cpUpdated > 0 ||
		stats.dgUpdated > 0 || stats.poolsUpdated > 0 {
		appMgr.outputConfig()
	} else if appMgr.vsQueue.Len() == 0 && appMgr.nsQueue.Len() == 0 {
		appMgr.resources.Lock()
		defer appMgr.resources.Unlock()
		if !appMgr.initialState {
			appMgr.outputConfigLocked()
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
	cfgMapsByIndex, err := appInf.cfgMapInformer.GetIndexer().ByIndex(
		"namespace", sKey.Namespace)
	if nil != err {
		log.Warningf("Unable to list config maps for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}

	for _, obj := range cfgMapsByIndex {
		// We need to look at all config maps in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		cm := obj.(*v1.ConfigMap)
		if cm.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}
		rsCfg, err := parseConfigMap(cm, appMgr.schemaLocal)
		if nil != err {
			bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, sKey.ServiceName, "parse-error").Set(1)
			// Ignore this config map for the time being. When the user updates it
			// so that it is valid it will be requeued.
			log.Errorf("Error parsing ConfigMap %v_%v",
				cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
			continue
		}

		// Check if SSLProfile(s) are contained in Secrets
		if appMgr.useSecrets {
			for _, profile := range rsCfg.Virtual.Profiles {
				if profile.Context != customProfileClient {
					continue
				}
				profileName := fmt.Sprintf("%s/%s", profile.Partition, profile.Name)
				// Check if profile is contained in a Secret
				secret, err := appMgr.kubeClient.Core().Secrets(cm.ObjectMeta.Namespace).
					Get(profileName, metav1.GetOptions{})
				if err != nil {
					// No secret, so we assume the profile is a BIG-IP default
					log.Debugf("No Secret with name '%s', parsing secretName as path instead.",
						profileName)
					continue
				}
				err, updated := appMgr.createSecretSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("%v", err)
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
		log.Warningf("Unable to list ingresses for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}
	svcFwdRulesMap := NewServiceFwdRuleMap()
	for _, obj := range ingByIndex {
		// We need to look at all ingresses in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		ing := obj.(*v1beta1.Ingress)
		if ing.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}

		// Resolve first Ingress Host name (if required)
		_, exists := ing.ObjectMeta.Annotations[f5VsBindAddrAnnotation]
		if !exists && appMgr.resolveIng != "" {
			appMgr.resolveIngressHost(ing, sKey.Namespace)
		}

		// Get a list of dependencies removed so their pools can be removed.
		objKey, objDeps := NewObjectDependencies(ing)
		svcDepKey := ObjectDependency{
			Kind:      "Service",
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
		_, depsRemoved := appMgr.resources.UpdateDependencies(
			objKey, objDeps, svcDepKey, ingressLookupFunc)

		for _, portStruct := range appMgr.virtualPorts(ing) {
			rsCfg := createRSConfigFromIngress(
				ing,
				appMgr.resources,
				sKey.Namespace,
				appInf.svcInformer.GetIndexer(),
				portStruct,
				appMgr.defaultIngIP,
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
			hmStr, found := ing.ObjectMeta.Annotations[healthMonitorAnnotation]
			if found {
				var monitors AnnotationHealthMonitors
				err := json.Unmarshal([]byte(hmStr), &monitors)
				if err != nil {
					msg := fmt.Sprintf(
						"Unable to parse health monitor JSON array '%v': %v", hmStr, err)
					log.Errorf("%s", msg)
					appMgr.recordIngressEvent(ing, "InvalidData", msg)
				} else {
					if nil != ing.Spec.Backend {
						fullPoolName := fmt.Sprintf("/%s/%s", rsCfg.Virtual.Partition,
							formatIngressPoolName(sKey.Namespace, sKey.ServiceName))
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
			var svcs []string
			if nil != ing.Spec.Rules { // multi-service
				for _, rl := range ing.Spec.Rules {
					if nil != rl.IngressRuleValue.HTTP {
						for _, pth := range rl.IngressRuleValue.HTTP.Paths {
							svcs = append(svcs, pth.Backend.ServiceName)
						}
					}
				}
			} else { // single-service
				svcs = append(svcs, ing.Spec.Backend.ServiceName)
			}

			// Remove any left over pools from services no longer used by this Ingress
			for _, dep := range depsRemoved {
				if dep.Kind == "Service" {
					cfgChanged, svcKey := rsCfg.RemovePool(
						dep.Namespace, formatIngressPoolName(dep.Namespace, dep.Name))
					if cfgChanged {
						stats.poolsUpdated++
					}
					if nil != svcKey {
						appMgr.resources.DeleteKeyRef(*svcKey, rsName)
					}
				}
			}

			if ok, found, updated := appMgr.handleConfigForType(
				rsCfg, sKey, rsMap, rsName, svcPortMap,
				svc, appInf, svcs, ing); !ok {
				stats.vsUpdated += updated
				continue
			} else {
				if updated > 0 && !appMgr.processAllMultiSvc(len(rsCfg.Pools),
					rsCfg.GetName()) {
					updated -= 1
				}
				stats.vsFound += found
				stats.vsUpdated += updated
				if updated > 0 {
					msg := fmt.Sprintf(
						"Created a ResourceConfig '%v' for the Ingress.",
						rsCfg.GetName())
					appMgr.recordIngressEvent(ing, "ResourceConfigured", msg)
				}
			}
			// Set the Ingress Status IP address
			appMgr.setIngressStatus(ing, rsCfg)
		}
	}
	if len(svcFwdRulesMap) > 0 {
		httpsRedirectDg := nameRef{
			Name:      httpsRedirectDgName,
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
		log.Warningf("Unable to list routes for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}

	// Rebuild all internal data groups for routes as we process each
	svcFwdRulesMap := NewServiceFwdRuleMap()
	for _, route := range routeByIndex {
		if route.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}

		//FIXME(kenr): why do we process services that aren't associated
		//             with a route?
		svcName := getRouteCanonicalServiceName(route)
		if existsRouteServiceName(route, sKey.ServiceName) {
			svcName = sKey.ServiceName
		}

		// Collect all service names for this Route.
		svcNames := getRouteServiceNames(route)

		// Get a list of dependencies removed so their pools can be removed.
		objKey, objDeps := NewObjectDependencies(route)
		svcDepKey := ObjectDependency{
			Kind:      "Service",
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
			}
		}

		updateDataGroupForABRoute(route, svcName, DEFAULT_PARTITION, sKey.Namespace, dgMap)

		pStructs := []portStruct{{protocol: "http", port: DEFAULT_HTTP_PORT},
			{protocol: "https", port: DEFAULT_HTTPS_PORT}}
		for _, ps := range pStructs {
			rsCfg, err, pool := createRSConfigFromRoute(route, svcName,
				appMgr.resources, appMgr.routeConfig, ps,
				appInf.svcInformer.GetIndexer(), svcFwdRulesMap)
			if err != nil {
				// We return err if there was an error creating a rule
				log.Warningf("%v", err)
				continue
			}

			rsName := rsCfg.GetName()

			// Handle Route health monitors
			hmStr, exists := route.ObjectMeta.Annotations[healthMonitorAnnotation]
			if exists {
				var monitors AnnotationHealthMonitors
				err := json.Unmarshal([]byte(hmStr), &monitors)
				if err != nil {
					log.Errorf("Unable to parse health monitor JSON array '%v': %v",
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
				case routeapi.TLSTerminationReencrypt:
					appMgr.setClientSslProfile(stats, sKey, rsCfg, route)
					serverSsl := appMgr.setServerSslProfile(stats, sKey, rsCfg, route)
					if "" != serverSsl {
						updateDataGroup(dgMap, reencryptServerSslDgName,
							DEFAULT_PARTITION, sKey.Namespace, route.Spec.Host, serverSsl)
					}
				}
			}

			// Remove any left over pools from services no longer used by this Route
			for _, dep := range depsRemoved {
				if dep.Kind == "Service" {
					cfgChanged, svcKey := rsCfg.RemovePool(
						dep.Namespace, formatRoutePoolName(dep.Namespace, dep.Name))
					if cfgChanged {
						stats.poolsUpdated++
					}
					if nil != svcKey {
						appMgr.resources.DeleteKeyRef(*svcKey, rsName)
					}
				}
			}

			_, found, updated := appMgr.handleConfigForType(
				rsCfg, sKey, rsMap, rsName, svcPortMap,
				svc, appInf, svcNames, nil)
			stats.vsFound += found
			stats.vsUpdated += updated
		}
	}

	if len(svcFwdRulesMap) > 0 {
		httpsRedirectDg := nameRef{
			Name:      httpsRedirectDgName,
			Partition: DEFAULT_PARTITION,
		}
		if _, found := dgMap[httpsRedirectDg]; !found {
			dgMap[httpsRedirectDg] = make(DataGroupNamespaceMap)
		}
		svcFwdRulesMap.AddToDataGroup(dgMap[httpsRedirectDg])
	}

	return nil
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
		log.Errorf("Unable to parse boolean value '%v': %v", val, err)
		return defaultValue
	}
	return bVal
}

type secretKey struct {
	Name         string
	ResourceName string
}

// Return value is whether or not a custom profile was updated
func (appMgr *Manager) handleIngressTls(
	rsCfg *ResourceConfig,
	ing *v1beta1.Ingress,
	svcFwdRulesMap ServiceFwdRuleMap,
) bool {
	if 0 == len(ing.Spec.TLS) {
		// Nothing to do if no TLS section
		return false
	}
	if nil == rsCfg.Virtual.VirtualAddress ||
		rsCfg.Virtual.VirtualAddress.BindAddr == "" {
		// Nothing to do for pool-only mode
		return false
	}

	var httpsPort int32
	if port, ok :=
		ing.ObjectMeta.Annotations[f5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// If we are processing the HTTPS server,
	// then we don't need a redirect policy, only profiles
	if rsCfg.Virtual.VirtualAddress.Port == httpsPort {
		var cpUpdated, updateState bool
		for _, tls := range ing.Spec.TLS {
			// Check if profile is contained in a Secret
			if appMgr.useSecrets {
				secret, err := appMgr.kubeClient.Core().Secrets(ing.ObjectMeta.Namespace).
					Get(tls.SecretName, metav1.GetOptions{})
				if err != nil {
					// No secret, so we assume the profile is a BIG-IP default
					log.Debugf("No Secret with name '%s': %s. Parsing secretName as path instead.",
						tls.SecretName, err)
					profRef := convertStringToProfileRef(
						tls.SecretName, customProfileClient, ing.ObjectMeta.Namespace)
					rsCfg.Virtual.AddOrUpdateProfile(profRef)
					continue
				}
				err, cpUpdated = appMgr.createSecretSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("%v", err)
					continue
				}
				updateState = updateState || cpUpdated
				profRef := ProfileRef{
					Partition: rsCfg.Virtual.Partition,
					Name:      tls.SecretName,
					Context:   customProfileClient,
					Namespace: ing.ObjectMeta.Namespace,
				}
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				secretName := formatIngressSslProfileName(tls.SecretName)
				profRef := convertStringToProfileRef(
					secretName, customProfileClient, ing.ObjectMeta.Namespace)
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			}
		}
		return cpUpdated
	}

	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		ingressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		ingressAllowHttp, false)
	// -----------------------------------------------------------------
	// | State | sslRedirect | allowHttp | Description                 |
	// -----------------------------------------------------------------
	// |   1   |     F       |    F      | Just HTTPS, nothing on HTTP |
	// -----------------------------------------------------------------
	// |   2   |     T       |    F      | HTTP redirects to HTTPS     |
	// -----------------------------------------------------------------
	// |   2   |     T       |    T      | Honor sslRedirect == true   |
	// -----------------------------------------------------------------
	// |   3   |     F       |    T      | Both HTTP and HTTPS         |
	// -----------------------------------------------------------------
	if sslRedirect {
		// State 2, set HTTP redirect iRule
		log.Debugf("TLS: Applying HTTP redirect iRule.")
		ruleName := joinBigipPath(DEFAULT_PARTITION, httpRedirectIRuleName)
		if httpsPort != DEFAULT_HTTPS_PORT {
			ruleName = fmt.Sprintf("%s_%d", ruleName, httpsPort)
			appMgr.addIRule(ruleName, DEFAULT_PARTITION,
				httpRedirectIRule(httpsPort))
		}
		rsCfg.Virtual.AddIRule(ruleName)
		if nil != ing.Spec.Backend {
			svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
				ing.Spec.Backend.ServiceName, "*", "/")
		}
		for _, rul := range ing.Spec.Rules {
			if nil != rul.HTTP {
				host := rul.Host
				for _, path := range rul.HTTP.Paths {
					svcFwdRulesMap.AddEntry(ing.ObjectMeta.Namespace,
						path.Backend.ServiceName, host, path.Path)
				}
			}
		}
	} else if allowHttp {
		// State 3, do not apply any policy
		log.Debugf("TLS: Not applying any policies.")
	}
	return false
}

type portStruct struct {
	protocol string
	port     int32
}

// Return the required ports for Ingress VS (depending on sslRedirect/allowHttp vals)
func (appMgr *Manager) virtualPorts(ing *v1beta1.Ingress) []portStruct {
	var httpPort int32
	var httpsPort int32
	if port, ok := ing.ObjectMeta.Annotations[f5VsHttpPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpPort = int32(p)
	} else {
		httpPort = DEFAULT_HTTP_PORT
	}
	if port, ok := ing.ObjectMeta.Annotations[f5VsHttpsPortAnnotation]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpsPort = int32(p)
	} else {
		httpsPort = DEFAULT_HTTPS_PORT
	}
	// sslRedirect defaults to true, allowHttp defaults to false.
	sslRedirect := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		ingressSslRedirect, true)
	allowHttp := getBooleanAnnotation(ing.ObjectMeta.Annotations,
		ingressAllowHttp, false)

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
	ing *v1beta1.Ingress, // Used for writing events
) (bool, int, int) {
	vsFound := 0
	vsUpdated := 0

	// Get the pool that matches the sKey we are processing
	var pool Pool
	found := false
	plIdx := 0
	poolInNamespace := func(cfg *ResourceConfig, name, namespace string) bool {
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

	svcKey := serviceKey{
		Namespace:   sKey.Namespace,
		ServiceName: pool.ServiceName,
		ServicePort: pool.ServicePort,
	}

	// Match, remove config from rsMap so we don't delete it at the end.
	// (rsMap contains configs we want to delete).
	// In the case of Ingress/Routes: If the svc(s) of the currently processed ingress/route
	// doesn't match the svc in our serviceKey, then we don't want to remove the config from the map.
	// Multiple Ingress/Routes can share a config, so if one Ingress/Route is deleted, then just
	// the pools for that resource should be deleted from our config. By keeping the config in the map,
	// we delete the necessary pools later on, while leaving everything else intact.
	serviceMatch := func(svcs []string, sKey serviceQueueKey) bool {
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
		log.Debugf("Process Service delete - name: %v namespace: %v",
			pool.ServiceName, svcKey.Namespace)
		log.Infof("Port '%v' for service '%v' was not found.",
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
		log.Infof("Service '%v' has not been found.", pool.ServiceName)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "service-not-found").Set(1)
		bigIPPrometheus.MonitoredServices.WithLabelValues(sKey.Namespace, rsName, "success").Set(0)

		if !deactivated {
			deactivated = true
			if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
				vsUpdated += 1
			}
		}

		// If this is an Ingress resource, add an event that the service wasn't found
		if ing != nil {
			msg := fmt.Sprintf("Service '%v' has not been found.",
				pool.ServiceName)
			appMgr.recordIngressEvent(ing, "ServiceNotFound", msg)
		}
		return false, vsFound, vsUpdated
	}

	// Update pool members.
	vsFound += 1
	correctBackend := true
	var reason string
	var msg string

	if appMgr.IsNodePort() {
		correctBackend, reason, msg =
			appMgr.updatePoolMembersForNodePort(svc, svcKey, rsCfg, plIdx)
	} else {
		correctBackend, reason, msg =
			appMgr.updatePoolMembersForCluster(svc, svcKey, rsCfg, appInf, plIdx)
	}

	// This will only update the config if the vs actually changed.
	if appMgr.saveVirtualServer(svcKey, rsName, rsCfg) {
		vsUpdated += 1

		// If this is an Ingress resource, add an event if there was a backend error
		if !correctBackend {
			if ing != nil {
				appMgr.recordIngressEvent(ing, reason, msg)
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
	}
}

func (appMgr *Manager) updatePoolMembersForNodePort(
	svc *v1.Service,
	svcKey serviceKey,
	rsCfg *ResourceConfig,
	index int,
) (bool, string, string) {
	if svc.Spec.Type == v1.ServiceTypeNodePort {
		for _, portSpec := range svc.Spec.Ports {
			if portSpec.Port == svcKey.ServicePort {
				log.Debugf("Service backend matched %+v: using node port %v",
					svcKey, portSpec.NodePort)
				rsCfg.MetaData.Active = true
				rsCfg.Pools[index].Members =
					appMgr.getEndpointsForNodePort(portSpec.NodePort)
			}
		}
		return true, "", ""
	} else {
		msg := fmt.Sprintf("Requested service backend '%+v' not of NodePort type",
			svcKey.ServiceName)
		log.Debug(msg)
		return false, "IncorrectBackendServiceType", msg
	}
}

func (appMgr *Manager) updatePoolMembersForCluster(
	svc *v1.Service,
	sKey serviceKey,
	rsCfg *ResourceConfig,
	appInf *appInformer,
	index int,
) (bool, string, string) {
	svcKey := sKey.Namespace + "/" + sKey.ServiceName
	item, found, _ := appInf.endptInformer.GetStore().GetByKey(svcKey)
	if !found {
		msg := fmt.Sprintf("Endpoints for service '%v' not found!", svcKey)
		log.Debug(msg)
		return false, "EndpointsNotFound", msg
	}
	eps, _ := item.(*v1.Endpoints)
	for _, portSpec := range svc.Spec.Ports {
		if portSpec.Port == sKey.ServicePort {
			ipPorts := getEndpointsForService(portSpec.Name, eps)
			log.Debugf("Found endpoints for backend %+v: %v", sKey, ipPorts)
			rsCfg.MetaData.Active = true
			rsCfg.Pools[index].Members = ipPorts
		}
	}
	return true, "", ""
}

func (appMgr *Manager) deactivateVirtualServer(
	sKey serviceKey,
	rsName string,
	rsCfg *ResourceConfig,
	index int,
) bool {
	updateConfig := false
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	if rs, ok := appMgr.resources.Get(sKey, rsName); ok {
		rsCfg.MetaData.Active = false
		rsCfg.Pools[index].Members = nil
		if !reflect.DeepEqual(rs, rsCfg) {
			log.Debugf("Service delete matching backend %v %v deactivating config",
				sKey, rsName)
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
	sKey serviceKey,
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
		log.Warningf("Overwriting existing entry for backend %+v", sKey)
	}
	appMgr.resources.Assign(sKey, rsName, newRsCfg)
	return true
}

func (appMgr *Manager) getResourcesForKey(sKey serviceQueueKey) ResourceMap {
	// Return a copy of what is stored in resources
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	rsMap := make(ResourceMap)
	appMgr.resources.ForEach(func(key serviceKey, cfg *ResourceConfig) {
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
		tmpKey := serviceKey{
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
	// FIXME: This function is mostly obsolete for Ingress and Routes due to
	// the new object dependency code, but is still needed when the Ingress
	// or route resource is deleted to handle the profiles, and is still
	// needed for ConfigMaps
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	rsUpdated := 0
	namespace := sKey.Namespace
	svcName := sKey.ServiceName
	var resourceName string
	for _, cfg := range appMgr.resources.GetAllResources() {
		if cfg.MetaData.ResourceType == "configmap" ||
			cfg.MetaData.ResourceType == "iapp" {
			continue
		}
		for i, pool := range cfg.Pools {
			// Make sure we aren't processing empty pool
			if pool.Name != "" {
				key := serviceKey{
					ServiceName: pool.ServiceName,
					ServicePort: pool.ServicePort,
					Namespace:   namespace,
				}
				poolNS := strings.Split(pool.Name, "_")[1]
				_, ok := appMgr.resources.Get(key, cfg.GetName())
				if pool.ServiceName == svcName && poolNS == namespace && (!ok || !svcFound) {
					poolName := joinBigipPath(cfg.Virtual.Partition, pool.Name)
					// Delete rule
					for _, pol := range cfg.Policies {
						// Loop through rules to find which one to remove
						ruleOffsets := []int{}
						for i, rule := range pol.Rules {
							if len(rule.Actions) > 0 && rule.Actions[0].Pool == poolName {
								if cfg.MetaData.ResourceType == "route" {
									resourceName = strings.Split(rule.Name, "_")[3]
								}
								ruleOffsets = append(ruleOffsets, i)
							}
						}
						polChanged := pol.RemoveRules(ruleOffsets)
						// Update or remove the policy
						if 0 == len(pol.Rules) {
							cfg.RemovePolicy(pol)
						} else if polChanged {
							cfg.SetPolicy(pol)
						}
					}
					// Delete pool
					cfg.RemovePoolAt(i)
					appMgr.resources.deleteKeyRefLocked(key, cfg.GetName())
					if resourceName != "" {
						// Delete profileRef (Route)
						if cfg.MetaData.ResourceType == "route" {
							profRef := makeRouteClientSSLProfileRef(
								cfg.Virtual.Partition, namespace, resourceName)
							cfg.Virtual.RemoveProfile(profRef)
							serverProfile := makeRouteServerSSLProfileRef(
								cfg.Virtual.Partition, namespace, resourceName)
							cfg.Virtual.RemoveProfile(serverProfile)
						}
					}
					rsUpdated += 1
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
	} else if cm.ObjectMeta.Annotations[vsStatusBindAddrAnnotation] !=
		rsCfg.Virtual.VirtualAddress.BindAddr {
		doUpdate = true
	}
	if doUpdate {
		cm.ObjectMeta.Annotations[vsStatusBindAddrAnnotation] =
			rsCfg.Virtual.VirtualAddress.BindAddr
		_, err := appMgr.kubeClient.CoreV1().ConfigMaps(sKey.Namespace).Update(cm)
		if nil != err {
			log.Warningf("Error when creating status IP annotation: %s", err)
		} else {
			log.Debugf("Updating ConfigMap %+v annotation - %v: %v",
				sKey, vsStatusBindAddrAnnotation,
				rsCfg.Virtual.VirtualAddress.BindAddr)
		}
	}
}

func (appMgr *Manager) setIngressStatus(
	ing *v1beta1.Ingress,
	rsCfg *ResourceConfig,
) {
	// Set the ingress status to include the virtual IP
	ip, _ := split_ip_with_route_domain(rsCfg.Virtual.VirtualAddress.BindAddr)
	lbIngress := v1.LoadBalancerIngress{IP: ip}
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, lbIngress)
	} else if ing.Status.LoadBalancer.Ingress[0].IP != ip {
		ing.Status.LoadBalancer.Ingress[0] = lbIngress
	}
	_, updateErr := appMgr.kubeClient.ExtensionsV1beta1().
		Ingresses(ing.ObjectMeta.Namespace).UpdateStatus(ing)
	if nil != updateErr {
		// Multi-service causes the controller to try to update the status multiple times
		// at once. Ignore this error.
		if strings.Contains(updateErr.Error(), "object has been modified") {
			return
		}
		warning := fmt.Sprintf(
			"Error when setting Ingress status IP for virtual server %v: %v",
			rsCfg.GetName(), updateErr)
		log.Warning(warning)
		appMgr.recordIngressEvent(ing, "StatusIPError", warning)
	}
}

// Resolve the first host name in an Ingress and use the IP address as the VS address
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
			logDNSError(fmt.Sprintf("First host is empty on Ingress '%s'; cannot resolve.",
				ing.ObjectMeta.Name))
			return
		}
	} else {
		logDNSError(fmt.Sprintf("No host found for DNS resolution on Ingress '%s'",
			ing.ObjectMeta.Name))
		return
	}

	if appMgr.resolveIng == "LOOKUP" {
		// Use local DNS
		netIPs, err = net.LookupIP(host)
		if nil != err {
			logDNSError(fmt.Sprintf("Error while resolving host '%s': %s", host, err))
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
				logDNSError(fmt.Sprintf("Error while resolving host '%s': %s",
					appMgr.resolveIng, err))
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
			logDNSError(fmt.Sprintf("Error while resolving host '%s' "+
				"using DNS server '%s': %s", host, appMgr.resolveIng, err))
			return
		} else if len(res.Answer) == 0 {
			logDNSError(fmt.Sprintf("No results for host '%s' "+
				"using DNS server '%s'", host, appMgr.resolveIng))
			return
		}
		Arecord := res.Answer[0].(*dns.A)
		ipAddress = Arecord.A.String()
	}

	// Update the virtual-server annotation with the resolved IP Address
	if ing.ObjectMeta.Annotations == nil {
		ing.ObjectMeta.Annotations = make(map[string]string)
	}
	ing.ObjectMeta.Annotations[f5VsBindAddrAnnotation] = ipAddress
	_, err = appMgr.kubeClient.ExtensionsV1beta1().Ingresses(namespace).Update(ing)
	if nil != err {
		msg := fmt.Sprintf("Error while setting virtual-server IP for Ingress '%s': %s",
			ing.ObjectMeta.Name, err)
		log.Warning(msg)
		appMgr.recordIngressEvent(ing, "IPAnnotationError", msg)
	} else {
		msg := fmt.Sprintf("Resolved host '%s' as '%s'; "+
			"set '%s' annotation with address.", host, ipAddress, f5VsBindAddrAnnotation)
		log.Info(msg)
		appMgr.recordIngressEvent(ing, "HostResolvedSuccessfully", msg)
	}
}

func getEndpointsForService(
	portName string,
	eps *v1.Endpoints,
) []Member {
	var members []Member

	if eps == nil {
		return members
	}

	for _, subset := range eps.Subsets {
		for _, p := range subset.Ports {
			if portName == p.Name {
				for _, addr := range subset.Addresses {
					member := Member{
						Address: addr.IP,
						Port:    p.Port,
						Session: "user-enabled",
					}
					members = append(members, member)
				}
			}
		}
	}
	return members
}

func (appMgr *Manager) getEndpointsForNodePort(
	nodePort int32,
) []Member {
	nodes := appMgr.getNodesFromCache()
	var members []Member
	for _, v := range nodes {
		member := Member{
			Address: v,
			Port:    nodePort,
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
	log.Warningf("Could not get config for ConfigMap: %v - %v",
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
		sKey := serviceKey{serviceName, servicePort, cm.ObjectMeta.Namespace}
		rsName := formatConfigMapVSName(cm)
		if _, ok := appMgr.resources.Get(sKey, rsName); ok {
			appMgr.resources.Lock()
			defer appMgr.resources.Unlock()
			appMgr.resources.Delete(sKey, rsName)
			delete(cm.ObjectMeta.Annotations, vsStatusBindAddrAnnotation)
			appMgr.kubeClient.CoreV1().ConfigMaps(cm.ObjectMeta.Namespace).Update(cm)
			log.Warningf("Deleted virtual server associated with ConfigMap: %v",
				cm.ObjectMeta.Name)
			return true
		}
	}
	return false
}

// Check for a change in Node state
func (appMgr *Manager) ProcessNodeUpdate(
	obj interface{}, err error,
) {
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}

	newNodes, err := appMgr.getNodeAddresses(obj)
	if nil != err {
		log.Warningf("Unable to get list of nodes, err=%+v", err)
		return
	}
	sort.Strings(newNodes)

	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()

	// Only check for updates once we are in our initial state
	if appMgr.initialState {
		// Compare last set of nodes with new one
		if !reflect.DeepEqual(newNodes, appMgr.oldNodes) {
			log.Infof("ProcessNodeUpdate: Change in Node state detected")
			// serviceKey contains a service port in addition to namespace service
			// name, while the work queue does not use service port. Create a list
			// of unique work queue keys using a map.
			items := make(map[serviceQueueKey]int)
			appMgr.resources.ForEach(func(key serviceKey, cfg *ResourceConfig) {
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
func (appMgr *Manager) getNodesFromCache() []string {
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()
	nodes := make([]string, len(appMgr.oldNodes))
	copy(nodes, appMgr.oldNodes)

	return nodes
}

// Get a list of Node addresses
func (appMgr *Manager) getNodeAddresses(
	obj interface{},
) ([]string, error) {
	nodes, ok := obj.([]v1.Node)
	if false == ok {
		return nil,
			fmt.Errorf("poll update unexpected type, interface is not []v1.Node")
	}

	addrs := []string{}

	var addrType v1.NodeAddressType
	if appMgr.UseNodeInternal() {
		addrType = v1.NodeInternalIP
	} else {
		addrType = v1.NodeExternalIP
	}

	isUnSchedulable := func(node v1.Node) bool {
		for _, t := range node.Spec.Taints {
			if v1.TaintEffectNoSchedule == t.Effect {
				return true
			}
		}
		return node.Spec.Unschedulable
	}

	for _, node := range nodes {
		if 0 == len(appMgr.nodeLabelSelector) && isUnSchedulable(node) {
			// Skip unschedulable nodes only when there isn't a node
			// selector
			continue
		} else {
			nodeAddrs := node.Status.Addresses
			for _, addr := range nodeAddrs {
				if addr.Type == addrType {
					addrs = append(addrs, addr.Address)
				}
			}
		}
	}

	return addrs, nil
}
