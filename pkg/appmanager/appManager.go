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
	"io/ioutil"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"github.com/miekg/dns"
	routeapi "github.com/openshift/origin/pkg/route/api"
)

const DefaultConfigMapLabel = "f5type in (virtual-server)"
const vsBindAddrAnnotation = "status.virtual-server.f5.com/ip"
const ingressSslRedirect = "ingress.kubernetes.io/ssl-redirect"
const ingressAllowHttp = "ingress.kubernetes.io/allow-http"
const healthMonitorAnnotation = "virtual-server.f5.com/health"

type ResourceMap map[int32][]*ResourceConfig

type Manager struct {
	resources         *Resources
	customProfiles    CustomProfileStore
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
	// Event recorder
	broadcaster   record.EventBroadcaster
	eventRecorder record.EventRecorder
	eventSource   v1.EventSource
	// Route configurations
	routeConfig RouteConfig
	// Currently configured node label selector
	nodeLabelSelector string
	// Strategy for resolving Ingress Hosts into IP addresses (LOOKUP or custom DNS)
	resolveIng string
	// Use Secrets for SSL Profiles
	useSecrets bool
}

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	KubeClient        kubernetes.Interface
	restClient        rest.Interface // package local for unit testing only
	RouteClientV1     rest.Interface
	ConfigWriter      writer.Writer
	UseNodeInternal   bool
	IsNodePort        bool
	RouteConfig       RouteConfig
	ResolveIngress    string
	InitialState      bool                 // Unit testing only
	EventRecorder     record.EventRecorder // Unit testing only
	NodeLabelSelector string
	UseSecrets        bool
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
		initialState:      params.InitialState,
		eventRecorder:     params.EventRecorder,
		routeConfig:       params.RouteConfig,
		nodeLabelSelector: params.NodeLabelSelector,
		resolveIng:        params.ResolveIngress,
		useSecrets:        params.UseSecrets,
		vsQueue:           vsQueue,
		nsQueue:           nsQueue,
		appInformers:      make(map[string]*appInformer),
	}
	if nil != manager.kubeClient && nil == manager.restClientv1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.restClientv1 = manager.kubeClient.Core().RESTClient()
	}
	if nil != manager.kubeClient && nil == manager.restClientv1beta1 {
		// This is the normal production case, but need the checks for unit tests.
		manager.restClientv1beta1 = manager.kubeClient.Extensions().RESTClient()
	}
	manager.eventSource = v1.EventSource{Component: "k8s-bigip-ctlr"}
	manager.broadcaster = record.NewBroadcaster()
	if nil == manager.eventRecorder {
		manager.eventRecorder = manager.broadcaster.NewRecorder(scheme.Scheme, manager.eventSource)
	}

	return &manager
}

func (appMgr *Manager) loadDefaultCert(
	namespace,
	serverName string,
) (*ProfileRef, bool) {
	// OpenShift will put the default server SSL cert on each pod. We create a
	// server SSL profile for it and associate it to any reencrypt routes that
	// have not explicitly set a certificate.
	profileName := "openshift_route_cluster_default-server-ssl"
	profile := ProfileRef{
		Name:      profileName,
		Partition: DEFAULT_PARTITION,
		Context:   customProfileServer,
	}
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	skey := secretKey{Name: profileName}
	_, found := appMgr.customProfiles.profs[skey]
	if !found {
		path := "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
		data, err := ioutil.ReadFile(path)
		if nil != err {
			log.Errorf("Unable to load default cluster certificate '%v': %v",
				path, err)
			return nil, false
		}
		appMgr.customProfiles.profs[skey] =
			NewCustomProfile(
				profile,
				string(data),
				"", // no key
				serverName,
				false,
				appMgr.customProfiles,
			)
	}
	return &profile, !found
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
	appMgr.intDgMap[key] = NewInternalDataGroup(name, partition)
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
	if appInf, found := appMgr.appInformers[namespace]; found {
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
	if ok, key := appMgr.checkValidRoute(obj); ok {
		appMgr.vsQueue.Add(*key)
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

	if nil != appMgr.routeClientV1 {
		appMgr.addIRule(
			sslPassthroughIRuleName, DEFAULT_PARTITION, sslPassthroughIRule())
		appMgr.addInternalDataGroup(passthroughHostsDgName, DEFAULT_PARTITION)
		appMgr.addInternalDataGroup(reencryptHostsDgName, DEFAULT_PARTITION)
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
	vsFound   int
	vsUpdated int
	vsDeleted int
	cpUpdated int
	dgUpdated int
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

	var stats vsSyncStats
	err = appMgr.syncConfigMaps(&stats, sKey, rsMap, svcPortMap, svc, appInf)
	if nil != err {
		return err
	}

	err = appMgr.syncIngresses(&stats, sKey, rsMap, svcPortMap, svc, appInf)
	if nil != err {
		return err
	}
	if nil != appInf.routeInformer {
		err = appMgr.syncRoutes(&stats, sKey, rsMap, svcPortMap, svc, appInf)
		if nil != err {
			return err
		}
	}

	if len(rsMap) > 0 {
		// We get here when there are ports defined in the service that don't
		// have a corresponding config map.
		stats.vsDeleted = appMgr.deleteUnusedResources(sKey, rsMap)
		appMgr.deleteUnusedRoutes(sKey.Namespace, sKey.ServiceName)
	}
	log.Debugf("Updated %v of %v virtual server configs, deleted %v",
		stats.vsUpdated, stats.vsFound, stats.vsDeleted)

	// delete any custom profiles that are no longer referenced
	appMgr.deleteUnusedProfiles()

	if stats.vsUpdated > 0 || stats.vsDeleted > 0 || stats.cpUpdated > 0 ||
		stats.dgUpdated > 0 {
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
		rsCfg, err := parseConfigMap(cm)
		if nil != err {
			// Ignore this config map for the time being. When the user updates it
			// so that it is valid it will be requeued.
			fmt.Errorf("Error parsing ConfigMap %v_%v",
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
				err, updated := appMgr.handleSslProfile(rsCfg, secret)
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
		if ok, found, updated := appMgr.handleConfigForType(
			rsCfg, sKey, rsMap, rsName, svcPortMap, svc, appInf, ""); !ok {
			stats.vsUpdated += updated
			continue
		} else {
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
) error {
	ingByIndex, err := appInf.ingInformer.GetIndexer().ByIndex(
		"namespace", sKey.Namespace)
	if nil != err {
		log.Warningf("Unable to list ingresses for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}
	for _, obj := range ingByIndex {
		// We need to look at all ingresses in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		ing := obj.(*v1beta1.Ingress)
		if ing.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}

		// Resolve first Ingress Host name (if required)
		_, exists := ing.ObjectMeta.Annotations["virtual-server.f5.com/ip"]
		if !exists && appMgr.resolveIng != "" {
			appMgr.resolveIngressHost(ing, sKey.Namespace)
		}

		for _, portStruct := range appMgr.virtualPorts(ing) {
			rsCfg := createRSConfigFromIngress(ing, sKey.Namespace,
				appInf.svcInformer.GetIndexer(), portStruct)
			if rsCfg == nil {
				// Currently, an error is returned only if the Ingress is one we
				// do not care about
				continue
			}

			// Handle TLS configuration
			updated := appMgr.handleIngressTls(rsCfg, ing)
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
					appMgr.recordIngressEvent(ing, "InvalidData", msg, rsName)
				} else {
					if nil != ing.Spec.Backend {
						appMgr.handleSingleServiceHealthMonitors(
							rsName, rsCfg, ing, monitors)
					} else {
						appMgr.handleMultiServiceHealthMonitors(
							rsName, rsCfg, ing, monitors)
					}
				}
				rsCfg.SortMonitors()
			}

			if ok, found, updated := appMgr.handleConfigForType(
				rsCfg, sKey, rsMap, rsName, svcPortMap, svc, appInf, ""); !ok {
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
					appMgr.recordIngressEvent(ing, "ResourceConfigured", msg, "")
				}
			}
			// Set the Ingress Status IP address
			appMgr.setIngressStatus(ing, rsCfg)
		}
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
) error {
	routeByIndex, err := appInf.getOrderedRoutes(sKey.Namespace)
	if nil != err {
		log.Warningf("Unable to list routes for namespace '%v': %v",
			sKey.Namespace, err)
		return err
	}

	// Rebuild all internal data groups for routes as we process each
	dgMap := make(InternalDataGroupMap)
	for _, route := range routeByIndex {
		// We need to look at all routes in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		if nil != route.Spec.TLS {
			// The information stored in the internal data groups can span multiple
			// namespaces, so we need to keep them updated with all current routes
			// regardless of anything that happens below.
			switch route.Spec.TLS.Termination {
			case routeapi.TLSTerminationPassthrough:
				updateDataGroupForPassthroughRoute(route, DEFAULT_PARTITION, dgMap)
			case routeapi.TLSTerminationReencrypt:
				updateDataGroupForReencryptRoute(route, DEFAULT_PARTITION, dgMap)
			}
		}
		if route.ObjectMeta.Namespace != sKey.Namespace {
			continue
		}
		pStructs := []portStruct{{protocol: "http", port: DEFAULT_HTTP_PORT},
			{protocol: "https", port: DEFAULT_HTTPS_PORT}}
		for _, ps := range pStructs {
			rsCfg, err, pool := createRSConfigFromRoute(route,
				*appMgr.resources, appMgr.routeConfig, ps, appInf.svcInformer.GetIndexer())
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
					appMgr.handleRouteHealthMonitors(rsName, pool, &rsCfg, monitors, stats)
				}
				rsCfg.SortMonitors()
			}

			// TLS Cert/Key
			if nil != route.Spec.TLS &&
				rsCfg.Virtual.VirtualAddress.Port == DEFAULT_HTTPS_PORT {
				switch route.Spec.TLS.Termination {
				case routeapi.TLSTerminationEdge:
					appMgr.setClientSslProfile(stats, sKey, &rsCfg, route)
				case routeapi.TLSTerminationReencrypt:
					appMgr.setClientSslProfile(stats, sKey, &rsCfg, route)
					appMgr.setServerSslProfile(stats, sKey, &rsCfg, route)
				}
			}

			_, found, updated := appMgr.handleConfigForType(&rsCfg, sKey, rsMap,
				rsName, svcPortMap, svc, appInf, route.Spec.To.Name)
			stats.vsFound += found
			stats.vsUpdated += updated
		}
	}

	// Update internal data groups for routes if changed
	appMgr.updateRouteDataGroups(stats, dgMap, sKey.Namespace)

	return nil
}

func (appMgr *Manager) setClientSslProfile(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
	route *routeapi.Route,
) {
	// First handle the Default for SNI profile
	if appMgr.routeConfig.ClientSSL != "" {
		// User has provided a name
		prof := convertStringToProfileRef(
			appMgr.routeConfig.ClientSSL, customProfileClient)
		rsCfg.Virtual.AddOrUpdateProfile(prof)
	} else {
		// No provided name, so we create a default
		skey := secretKey{
			Name:         "default-route-clientssl",
			ResourceName: rsCfg.GetName(),
		}
		if _, ok := appMgr.customProfiles.profs[skey]; !ok {
			profile := ProfileRef{
				Name:      "default-route-clientssl",
				Partition: rsCfg.Virtual.Partition,
				Context:   customProfileClient,
			}
			// This is just a basic profile, so we don't need all the fields
			cp := NewCustomProfile(profile, "", "", "", true, appMgr.customProfiles)
			appMgr.customProfiles.profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profile)
		}
	}
	// Now handle the profile from the Route.
	// If annotation is set, use that profile instead of Route profile.
	if prof, ok := route.ObjectMeta.Annotations["virtual-server.f5.com/clientssl"]; ok {
		if nil != route.Spec.TLS {
			log.Debugf("Both clientssl annotation and cert/key provided for Route: %s, "+
				"using annotation.", route.ObjectMeta.Name)
			// Delete existing Route profile if it exists
			profRef := makeRouteClientSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
			rsCfg.Virtual.RemoveProfile(profRef)
		}
		profRef := convertStringToProfileRef(prof, customProfileClient)
		if add := rsCfg.Virtual.AddOrUpdateProfile(profRef); add {
			// Store this annotated profile in the metadata for future reference
			// if it gets deleted.
			rKey := routeKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   customProfileClient,
			}
			rsCfg.MetaData.RouteProfs[rKey] = prof
			stats.vsUpdated += 1
		}
	} else {
		profRef := ProfileRef{
			Partition: "Common",
			Name:      "clientssl",
			Context:   customProfileClient,
		}
		// We process the profile from the Route
		if "" != route.Spec.TLS.Certificate && "" != route.Spec.TLS.Key {
			profile := makeRouteClientSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)

			cp := NewCustomProfile(
				profile,
				route.Spec.TLS.Certificate,
				route.Spec.TLS.Key,
				route.Spec.Host,
				false,
				appMgr.customProfiles,
			)

			skey := secretKey{
				Name:         cp.Name,
				ResourceName: rsCfg.GetName(),
			}
			appMgr.customProfiles.Lock()
			defer appMgr.customProfiles.Unlock()
			if prof, ok := appMgr.customProfiles.profs[skey]; ok {
				if !reflect.DeepEqual(prof, cp) {
					stats.cpUpdated += 1
				}
			}
			appMgr.customProfiles.profs[skey] = cp
			profRef.Partition = cp.Partition
			profRef.Name = cp.Name
		}
		if add := rsCfg.Virtual.AddOrUpdateProfile(profRef); add {
			// Remove annotation profile if it exists
			rKey := routeKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   customProfileClient,
			}
			if profName, ok := rsCfg.MetaData.RouteProfs[rKey]; ok {
				delete(rsCfg.MetaData.RouteProfs, rKey)
				profRef := convertStringToProfileRef(profName, customProfileClient)
				rsCfg.Virtual.RemoveProfile(profRef)
			}
			stats.vsUpdated += 1
		}
	}
}

func (appMgr *Manager) setServerSslProfile(
	stats *vsSyncStats,
	sKey serviceQueueKey,
	rsCfg *ResourceConfig,
	route *routeapi.Route,
) {
	// First handle the Default for SNI profile
	if appMgr.routeConfig.ServerSSL != "" {
		// User has provided a name
		profile := ProfileRef{
			Name:      appMgr.routeConfig.ServerSSL,
			Partition: rsCfg.Virtual.Partition,
			Context:   customProfileServer,
		}
		rsCfg.Virtual.AddOrUpdateProfile(profile)
	} else {
		// No provided name, so we create a default
		skey := secretKey{
			Name:         "default-route-serverssl",
			ResourceName: rsCfg.GetName(),
		}
		if _, ok := appMgr.customProfiles.profs[skey]; !ok {
			profile := ProfileRef{
				Name:      "default-route-serverssl",
				Partition: rsCfg.Virtual.Partition,
				Context:   customProfileServer,
			}
			// This is just a basic profile, so we don't need all the fields
			cp := NewCustomProfile(profile, "", "", "", true, appMgr.customProfiles)
			appMgr.customProfiles.profs[skey] = cp
			rsCfg.Virtual.AddOrUpdateProfile(profile)
		}
	}
	if prof, ok := route.ObjectMeta.Annotations["virtual-server.f5.com/serverssl"]; ok {
		if nil != route.Spec.TLS {
			log.Debugf("Both serverssl annotation and CA cert provided for Route: %s, "+
				"using annotation.", route.ObjectMeta.Name)
			profRef := makeRouteServerSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
			rsCfg.Virtual.RemoveProfile(profRef)
		}
		partition, name := splitBigipPath(prof, false)
		if partition == "" {
			log.Warningf("No partition provided in profile name: %v, skipping...", prof)
			return
		}
		profile := ProfileRef{
			Name:      name,
			Partition: partition,
			Context:   customProfileServer,
		}
		if updated := rsCfg.Virtual.AddOrUpdateProfile(profile); updated {
			// Store this annotated profile in the metadata for future reference
			// if it gets deleted.
			rKey := routeKey{
				Name:      route.ObjectMeta.Name,
				Namespace: route.ObjectMeta.Namespace,
				Context:   customProfileServer,
			}
			rsCfg.MetaData.RouteProfs[rKey] = prof
			stats.vsUpdated += 1
		}
	} else {
		if "" != route.Spec.TLS.DestinationCACertificate {
			// Create new SSL server profile with the provided CA Certificate.
			profile := makeRouteServerSSLProfileRef(
				rsCfg.Virtual.Partition, sKey.Namespace, route.ObjectMeta.Name)
			cp := NewCustomProfile(
				profile,
				route.Spec.TLS.DestinationCACertificate,
				"", // no key
				route.Spec.Host,
				false,
				appMgr.customProfiles,
			)

			skey := secretKey{
				Name:         cp.Name,
				ResourceName: rsCfg.GetName(),
			}
			appMgr.customProfiles.Lock()
			defer appMgr.customProfiles.Unlock()
			if prof, ok := appMgr.customProfiles.profs[skey]; ok {
				if !reflect.DeepEqual(prof, cp) {
					stats.cpUpdated += 1
				}
			}
			appMgr.customProfiles.profs[skey] = cp
			if updated := rsCfg.Virtual.AddOrUpdateProfile(profile); updated {
				// Remove annotation profile if it exists
				rKey := routeKey{
					Name:      route.ObjectMeta.Name,
					Namespace: route.ObjectMeta.Namespace,
					Context:   customProfileServer,
				}
				if prof, ok := rsCfg.MetaData.RouteProfs[rKey]; ok {
					delete(rsCfg.MetaData.RouteProfs, rKey)
					partition, name := splitBigipPath(prof, false)
					rsCfg.Virtual.RemoveProfile(ProfileRef{
						Name:      name,
						Partition: partition,
						Context:   customProfileServer,
					})
				}
				stats.vsUpdated += 1
			}
		} else {
			profile, added :=
				appMgr.loadDefaultCert(sKey.Namespace, route.Spec.Host)
			if nil != profile {
				rsCfg.Virtual.AddOrUpdateProfile(*profile)
			}
			if added {
				stats.cpUpdated += 1
			}
		}
	}
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
		ing.ObjectMeta.Annotations["virtual-server.f5.com/https-port"]; ok == true {
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
						tls.SecretName, customProfileClient)
					rsCfg.Virtual.AddOrUpdateProfile(profRef)
					continue
				}
				err, cpUpdated = appMgr.handleSslProfile(rsCfg, secret)
				if err != nil {
					log.Warningf("%v", err)
					continue
				}
				updateState = updateState || cpUpdated
				profRef := ProfileRef{
					Partition: rsCfg.Virtual.Partition,
					Name:      tls.SecretName,
					Context:   customProfileClient,
				}
				rsCfg.Virtual.AddOrUpdateProfile(profRef)
			} else {
				secretName := formatIngressSslProfileName(tls.SecretName)
				profRef := convertStringToProfileRef(secretName, customProfileClient)
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
	var rule *Rule
	var policyName string
	if sslRedirect {
		// State 2, set HTTP redirect iRule
		log.Debugf("TLS: Applying HTTP redirect iRule.")
		ruleName := fmt.Sprintf("/%s/%s", DEFAULT_PARTITION, httpRedirectIRuleName)
		if httpsPort != DEFAULT_HTTPS_PORT {
			ruleName = fmt.Sprintf("%s_%d", ruleName, httpsPort)
			appMgr.addIRule(ruleName, DEFAULT_PARTITION,
				httpRedirectIRule(httpsPort))
		}
		rsCfg.Virtual.AddIRule(ruleName)
	} else if allowHttp {
		// State 3, do not apply any policy
		log.Debugf("TLS: Not applying any policies.")
	}

	if nil != rule && "" != policyName {
		policy := rsCfg.FindPolicy("forwarding")
		if nil == policy {
			policy = createPolicy(Rules{rule}, policyName, rsCfg.Virtual.Partition)
		} else {
			rule.Ordinal = len(policy.Rules)
			policy.Rules = append(policy.Rules, rule)
		}
		rsCfg.SetPolicy(*policy)
	}
	return false
}

func (appMgr *Manager) handleSslProfile(
	rsCfg *ResourceConfig,
	secret *v1.Secret,
) (error, bool) {
	if _, ok := secret.Data["tls.crt"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.crt' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}
	if _, ok := secret.Data["tls.key"]; !ok {
		err := fmt.Errorf("Invalid Secret '%v': 'tls.key' field not specified.",
			secret.ObjectMeta.Name)
		return err, false
	}

	cp := CustomProfile{
		Name:      secret.ObjectMeta.Name,
		Partition: rsCfg.Virtual.Partition,
		Context:   customProfileClient,
		Cert:      string(secret.Data["tls.crt"]),
		Key:       string(secret.Data["tls.key"]),
	}
	skey := secretKey{
		Name:         cp.Name,
		ResourceName: rsCfg.GetName(),
	}
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	if prof, ok := appMgr.customProfiles.profs[skey]; ok {
		if !reflect.DeepEqual(prof, cp) {
			appMgr.customProfiles.profs[skey] = cp
			return nil, true
		} else {
			return nil, false
		}
	}
	appMgr.customProfiles.profs[skey] = cp
	return nil, false
}

type portStruct struct {
	protocol string
	port     int32
}

// Return the required ports for Ingress VS (depending on sslRedirect/allowHttp vals)
func (appMgr *Manager) virtualPorts(ing *v1beta1.Ingress) []portStruct {
	var httpPort int32
	var httpsPort int32
	if port, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/http-port"]; ok == true {
		p, _ := strconv.ParseInt(port, 10, 32)
		httpPort = int32(p)
	} else {
		httpPort = DEFAULT_HTTP_PORT
	}
	if port, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/https-port"]; ok == true {
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
	currRouteSvc string, // Only used for Routes
) (bool, int, int) {
	vsFound := 0
	vsUpdated := 0

	var pool Pool
	found := false
	plIdx := 0
	// Parses a pool name to see if it is in the expected namespace.
	// We don't know if the pool is from a ConfigMap/Ingress or Route,
	// so we parse in two different ways.
	poolInNamespace := func(name, namespace string) bool {
		if strings.HasPrefix(name, "openshift") &&
			(strings.Split(name, "_")[1]) == namespace {
			return true
		} else if strings.HasPrefix(name, namespace) {
			return true
		}
		return false
	}
	for i, pl := range rsCfg.Pools {
		if pl.ServiceName == sKey.ServiceName &&
			poolInNamespace(pl.Name, sKey.Namespace) {
			found = true
			pool = pl
			plIdx = i
			break
		}
	}
	if !found {
		// If the current cfg has no pool for this service, remove any pools
		// associated with the service.
		appMgr.removePoolsForService(rsName, sKey.ServiceName)
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

	// Match, remove from rsMap so we don't delete it at the end.
	// In the case of Routes: If the svc of the currently processed route doesn't match
	// the svc in our serviceKey, then we don't want to delete it from the map (all routes
	// with the same protocol have the same VS name, so we don't want to ignore a route that
	// was actually deleted).
	cfgList := rsMap[pool.ServicePort]
	if currRouteSvc == "" || currRouteSvc == sKey.ServiceName {
		if len(cfgList) == 1 {
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
	if _, ok := svcPortMap[pool.ServicePort]; !ok {
		log.Debugf("Process Service delete - name: %v namespace: %v",
			pool.ServiceName, svcKey.Namespace)
		log.Infof("Port '%v' for service '%v' was not found.",
			pool.ServicePort, pool.ServiceName)
		if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
			vsUpdated += 1
		}
		deactivated = true
	}

	if nil == svc {
		// The service is gone, de-activate it in the config.
		log.Infof("Service '%v' has not been found.", pool.ServiceName)
		if !deactivated {
			deactivated = true
			if appMgr.deactivateVirtualServer(svcKey, rsName, rsCfg, plIdx) {
				vsUpdated += 1
			}
		}

		// If this is an Ingress resource, add an event that the service wasn't found
		if strings.HasSuffix(rsName, "ingress") {
			msg := fmt.Sprintf("Service '%v' has not been found.",
				pool.ServiceName)
			appMgr.recordIngressEvent(nil, "ServiceNotFound", msg, rsName)
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
			if strings.HasSuffix(rsCfg.GetName(), "ingress") {
				appMgr.recordIngressEvent(nil, reason, msg, rsCfg.GetName())
			}
		}
	}

	return true, vsFound, vsUpdated
}

func (appMgr *Manager) removePoolsForService(rsName, serviceName string) {
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	cfg, exists := appMgr.resources.GetByName(rsName)
	if !exists {
		return
	}
	fwdPolicy := cfg.FindPolicy("forwarding")
	fwdPolicyChanged := false
	for i, pool := range cfg.Pools {
		if pool.ServiceName == serviceName {
			cfg.RemovePoolAt(i)
			poolName := fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, pool.Name)
			if nil != fwdPolicy {
				ruleOffsets := []int{}
				for j, rule := range fwdPolicy.Rules {
					for _, action := range rule.Actions {
						if action.Forward && action.Pool == poolName {
							ruleOffsets = append(ruleOffsets, j)
						}
					}
				}
				if len(ruleOffsets) > 0 {
					for j := len(ruleOffsets) - 1; j >= 0; j-- {
						fwdPolicy.RemoveRuleAt(ruleOffsets[j])
						fwdPolicyChanged = true
					}
					for j, rule := range fwdPolicy.Rules {
						rule.Name = fmt.Sprintf("%d", j)
						rule.Ordinal = j
					}
				}
				if fwdPolicyChanged {
					cfg.SetPolicy(*fwdPolicy)
				}
			}
		}
	}
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
				rsCfg.MetaData.NodePort = portSpec.NodePort
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

func (appMgr *Manager) deleteUnusedResources(
	sKey serviceQueueKey,
	rsMap ResourceMap) int {
	rsDeleted := 0
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
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

// If a route is deleted, loop through other route configs and delete pools/rules/profiles
// for the deleted route.
func (appMgr *Manager) deleteUnusedRoutes(namespace, svc string) {
	appMgr.resources.Lock()
	defer appMgr.resources.Unlock()
	var routeName string
	for _, cfg := range appMgr.resources.GetAllResources() {
		if cfg.MetaData.ResourceType != "route" {
			continue
		}
		for i, pool := range cfg.Pools {
			// Make sure we aren't processing empty pool
			if pool.Name != "" {
				sKey := serviceKey{
					ServiceName: pool.ServiceName,
					ServicePort: pool.ServicePort,
					Namespace:   namespace,
				}
				poolNS := strings.Split(pool.Name, "_")[1]
				_, ok := appMgr.resources.Get(sKey, cfg.GetName())
				if pool.ServiceName == svc && poolNS == namespace && !ok {
					poolName := fmt.Sprintf("/%s/%s", cfg.Virtual.Partition, pool.Name)
					// Delete rule
					for _, pol := range cfg.Policies {
						if len(pol.Rules) == 1 {
							routeName = strings.Split(pol.Rules[0].Name, "_")[3]
							nr := nameRef{
								Name:      pol.Name,
								Partition: pol.Partition,
							}
							cfg.RemovePolicy(nr)
							continue
						}
						for i, rule := range pol.Rules {
							if len(rule.Actions) > 0 && rule.Actions[0].Pool == poolName {
								routeName = strings.Split(rule.Name, "_")[3]
								pol.RemoveRuleAt(i)
								cfg.SetPolicy(pol)
							}
						}
					}
					// Delete pool
					cfg.RemovePoolAt(i)
					if routeName != "" {
						// Delete profile
						profRef := makeRouteClientSSLProfileRef(
							cfg.Virtual.Partition, namespace, routeName)
						cfg.Virtual.RemoveProfile(profRef)
						serverProfile := makeRouteServerSSLProfileRef(
							cfg.Virtual.Partition, namespace, routeName)
						cfg.Virtual.RemoveProfile(serverProfile)
					}
				}
			}
		}
	}
}

func (appMgr *Manager) deleteUnusedProfiles() {
	var found bool
	appMgr.customProfiles.Lock()
	defer appMgr.customProfiles.Unlock()
	for key, profile := range appMgr.customProfiles.profs {
		found = false
		for _, cfg := range appMgr.resources.GetAllResources() {
			if key.ResourceName == cfg.GetName() &&
				cfg.Virtual.ReferencesProfile(profile) {
				found = true
			}
		}
		if !found {
			delete(appMgr.customProfiles.profs, key)
		}
	}
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
	} else if cm.ObjectMeta.Annotations[vsBindAddrAnnotation] !=
		rsCfg.Virtual.VirtualAddress.BindAddr {
		doUpdate = true
	}
	if doUpdate {
		cm.ObjectMeta.Annotations[vsBindAddrAnnotation] =
			rsCfg.Virtual.VirtualAddress.BindAddr
		_, err := appMgr.kubeClient.CoreV1().ConfigMaps(sKey.Namespace).Update(cm)
		if nil != err {
			log.Warningf("Error when creating status IP annotation: %s", err)
		} else {
			log.Debugf("Updating ConfigMap %+v annotation - %v: %v",
				sKey, vsBindAddrAnnotation,
				rsCfg.Virtual.VirtualAddress.BindAddr)
		}
	}
}

func (appMgr *Manager) setIngressStatus(
	ing *v1beta1.Ingress,
	rsCfg *ResourceConfig,
) {
	// Set the ingress status to include the virtual IP
	lbIngress := v1.LoadBalancerIngress{IP: rsCfg.Virtual.VirtualAddress.BindAddr}
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, lbIngress)
	} else if ing.Status.LoadBalancer.Ingress[0].IP != rsCfg.Virtual.VirtualAddress.BindAddr {
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
		appMgr.recordIngressEvent(ing, "StatusIPError", warning, "")
	}
}

// This function expects either an Ingress resource or the name of a VS for an Ingress
func (appMgr *Manager) recordIngressEvent(ing *v1beta1.Ingress,
	reason,
	message,
	rsName string) {
	var namespace string
	var name string
	if ing != nil {
		namespace = ing.ObjectMeta.Namespace
	} else {
		namespace = strings.Split(rsName, "_")[0]
		name = rsName[len(namespace)+1 : len(rsName)-len("-ingress")]
	}
	appMgr.broadcaster.StartRecordingToSink(&corev1.EventSinkImpl{
		Interface: appMgr.kubeClient.Core().Events(namespace)})

	// If we aren't given an Ingress resource, we use the name to find it
	var err error
	if ing == nil {
		ing, err = appMgr.kubeClient.Extensions().Ingresses(namespace).
			Get(name, metav1.GetOptions{})
		if nil != err {
			log.Warningf("Could not find Ingress resource '%v'.", name)
			return
		}
	}

	// Create the event
	appMgr.eventRecorder.Event(ing, v1.EventTypeNormal, reason, message)
}

// Resolve the first host name in an Ingress and use the IP address as the VS address
func (appMgr *Manager) resolveIngressHost(ing *v1beta1.Ingress, namespace string) {
	var host, ipAddress string
	var err error
	var netIPs []net.IP
	logDNSError := func(msg string) {
		log.Warning(msg)
		appMgr.recordIngressEvent(ing, "DNSResolutionError", msg, "")
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
		if _, err := strconv.Atoi(slice[len(slice)-1]); err == nil {
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
		res, _, err := client.Exchange(&msg, customDNS+":"+port)
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
	ing.ObjectMeta.Annotations["virtual-server.f5.com/ip"] = ipAddress
	_, err = appMgr.kubeClient.ExtensionsV1beta1().Ingresses(namespace).Update(ing)
	if nil != err {
		msg := fmt.Sprintf("Error while setting virtual-server IP for Ingress '%s': %s",
			ing.ObjectMeta.Name, err)
		log.Warning(msg)
		appMgr.recordIngressEvent(ing, "IPAnnotationError", msg, "")
	} else {
		msg := fmt.Sprintf("Resolved host '%s' as '%s'; "+
			"set 'virtual-server.f5.com/ip' annotation with address.", host, ipAddress)
		log.Info(msg)
		appMgr.recordIngressEvent(ing, "HostResolvedSuccessfully", msg, "")
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
			delete(cm.ObjectMeta.Annotations, vsBindAddrAnnotation)
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
			for _, cfg := range appMgr.resources.GetAllResources() {
				var members []Member
				for _, node := range newNodes {
					member := Member{
						Address: node,
						Port:    cfg.MetaData.NodePort,
						Session: "user-enabled",
					}
					members = append(members, member)
				}
				cfg.Pools[0].Members = members
			}
			// Output the Big-IP config
			appMgr.outputConfigLocked()

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
