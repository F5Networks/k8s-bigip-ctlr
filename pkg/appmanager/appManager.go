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
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "f5/vlogger"
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
)

const DefaultConfigMapLabel = "f5type in (virtual-server)"
const vsBindAddrAnnotation = "status.virtual-server.f5.com/ip"

type VirtualServerPortMap map[int32][]*VirtualServerConfig

type Manager struct {
	vservers          *VirtualServers
	kubeClient        kubernetes.Interface
	restClientv1      rest.Interface
	restClientv1beta1 rest.Interface
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
	// App informer support
	vsQueue      workqueue.RateLimitingInterface
	appInformers map[string]*appInformer
	// Namespace informer support (namespace labels)
	nsQueue    workqueue.RateLimitingInterface
	nsInformer cache.SharedIndexInformer
	// Parameter to specify whether or not to watch/manage Ingress resources
	manage_ingress bool
	// Event recorder
	broadcaster   record.EventBroadcaster
	eventRecorder record.EventRecorder
	eventSource   v1.EventSource
}

// Struct to allow NewManager to receive all or only specific parameters.
type Params struct {
	KubeClient      kubernetes.Interface
	restClient      rest.Interface // package local for unit testing only
	ConfigWriter    writer.Writer
	UseNodeInternal bool
	IsNodePort      bool
	ManageIngress   bool
	InitialState    bool                 // Unit testing only
	EventRecorder   record.EventRecorder // Unit testing only
}

// Create and return a new app manager that meets the Manager interface
func NewManager(params *Params) *Manager {
	vsQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "virtual-server-controller")
	nsQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "namespace-controller")
	manager := Manager{
		vservers:          NewVirtualServers(),
		kubeClient:        params.KubeClient,
		restClientv1:      params.restClient,
		restClientv1beta1: params.restClient,
		configWriter:      params.ConfigWriter,
		useNodeInternal:   params.UseNodeInternal,
		isNodePort:        params.IsNodePort,
		manage_ingress:    params.ManageIngress,
		initialState:      params.InitialState,
		eventRecorder:     params.EventRecorder,
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
	appInf = appMgr.newAppInformer(namespace, appMgr.manage_ingress,
		cfgMapSelector, resyncPeriod)
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
		// Clean up all virtual servers that reference a removed namespace
		appInf.stopInformers()
		appMgr.removeNamespaceLocked(nsName)
		appMgr.vservers.Lock()
		defer appMgr.vservers.Unlock()
		vsDeleted := 0
		appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
			if key.Namespace == nsName {
				if appMgr.vservers.Delete(key, "") {
					vsDeleted += 1
				}
			}
		})
		if vsDeleted > 0 {
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

type vsQueueKey struct {
	Namespace   string
	ServiceName string
}

type appInformer struct {
	namespace      string
	cfgMapInformer cache.SharedIndexInformer
	svcInformer    cache.SharedIndexInformer
	endptInformer  cache.SharedIndexInformer
	ingInformer    cache.SharedIndexInformer
	stopCh         chan struct{}
	manage_ingress bool
}

func (appMgr *Manager) newAppInformer(
	namespace string,
	manage_ingress bool,
	cfgMapSelector labels.Selector,
	resyncPeriod time.Duration,
) *appInformer {
	appInf := appInformer{
		namespace:      namespace,
		stopCh:         make(chan struct{}),
		manage_ingress: manage_ingress,
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
	if appInf.manage_ingress {
		go appInf.ingInformer.Run(appInf.stopCh)
	}
}

func (appInf *appInformer) waitForCacheSync() {
	if appInf.manage_ingress {
		cache.WaitForCacheSync(
			appInf.stopCh,
			appInf.cfgMapInformer.HasSynced,
			appInf.svcInformer.HasSynced,
			appInf.endptInformer.HasSynced,
			appInf.ingInformer.HasSynced,
		)
	} else {
		cache.WaitForCacheSync(
			appInf.stopCh,
			appInf.cfgMapInformer.HasSynced,
			appInf.svcInformer.HasSynced,
			appInf.endptInformer.HasSynced,
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

	err := appMgr.syncVirtualServer(key.(vsQueueKey))
	if err == nil {
		appMgr.vsQueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Sync %v failed with %v", key, err))
	appMgr.vsQueue.AddRateLimited(key)

	return true
}

func (appMgr *Manager) syncVirtualServer(vsKey vsQueueKey) error {
	startTime := time.Now()
	defer func() {
		endTime := time.Now()
		log.Debugf("Finished syncing virtual servers %+v (%v)",
			vsKey, endTime.Sub(startTime))
	}()

	// Get the informers for the namespace. This will tell us if we care about
	// this item.
	appInf, haveNamespace := appMgr.getNamespaceInformer(vsKey.Namespace)
	if !haveNamespace {
		// This shouldn't happen as the namespace is checked for every item before
		// it is added to the queue, but issue a warning if it does.
		log.Warningf(
			"Received an update for an item from an un-watched namespace %v",
			vsKey.Namespace)
		return nil
	}

	// Lookup the service
	svcKey := vsKey.Namespace + "/" + vsKey.ServiceName
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

	// vsMap stores all config maps currently in vservers matching vsKey,
	// indexed by port.
	vsMap := appMgr.getVirtualServersForKey(vsKey)

	vsFound := 0
	vsUpdated := 0
	vsDeleted := 0
	cfgMapsByIndex, err := appInf.cfgMapInformer.GetIndexer().ByIndex(
		"namespace", vsKey.Namespace)
	if nil != err {
		log.Warningf("Unable to list config maps for namespace '%v': %v",
			vsKey.Namespace, err)
		return err
	}
	for _, obj := range cfgMapsByIndex {
		// We need to look at all config maps in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		cm := obj.(*v1.ConfigMap)
		if cm.ObjectMeta.Namespace != vsKey.Namespace {
			continue
		}
		vsCfg, err := parseVirtualServerConfig(cm)
		if nil != err {
			// Ignore this config map for the time being. When the user updates it
			// so that it is valid it will be requeued.
			fmt.Errorf("Error parsing ConfigMap %v_%v",
				cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
			continue
		}
		vsName := formatConfigMapVSName(cm)
		if ok, found, updated := appMgr.handleVSForResource(
			vsCfg, vsKey, vsMap, vsName, svcPortMap, svc, appInf); !ok {
			continue
		} else {
			vsFound += found
			vsUpdated += updated
		}

		// Set a status annotation to contain the virtualAddress bindAddr
		if vsCfg.VirtualServer.Frontend.IApp == "" &&
			vsCfg.VirtualServer.Frontend.VirtualAddress != nil &&
			vsCfg.VirtualServer.Frontend.VirtualAddress.BindAddr != "" {
			appMgr.setBindAddrAnnotation(cm, vsKey, vsCfg)
		}
	}
	ingByIndex, err := appInf.ingInformer.GetIndexer().ByIndex(
		"namespace", vsKey.Namespace)
	if nil != err {
		log.Warningf("Unable to list ingresses for namespace '%v': %v",
			vsKey.Namespace, err)
		return err
	}
	for _, obj := range ingByIndex {
		// We need to look at all ingresses in the store, parse the data blob,
		// and see if it belongs to the service that has changed.
		ing := obj.(*v1beta1.Ingress)
		if ing.ObjectMeta.Namespace != vsKey.Namespace {
			continue
		}
		vsCfg := createVSConfigFromIngress(ing)
		if vsCfg == nil {
			// Currently, an error is returned only if the Ingress is one we
			// do not care about
			continue
		}

		// Handle TLS configuration
		appMgr.handleIngressTls(vsCfg, ing)

		vsName := formatIngressVSName(ing)
		if ok, found, updated := appMgr.handleVSForResource(
			vsCfg, vsKey, vsMap, vsName, svcPortMap, svc, appInf); !ok {
			continue
		} else {
			vsFound += found
			vsUpdated += updated
			if updated > 0 {
				msg := fmt.Sprintf(
					"Configured a virtual server '%v' for the Ingress.",
					vsCfg.VirtualServer.Frontend.VirtualServerName)
				appMgr.recordIngressEvent(ing, "VirtualServerConfigured", msg, "")
			}
		}

		// Set the Ingress Status IP address
		appMgr.setIngressStatus(ing, vsCfg)
	}

	if len(vsMap) > 0 {
		// We get here when there are ports defined in the service that don't
		// have a corresponding config map.
		vsDeleted = appMgr.deleteUnusedVirtualServers(vsKey, vsMap)
	}

	log.Debugf("Updated %v of %v virtual server configs, deleted %v",
		vsUpdated, vsFound, vsDeleted)

	if vsUpdated > 0 || vsDeleted > 0 {
		appMgr.outputConfig()
	} else if appMgr.vsQueue.Len() == 0 && appMgr.nsQueue.Len() == 0 {
		appMgr.vservers.Lock()
		defer appMgr.vservers.Unlock()
		if !appMgr.initialState {
			appMgr.outputConfigLocked()
		}
	}

	return nil
}

func (appMgr *Manager) handleIngressTls(
	vsCfg *VirtualServerConfig,
	ing *v1beta1.Ingress,
) {
	if len(ing.Spec.Rules) == 0 {
		// single service ingress
		if nil == vsCfg.VirtualServer.Frontend.VirtualAddress {
			// Nothing to do for pool-only mode
			return
		}
		for _, tls := range ing.Spec.TLS {
			secretName := formatIngressSslProfileName(tls.SecretName)
			vsCfg.AddFrontendSslProfileName(secretName)
		}
	} else {
		// NOTE(garyr): Only single service ingress is currently supported.
	}
}

// Common handling function for both ConfigMaps and Ingresses
func (appMgr *Manager) handleVSForResource(
	vsCfg *VirtualServerConfig,
	vsKey vsQueueKey,
	vsMap VirtualServerPortMap,
	vsName string,
	svcPortMap map[int32]bool,
	svc *v1.Service,
	appInf *appInformer,
) (bool, int, int) {
	vsFound := 0
	vsUpdated := 0

	if vsCfg.VirtualServer.Backend.ServiceName != vsKey.ServiceName {
		return false, vsFound, vsUpdated
	}

	svcKey := serviceKey{
		Namespace:   vsKey.Namespace,
		ServiceName: vsKey.ServiceName,
		ServicePort: vsCfg.VirtualServer.Backend.ServicePort,
	}
	// Match, remove from vsMap so we don't delete it at the end.
	cfgList := vsMap[vsCfg.VirtualServer.Backend.ServicePort]
	if len(cfgList) == 1 {
		delete(vsMap, vsCfg.VirtualServer.Backend.ServicePort)
	} else {
		for index, val := range cfgList {
			if val.VirtualServer.Frontend.VirtualServerName == vsName {
				cfgList = append(cfgList[:index], cfgList[index+1:]...)
			}
		}
		vsMap[vsCfg.VirtualServer.Backend.ServicePort] = cfgList
	}

	if _, ok := svcPortMap[vsCfg.VirtualServer.Backend.ServicePort]; !ok {
		log.Debugf("Process Service delete - name: %v namespace: %v",
			vsKey.ServiceName, vsKey.Namespace)
		if appMgr.deactivateVirtualServer(svcKey, vsName, vsCfg) {
			vsUpdated += 1
		}
	}

	// Set the virtual server name in our parsed copy so we can compare it
	// later to see if it has actually changed.
	vsCfg.VirtualServer.Frontend.VirtualServerName = vsName

	if nil == svc {
		// The service is gone, de-activate it in the config.
		if appMgr.deactivateVirtualServer(svcKey, vsName, vsCfg) {
			vsUpdated += 1
		}

		// If this is an Ingress resource, add an event that the service wasn't found
		if strings.HasSuffix(vsCfg.VirtualServer.Frontend.VirtualServerName, "ingress") {
			msg := fmt.Sprintf("Service '%v' has not been found.",
				vsCfg.VirtualServer.Backend.ServiceName)
			appMgr.recordIngressEvent(nil, "ServiceNotFound", msg,
				vsCfg.VirtualServer.Frontend.VirtualServerName)
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
			appMgr.updatePoolMembersForNodePort(svc, svcKey, vsCfg)
	} else {
		correctBackend, reason, msg =
			appMgr.updatePoolMembersForCluster(svc, svcKey, vsCfg, appInf)
	}

	// This will only update the config if the vs actually changed.
	if appMgr.saveVirtualServer(svcKey, vsName, vsCfg) {
		vsUpdated += 1

		// If this is an Ingress resource, add an event if there was a backend error
		if !correctBackend {
			if strings.HasSuffix(vsCfg.VirtualServer.Frontend.VirtualServerName, "ingress") {
				appMgr.recordIngressEvent(nil, reason, msg,
					vsCfg.VirtualServer.Frontend.VirtualServerName)
			}
		}
	}

	return true, vsFound, vsUpdated
}

func (appMgr *Manager) updatePoolMembersForNodePort(
	svc *v1.Service,
	vsKey serviceKey,
	vsCfg *VirtualServerConfig,
) (bool, string, string) {
	if svc.Spec.Type == v1.ServiceTypeNodePort {
		for _, portSpec := range svc.Spec.Ports {
			if portSpec.Port == vsKey.ServicePort {
				log.Debugf("Service backend matched %+v: using node port %v",
					vsKey, portSpec.NodePort)
				vsCfg.MetaData.Active = true
				vsCfg.MetaData.NodePort = portSpec.NodePort
				vsCfg.VirtualServer.Backend.PoolMemberAddrs =
					appMgr.getEndpointsForNodePort(portSpec.NodePort)
			}
		}
		return true, "", ""
	} else {
		msg := fmt.Sprintf("Requested service backend '%+v' not of NodePort type",
			vsKey.ServiceName)
		log.Debug(msg)
		return false, "IncorrectBackendServiceType", msg
	}
}

func (appMgr *Manager) updatePoolMembersForCluster(
	svc *v1.Service,
	vsKey serviceKey,
	vsCfg *VirtualServerConfig,
	appInf *appInformer,
) (bool, string, string) {
	svcKey := vsKey.Namespace + "/" + vsKey.ServiceName
	item, found, _ := appInf.endptInformer.GetStore().GetByKey(svcKey)
	if !found {
		msg := fmt.Sprintf("Endpoints for service '%v' not found!", svcKey)
		log.Debug(msg)
		return false, "EndpointsNotFound", msg
	}
	eps, _ := item.(*v1.Endpoints)
	for _, portSpec := range svc.Spec.Ports {
		if portSpec.Port == vsKey.ServicePort {
			ipPorts := getEndpointsForService(portSpec.Name, eps)
			log.Debugf("Found endpoints for backend %+v: %v", vsKey, ipPorts)
			vsCfg.MetaData.Active = true
			vsCfg.VirtualServer.Backend.PoolMemberAddrs = ipPorts
		}
	}
	return true, "", ""
}

func (appMgr *Manager) deactivateVirtualServer(
	vsKey serviceKey,
	vsName string,
	vsCfg *VirtualServerConfig,
) bool {
	updateConfig := false
	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	if vs, ok := appMgr.vservers.Get(vsKey, vsName); ok {
		vsCfg.MetaData.Active = false
		vsCfg.VirtualServer.Backend.PoolMemberAddrs = nil
		if !reflect.DeepEqual(vs, vsCfg) {
			log.Debugf("Service delete matching backend %v %v deactivating config",
				vsKey, vsName)
			updateConfig = true
		}
	} else {
		// We have a config map but not a server. Put in the virtual server from
		// the config map.
		updateConfig = true
	}
	if updateConfig {
		appMgr.vservers.Assign(vsKey, vsName, vsCfg)
	}
	return updateConfig
}

func (appMgr *Manager) saveVirtualServer(
	vsKey serviceKey,
	vsName string,
	newVsCfg *VirtualServerConfig,
) bool {
	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	if oldVsCfg, ok := appMgr.vservers.Get(vsKey, vsName); ok {
		if reflect.DeepEqual(oldVsCfg, newVsCfg) {
			// not changed, don't trigger a config write
			return false
		}
		log.Warningf("Overwriting existing entry for backend %+v", vsKey)
	}
	appMgr.vservers.Assign(vsKey, vsName, newVsCfg)
	return true
}

func (appMgr *Manager) getVirtualServersForKey(
	vsKey vsQueueKey,
) VirtualServerPortMap {
	// Return a copy of what is stored in vservers, mapped by port.
	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	vsMap := make(VirtualServerPortMap)
	appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
		if key.Namespace == vsKey.Namespace &&
			key.ServiceName == vsKey.ServiceName {
			vsMap[cfg.VirtualServer.Backend.ServicePort] =
				append(vsMap[cfg.VirtualServer.Backend.ServicePort], cfg)
		}
	})
	return vsMap
}

func (appMgr *Manager) deleteUnusedVirtualServers(
	vsKey vsQueueKey,
	vsMap VirtualServerPortMap,
) int {
	vsDeleted := 0
	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	for port, cfgList := range vsMap {
		tmpKey := serviceKey{
			Namespace:   vsKey.Namespace,
			ServiceName: vsKey.ServiceName,
			ServicePort: port,
		}
		for _, cfg := range cfgList {
			vsName := cfg.VirtualServer.Frontend.VirtualServerName
			if appMgr.vservers.Delete(tmpKey, vsName) {
				vsDeleted += 1
			}
		}
	}
	return vsDeleted
}

func (appMgr *Manager) setBindAddrAnnotation(
	cm *v1.ConfigMap,
	vsKey vsQueueKey,
	vsCfg *VirtualServerConfig,
) {
	var doUpdate bool
	if cm.ObjectMeta.Annotations == nil {
		cm.ObjectMeta.Annotations = make(map[string]string)
		doUpdate = true
	} else if cm.ObjectMeta.Annotations[vsBindAddrAnnotation] !=
		vsCfg.VirtualServer.Frontend.VirtualAddress.BindAddr {
		doUpdate = true
	}
	if doUpdate {
		cm.ObjectMeta.Annotations[vsBindAddrAnnotation] =
			vsCfg.VirtualServer.Frontend.VirtualAddress.BindAddr
		_, err := appMgr.kubeClient.CoreV1().ConfigMaps(vsKey.Namespace).Update(cm)
		if nil != err {
			log.Warningf("Error when creating status IP annotation: %s", err)
		} else {
			log.Debugf("Updating ConfigMap %+v annotation - %v: %v",
				vsKey, vsBindAddrAnnotation,
				vsCfg.VirtualServer.Frontend.VirtualAddress.BindAddr)
		}
	}
}

func (appMgr *Manager) setIngressStatus(
	ing *v1beta1.Ingress,
	vsCfg *VirtualServerConfig,
) {
	// Set the ingress status to include the virtual IP
	lbIngress := v1.LoadBalancerIngress{IP: vsCfg.VirtualServer.Frontend.VirtualAddress.BindAddr}
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, lbIngress)
	} else if ing.Status.LoadBalancer.Ingress[0].IP != vsCfg.VirtualServer.Frontend.VirtualAddress.BindAddr {
		ing.Status.LoadBalancer.Ingress[0] = lbIngress
	}
	_, updateErr := appMgr.kubeClient.ExtensionsV1beta1().
		Ingresses(ing.ObjectMeta.Namespace).UpdateStatus(ing)
	if nil != updateErr {
		warning := fmt.Sprintf(
			"Error when setting Ingress status IP for virtual server %v: %v",
			vsCfg.VirtualServer.Frontend.VirtualServerName, updateErr)
		log.Warning(warning)
		appMgr.recordIngressEvent(ing, "StatusIPError", warning, "")
	}
}

// This function expects either an Ingress resource or the name of a VS for an Ingress
func (appMgr *Manager) recordIngressEvent(ing *v1beta1.Ingress,
	reason,
	message,
	vsName string) {
	var namespace string
	var name string
	if ing != nil {
		namespace = ing.ObjectMeta.Namespace
	} else {
		namespace = strings.Split(vsName, "_")[0]
		name = vsName[len(namespace)+1 : len(vsName)-len("-ingress")]
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

func (appMgr *Manager) checkValidConfigMap(
	obj interface{},
) (bool, *vsQueueKey) {
	// Identify the specific service being referenced, and return it if it's
	// one we care about.
	cm := obj.(*v1.ConfigMap)
	namespace := cm.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	cfg, err := parseVirtualServerConfig(cm)
	if nil != err {
		if handleVirtualServerConfigParseFailure(appMgr, cm, cfg, err) {
			// vservers is updated if true is returned, write out the config.
			appMgr.outputConfig()
		}
		return false, nil
	}

	return true, &vsQueueKey{
		Namespace:   namespace,
		ServiceName: cfg.VirtualServer.Backend.ServiceName,
	}
}

func (appMgr *Manager) enqueueConfigMap(obj interface{}) {
	if ok, key := appMgr.checkValidConfigMap(obj); ok {
		appMgr.vsQueue.Add(*key)
	}
}

func (appMgr *Manager) checkValidService(
	obj interface{},
) (bool, *vsQueueKey) {
	// Check if the service to see if we care about it.
	svc := obj.(*v1.Service)
	namespace := svc.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	return true, &vsQueueKey{
		Namespace:   namespace,
		ServiceName: svc.ObjectMeta.Name,
	}
}

func (appMgr *Manager) enqueueService(obj interface{}) {
	if ok, key := appMgr.checkValidService(obj); ok {
		appMgr.vsQueue.Add(*key)
	}
}

func (appMgr *Manager) checkValidEndpoints(
	obj interface{},
) (bool, *vsQueueKey) {
	eps := obj.(*v1.Endpoints)
	namespace := eps.ObjectMeta.Namespace
	// Check if the service to see if we care about it.
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	return true, &vsQueueKey{
		Namespace:   namespace,
		ServiceName: eps.ObjectMeta.Name,
	}
}

func (appMgr *Manager) enqueueEndpoints(obj interface{}) {
	if ok, key := appMgr.checkValidEndpoints(obj); ok {
		appMgr.vsQueue.Add(*key)
	}
}

func (appMgr *Manager) checkValidIngress(
	obj interface{},
) (bool, *vsQueueKey) {
	ing := obj.(*v1beta1.Ingress)
	namespace := ing.ObjectMeta.Namespace
	_, ok := appMgr.getNamespaceInformer(namespace)
	if !ok {
		// Not watching this namespace
		return false, nil
	}
	vsCfg := createVSConfigFromIngress(ing)
	if vsCfg == nil {
		vsName := formatIngressVSName(ing)
		serviceName := ing.Spec.Backend.ServiceName
		servicePort := ing.Spec.Backend.ServicePort.IntVal
		vsKey := serviceKey{serviceName, servicePort, ing.ObjectMeta.Namespace}
		if _, ok := appMgr.vservers.Get(vsKey, vsName); ok {
			appMgr.vservers.Lock()
			appMgr.vservers.Delete(vsKey, vsName)
			appMgr.vservers.Unlock()
			appMgr.outputConfig()
		}
		return false, nil
	}

	return true, &vsQueueKey{
		Namespace:   namespace,
		ServiceName: ing.Spec.Backend.ServiceName,
	}
}

func (appMgr *Manager) enqueueIngress(obj interface{}) {
	if ok, key := appMgr.checkValidIngress(obj); ok {
		appMgr.vsQueue.Add(*key)
	}
}

func getEndpointsForService(
	portName string,
	eps *v1.Endpoints,
) []string {
	var ipPorts []string

	if eps == nil {
		return ipPorts
	}

	for _, subset := range eps.Subsets {
		for _, p := range subset.Ports {
			if portName == p.Name {
				port := strconv.Itoa(int(p.Port))
				for _, addr := range subset.Addresses {
					var b bytes.Buffer
					b.WriteString(addr.IP)
					b.WriteRune(':')
					b.WriteString(port)
					ipPorts = append(ipPorts, b.String())
				}
			}
		}
	}
	if 0 != len(ipPorts) {
		sort.Strings(ipPorts)
	}
	return ipPorts
}

func (appMgr *Manager) getEndpointsForNodePort(
	nodePort int32,
) []string {
	port := strconv.Itoa(int(nodePort))
	nodes := appMgr.getNodesFromCache()
	for i, v := range nodes {
		var b bytes.Buffer
		b.WriteString(v)
		b.WriteRune(':')
		b.WriteString(port)
		nodes[i] = b.String()
	}

	return nodes
}

func handleVirtualServerConfigParseFailure(
	appMgr *Manager,
	cm *v1.ConfigMap,
	cfg *VirtualServerConfig,
	err error,
) bool {
	log.Warningf("Could not get config for ConfigMap: %v - %v",
		cm.ObjectMeta.Name, err)
	// If virtual server exists for invalid configmap, delete it
	if nil != cfg {
		serviceName := cfg.VirtualServer.Backend.ServiceName
		servicePort := cfg.VirtualServer.Backend.ServicePort
		vsKey := serviceKey{serviceName, servicePort, cm.ObjectMeta.Namespace}
		vsName := formatConfigMapVSName(cm)
		if _, ok := appMgr.vservers.Get(vsKey, vsName); ok {
			appMgr.vservers.Lock()
			defer appMgr.vservers.Unlock()
			appMgr.vservers.Delete(vsKey, vsName)
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

	appMgr.vservers.Lock()
	defer appMgr.vservers.Unlock()
	appMgr.oldNodesMutex.Lock()
	defer appMgr.oldNodesMutex.Unlock()

	// Only check for updates once we are in our initial state
	if appMgr.initialState {
		// Compare last set of nodes with new one
		if !reflect.DeepEqual(newNodes, appMgr.oldNodes) {
			log.Infof("ProcessNodeUpdate: Change in Node state detected")
			appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
				port := strconv.Itoa(int(cfg.MetaData.NodePort))
				var newAddrPorts []string
				for _, node := range newNodes {
					var b bytes.Buffer
					b.WriteString(node)
					b.WriteRune(':')
					b.WriteString(port)
					newAddrPorts = append(newAddrPorts, b.String())
				}
				cfg.VirtualServer.Backend.PoolMemberAddrs = newAddrPorts
			})
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

// Dump out the Virtual Server configs to a file
func (appMgr *Manager) outputConfig() {
	appMgr.vservers.Lock()
	appMgr.outputConfigLocked()
	appMgr.vservers.Unlock()
}

// Dump out the Virtual Server configs to a file
// This function MUST be called with the virtualServers
// lock held.
func (appMgr *Manager) outputConfigLocked() {

	// Initialize the Services array as empty; json.Marshal() writes
	// an uninitialized array as 'null', but we want an empty array
	// written as '[]' instead
	services := VirtualServerConfigs{}

	// Filter the configs to only those that have active services
	appMgr.vservers.ForEach(func(key serviceKey, cfg *VirtualServerConfig) {
		if cfg.MetaData.Active == true {
			services = append(services, cfg)
		}
	})
	if appMgr.vsQueue.Len() == 0 && appMgr.nsQueue.Len() == 0 ||
		appMgr.initialState == true {
		doneCh, errCh, err := appMgr.ConfigWriter().SendSection("services", services)
		if nil != err {
			log.Warningf("Failed to write Big-IP config data: %v", err)
		} else {
			select {
			case <-doneCh:
				log.Infof("Wrote %v Virtual Server configs", len(services))
				if log.LL_DEBUG == log.GetLogLevel() {
					output, err := json.Marshal(services)
					if nil != err {
						log.Warningf("Failed creating output debug log: %v", err)
					} else {
						log.Debugf("Services: %s", output)
					}
				}
			case e := <-errCh:
				log.Warningf("Failed to write Big-IP config data: %v", e)
			case <-time.After(time.Second):
				log.Warning("Did not receive config write response in 1s")
			}
		}
		appMgr.initialState = true
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

	for _, node := range nodes {
		if node.Spec.Unschedulable {
			// Skip master node
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

// Create a VirtualServerConfig based on an Ingress resource config
func createVSConfigFromIngress(ing *v1beta1.Ingress) *VirtualServerConfig {
	var cfg VirtualServerConfig

	if class, ok := ing.ObjectMeta.Annotations["kubernetes.io/ingress.class"]; ok == true {
		if class != "f5" {
			return nil
		}
	}

	cfg.VirtualServer.Frontend.Mode = "http"
	if balance, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/balance"]; ok == true {
		cfg.VirtualServer.Frontend.Balance = balance
	} else {
		cfg.VirtualServer.Frontend.Balance = DEFAULT_BALANCE
	}
	cfg.VirtualServer.Frontend.VirtualAddress = &virtualAddress{}

	if partition, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/partition"]; ok == true {
		cfg.VirtualServer.Frontend.Partition = partition
	} else {
		cfg.VirtualServer.Frontend.Partition = DEFAULT_PARTITION
	}

	if httpPort, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/http-port"]; ok == true {
		port, _ := strconv.ParseInt(httpPort, 10, 32)
		cfg.VirtualServer.Frontend.VirtualAddress.Port = int32(port)
	} else {
		cfg.VirtualServer.Frontend.VirtualAddress.Port = DEFAULT_HTTP_PORT
	}

	if addr, ok := ing.ObjectMeta.Annotations["virtual-server.f5.com/ip"]; ok == true {
		cfg.VirtualServer.Frontend.VirtualAddress.BindAddr = addr
	} else {
		log.Infof("No virtual IP was specified for the virtual server %s, creating pool only.",
			ing.ObjectMeta.Name)
	}

	cfg.VirtualServer.Backend.ServiceName = ing.Spec.Backend.ServiceName
	cfg.VirtualServer.Backend.ServicePort = ing.Spec.Backend.ServicePort.IntVal

	return &cfg
}
