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

package controller

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"

	routeapi "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/informers/externalversions/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var K8SCoreServices = map[string]bool{
	"kube-dns":                    true,
	"kube-scheduler":              true,
	"kube-controller-manager":     true,
	"kube-apiserver":              true,
	"docker-registry":             true,
	"kubernetes":                  true,
	"registry-console":            true,
	"router":                      true,
	"kubelet":                     true,
	"console":                     true,
	"alertmanager-main":           true,
	"alertmanager-operated":       true,
	"cluster-monitoring-operator": true,
	"kube-state-metrics":          true,
	"node-exporter":               true,
	"kube-proxy":                  true,
	"flannel":                     true,
	"etcd":                        true,
	"antrea":                      true,
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

// start the VirtualServer informer
func (crInfr *CRInformer) start() {
	var cacheSyncs []cache.InformerSynced

	if crInfr.vsInformer != nil {
		log.Infof("Starting VirtualServer Informer")
		go crInfr.vsInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.vsInformer.HasSynced)
	}
	if crInfr.tlsInformer != nil {
		log.Infof("Starting TLSProfile Informer")
		go crInfr.tlsInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.tlsInformer.HasSynced)
	}
	if crInfr.tsInformer != nil {
		log.Infof("Starting TransportServer Informer")
		go crInfr.tsInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.tsInformer.HasSynced)
	}
	if crInfr.ilInformer != nil {
		log.Infof("Starting IngressLink Informer")
		go crInfr.ilInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.ilInformer.HasSynced)
	}
	cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		crInfr.stopCh,
		cacheSyncs...,
	)
}

func (crInfr *CRInformer) stop() {
	close(crInfr.stopCh)
}

func (nrInfr *NRInformer) start() {
	var cacheSyncs []cache.InformerSynced
	if nrInfr.routeInformer != nil {
		go nrInfr.routeInformer.Run(nrInfr.stopCh)
		cacheSyncs = append(cacheSyncs, nrInfr.routeInformer.HasSynced)
	}
	cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		nrInfr.stopCh,
		cacheSyncs...,
	)
}

func (nrInfr *NRInformer) stop() {
	close(nrInfr.stopCh)
}

func (comInfr *CommonInformer) start() {
	var cacheSyncs []cache.InformerSynced
	if comInfr.svcInformer != nil {
		go comInfr.svcInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.svcInformer.HasSynced)
	}
	if comInfr.epsInformer != nil {
		go comInfr.epsInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.epsInformer.HasSynced)
	}
	if comInfr.ednsInformer != nil {
		log.Infof("Starting ExternalDNS Informer")
		go comInfr.ednsInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.ednsInformer.HasSynced)
	}
	if comInfr.plcInformer != nil {
		go comInfr.plcInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.plcInformer.HasSynced)
	}
	if comInfr.podInformer != nil {
		go comInfr.podInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.podInformer.HasSynced)
	}
	if comInfr.secretsInformer != nil {
		go comInfr.secretsInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.secretsInformer.HasSynced)
	}
	if comInfr.cmInformer != nil {
		go comInfr.cmInformer.Run(comInfr.stopCh)
		cacheSyncs = append(cacheSyncs, comInfr.cmInformer.HasSynced)
	}
	cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		comInfr.stopCh,
		cacheSyncs...,
	)
}

func (comInfr *CommonInformer) stop() {
	close(comInfr.stopCh)
}

func (ctlr *Controller) watchingAllNamespaces() bool {
	switch ctlr.mode {
	case OpenShiftMode, KubernetesMode:
		if len(ctlr.comInformers) == 0 || len(ctlr.nrInformers) == 0 {
			return false
		}
		_, watchingAll := ctlr.comInformers[""]
		return watchingAll
	case CustomResourceMode:
		if len(ctlr.crInformers) == 0 {
			// Not watching any namespaces.
			return false
		}
		_, watchingAll := ctlr.crInformers[""]
		return watchingAll
	}
	return false
}

func (ctlr *Controller) getNamespacedCRInformer(
	namespace string,
) (*CRInformer, bool) {
	if ctlr.watchingAllNamespaces() {
		namespace = ""
	}
	crInf, found := ctlr.crInformers[namespace]
	return crInf, found
}

func (ctlr *Controller) getNamespacedCommonInformer(
	namespace string,
) (*CommonInformer, bool) {
	if ctlr.watchingAllNamespaces() {
		namespace = ""
	}
	comInf, found := ctlr.comInformers[namespace]
	return comInf, found
}

func (ctlr *Controller) getNamespacedNativeInformer(
	namespace string,
) (*NRInformer, bool) {
	if ctlr.watchingAllNamespaces() {
		namespace = ""
	}
	nrInf, found := ctlr.nrInformers[namespace]
	return nrInf, found
}

func (ctlr *Controller) getWatchingNamespaces() []string {
	var namespaces []string
	if ctlr.watchingAllNamespaces() {
		nss, err := ctlr.kubeClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("Unable to Fetch Namespaces: %v", err)
			return nil
		}
		for _, ns := range nss.Items {
			namespaces = append(namespaces, ns.Name)
		}
		return namespaces
	}
	for ns, _ := range ctlr.namespaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

func (ctlr *Controller) addNamespacedInformers(
	namespace string,
	startInformer bool,
) error {
	if ctlr.watchingAllNamespaces() {
		return fmt.Errorf(
			"Cannot add additional namespaces when already watching all.")
	}
	if len(ctlr.crInformers) > 0 && "" == namespace {
		return fmt.Errorf(
			"Cannot watch all namespaces when already watching specific ones.")
	}

	// add common informers  in all modes
	if _, found := ctlr.comInformers[namespace]; !found {
		comInf := ctlr.newNamespacedCommonResourceInformer(namespace)
		ctlr.addCommonResourceEventHandlers(comInf)
		ctlr.comInformers[namespace] = comInf
		if startInformer {
			comInf.start()
		}
	}

	switch ctlr.mode {
	case OpenShiftMode, KubernetesMode:
		// Create native resource informers in openshift mode only
		if _, found := ctlr.nrInformers[namespace]; !found {
			nrInf := ctlr.newNamespacedNativeResourceInformer(namespace)
			ctlr.addNativeResourceEventHandlers(nrInf)
			ctlr.nrInformers[namespace] = nrInf
			if startInformer {
				nrInf.start()
			}
		}
	default:
		// create customer resource informers in custom resource mode
		// Enabling CRInformers only for custom resource mode
		if _, found := ctlr.crInformers[namespace]; !found {
			crInf := ctlr.newNamespacedCustomResourceInformer(namespace)
			ctlr.addCustomResourceEventHandlers(crInf)
			ctlr.crInformers[namespace] = crInf
			if startInformer {
				crInf.start()
			}
		}
	}
	return nil
}

func (ctlr *Controller) newNamespacedCustomResourceInformer(
	namespace string,
) *CRInformer {
	log.Debugf("Creating Custom Resource Informers for Namespace: %v", namespace)
	crOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = ctlr.customResourceSelector.String()
	}
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	resyncPeriod := 0 * time.Second

	crInf := &CRInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
	}

	crInf.ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
		ctlr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		everything,
	)

	crInf.vsInformer = cisinfv1.NewFilteredVirtualServerInformer(
		ctlr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	crInf.tlsInformer = cisinfv1.NewFilteredTLSProfileInformer(
		ctlr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	crInf.tsInformer = cisinfv1.NewFilteredTransportServerInformer(
		ctlr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	return crInf
}

func (ctlr *Controller) newNamespacedNativeResourceInformer(
	namespace string,
) *NRInformer {
	log.Debugf("Creating Native Resource Informers for Namespace: %v", namespace)
	resyncPeriod := 0 * time.Second
	nrInformer := &NRInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
	}
	switch ctlr.mode {
	case OpenShiftMode:
		// Ensure the default server cert is loaded
		//appMgr.loadDefaultCert() why?
		nrInformer.routeInformer = cache.NewSharedIndexInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					options.LabelSelector = ctlr.routeLabel
					return ctlr.routeClientV1.Routes(namespace).List(context.TODO(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					options.LabelSelector = ctlr.routeLabel
					return ctlr.routeClientV1.Routes(namespace).Watch(context.TODO(), options)
				},
			},
			&routeapi.Route{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}

	return nrInformer
}

func (ctlr *Controller) getNodeInformer(clusterName string) NodeInformer {
	resyncPeriod := 0 * time.Second
	var restClientv1 rest.Interface
	nodeOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = ctlr.nodeLabelSelector
	}
	if clusterName == "" {
		restClientv1 = ctlr.kubeClient.CoreV1().RESTClient()
	} else {
		if config, ok := ctlr.multiClusterConfigs.ClusterConfigs[clusterName]; ok {
			restClientv1 = config.KubeClient.CoreV1().RESTClient()
		}
	}
	return NodeInformer{stopCh: make(chan struct{}),
		nodeInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"nodes",
				"",
				nodeOptions,
			),
			&corev1.Node{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		clusterName: clusterName,
	}
}

func (ctlr *Controller) addNodeEventUpdateHandler(nodeInformer *NodeInformer) {
	if nodeInformer.nodeInformer != nil {
		nodeInformer.nodeInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.SetupNodeProcessing(nodeInformer.clusterName) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.SetupNodeProcessing(nodeInformer.clusterName) },
				DeleteFunc: func(obj interface{}) { ctlr.SetupNodeProcessing(nodeInformer.clusterName) },
			},
		)
		nodeInformer.nodeInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(NodeUpdate, nodeInformer.clusterName))
	}
}

func (ctlr *Controller) newNamespacedCommonResourceInformer(
	namespace string,
) *CommonInformer {
	log.Debugf("Creating Common Resource Informers for Namespace: %v", namespace)
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	resyncPeriod := 0 * time.Second
	restClientv1 := ctlr.kubeClient.CoreV1().RESTClient()
	crOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = ctlr.customResourceSelector.String()
	}
	comInf := &CommonInformer{
		namespace: namespace,
		stopCh:    make(chan struct{}),
		svcInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"services",
				namespace,
				everything,
			),
			&corev1.Service{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
		secretsInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"secrets",
				namespace,
				everything,
			),
			&corev1.Secret{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}
	// Skipping endpoint informer creation for namespace in non cluster mode when extended cm is not provided
	if ctlr.PoolMemberType != Cluster && ctlr.PoolMemberType != Auto && ctlr.multiClusterMode != "" {
		log.Debugf("[Multicluster] Skipping endpoint informer creation for namespace %v in %v mode", namespace, ctlr.mode)
	} else {
		comInf.epsInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"endpoints",
				namespace,
				everything,
			),
			&corev1.Endpoints{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}

	comInf.ednsInformer = cisinfv1.NewFilteredExternalDNSInformer(
		ctlr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)

	comInf.plcInformer = cisinfv1.NewFilteredPolicyInformer(
		ctlr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	// start the cm informer if it's specified in deployment
	if ctlr.globalExtendedCMKey != "" {
		nrOptions := func(options *metav1.ListOptions) {
			options.LabelSelector = ctlr.nativeResourceSelector.String()
		}
		comInf.cmInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"configmaps",
				namespace,
				nrOptions,
			),
			&corev1.ConfigMap{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}
	//enable pod informer for nodeport local mode and openshift mode
	if ctlr.PoolMemberType == NodePortLocal || ctlr.mode == OpenShiftMode {
		comInf.podInformer = cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"pods",
				namespace,
				everything,
			),
			&corev1.Pod{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		)
	}
	return comInf
}

func (ctlr *Controller) addCustomResourceEventHandlers(crInf *CRInformer) {
	if crInf.vsInformer != nil {
		crInf.vsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueVirtualServer(obj) },
				UpdateFunc: func(old, cur interface{}) { ctlr.enqueueUpdatedVirtualServer(old, cur) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedVirtualServer(obj) },
			},
		)
		crInf.vsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(VirtualServer, Local))
	}

	if crInf.tlsInformer != nil {
		crInf.tlsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueTLSProfile(obj, Create) },
				UpdateFunc: func(old, cur interface{}) { ctlr.enqueueTLSProfile(cur, Update) },
				// DeleteFunc: func(obj interface{}) { ctlr.enqueueTLSProfile(obj) },
			},
		)
		crInf.tlsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(TLSProfile, Local))
	}

	if crInf.tsInformer != nil {
		crInf.tsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueTransportServer(obj) },
				UpdateFunc: func(old, cur interface{}) { ctlr.enqueueUpdatedTransportServer(old, cur) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedTransportServer(obj) },
			},
		)
		crInf.tsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(TransportServer, Local))
	}

	if crInf.ilInformer != nil {
		crInf.ilInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueIngressLink(obj) },
				UpdateFunc: func(oldObj, newObj interface{}) { ctlr.enqueueUpdatedIngressLink(oldObj, newObj) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedIngressLink(obj) },
			},
		)
		crInf.ilInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(IngressLink, Local))
	}
}

func (ctlr *Controller) addCommonResourceEventHandlers(comInf *CommonInformer) {
	if comInf.svcInformer != nil {
		comInf.svcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueService(obj, "") },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueUpdatedService(obj, cur, "") },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedService(obj, "") },
			},
		)
		comInf.svcInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Service, Local))
	}

	if comInf.epsInformer != nil {
		comInf.epsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueEndpoints(obj, Create, "") },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueEndpoints(cur, Update, "") },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueEndpoints(obj, Delete, "") },
			},
		)
		comInf.epsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Endpoints, Local))
	}

	if comInf.ednsInformer != nil {
		comInf.ednsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueExternalDNS(obj) },
				UpdateFunc: func(oldObj, newObj interface{}) { ctlr.enqueueUpdatedExternalDNS(oldObj, newObj) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedExternalDNS(obj) },
			})
		comInf.ednsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(ExternalDNS, Local))
	}

	if comInf.plcInformer != nil {
		comInf.plcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePolicy(obj, Create) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePolicy(cur, Update) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPolicy(obj) },
			},
		)
		comInf.plcInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(CustomPolicy, Local))
	}

	if comInf.podInformer != nil {
		comInf.podInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueuePod(obj, "") },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueuePod(cur, "") },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedPod(obj, "") },
			},
		)
		comInf.podInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Pod, Local))
	}

	if comInf.secretsInformer != nil {
		comInf.secretsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueSecret(obj, Create) },
				UpdateFunc: func(obj, cur interface{}) { ctlr.enqueueSecret(cur, Update) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueSecret(obj, Delete) },
			},
		)
		comInf.secretsInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Secret, Local))
	}

	if comInf.cmInformer != nil {
		comInf.cmInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueConfigmap(obj, Create) },
				UpdateFunc: func(old, obj interface{}) { ctlr.enqueueConfigmap(obj, Update) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedConfigmap(obj) },
			},
		)
		comInf.cmInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(ConfigMap, Local))
	}

}

func (ctlr *Controller) addNativeResourceEventHandlers(nrInf *NRInformer) {
	if nrInf.routeInformer != nil {
		nrInf.routeInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { ctlr.enqueueRoute(obj, Create) },
				UpdateFunc: func(old, cur interface{}) { ctlr.enqueueUpdatedRoute(old, cur) },
				DeleteFunc: func(obj interface{}) { ctlr.enqueueRoute(obj, Delete) },
			},
		)
		nrInf.routeInformer.SetWatchErrorHandler(ctlr.getErrorHandlerFunc(Route, Local))
	}
}

func (ctlr *Controller) getEventHandlerForIPAM() *cache.ResourceEventHandlerFuncs {
	return &cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { ctlr.enqueueIPAM(obj) },
		UpdateFunc: func(oldObj, newObj interface{}) { ctlr.enqueueUpdatedIPAM(oldObj, newObj) },
		DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedIPAM(obj) },
	}
}

func (ctlr *Controller) enqueueIPAM(obj interface{}) {
	ipamObj := obj.(*ficV1.IPAM)

	if ipamObj.Namespace+"/"+ipamObj.Name != ctlr.ipamCR {
		return
	}

	log.Debugf("Enqueueing IPAM: %v", ipamObj)
	key := &rqKey{
		namespace: ipamObj.ObjectMeta.Namespace,
		kind:      IPAM,
		rscName:   ipamObj.ObjectMeta.Name,
		rsc:       obj,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueUpdatedIPAM(oldObj, newObj interface{}) {
	oldIpam := oldObj.(*ficV1.IPAM)
	curIpam := newObj.(*ficV1.IPAM)

	if curIpam.Namespace+"/"+curIpam.Name != ctlr.ipamCR {
		return
	}

	if reflect.DeepEqual(oldIpam.Status, curIpam.Status) {
		return
	}

	log.Debugf("Enqueueing Updated IPAM: %v", curIpam)
	key := &rqKey{
		namespace: curIpam.ObjectMeta.Namespace,
		kind:      IPAM,
		rscName:   curIpam.ObjectMeta.Name,
		rsc:       newObj,
		event:     Update,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedIPAM(obj interface{}) {
	ipamObj := obj.(*ficV1.IPAM)

	if ipamObj.Namespace+"/"+ipamObj.Name != ctlr.ipamCR {
		return
	}

	log.Debugf("Enqueueing IPAM: %v", ipamObj)
	key := &rqKey{
		namespace: ipamObj.ObjectMeta.Namespace,
		kind:      IPAM,
		rscName:   ipamObj.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueVirtualServer(obj interface{}) {
	vs := obj.(*cisapiv1.VirtualServer)
	log.Debugf("Enqueueing VirtualServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueUpdatedVirtualServer(oldObj, newObj interface{}) {
	oldVS := oldObj.(*cisapiv1.VirtualServer)
	newVS := newObj.(*cisapiv1.VirtualServer)
	// Skip virtual servers on status updates
	if reflect.DeepEqual(oldVS.Spec, newVS.Spec) && reflect.DeepEqual(oldVS.Labels, newVS.Labels) {
		return
	}
	updateEvent := true
	oldVSPartition := ctlr.getCRPartition(oldVS.Spec.Partition)
	newVSPartition := ctlr.getCRPartition(newVS.Spec.Partition)
	if oldVS.Spec.VirtualServerAddress != newVS.Spec.VirtualServerAddress ||
		oldVS.Spec.VirtualServerHTTPPort != newVS.Spec.VirtualServerHTTPPort ||
		oldVS.Spec.VirtualServerHTTPSPort != newVS.Spec.VirtualServerHTTPSPort ||
		oldVS.Spec.VirtualServerName != newVS.Spec.VirtualServerName ||
		oldVS.Spec.Host != newVS.Spec.Host ||
		!reflect.DeepEqual(oldVS.Spec.HostAliases, newVS.Spec.HostAliases) ||
		oldVS.Spec.IPAMLabel != newVS.Spec.IPAMLabel ||
		oldVS.Spec.HostGroup != newVS.Spec.HostGroup ||
		oldVSPartition != newVSPartition {
		log.Debugf("Enqueueing Old VirtualServer: %v", oldVS)

		// delete vs from previous partition on priority when partition is changed
		if oldVSPartition != newVSPartition {
			ctlr.resources.updatePartitionPriority(oldVSPartition, 1)
		}

		key := &rqKey{
			namespace: oldVS.ObjectMeta.Namespace,
			kind:      VirtualServer,
			rscName:   oldVS.ObjectMeta.Name,
			rsc:       oldObj,
			event:     Delete,
		}
		updateEvent = false
		ctlr.resourceQueue.Add(key)
	}

	log.Debugf("Enqueueing VirtualServer: %v", newVS)
	key := &rqKey{
		namespace: newVS.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   newVS.ObjectMeta.Name,
		rsc:       newObj,
		event:     Create,
	}
	if updateEvent {
		key.event = Update
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedVirtualServer(obj interface{}) {
	vs := obj.(*cisapiv1.VirtualServer)
	log.Debugf("Enqueueing VirtualServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueTLSProfile(obj interface{}, event string) {
	tls := obj.(*cisapiv1.TLSProfile)
	log.Debugf("Enqueueing TLSProfile: %v", tls)
	key := &rqKey{
		namespace: tls.ObjectMeta.Namespace,
		kind:      TLSProfile,
		rscName:   tls.ObjectMeta.Name,
		rsc:       obj,
		event:     event,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueTransportServer(obj interface{}) {
	ts := obj.(*cisapiv1.TransportServer)
	log.Debugf("Enqueueing TransportServer: %v", ts)
	key := &rqKey{
		namespace: ts.ObjectMeta.Namespace,
		kind:      TransportServer,
		rscName:   ts.ObjectMeta.Name,
		rsc:       obj,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueUpdatedTransportServer(oldObj, newObj interface{}) {
	oldVS := oldObj.(*cisapiv1.TransportServer)
	newVS := newObj.(*cisapiv1.TransportServer)
	// Skip transport servers on status updates
	if reflect.DeepEqual(oldVS.Spec, newVS.Spec) && reflect.DeepEqual(oldVS.Labels, newVS.Labels) {
		return
	}
	updateEvent := true
	oldVSPartition := ctlr.getCRPartition(oldVS.Spec.Partition)
	newVSPartition := ctlr.getCRPartition(newVS.Spec.Partition)
	if oldVS.Spec.VirtualServerAddress != newVS.Spec.VirtualServerAddress ||
		oldVS.Spec.VirtualServerPort != newVS.Spec.VirtualServerPort ||
		oldVS.Spec.VirtualServerName != newVS.Spec.VirtualServerName ||
		oldVS.Spec.IPAMLabel != newVS.Spec.IPAMLabel ||
		oldVS.Spec.HostGroup != newVS.Spec.HostGroup ||
		oldVSPartition != newVSPartition {
		log.Debugf("Enqueueing TransportServer: %v", oldVS)

		// delete vs from previous partition on priority when partition is changed
		if oldVSPartition != newVSPartition {
			ctlr.resources.updatePartitionPriority(oldVSPartition, 1)
		}

		key := &rqKey{
			namespace: oldVS.ObjectMeta.Namespace,
			kind:      TransportServer,
			rscName:   oldVS.ObjectMeta.Name,
			rsc:       oldObj,
			event:     Delete,
		}
		ctlr.resourceQueue.Add(key)
		updateEvent = false
	}

	log.Debugf("Enqueueing TransportServer: %v", newVS)
	key := &rqKey{
		namespace: newVS.ObjectMeta.Namespace,
		kind:      TransportServer,
		rscName:   newVS.ObjectMeta.Name,
		rsc:       newObj,
		event:     Create,
	}
	if updateEvent {
		key.event = Update
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedTransportServer(obj interface{}) {
	vs := obj.(*cisapiv1.TransportServer)
	log.Debugf("Enqueueing TransportServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      TransportServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueuePolicy(obj interface{}, event string) {
	pol := obj.(*cisapiv1.Policy)
	log.Debugf("Enqueueing Policy: %v", pol)
	key := &rqKey{
		namespace: pol.ObjectMeta.Namespace,
		kind:      CustomPolicy,
		rscName:   pol.ObjectMeta.Name,
		rsc:       obj,
		event:     event,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedPolicy(obj interface{}) {
	pol := obj.(*cisapiv1.Policy)
	log.Debugf("Enqueueing Policy: %v", pol)
	key := &rqKey{
		namespace: pol.ObjectMeta.Namespace,
		kind:      CustomPolicy,
		rscName:   pol.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueIngressLink(obj interface{}) {
	ingLink := obj.(*cisapiv1.IngressLink)
	log.Debugf("Enqueueing IngressLink: %v", ingLink)
	key := &rqKey{
		namespace: ingLink.ObjectMeta.Namespace,
		kind:      IngressLink,
		rscName:   ingLink.ObjectMeta.Name,
		rsc:       obj,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedIngressLink(obj interface{}) {
	ingLink := obj.(*cisapiv1.IngressLink)
	log.Debugf("Enqueueing IngressLink: %v on Delete", ingLink)
	key := &rqKey{
		namespace: ingLink.ObjectMeta.Namespace,
		kind:      IngressLink,
		rscName:   ingLink.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueUpdatedIngressLink(oldObj, newObj interface{}) {
	oldIngLink := oldObj.(*cisapiv1.IngressLink)
	newIngLink := newObj.(*cisapiv1.IngressLink)

	oldILPartition := ctlr.getCRPartition(oldIngLink.Spec.Partition)
	newILPartition := ctlr.getCRPartition(newIngLink.Spec.Partition)
	if oldIngLink.Spec.VirtualServerAddress != newIngLink.Spec.VirtualServerAddress ||
		oldIngLink.Spec.IPAMLabel != newIngLink.Spec.IPAMLabel ||
		oldILPartition != newILPartition {

		// delete vs from previous partition on priority when partition is changed
		if oldILPartition != newILPartition {
			ctlr.resources.updatePartitionPriority(oldILPartition, 1)
		}

		key := &rqKey{
			namespace: oldIngLink.ObjectMeta.Namespace,
			kind:      IngressLink,
			rscName:   oldIngLink.ObjectMeta.Name,
			rsc:       oldIngLink,
			event:     Delete,
		}

		ctlr.resourceQueue.Add(key)
	}

	log.Debugf("Enqueueing IngressLink: %v on Update", newIngLink)
	key := &rqKey{
		namespace: newIngLink.ObjectMeta.Namespace,
		kind:      IngressLink,
		rscName:   newIngLink.ObjectMeta.Name,
		rsc:       newIngLink,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueExternalDNS(obj interface{}) {
	edns := obj.(*cisapiv1.ExternalDNS)
	log.Debugf("Enqueueing ExternalDNS: %v", edns)
	key := &rqKey{
		namespace: edns.ObjectMeta.Namespace,
		kind:      ExternalDNS,
		rscName:   edns.ObjectMeta.Name,
		rsc:       obj,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueUpdatedExternalDNS(oldObj, newObj interface{}) {
	oldEDNS := oldObj.(*cisapiv1.ExternalDNS)
	edns := newObj.(*cisapiv1.ExternalDNS)

	if oldEDNS.Spec.DomainName != edns.Spec.DomainName {
		key := &rqKey{
			namespace: oldEDNS.ObjectMeta.Namespace,
			kind:      ExternalDNS,
			rscName:   oldEDNS.ObjectMeta.Name,
			rsc:       oldEDNS,
			event:     Delete,
		}

		ctlr.resourceQueue.Add(key)
	}

	log.Debugf("Enqueueing Updated ExternalDNS: %v", edns)
	key := &rqKey{
		namespace: edns.ObjectMeta.Namespace,
		kind:      ExternalDNS,
		rscName:   edns.ObjectMeta.Name,
		rsc:       edns,
		event:     Create,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedExternalDNS(obj interface{}) {
	edns := obj.(*cisapiv1.ExternalDNS)
	log.Debugf("Enqueueing ExternalDNS: %v", edns)
	key := &rqKey{
		namespace: edns.ObjectMeta.Namespace,
		kind:      ExternalDNS,
		rscName:   edns.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueService(obj interface{}, clusterName string) {
	svc := obj.(*corev1.Service)
	// Ignore K8S Core Services
	if _, ok := K8SCoreServices[svc.Name]; ok {
		return
	}
	if ctlr.mode == OpenShiftMode {
		if _, ok := OSCPCoreServices[svc.Name]; ok {
			return
		}
	}
	log.Debugf("Enqueueing Service: %v %v", svc, getClusterLog(clusterName))
	key := &rqKey{
		namespace:   svc.ObjectMeta.Namespace,
		kind:        Service,
		rscName:     svc.ObjectMeta.Name,
		rsc:         obj,
		event:       Create,
		clusterName: clusterName,
	}
	ctlr.resourceQueue.Add(key)
}

func getClusterLog(clusterName string) string {
	clusterNameLog := ""
	if clusterName != "" {
		clusterNameLog = "from cluster: " + clusterName
	} else {
		clusterNameLog = fmt.Sprintf("from cluster: %v", Local)
	}
	return clusterNameLog
}
func (ctlr *Controller) enqueueUpdatedService(obj, cur interface{}, clusterName string) {
	svc := obj.(*corev1.Service)
	curSvc := cur.(*corev1.Service)
	// Ignore K8S Core Services
	if _, ok := K8SCoreServices[svc.Name]; ok {
		return
	}
	if ctlr.mode == OpenShiftMode {
		if _, ok := OSCPCoreServices[svc.Name]; ok {
			return
		}
	}

	if (svc.Spec.Type != curSvc.Spec.Type && svc.Spec.Type == corev1.ServiceTypeLoadBalancer) ||
		(svc.Spec.Type == corev1.ServiceTypeLoadBalancer && svc.Annotations[LBServiceIPAnnotation] != curSvc.Annotations[LBServiceIPAnnotation]) ||
		(svc.Annotations[LBServiceIPAMLabelAnnotation] != curSvc.Annotations[LBServiceIPAMLabelAnnotation]) ||
		!reflect.DeepEqual(svc.Labels, curSvc.Labels) || !reflect.DeepEqual(svc.Spec.Ports, curSvc.Spec.Ports) ||
		!reflect.DeepEqual(svc.Spec.Selector, curSvc.Spec.Selector) {
		log.Debugf("Enqueueing Old Service: %v %v", svc, getClusterLog(clusterName))
		key := &rqKey{
			namespace:   svc.ObjectMeta.Namespace,
			kind:        Service,
			rscName:     svc.ObjectMeta.Name,
			rsc:         obj,
			event:       Delete,
			clusterName: clusterName,
		}
		ctlr.resourceQueue.Add(key)
	}

	log.Debugf("Enqueueing Updated Service: %v %v", curSvc, getClusterLog(clusterName))
	key := &rqKey{
		namespace:   curSvc.ObjectMeta.Namespace,
		kind:        Service,
		rscName:     curSvc.ObjectMeta.Name,
		rsc:         cur,
		event:       Create,
		clusterName: clusterName,
	}
	if !reflect.DeepEqual(svc.Spec.Ports, curSvc.Spec.Ports) {
		key.svcPortUpdated = true
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedService(obj interface{}, clusterName string) {
	svc := obj.(*corev1.Service)
	// Ignore K8S Core Services
	if _, ok := K8SCoreServices[svc.Name]; ok {
		return
	}
	if ctlr.mode == OpenShiftMode {
		if _, ok := OSCPCoreServices[svc.Name]; ok {
			return
		}
	}
	log.Debugf("Enqueueing Service: %v %v", svc, getClusterLog(clusterName))
	key := &rqKey{
		namespace:   svc.ObjectMeta.Namespace,
		kind:        Service,
		rscName:     svc.ObjectMeta.Name,
		rsc:         obj,
		event:       Delete,
		clusterName: clusterName,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueEndpoints(obj interface{}, event string, clusterName string) {
	eps := obj.(*corev1.Endpoints)
	// Ignore K8S Core Services
	if _, ok := K8SCoreServices[eps.Name]; ok {
		return
	}
	if ctlr.mode == OpenShiftMode {
		if _, ok := OSCPCoreServices[eps.Name]; ok {
			return
		}
	}
	log.Debugf("Enqueueing Endpoints: %v %v", eps, getClusterLog(clusterName))
	key := &rqKey{
		namespace:   eps.ObjectMeta.Namespace,
		kind:        Endpoints,
		rscName:     eps.ObjectMeta.Name,
		rsc:         obj,
		event:       event,
		clusterName: clusterName,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueSecret(obj interface{}, event string) {
	secret := obj.(*corev1.Secret)
	log.Debugf("Enqueueing Secrets: %v/%v", secret.Namespace, secret.Name)
	key := &rqKey{
		namespace: secret.ObjectMeta.Namespace,
		kind:      K8sSecret,
		rscName:   secret.ObjectMeta.Name,
		rsc:       obj,
		event:     event,
	}
	ctlr.resourceQueue.Add(key)

}

func (ctlr *Controller) enqueueRoute(obj interface{}, event string) {
	rt := obj.(*routeapi.Route)
	log.Debugf("Enqueueing Route: %v/%v", rt.ObjectMeta.Namespace, rt.ObjectMeta.Name)
	key := &rqKey{
		namespace: rt.ObjectMeta.Namespace,
		kind:      Route,
		rscName:   rt.ObjectMeta.Name,
		rsc:       obj,
		event:     event,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueUpdatedRoute(old, cur interface{}) {
	oldRoute := old.(*routeapi.Route)
	newRoute := cur.(*routeapi.Route)

	if reflect.DeepEqual(oldRoute.Spec, newRoute.Spec) && reflect.DeepEqual(oldRoute.Annotations, newRoute.Annotations) {
		return
	}
	log.Debugf("Enqueueing Route: %v/%v", newRoute.ObjectMeta.Namespace, newRoute.ObjectMeta.Name)
	key := &rqKey{
		namespace: newRoute.ObjectMeta.Namespace,
		kind:      Route,
		rscName:   newRoute.ObjectMeta.Name,
		event:     Update,
		rsc:       cur,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueConfigmap(obj interface{}, event string) {
	cm := obj.(*corev1.ConfigMap)

	// Filter out configmaps that are neither f5nr configmaps nor routeSpecConfigmap
	//if !ctlr.nativeResourceSelector.Matches(labels.Set(cm.GetLabels())) &&
	//	ctlr.globalExtendedCMKey != cm.Namespace+"/"+cm.Name {
	//
	//	return
	//}

	log.Debugf("Enqueueing ConfigMap: %v/%v", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
	key := &rqKey{
		namespace: cm.ObjectMeta.Namespace,
		kind:      ConfigMap,
		rscName:   cm.ObjectMeta.Name,
		rsc:       obj,
		event:     event,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedConfigmap(obj interface{}) {
	cm := obj.(*corev1.ConfigMap)

	log.Debugf("Enqueueing ConfigMap: %v/%v", cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
	key := &rqKey{
		namespace: cm.ObjectMeta.Namespace,
		kind:      ConfigMap,
		rscName:   cm.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedRoute(obj interface{}) {
	rt := obj.(*routeapi.Route)

	log.Debugf("Enqueueing Deleted Route: %v/%v", rt.ObjectMeta.Namespace, rt.ObjectMeta.Name)
	key := &rqKey{
		namespace: rt.ObjectMeta.Namespace,
		kind:      Route,
		rscName:   rt.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueuePod(obj interface{}, clusterName string) {
	pod := obj.(*corev1.Pod)
	//skip if pod belongs to coreService
	if ctlr.checkCoreserviceLabels(pod.Labels) {
		return
	}
	log.Debugf("Enqueueing pod: %v/%v %v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, getClusterLog(clusterName))
	key := &rqKey{
		namespace:   pod.ObjectMeta.Namespace,
		kind:        Pod,
		rscName:     pod.ObjectMeta.Name,
		rsc:         obj,
		clusterName: clusterName,
	}

	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedPod(obj interface{}, clusterName string) {
	var pod *corev1.Pod
	switch obj.(type) {
	case *corev1.Pod:
		pod = obj.(*corev1.Pod)
	case cache.DeletedFinalStateUnknown:
		dFSUObj := obj.(cache.DeletedFinalStateUnknown)
		var ok bool
		pod, ok = dFSUObj.Obj.(*corev1.Pod)
		if pod == nil || !ok {
			log.Warningf("Unknown object received as pod deletion event: %v %v", dFSUObj.Key, getClusterLog(clusterName))
			return
		}
	default:
		log.Warningf("Unknown object received as pod deletion event: %v %v", obj, getClusterLog(clusterName))
		return
	}

	//skip if pod belongs to coreService
	if ctlr.checkCoreserviceLabels(pod.Labels) {
		return
	}
	log.Debugf("Enqueueing pod: %v/%v %v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, getClusterLog(clusterName))
	key := &rqKey{
		namespace:   pod.ObjectMeta.Namespace,
		kind:        Pod,
		rscName:     pod.ObjectMeta.Name,
		rsc:         obj,
		event:       Delete,
		clusterName: clusterName,
	}
	ctlr.resourceQueue.Add(key)
}

func (nsInfr *NSInformer) start() {
	if nsInfr.nsInformer != nil {
		log.Infof("Starting Namespace Informer")
		go nsInfr.nsInformer.Run(nsInfr.stopCh)
	}
}

func (nsInfr *NSInformer) stop() {
	close(nsInfr.stopCh)
}

func (nodeInfr *NodeInformer) start() {
	var cacheSyncs []cache.InformerSynced
	infSyncCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if nodeInfr.nodeInformer != nil {
		log.Infof("Starting %v Node Informer", nodeInfr.clusterName)
		go nodeInfr.nodeInformer.Run(nodeInfr.stopCh)
		cacheSyncs = append(cacheSyncs, nodeInfr.nodeInformer.HasSynced)
	}
	if cache.WaitForNamedCacheSync(
		"F5 CIS Ingress Controller",
		infSyncCtx.Done(),
		cacheSyncs...,
	) {
		log.Debug("Successfully synced node informer cache")
	} else {
		log.Warningf("Failed to sync node informer cache")
	}
}

func (nodeInfr *NodeInformer) stop() {
	close(nodeInfr.stopCh)
}

func (ctlr *Controller) createNamespaceLabeledInformer(label string) error {
	selector, err := createLabelSelector(label)
	if err != nil {
		return fmt.Errorf("unable to setup namespace-label informer for label: %v, Error:%v", label, err)
	}
	namespaceOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = selector.String()
	}

	if 0 != len(ctlr.crInformers) {
		return fmt.Errorf("cannot set a namespace label informer when informers " +
			"have been setup for one or more namespaces")
	}

	resyncPeriod := 0 * time.Second
	restClientv1 := ctlr.kubeClient.CoreV1().RESTClient()

	ctlr.nsInformers[label] = &NSInformer{
		stopCh: make(chan struct{}),
		nsInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"namespaces",
				"",
				namespaceOptions,
			),
			&corev1.Namespace{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}

	ctlr.nsInformers[label].nsInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { ctlr.enqueueNamespace(obj) },
			DeleteFunc: func(obj interface{}) { ctlr.enqueueDeletedNamespace(obj) },
		},
		resyncPeriod,
	)

	return nil
}

func (ctlr *Controller) enqueueNamespace(obj interface{}) {
	ns := obj.(*corev1.Namespace)
	log.Debugf("Enqueueing Namespace: %v", ns)
	key := &rqKey{
		namespace: ns.ObjectMeta.Namespace,
		kind:      Namespace,
		rscName:   ns.ObjectMeta.Name,
		rsc:       obj,
		event:     Create,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) enqueueDeletedNamespace(obj interface{}) {
	ns := obj.(*corev1.Namespace)
	log.Debugf("Enqueueing Namespace: %v on Delete", ns)
	key := &rqKey{
		namespace: ns.ObjectMeta.Namespace,
		kind:      Namespace,
		rscName:   ns.ObjectMeta.Name,
		rsc:       obj,
		event:     Delete,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) checkCoreserviceLabels(labels map[string]string) bool {
	for _, v := range labels {
		if _, ok := K8SCoreServices[v]; ok {
			return true
		}
		if ctlr.mode == OpenShiftMode {
			if _, ok := OSCPCoreServices[v]; ok {
				return true
			}
		}
	}
	return false
}

func (ctlr *Controller) enqueuePrimaryClusterProbeEvent() {
	log.Infof("[MultiCluster] Enqueueing primary CIS/cluster down event")
	key := &rqKey{
		kind: HACIS,
	}
	ctlr.resourceQueue.Add(key)
}

func (ctlr *Controller) getErrorHandlerFunc(rsType, clusterName string) func(r *cache.Reflector, err error) {
	return func(r *cache.Reflector, err error) {
		switch {
		case apierrors.IsResourceExpired(err) || apierrors.IsGone(err):
			// Don't set LastSyncResourceVersionUnavailable - LIST call with ResourceVersion=RV already
			// has a semantic that it returns data at least as fresh as provided RV.
			// So first try to LIST with setting RV to resource version of last observed object.
			log.Errorf("Watch of %v in cluster %v closed with: %v", rsType, clusterName, err)
		case err == io.EOF:
			// watch closed normally
		case err == io.ErrUnexpectedEOF:
			log.Errorf("Watch for %v in cluster %v closed with unexpected EOF: %v", rsType, clusterName, err)
		default:
			utilruntime.HandleError(fmt.Errorf("[ERROR] Failed to watch %v in cluster %v: %v", rsType, clusterName, err))
		}
	}
}
