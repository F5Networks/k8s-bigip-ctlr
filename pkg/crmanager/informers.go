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

package crmanager

import (
	"fmt"
	"reflect"
	"time"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/config/client/informers/externalversions/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

var K8SCoreServices = [...]string{"kube-dns", "kube-scheduler", "kube-controller-manager", "docker-registry", "kubernetes", "registry-console", "router", "kubelet", "console", "alertmanager-main", "alertmanager-operated", "cluster-monitoring-operator", "grafana", "kube-state-metrics", "node-exporter", "prometheus-k8s", "prometheus-operated", "prometheus-operatorwebconsole"}

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
	if crInfr.ednsInformer != nil {
		log.Infof("Starting ExternalDNS Informer")
		go crInfr.ednsInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.ednsInformer.HasSynced)
	}
	if crInfr.svcInformer != nil {
		go crInfr.svcInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.svcInformer.HasSynced)
	}
	if crInfr.epsInformer != nil {
		go crInfr.epsInformer.Run(crInfr.stopCh)
		cacheSyncs = append(cacheSyncs, crInfr.epsInformer.HasSynced)
	}

	cache.WaitForNamedCacheSync(
		"F5 CIS CRD Controller",
		crInfr.stopCh,
		cacheSyncs...,
	)
}

func (crInfr *CRInformer) stop() {
	close(crInfr.stopCh)
}

func (crMgr *CRManager) watchingAllNamespaces() bool {
	if 0 == len(crMgr.crInformers) {
		// Not watching any namespaces.
		return false
	}
	_, watchingAll := crMgr.crInformers[""]
	return watchingAll
}

func (crMgr *CRManager) addNamespacedInformer(
	namespace string,
) error {
	if crMgr.watchingAllNamespaces() {
		return fmt.Errorf(
			"Cannot add additional namespaces when already watching all.")
	}
	if len(crMgr.crInformers) > 0 && "" == namespace {
		return fmt.Errorf(
			"Cannot watch all namespaces when already watching specific ones.")
	}
	var crInf *CRInformer
	var found bool
	if crInf, found = crMgr.crInformers[namespace]; found {
		return nil
	}
	crInf = crMgr.newNamespacedInformer(namespace)
	crMgr.addEventHandlers(crInf)
	crMgr.crInformers[namespace] = crInf
	return nil
}

func (crMgr *CRManager) newNamespacedInformer(
	namespace string,
) *CRInformer {
	log.Debugf("Creating Informers for Namespace %v", namespace)
	crOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = crMgr.resourceSelector.String()
	}
	everything := func(options *metav1.ListOptions) {
		options.LabelSelector = ""
	}
	resyncPeriod := 0 * time.Second
	restClientv1 := crMgr.kubeClient.CoreV1().RESTClient()

	crInf := &CRInformer{
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
		epsInformer: cache.NewSharedIndexInformer(
			cache.NewFilteredListWatchFromClient(
				restClientv1,
				"endpoints",
				namespace,
				everything,
			),
			&corev1.Endpoints{},
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		),
	}

	crInf.ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
		crMgr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		everything,
	)

	crInf.vsInformer = cisinfv1.NewFilteredVirtualServerInformer(
		crMgr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	crInf.tlsInformer = cisinfv1.NewFilteredTLSProfileInformer(
		crMgr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	crInf.tsInformer = cisinfv1.NewFilteredTransportServerInformer(
		crMgr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)
	crInf.ednsInformer = cisinfv1.NewFilteredExternalDNSInformer(
		crMgr.kubeCRClient,
		namespace,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		crOptions,
	)

	return crInf
}

func (crMgr *CRManager) addEventHandlers(crInf *CRInformer) {
	if crInf.vsInformer != nil {
		crInf.vsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueVirtualServer(obj) },
				UpdateFunc: func(old, cur interface{}) { crMgr.enqueueUpdatedVirtualServer(old, cur) },
				DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedVirtualServer(obj) },
			},
		)
	}

	if crInf.tlsInformer != nil {
		crInf.tlsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueTLSServer(obj) },
				UpdateFunc: func(old, cur interface{}) { crMgr.enqueueTLSServer(cur) },
				// DeleteFunc: func(obj interface{}) { crMgr.enqueueTLSServer(obj) },
			},
		)
	}

	if crInf.tsInformer != nil {
		crInf.tsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueTransportServer(obj) },
				UpdateFunc: func(old, cur interface{}) { crMgr.enqueueUpdatedTransportServer(old, cur) },
				DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedTransportServer(obj) },
			},
		)
	}

	if crInf.ilInformer != nil {
		crInf.ilInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueIngressLink(obj) },
				UpdateFunc: func(oldObj, newObj interface{}) { crMgr.enqueueUpdatedIngressLink(oldObj, newObj) },
				DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedIngressLink(obj) },
			},
		)
	}

	if crInf.ednsInformer != nil {
		crInf.ednsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueExternalDNS(obj) },
				UpdateFunc: func(oldObj, newObj interface{}) { crMgr.enqueueUpdatedExternalDNS(oldObj, newObj) },
				DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedExternalDNS(obj) },
			})
	}

	if crInf.svcInformer != nil {
		crInf.svcInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueService(obj) },
				UpdateFunc: func(obj, cur interface{}) { crMgr.enqueueUpdatedService(obj, cur) },
				DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedService(obj) },
			},
		)
	}

	if crInf.epsInformer != nil {
		crInf.epsInformer.AddEventHandler(
			&cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj interface{}) { crMgr.enqueueEndpoints(obj) },
				UpdateFunc: func(obj, cur interface{}) { crMgr.enqueueEndpoints(cur) },
				DeleteFunc: func(obj interface{}) { crMgr.enqueueEndpoints(obj) },
			},
		)
	}
}

func (crMgr *CRManager) getEventHandlerForIPAM() *cache.ResourceEventHandlerFuncs {
	return &cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { crMgr.enqueueIPAM(obj) },
		UpdateFunc: func(oldObj, newObj interface{}) { crMgr.enqueueUpdatedIPAM(oldObj, newObj) },
		DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedIPAM(obj) },
	}
}

func (crMgr *CRManager) enqueueIPAM(obj interface{}) {
	ipamObj := obj.(*ficV1.F5IPAM)

	if ipamObj.Namespace+"/"+ipamObj.Name != crMgr.ipamCR {
		return
	}

	log.Infof("Enqueueing IPAM: %v", ipamObj)
	key := &rqKey{
		namespace: ipamObj.ObjectMeta.Namespace,
		kind:      IPAM,
		rscName:   ipamObj.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueUpdatedIPAM(oldObj, newObj interface{}) {
	oldIpam := oldObj.(*ficV1.F5IPAM)
	curIpam := newObj.(*ficV1.F5IPAM)

	if curIpam.Namespace+"/"+curIpam.Name != crMgr.ipamCR {
		return
	}

	if reflect.DeepEqual(oldIpam.Status, curIpam.Status) {
		return
	}

	log.Infof("Enqueueing Updated IPAM: %v", curIpam)
	key := &rqKey{
		namespace: curIpam.ObjectMeta.Namespace,
		kind:      IPAM,
		rscName:   curIpam.ObjectMeta.Name,
		rsc:       newObj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedIPAM(obj interface{}) {
	ipamObj := obj.(*ficV1.F5IPAM)

	if ipamObj.Namespace+"/"+ipamObj.Name != crMgr.ipamCR {
		return
	}

	log.Infof("Enqueueing IPAM: %v", ipamObj)
	key := &rqKey{
		namespace: ipamObj.ObjectMeta.Namespace,
		kind:      IPAM,
		rscName:   ipamObj.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) getNamespacedInformer(
	namespace string,
) (*CRInformer, bool) {
	if crMgr.watchingAllNamespaces() {
		namespace = ""
	}
	crInf, found := crMgr.crInformers[namespace]
	return crInf, found
}

func (crMgr *CRManager) enqueueVirtualServer(obj interface{}) {
	vs := obj.(*cisapiv1.VirtualServer)
	log.Debugf("Enqueueing VirtualServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueUpdatedVirtualServer(oldObj, newObj interface{}) {
	oldVS := oldObj.(*cisapiv1.VirtualServer)
	newVS := newObj.(*cisapiv1.VirtualServer)

	if oldVS.Spec.VirtualServerAddress != newVS.Spec.VirtualServerAddress ||
		oldVS.Spec.VirtualServerHTTPPort != newVS.Spec.VirtualServerHTTPPort ||
		oldVS.Spec.VirtualServerHTTPSPort != newVS.Spec.VirtualServerHTTPSPort ||
		oldVS.Spec.VirtualServerName != newVS.Spec.VirtualServerName ||
		oldVS.Spec.Host != newVS.Spec.Host ||
		oldVS.Spec.IPAMLabel != newVS.Spec.IPAMLabel {
		log.Debugf("Enqueueing Old VirtualServer: %v", oldVS)
		key := &rqKey{
			namespace: oldVS.ObjectMeta.Namespace,
			kind:      VirtualServer,
			rscName:   oldVS.ObjectMeta.Name,
			rsc:       oldObj,
			rscDelete: true,
		}
		crMgr.rscQueue.Add(key)
	}

	log.Debugf("Enqueueing VirtualServer: %v", newVS)
	key := &rqKey{
		namespace: newVS.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   newVS.ObjectMeta.Name,
		rsc:       newObj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedVirtualServer(obj interface{}) {
	vs := obj.(*cisapiv1.VirtualServer)
	log.Debugf("Enqueueing VirtualServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      VirtualServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueTLSServer(obj interface{}) {
	tls := obj.(*cisapiv1.TLSProfile)
	log.Infof("Enqueueing TLSProfile: %v", tls)
	key := &rqKey{
		namespace: tls.ObjectMeta.Namespace,
		kind:      TLSProfile,
		rscName:   tls.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueTransportServer(obj interface{}) {
	ts := obj.(*cisapiv1.TransportServer)
	log.Infof("Enqueueing TransportServer: %v", ts)
	key := &rqKey{
		namespace: ts.ObjectMeta.Namespace,
		kind:      TransportServer,
		rscName:   ts.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueUpdatedTransportServer(oldObj, newObj interface{}) {
	oldVS := oldObj.(*cisapiv1.TransportServer)
	newVS := newObj.(*cisapiv1.TransportServer)

	if oldVS.Spec.VirtualServerAddress != newVS.Spec.VirtualServerAddress ||
		oldVS.Spec.VirtualServerPort != newVS.Spec.VirtualServerPort ||
		oldVS.Spec.VirtualServerName != newVS.Spec.VirtualServerName ||
		oldVS.Spec.IPAMLabel != newVS.Spec.IPAMLabel {
		log.Debugf("Enqueueing TransportServer: %v", oldVS)
		key := &rqKey{
			namespace: oldVS.ObjectMeta.Namespace,
			kind:      TransportServer,
			rscName:   oldVS.ObjectMeta.Name,
			rsc:       oldObj,
			rscDelete: true,
		}
		crMgr.rscQueue.Add(key)
	}

	log.Debugf("Enqueueing TransportServer: %v", newVS)
	key := &rqKey{
		namespace: newVS.ObjectMeta.Namespace,
		kind:      TransportServer,
		rscName:   newVS.ObjectMeta.Name,
		rsc:       newObj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedTransportServer(obj interface{}) {
	vs := obj.(*cisapiv1.TransportServer)
	log.Debugf("Enqueueing TransportServer: %v", vs)
	key := &rqKey{
		namespace: vs.ObjectMeta.Namespace,
		kind:      TransportServer,
		rscName:   vs.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueIngressLink(obj interface{}) {
	ingLink := obj.(*cisapiv1.IngressLink)
	log.Infof("Enqueueing IngressLink: %v", ingLink)
	key := &rqKey{
		namespace: ingLink.ObjectMeta.Namespace,
		kind:      IngressLink,
		rscName:   ingLink.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedIngressLink(obj interface{}) {
	ingLink := obj.(*cisapiv1.IngressLink)
	log.Infof("Enqueueing IngressLink: %v on Delete", ingLink)
	key := &rqKey{
		namespace: ingLink.ObjectMeta.Namespace,
		kind:      IngressLink,
		rscName:   ingLink.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueUpdatedIngressLink(oldObj, newObj interface{}) {
	oldIngLink := oldObj.(*cisapiv1.IngressLink)
	newIngLink := newObj.(*cisapiv1.IngressLink)

	if oldIngLink.Spec.VirtualServerAddress != newIngLink.Spec.VirtualServerAddress {
		key := &rqKey{
			namespace: oldIngLink.ObjectMeta.Namespace,
			kind:      IngressLink,
			rscName:   oldIngLink.ObjectMeta.Name,
			rsc:       oldIngLink,
			rscDelete: true,
		}

		crMgr.rscQueue.Add(key)
	}

	log.Infof("Enqueueing IngressLink: %v on Update", newIngLink)
	key := &rqKey{
		namespace: newIngLink.ObjectMeta.Namespace,
		kind:      IngressLink,
		rscName:   newIngLink.ObjectMeta.Name,
		rsc:       newIngLink,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueExternalDNS(obj interface{}) {
	edns := obj.(*cisapiv1.ExternalDNS)
	log.Infof("Enqueueing ExternalDNS: %v", edns)
	key := &rqKey{
		namespace: edns.ObjectMeta.Namespace,
		kind:      ExternalDNS,
		rscName:   edns.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueUpdatedExternalDNS(oldObj, newObj interface{}) {
	oldEDNS := oldObj.(*cisapiv1.ExternalDNS)
	edns := newObj.(*cisapiv1.ExternalDNS)

	if oldEDNS.Spec.DomainName != edns.Spec.DomainName {
		key := &rqKey{
			namespace: oldEDNS.ObjectMeta.Namespace,
			kind:      ExternalDNS,
			rscName:   oldEDNS.ObjectMeta.Name,
			rsc:       oldEDNS,
			rscDelete: true,
		}

		crMgr.rscQueue.Add(key)
	}

	log.Infof("Enqueueing Updated ExternalDNS: %v", edns)
	key := &rqKey{
		namespace: edns.ObjectMeta.Namespace,
		kind:      ExternalDNS,
		rscName:   edns.ObjectMeta.Name,
		rsc:       edns,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedExternalDNS(obj interface{}) {
	edns := obj.(*cisapiv1.ExternalDNS)
	log.Infof("Enqueueing ExternalDNS: %v", edns)
	key := &rqKey{
		namespace: edns.ObjectMeta.Namespace,
		kind:      ExternalDNS,
		rscName:   edns.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueService(obj interface{}) {
	svc := obj.(*corev1.Service)
	// Ignore K8S Core Services
	for _, svcName := range K8SCoreServices {
		if svc.ObjectMeta.Name == svcName {
			return
		}
	}
	log.Debugf("Enqueueing Service: %v", svc)
	key := &rqKey{
		namespace: svc.ObjectMeta.Namespace,
		kind:      Service,
		rscName:   svc.ObjectMeta.Name,
		rsc:       obj,
	}
	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueUpdatedService(obj, cur interface{}) {
	svc := obj.(*corev1.Service)
	curSvc := cur.(*corev1.Service)
	// Ignore K8S Core Services
	for _, svcName := range K8SCoreServices {
		if svc.ObjectMeta.Name == svcName {
			return
		}
	}

	if (svc.Spec.Type != curSvc.Spec.Type && svc.Spec.Type == corev1.ServiceTypeLoadBalancer) ||
		(svc.Annotations[LBServiceIPAMLabelAnnotation] != curSvc.Annotations[LBServiceIPAMLabelAnnotation]) {
		log.Debugf("Enqueueing Old Service: %v", svc)
		key := &rqKey{
			namespace: svc.ObjectMeta.Namespace,
			kind:      Service,
			rscName:   svc.ObjectMeta.Name,
			rsc:       obj,
			rscDelete: true,
		}
		crMgr.rscQueue.Add(key)
	}

	log.Debugf("Enqueueing Updated Service: %v", curSvc)
	key := &rqKey{
		namespace: curSvc.ObjectMeta.Namespace,
		kind:      Service,
		rscName:   curSvc.ObjectMeta.Name,
		rsc:       cur,
	}
	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedService(obj interface{}) {
	svc := obj.(*corev1.Service)
	// Ignore K8S Core Services
	for _, svcName := range K8SCoreServices {
		if svc.ObjectMeta.Name == svcName {
			return
		}
	}
	log.Debugf("Enqueueing Service: %v", svc)
	key := &rqKey{
		namespace: svc.ObjectMeta.Namespace,
		kind:      Service,
		rscName:   svc.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}
	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueEndpoints(obj interface{}) {
	eps := obj.(*corev1.Endpoints)
	// Ignore K8S Core Services
	for _, epname := range K8SCoreServices {
		if eps.ObjectMeta.Name == epname {
			return
		}
	}
	log.Debugf("Enqueueing Endpoints: %v", eps)
	key := &rqKey{
		namespace: eps.ObjectMeta.Namespace,
		kind:      Endpoints,
		rscName:   eps.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
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

func (crMgr *CRManager) createNamespaceLabeledInformer(selector labels.Selector) error {
	namespaceOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = selector.String()
	}

	if nil != crMgr.nsInformer && nil != crMgr.nsInformer.nsInformer {
		return fmt.Errorf("Already have a namespace label informer added.")
	}
	if 0 != len(crMgr.crInformers) {
		return fmt.Errorf("Cannot set a namespace label informer when informers " +
			"have been setup for one or more namespaces.")
	}

	resyncPeriod := 0 * time.Second
	restClientv1 := crMgr.kubeClient.CoreV1().RESTClient()

	crMgr.nsInformer = &NSInformer{
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

	crMgr.nsInformer.nsInformer.AddEventHandlerWithResyncPeriod(
		&cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { crMgr.enqueueNamespace(obj) },
			DeleteFunc: func(obj interface{}) { crMgr.enqueueDeletedNamespace(obj) },
		},
		resyncPeriod,
	)

	return nil
}

func (crMgr *CRManager) enqueueNamespace(obj interface{}) {
	ns := obj.(*corev1.Namespace)
	log.Infof("Enqueueing Namespace: %v", ns)
	key := &rqKey{
		namespace: ns.ObjectMeta.Namespace,
		kind:      Namespace,
		rscName:   ns.ObjectMeta.Name,
		rsc:       obj,
	}

	crMgr.rscQueue.Add(key)
}

func (crMgr *CRManager) enqueueDeletedNamespace(obj interface{}) {
	ns := obj.(*corev1.Namespace)
	log.Infof("Enqueueing Namespace: %v on Delete", ns)
	key := &rqKey{
		namespace: ns.ObjectMeta.Namespace,
		kind:      Namespace,
		rscName:   ns.ObjectMeta.Name,
		rsc:       obj,
		rscDelete: true,
	}

	crMgr.rscQueue.Add(key)
}
