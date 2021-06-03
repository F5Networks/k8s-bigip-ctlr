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
	"net"
	"net/url"
	"strings"
	"time"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	"github.com/F5Networks/k8s-bigip-ctlr/config/client/clientset/versioned"
	apm "github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
)

const (
	// DefaultCustomResourceLabel is a label used for F5 Custom Resources.
	DefaultCustomResourceLabel = "f5cr in (true)"
	// VirtualServer is a F5 Custom Resource Kind.
	VirtualServer = "VirtualServer"
	// TLSProfile is a F5 Custom Resource Kind
	TLSProfile = "TLSProfile"
	// IngressLink is a Custom Resource used by both F5 and Nginx
	IngressLink = "IngressLink"
	// TransportServer is a F5 Custom Resource Kind
	TransportServer = "TransportServer"
	// ExternalDNS is a F5 Customr Resource Kind
	ExternalDNS = "ExternalDNS"
	// IPAM is a F5 Customr Resource Kind
	IPAM = "IPAM"
	// Service is a k8s native Service Resource.
	Service = "Service"
	// Endpoints is a k8s native Endpoint Resource.
	Endpoints = "Endpoints"
	// Namespace is k8s namespace
	Namespace = "Namespace"

	NodePortMode = "nodeport"

	PolicyControlForward = "forwarding"
	// Namespace for IPAM CRD
	IPAMNamespace = "kube-system"
	//Name for ipam CR
	ipamCRName = "ipam"

	// TLS Terminations
	TLSEdge             = "edge"
	TLSReencrypt        = "reencrypt"
	TLSPassthrough      = "passthrough"
	TLSRedirectInsecure = "redirect"
	TLSAllowInsecure    = "allow"
	TLSNoInsecure       = "none"

	// HTTP Events for LTM Policy
	HTTPRequest    = "HTTPRequest"
	TLSClientHello = "TLSClientHello"

	LBServiceIPAMLabelAnnotation = "cis.f5.com/ipamLabel"
)

// NewCRManager creates a new CRManager Instance.
func NewCRManager(params Params) *CRManager {

	crMgr := &CRManager{
		namespaces:  make(map[string]bool),
		crInformers: make(map[string]*CRInformer),
		rscQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller"),
		resources:          NewResources(),
		Agent:              params.Agent,
		ControllerMode:     params.ControllerMode,
		UseNodeInternal:    params.UseNodeInternal,
		initState:          true,
		SSLContext:         make(map[string]*v1.Secret),
		customProfiles:     NewCustomProfiles(),
		dgPath:             strings.Join([]string{DEFAULT_PARTITION, "Shared"}, "/"),
		shareNodes:         params.ShareNodes,
		eventNotifier:      apm.NewEventNotifier(nil),
		defaultRouteDomain: params.DefaultRouteDomain,
	}

	log.Debug("Custom Resource Manager Created")

	crMgr.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)

	if err := crMgr.setupClients(params.Config); err != nil {
		log.Errorf("Failed to Setup Clients: %v", err)
	}

	namespaceSelector, err := createLabelSelector(params.NamespaceLabel)

	if params.NamespaceLabel == "" || err != nil {
		if len(params.Namespaces) == 0 {
			crMgr.namespaces[""] = true
			log.Debug("No namespaces provided. Watching all namespaces")
		} else {
			for _, ns := range params.Namespaces {
				crMgr.namespaces[ns] = true
			}
		}
	} else {
		err2 := crMgr.createNamespaceLabeledInformer(namespaceSelector)
		if err2 != nil {
			for _, v := range crMgr.nsInformer.nsInformer.GetIndexer().List() {
				ns := v.(*v1.Namespace)
				crMgr.namespaces[ns.ObjectMeta.Name] = true
			}
		}
	}

	if err3 := crMgr.setupInformers(); err3 != nil {
		log.Error("Failed to Setup Informers")
	}

	err = crMgr.SetupNodePolling(
		params.NodePollInterval,
		params.NodeLabelSelector,
		params.VXLANMode,
		params.VXLANName,
	)
	if err != nil {
		log.Errorf("Failed to Setup Node Polling: %v", err)
	}
	if params.IPAM {
		ipamParams := ipammachinery.Params{
			Config:        params.Config,
			EventHandlers: crMgr.getEventHandlerForIPAM(),
			Namespaces:    []string{IPAMNamespace},
		}

		ipamClient := ipammachinery.NewIPAMClient(ipamParams)
		crMgr.ipamCli = ipamClient

		crMgr.registerIPAMCRD()
		time.Sleep(3 * time.Second)
		_ = crMgr.createIPAMResource()
	}

	go crMgr.Start()
	return crMgr
}

//Register IPAM CRD
func (crMgr *CRManager) registerIPAMCRD() {
	err := ipammachinery.RegisterCRD(crMgr.kubeAPIClient)
	if err != nil {
		log.Debugf("[IPAM] error while registering CRD %v", err)
	}
}

//Create IPAM CRD
func (crMgr *CRManager) createIPAMResource() error {

	frameIPAMResourceName := func(bipUrl string) string {
		log.Debugf("BIP URL: %v", bipUrl)
		if net.ParseIP(bipUrl) != nil {
			return strings.Join([]string{ipamCRName, bipUrl, DEFAULT_PARTITION}, ".")
		}

		u, err := url.Parse(bipUrl)
		if err != nil {
			log.Errorf("Unable to frame IPAM resource name in standard format")
			return strings.Join([]string{ipamCRName, DEFAULT_PARTITION}, ".")
		}
		var host string
		if strings.Contains(u.Host, ":") {
			host, _, _ = net.SplitHostPort(u.Host)
		} else {
			host = u.Host
		}

		if host == "" {
			log.Errorf("Unable to frame IPAM resource name in standard format")
			return strings.Join([]string{ipamCRName, DEFAULT_PARTITION}, ".")
		}

		return strings.Join([]string{ipamCRName, host, DEFAULT_PARTITION}, ".")
	}

	crName := frameIPAMResourceName(crMgr.Agent.BIGIPURL)
	f5ipam := &ficV1.F5IPAM{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      crName,
			Namespace: IPAMNamespace,
		},
		Spec: ficV1.F5IPAMSpec{
			HostSpecs: make([]*ficV1.HostSpec, 0),
		},
		Status: ficV1.F5IPAMStatus{
			IPStatus: make([]*ficV1.IPSpec, 0),
		},
	}
	crMgr.ipamCR = IPAMNamespace + "/" + crName

	ipamCR, err := crMgr.ipamCli.Create(f5ipam)
	if err == nil {
		log.Debugf("[ipam] Created IPAM Custom Resource: \n%v\n", ipamCR)
		return nil
	}

	if strings.Contains(err.Error(), "already exists") {
		err = crMgr.ipamCli.Delete(IPAMNamespace, crName, metaV1.DeleteOptions{})
		if err != nil {
			log.Debugf("[ipam] Delete failed. Error: %s", err.Error())
		}

		time.Sleep(3 * time.Second)

		ipamCR, err = crMgr.ipamCli.Create(f5ipam)
		if err == nil {
			log.Debugf("[ipam] Created IPAM Custom Resource: \n%v\n", ipamCR)
			return nil
		}
	}

	log.Debugf("[ipam] error while creating IPAM custom resource. %v", err.Error())
	return err
}

// createLabelSelector returns label used to identify F5 specific
// Custom Resources.
func createLabelSelector(label string) (labels.Selector, error) {
	var l labels.Selector
	var err error

	if label == "" {
		l = labels.Everything()
	} else {
		l, err = labels.Parse(label)
		if err != nil {
			return labels.Everything(), fmt.Errorf("failed to parse Label Selector string: %v", err)
		}
	}
	return l, nil
}

// setupClients sets Kubernetes Clients.
func (crMgr *CRManager) setupClients(config *rest.Config) error {
	kubeCRClient, err := versioned.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create Custum Resource kubeClient: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create kubeClient: %v", err)
	}

	var ipamCRConfig *rest.Config
	if ipamCRConfig, err = rest.InClusterConfig(); err != nil {
		log.Errorf("error creating client configuration: %v", err)
	}
	kubeIPAMClient, err := extClient.NewForConfig(ipamCRConfig)
	if err != nil {
		log.Errorf("Failed to create client: %v", err)
	}

	log.Debug("Client Created")
	crMgr.kubeAPIClient = kubeIPAMClient
	crMgr.kubeCRClient = kubeCRClient
	crMgr.kubeClient = kubeClient
	return nil
}

func (crMgr *CRManager) setupInformers() error {
	for n := range crMgr.namespaces {
		if err := crMgr.addNamespacedInformer(n); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v, Error:%v", n, err)
			return err
		}
	}
	return nil
}

// Start the Custom Resource Manager
func (crMgr *CRManager) Start() {
	log.Infof("Starting Custom Resource Manager")
	defer utilruntime.HandleCrash()
	defer crMgr.rscQueue.ShutDown()
	for _, inf := range crMgr.crInformers {
		inf.start()
	}

	if crMgr.nsInformer != nil {
		crMgr.nsInformer.start()
	}

	if crMgr.ipamCli != nil {
		go crMgr.ipamCli.Start()
	}

	crMgr.nodePoller.Run()

	stopChan := make(chan struct{})
	go wait.Until(crMgr.customResourceWorker, time.Second, stopChan)

	<-stopChan
	crMgr.Stop()
}

// Stop the Custom Resource Manager.
func (crMgr *CRManager) Stop() {
	for _, inf := range crMgr.crInformers {
		inf.stop()
	}
	if crMgr.nsInformer != nil {
		crMgr.nsInformer.stop()
	}

	crMgr.nodePoller.Stop()
	crMgr.Agent.Stop()
	if crMgr.ipamCli != nil {
		crMgr.ipamCli.Stop()
	}
}
