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
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

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
	// ExternalDNS is a F5 Custom Resource Kind
	ExternalDNS = "ExternalDNS"
	// Policy is collection of BIG-IP profiles, LTM policies and iRules
	CustomPolicy = "CustomPolicy"
	// IPAM is a F5 Custom Resource Kind
	IPAM = "IPAM"
	// Service is a k8s native Service Resource.
	Service = "Service"
	//Pod  is a k8s native object
	Pod = "Pod"
	// Endpoints is a k8s native Endpoint Resource.
	Endpoints = "Endpoints"
	// Namespace is k8s namespace
	Namespace = "Namespace"

	NodePort = "nodeport"

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
	HealthMonitorAnnotation      = "cis.f5.com/health"
	//Antrea NodePortLocal support
	NPLPodAnnotation = "nodeportlocal.antrea.io"
	NPLSvcAnnotation = "nodeportlocal.antrea.io/enabled"
	NodePortLocal    = "nodeportlocal"
)

// NewController creates a new Controller Instance.
func NewController(params Params) *Controller {

	ctlr := &Controller{
		namespaces:  make(map[string]bool),
		crInformers: make(map[string]*CRInformer),
		rscQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller"),
		resources:          NewResourceStore(),
		Agent:              params.Agent,
		PoolMemberType:     params.PoolMemberType,
		UseNodeInternal:    params.UseNodeInternal,
		initState:          true,
		SSLContext:         make(map[string]*v1.Secret),
		dgPath:             strings.Join([]string{DEFAULT_PARTITION, "Shared"}, "/"),
		shareNodes:         params.ShareNodes,
		eventNotifier:      apm.NewEventNotifier(nil),
		defaultRouteDomain: params.DefaultRouteDomain,
	}

	log.Debug("Custom Resource Manager Created")

	ctlr.resourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)

	if err := ctlr.setupClients(params.Config); err != nil {
		log.Errorf("Failed to Setup Clients: %v", err)
	}

	namespaceSelector, err := createLabelSelector(params.NamespaceLabel)

	if params.NamespaceLabel == "" || err != nil {
		if len(params.Namespaces) == 0 {
			ctlr.namespaces[""] = true
			log.Debug("No namespaces provided. Watching all namespaces")
		} else {
			for _, ns := range params.Namespaces {
				ctlr.namespaces[ns] = true
			}
		}
	} else {
		err2 := ctlr.createNamespaceLabeledInformer(namespaceSelector)
		if err2 != nil {
			for _, v := range ctlr.nsInformer.nsInformer.GetIndexer().List() {
				ns := v.(*v1.Namespace)
				ctlr.namespaces[ns.ObjectMeta.Name] = true
			}
		}
	}

	if err3 := ctlr.setupInformers(); err3 != nil {
		log.Error("Failed to Setup Informers")
	}

	err = ctlr.SetupNodePolling(
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
			EventHandlers: ctlr.getEventHandlerForIPAM(),
			Namespaces:    []string{IPAMNamespace},
		}

		ipamClient := ipammachinery.NewIPAMClient(ipamParams)
		ctlr.ipamCli = ipamClient

		ctlr.registerIPAMCRD()
		time.Sleep(3 * time.Second)
		_ = ctlr.createIPAMResource()
	}

	respChan := make(chan int)
	ctlr.Agent.SetResponseChannel(respChan)
	go ctlr.responseHandler(respChan)
	go ctlr.Start()
	return ctlr
}

//Register IPAM CRD
func (ctlr *Controller) registerIPAMCRD() {
	err := ipammachinery.RegisterCRD(ctlr.kubeAPIClient)
	if err != nil {
		log.Errorf("[IPAM] error while registering CRD %v", err)
	}
}

//Create IPAM CRD
func (ctlr *Controller) createIPAMResource() error {

	frameIPAMResourceName := func() string {
		prtn := ""
		for _, ch := range DEFAULT_PARTITION {
			elem := string(ch)
			if unicode.IsUpper(ch) {
				elem = strings.ToLower(elem) + "-"
			}
			prtn += elem
		}
		if string(prtn[len(prtn)-1]) == "-" {
			prtn = prtn + ipamCRName
		} else {
			prtn = prtn + "." + ipamCRName
		}

		prtn = strings.Replace(prtn, "_", "-", -1)
		prtn = strings.Replace(prtn, "--", "-", -1)

		hostsplit := strings.Split(os.Getenv("HOSTNAME"), "-")
		var host string
		if len(hostsplit) > 2 {
			host = strings.Join(hostsplit[0:len(hostsplit)-2], "-")
		} else {
			host = strings.Join(hostsplit, "-")
		}
		return strings.Join([]string{host, prtn}, ".")
	}

	crName := frameIPAMResourceName()
	f5ipam := &ficV1.IPAM{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      crName,
			Namespace: IPAMNamespace,
		},
		Spec: ficV1.IPAMSpec{
			HostSpecs: make([]*ficV1.HostSpec, 0),
		},
		Status: ficV1.IPAMStatus{
			IPStatus: make([]*ficV1.IPSpec, 0),
		},
	}
	ctlr.ipamCR = IPAMNamespace + "/" + crName

	ipamCR, err := ctlr.ipamCli.Create(f5ipam)
	if err == nil {
		log.Debugf("[ipam] Created IPAM Custom Resource: \n%v\n", ipamCR)
		return nil
	}

	if strings.Contains(err.Error(), "already exists") {
		err = ctlr.ipamCli.Delete(IPAMNamespace, crName, metaV1.DeleteOptions{})
		if err != nil {
			log.Debugf("[ipam] Delete failed. Error: %s", err.Error())
		}

		time.Sleep(3 * time.Second)

		ipamCR, err = ctlr.ipamCli.Create(f5ipam)
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
func (ctlr *Controller) setupClients(config *rest.Config) error {
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
	ctlr.kubeAPIClient = kubeIPAMClient
	ctlr.kubeCRClient = kubeCRClient
	ctlr.kubeClient = kubeClient
	return nil
}

func (ctlr *Controller) setupInformers() error {
	for n := range ctlr.namespaces {
		if err := ctlr.addNamespacedInformer(n); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v, Error:%v", n, err)
			return err
		}
	}
	return nil
}

// Start the Controller
func (ctlr *Controller) Start() {
	log.Infof("Starting Controller")
	defer utilruntime.HandleCrash()
	defer ctlr.rscQueue.ShutDown()
	for _, inf := range ctlr.crInformers {
		inf.start()
	}

	if ctlr.nsInformer != nil {
		ctlr.nsInformer.start()
	}

	if ctlr.ipamCli != nil {
		go ctlr.ipamCli.Start()
	}

	ctlr.nodePoller.Run()

	stopChan := make(chan struct{})
	go wait.Until(ctlr.customResourceWorker, time.Second, stopChan)

	<-stopChan
	ctlr.Stop()
}

// Stop the Controller
func (ctlr *Controller) Stop() {
	for _, inf := range ctlr.crInformers {
		inf.stop()
	}
	if ctlr.nsInformer != nil {
		ctlr.nsInformer.stop()
	}

	ctlr.nodePoller.Stop()
	ctlr.Agent.Stop()
	if ctlr.ipamCli != nil {
		ctlr.ipamCli.Stop()
	}
}
