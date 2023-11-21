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
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/tokenmanager"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/clustermanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"

	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
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

// NewController creates a new Controller Instance.
func NewController(params Params) *Controller {

	ctlr := &Controller{
		namespaces:      make(map[string]bool),
		resources:       NewResourceStore(),
		Agent:           params.Agent,
		PoolMemberType:  params.PoolMemberType,
		UseNodeInternal: params.UseNodeInternal,
		Partition:       params.Partition,
		initState:       true,
		dgPath:          strings.Join([]string{DEFAULT_PARTITION, "Shared"}, "/"),
		shareNodes:      params.ShareNodes,
		//eventNotifier:         apm.NewEventNotifier(nil),
		defaultRouteDomain:    params.DefaultRouteDomain,
		StaticRoutingMode:     params.StaticRoutingMode,
		OrchestrationCNI:      params.OrchestrationCNI,
		StaticRouteNodeCIDR:   params.StaticRouteNodeCIDR,
		multiClusterConfigs:   clustermanager.NewMultiClusterConfig(),
		multiClusterResources: newMultiClusterResourceStore(),
		multiClusterMode:      params.MultiClusterMode,
		clusterRatio:          make(map[string]*int),
		clusterAdminState:     make(map[string]cisapiv1.AdminState),
		CMTokenManager: tokenmanager.NewTokenManager(params.CMConfigDetails.URL, tokenmanager.Credentials{
			Username: params.CMConfigDetails.UserName, Password: params.CMConfigDetails.Password}),
	}

	ctlr.managedResources.ManageTransportServer = true

	log.Debug("Controller Created")
	// Sync CM token
	ctlr.CMTokenManager.SyncToken(make(chan struct{}))
	ctlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "nextgen-resource-controller")
	ctlr.comInformers = make(map[string]*CommonInformer)
	ctlr.multiClusterPoolInformers = make(map[string]map[string]*MultiClusterPoolInformer)
	ctlr.multiClusterNodeInformers = make(map[string]*NodeInformer)
	ctlr.nrInformers = make(map[string]*NRInformer)
	ctlr.crInformers = make(map[string]*CRInformer)
	ctlr.nsInformers = make(map[string]*NSInformer)
	ctlr.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
	ctlr.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)

	// set extended spec configCR for all
	ctlr.CISConfigCRKey = params.CISConfigCRKey

	//If pool-member-type type is nodeport enable share nodes ( for multi-partition)
	if ctlr.PoolMemberType == NodePort || ctlr.PoolMemberType == NodePortLocal {
		ctlr.shareNodes = true
	}

	if err := ctlr.setupClients(params.Config); err != nil {
		log.Errorf("Failed to Setup Clients: %v", err)
	}

	// Initialize the controller with base resources in CIS config CR
	key := strings.Split(ctlr.CISConfigCRKey, "")
	configCR, err := ctlr.kubeCRClient.CisV1().DeployConfigs(key[0]).Get(context.TODO(), key[1], metaV1.GetOptions{})
	if err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
	ctlr.baseConfig = BaseConfig{
		NodeLabel:      configCR.Spec.BaseConfig.NamespaceLabel,
		NamespaceLabel: configCR.Spec.BaseConfig.NamespaceLabel,
	}
	if ctlr.managedResources.ManageRoutes {
		ctlr.routeLabel = params.RouteLabel
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metaV1.Time)
		ctlr.processedHostPath = &processedHostPath
	}
	if ctlr.baseConfig.NamespaceLabel == "" {
		ctlr.namespaces[""] = true
		log.Debug("No namespaces provided. Watching all namespaces")
	} else {
		err2 := ctlr.createNamespaceLabeledInformer(ctlr.baseConfig.NamespaceLabel)
		if err2 != nil {
			log.Errorf("%v", err2)
			for _, nsInf := range ctlr.nsInformers {
				for _, v := range nsInf.nsInformer.GetIndexer().List() {
					ns := v.(*v1.Namespace)
					ctlr.namespaces[ns.ObjectMeta.Name] = true
				}
			}
		}
	}

	if err3 := ctlr.setupInformers(); err3 != nil {
		log.Error("Failed to Setup Informers")
	}

	ctlr.setupIPAM(params)

	//ctlr.setupVXLANManager(params)

	go ctlr.responseHandler(ctlr.Agent.respChan)

	go ctlr.Start()

	go ctlr.setOtherSDNType()

	// enable metrics
	go ctlr.Agent.enableMetrics()

	// Start the CIS health check
	go ctlr.CISHealthCheck()

	return ctlr
}

func (ctlr *Controller) setupIPAM(params Params) {
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
}

// Set Other SDNType
func (ctlr *Controller) setOtherSDNType() {
	ctlr.TeemData.Lock()
	defer ctlr.TeemData.Unlock()
	if ctlr.OrchestrationCNI == "" && (ctlr.TeemData.SDNType == "other" || ctlr.TeemData.SDNType == "flannel") {
		kubePods, err := ctlr.kubeClient.CoreV1().Pods("").List(context.TODO(), metaV1.ListOptions{})
		if nil != err {
			log.Errorf("Could not list Kubernetes Pods for CNI Chek: %v", err)
			return
		}
		for _, kPod := range kubePods.Items {
			if strings.Contains(kPod.Name, "cilium") && kPod.Status.Phase == "Running" {
				ctlr.TeemData.SDNType = "cilium"
				return
			}
			if strings.Contains(kPod.Name, "calico") && kPod.Status.Phase == "Running" {
				ctlr.TeemData.SDNType = "calico"
				return
			}
		}
	}
}

// Register IPAM CRD
func (ctlr *Controller) registerIPAMCRD() {
	err := ipammachinery.RegisterCRD(ctlr.kubeAPIClient)
	if err != nil {
		log.Errorf("[IPAM] error while registering CRD %v", err)
	}
}

// Create IPAM CRD
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
		log.Debugf("[IPAM] Created IPAM Custom Resource: \n%v\n", ipamCR)
		return nil
	}

	log.Debugf("[IPAM] error while creating IPAM custom resource %v", err.Error())
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
	var kubeCRClient *versioned.Clientset
	var err error
	kubeCRClient, err = versioned.NewForConfig(config)
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

	var rclient *routeclient.RouteV1Client
	if ctlr.managedResources.ManageRoutes {
		rclient, err = routeclient.NewForConfig(config)
		if nil != err {
			return fmt.Errorf("Failed to create Route Client: %v", err)
		}
	}

	log.Debug("Client Created")
	ctlr.kubeAPIClient = kubeIPAMClient
	ctlr.kubeCRClient = kubeCRClient
	ctlr.kubeClient = kubeClient
	ctlr.routeClientV1 = rclient
	return nil
}

func (ctlr *Controller) setupInformers() error {
	for n := range ctlr.namespaces {
		if err := ctlr.addNamespacedInformers(n, false); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v, Error:%v", n, err)
			return err
		}
	}
	nodeInf := ctlr.getNodeInformer("")
	ctlr.nodeInformer = &nodeInf
	ctlr.addNodeEventUpdateHandler(ctlr.nodeInformer)
	return nil
}

// Start the Controller
func (ctlr *Controller) Start() {
	log.Infof("Starting Controller")
	defer utilruntime.HandleCrash()
	defer ctlr.resourceQueue.ShutDown()

	// start nsinformer in all modes
	for _, nsInf := range ctlr.nsInformers {
		nsInf.start()
	}

	// start nodeinformer in all modes
	ctlr.nodeInformer.start()

	// start comInformers for all modes
	for _, inf := range ctlr.comInformers {
		inf.start()
	}
	if ctlr.managedResources.ManageRoutes { // nrInformers only with openShiftMode
		for _, inf := range ctlr.nrInformers {
			inf.start()
		}
	}
	if ctlr.managedResources.ManageCustomResources { // start customer resource informers in custom resource mode only
		for _, inf := range ctlr.crInformers {
			inf.start()
		}
	}

	if ctlr.ipamCli != nil {
		go ctlr.ipamCli.Start()
	}

	stopChan := make(chan struct{})

	go wait.Until(ctlr.nextGenResourceWorker, time.Second, stopChan)

	<-stopChan
	ctlr.Stop()
}

// Stop the Controller
func (ctlr *Controller) Stop() {

	if ctlr.managedResources.ManageRoutes { // stop native resource informers
		for _, inf := range ctlr.nrInformers {
			inf.stop()
		}
	}
	if ctlr.managedResources.ManageCustomResources { // stop custom resource informers
		for _, inf := range ctlr.crInformers {
			inf.stop()
		}
	}

	// stop common informers & namespace informers in all modes
	for _, inf := range ctlr.comInformers {
		inf.stop()
	}
	for _, nsInf := range ctlr.nsInformers {
		nsInf.stop()
	}
	// stop node Informer
	ctlr.nodeInformer.stop()

	// stop multi cluster informers
	for _, poolInformers := range ctlr.multiClusterPoolInformers {
		for _, inf := range poolInformers {
			inf.stop()
		}
	}

	if ctlr.ipamCli != nil {
		ctlr.ipamCli.Stop()
	}
	if ctlr.Agent.EventChan != nil {
		close(ctlr.Agent.EventChan)
	}
}

func (ctlr *Controller) CISHealthCheck() {
	// Expose cis health endpoint
	http.Handle("/ready", ctlr.CISHealthCheckHandler())
}

func (ctlr *Controller) CISHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ctlr.kubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := ctlr.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				response = "kube-api server is not reachable."
			}
			// Check if big-ip server is reachable
			_, _, _, err2 := ctlr.Agent.GetBigipAS3Version()
			if err2 != nil {
				response = response + "big-ip server is not reachable."
			}
			if err2 == nil && err == nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(response))
			}
		}
	})
}
