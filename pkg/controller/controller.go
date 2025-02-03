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
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/dynamic"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vxlan"

	ficV1 "github.com/F5Networks/f5-ipam-controller/pkg/ipamapis/apis/fic/v1"
	"github.com/F5Networks/f5-ipam-controller/pkg/ipammachinery"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/clustermanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"

	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	v1 "k8s.io/api/core/v1"
	extClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
)

const (
	// DefaultCustomResourceLabel is a label used for F5 Custom Resources.
	DefaultCustomResourceLabelKey = "f5cr"
	DefaultCustomResourceLabel    = DefaultCustomResourceLabelKey + " in (true)"
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
	//Secret  is a k8s native object
	K8sSecret = "Secret"
	// Endpoints is a k8s native Endpoint Resource.
	Endpoints = "Endpoints"
	// Namespace is k8s namespace
	Namespace = "Namespace"
	// ConfigMap is k8s native ConfigMap resource
	ConfigMap = "ConfigMap"
	// Route is OpenShift Route
	Route = "Route"
	// Node update
	NodeUpdate = "Node"

	NodePort = "nodeport"
	Cluster  = "cluster"

	PoolLBMemberRatio = "ratio-member"

	Local = "local"

	StandAloneCIS = "standalone"
	SecondaryCIS  = "secondary"
	PrimaryCIS    = "primary"
	// Namespace is k8s namespace
	HACIS = "HACIS"

	// Primary cluster health probe
	DefaultProbeInterval = 60
	DefaultRetryInterval = 15

	PolicyControlForward = "forwarding"
	// Namespace for IPAM CRD
	DefaultIPAMNamespace = "kube-system"
	//Name for ipam CR
	ipamCRName = "ipam"

	// TLS Terminations
	TLSEdge             = "edge"
	AllowSourceRange    = "allowSourceRange"
	DefaultPool         = "defaultPool"
	TLSReencrypt        = "reencrypt"
	TLSPassthrough      = "passthrough"
	TLSRedirectInsecure = "redirect"
	TLSAllowInsecure    = "allow"
	TLSNoInsecure       = "none"

	LBServiceIPAMLabelAnnotation            = "cis.f5.com/ipamLabel"
	LBServiceIPAnnotation                   = "cis.f5.com/ip"
	LBServiceHostAnnotation                 = "cis.f5.com/host"
	LBServicePartitionAnnotation            = "cis.f5.com/partition"
	LBServiceMultiClusterServicesAnnotation = "cis.f5.com/multiClusterServices"
	HealthMonitorAnnotation                 = "cis.f5.com/health"
	LBServicePolicyNameAnnotation           = "cis.f5.com/policyName"
	LegacyHealthMonitorAnnotation           = "virtual-server.f5.com/health"
	PodConcurrentConnectionsAnnotation      = "virtual-server.f5.com/pod-concurrent-connections"

	//Antrea NodePortLocal support
	NPLPodAnnotation = "nodeportlocal.antrea.io"
	NPLSvcAnnotation = "nodeportlocal.antrea.io/enabled"
	NodePortLocal    = "nodeportlocal"
	Auto             = "auto"

	// AS3 Related constants
	as3SupportedVersion = 3.18
	//Update as3Version,defaultAS3Version,defaultAS3Build while updating AS3 validation schema.
	//While upgrading version update $id value in schema json to https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/latest/as3-schema.json
	as3Version        = 3.52
	defaultAS3Version = "3.52.0"
	defaultAS3Build   = "5"
	clusterHealthPath = "/readyz"
)

// NewController creates a new Controller Instance.
func NewController(params Params, startController bool) *Controller {

	ctlr := &Controller{
		resources:                   NewResourceStore(),
		Agent:                       params.Agent,
		PoolMemberType:              params.PoolMemberType,
		UseNodeInternal:             params.UseNodeInternal,
		Partition:                   params.Partition,
		initState:                   true,
		dgPath:                      strings.Join([]string{DEFAULT_PARTITION, "Shared"}, "/"),
		shareNodes:                  params.ShareNodes,
		defaultRouteDomain:          params.DefaultRouteDomain,
		mode:                        params.Mode,
		ciliumTunnelName:            params.CiliumTunnelName,
		StaticRoutingMode:           params.StaticRoutingMode,
		OrchestrationCNI:            params.OrchestrationCNI,
		StaticRouteNodeCIDR:         params.StaticRouteNodeCIDR,
		multiClusterHandler:         NewClusterHandler(params.LocalClusterName),
		multiClusterResources:       newMultiClusterResourceStore(),
		multiClusterMode:            params.MultiClusterMode,
		loadBalancerClass:           params.LoadBalancerClass,
		manageLoadBalancerClassOnly: params.ManageLoadBalancerClassOnly,
		clusterRatio:                make(map[string]*int),
		clusterAdminState:           make(map[string]clustermanager.AdminState),
		vsAddressesMap:              make(map[string]string),
		tsAddressesMap:              make(map[string]string),
		ilAddressesMap:              make(map[string]string),
	}

	log.Debug("Controller Created")

	ctlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(), "nextgen-resource-controller")
	clusterConfig := newClusterConfig()
	clusterConfig.InformerStore = initInformerStore()
	clusterConfig.nodeLabelSelector = params.NodeLabelSelector
	clusterConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
	clusterConfig.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
	clusterConfig.orchestrationCNI = params.OrchestrationCNI
	clusterConfig.staticRoutingMode = params.StaticRoutingMode
	switch ctlr.mode {
	case OpenShiftMode, KubernetesMode:
		clusterConfig.routeLabel = params.RouteLabel
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metaV1.Time)
		ctlr.processedHostPath = &processedHostPath
	default:
		ctlr.mode = CustomResourceMode
	}
	// set extended spec configmap for all
	ctlr.globalExtendedCMKey = params.GlobalExtendedSpecConfigmap

	//If pool-member-type type is nodeport enable share nodes ( for multi-partition)
	if ctlr.PoolMemberType == NodePort || ctlr.PoolMemberType == NodePortLocal {
		ctlr.shareNodes = true
	}
	if err := ctlr.setupClientsforCluster(params.Config, params.IPAM, ctlr.mode == OpenShiftMode, ctlr.multiClusterHandler.LocalClusterName, clusterConfig); err != nil {
		log.Errorf("Failed to Setup Clients: %v", err)
	}
	// set the namespace label so it can be assigned for all clusters
	ctlr.multiClusterHandler.namespaceLabel = params.NamespaceLabel
	ctlr.multiClusterHandler.namespaces = params.Namespaces
	ctlr.multiClusterHandler.nodeLabelSelector = params.NodeLabelSelector
	ctlr.multiClusterHandler.routeLabel = params.RouteLabel
	ctlr.multiClusterHandler.staticRoutingMode = params.StaticRoutingMode
	ctlr.multiClusterHandler.orchestrationCNI = params.OrchestrationCNI
	// add the cluster config for local cluster
	ctlr.multiClusterHandler.addClusterConfig(ctlr.multiClusterHandler.LocalClusterName, clusterConfig)

	// handle namespace informers for cluster
	ctlr.handleNsInformersforCluster(ctlr.multiClusterHandler.LocalClusterName, false)

	if err3 := ctlr.setupInformers(ctlr.multiClusterHandler.LocalClusterName); err3 != nil {
		log.Error("Failed to Setup Informers")
	}

	if params.IPAM {
		if !ctlr.validateIPAMConfig(params.IpamNamespace) {
			log.Warningf("[IPAM] IPAM Namespace %s not found in the list of monitored namespaces", params.IpamNamespace)
		}
		ipamParams := ipammachinery.Params{
			Config:        params.Config,
			EventHandlers: ctlr.getEventHandlerForIPAM(),
			Namespaces:    []string{params.IpamNamespace},
		}

		ipamClient := ipammachinery.NewIPAMClient(ipamParams)
		ctlr.ipamCli = ipamClient
		ctlr.ipamClusterLabel = params.IPAMClusterLabel
		if params.IPAMClusterLabel != "" {
			ctlr.ipamClusterLabel = params.IPAMClusterLabel + "/"
		}
		ctlr.registerIPAMCRD()
		time.Sleep(3 * time.Second)
		_ = ctlr.createIPAMResource(params.IpamNamespace)
	}
	// setup vxlan manager
	if len(params.VXLANName) > 0 && len(params.VXLANMode) > 0 {
		tunnelName := params.VXLANName
		cleanPath := strings.TrimLeft(params.VXLANName, "/")
		slashPos := strings.Index(cleanPath, "/")
		if slashPos != -1 {
			tunnelName = cleanPath[slashPos+1:]
		}
		vxlanMgr, err := vxlan.NewVxlanMgr(
			params.VXLANMode,
			tunnelName,
			ctlr.ciliumTunnelName,
			ctlr.UseNodeInternal,
			ctlr.Agent.ConfigWriter,
			ctlr.Agent.EventChan,
		)
		if nil != err {
			log.Errorf("error creating vxlan manager: %v", err)
		}
		ctlr.vxlanMgr = vxlanMgr
	}

	if startController {
		go ctlr.responseHandler(ctlr.Agent.respChan)

		go ctlr.Start()

		go ctlr.setOtherSDNType()
		// Start the CIS health check
		go ctlr.CISHealthCheck()
		// Start the Resource Event Watcher
		go ctlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go ctlr.multiClusterHandler.ResourceStatusUpdater()
		// Initially cleanup all the unmonitored resource status, this will handle the edge cases when the resource label
		//is changed during CIS restart
		go ctlr.cleanupUnmonitoredResourceStatus()
	}

	return ctlr
}

// Set Other SDNType
func (ctlr *Controller) setOtherSDNType() {
	ctlr.TeemData.Lock()
	defer ctlr.TeemData.Unlock()
	if ctlr.OrchestrationCNI == "" && (ctlr.TeemData.SDNType == "other" || ctlr.TeemData.SDNType == "flannel") {
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		kubePods, err := clusterConfig.kubeClient.CoreV1().Pods("").List(context.TODO(), metaV1.ListOptions{})
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

// validate IPAM configuration
func (ctlr *Controller) validateIPAMConfig(ipamNamespace string) bool {
	// verify the ipam configuration
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	for ns, _ := range clusterConfig.namespaces {
		if ns == "" {
			return true
		} else {
			if ns == ipamNamespace {
				return true
			}
		}
	}
	return false
}

// Register IPAM CRD
func (ctlr *Controller) registerIPAMCRD() {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
	err := ipammachinery.RegisterCRD(clusterConfig.kubeIPAMClient)
	if err != nil {
		log.Errorf("[IPAM] error while registering CRD %v", err)
	}
}

// Create IPAM CRD
func (ctlr *Controller) createIPAMResource(ipamNamespace string) error {

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
			Namespace: ipamNamespace,
		},
		Spec: ficV1.IPAMSpec{
			HostSpecs: make([]*ficV1.HostSpec, 0),
		},
		Status: ficV1.IPAMStatus{
			IPStatus: make([]*ficV1.IPSpec, 0),
		},
	}
	ctlr.ipamCR = ipamNamespace + "/" + crName

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

// setupClientsforCluster sets Kubernetes Clients.
func (ctlr *Controller) setupClientsforCluster(config *rest.Config, ipamClient, routeClient bool, clusterName string, clusterConfig *ClusterConfig) error {
	kubeCRClient, err := clustermanager.CreateKubeCRClientFromKubeConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create Custom Resource kubeClient: %v", err)
	}

	kubeClient, err := clustermanager.CreateKubeClientFromKubeConfig(config)
	if err != nil {
		return fmt.Errorf("Failed to create kubeClient: %v", err)
	}

	var kubeIPAMClient *extClient.Clientset
	if ipamClient {
		kubeIPAMClient, err = clustermanager.CreateKubeIPAMClientFromKubeConfig(config)
		if err != nil {
			log.Errorf("Failed to create ipam client: %v", err)
		}
	}

	var rclient *routeclient.RouteV1Client
	if routeClient {
		rclient, err = clustermanager.CreateRouteClientFromKubeconfig(config)
		if nil != err {
			return fmt.Errorf("Failed to create Route Client: %v", err)
		}
	}

	var dynamicClient dynamic.Interface
	if clusterConfig.orchestrationCNI == CALICO_K8S && clusterConfig.staticRoutingMode {
		dynamicClient, err = dynamic.NewForConfig(config)
		if nil != err {
			return fmt.Errorf("Failed to create dynamic Client for cluster %s: %v", clusterName, err)
		}
	}
	log.Debugf("Clients Created for cluster: %s", clusterName)
	//Update the clusterConfig store
	clusterConfig.kubeClient = kubeClient
	clusterConfig.kubeCRClient = kubeCRClient
	clusterConfig.kubeIPAMClient = kubeIPAMClient
	clusterConfig.routeClientV1 = rclient
	clusterConfig.dynamicClient = dynamicClient
	return nil
}

func (ctlr *Controller) setupInformers(clusterName string) error {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(clusterName)
	for n := range clusterConfig.namespaces {
		if err := ctlr.addNamespacedInformers(n, false, clusterName); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v in cluster %s, Error:%v", n, clusterName, err)
			return err
		}
	}
	_ = ctlr.setNodeInformer(clusterName)
	// create block affinities informer for calico cni enabled clusters.
	if clusterConfig.orchestrationCNI == CALICO_K8S && clusterConfig.staticRoutingMode {
		if clusterConfig.dynamicClient != nil {
			_ = ctlr.newDynamicInformersForCluster(clusterConfig.dynamicClient, clusterName)
		}
	}
	return nil
}

// Start the Controller
func (ctlr *Controller) Start() {
	log.Infof("Starting Controller")
	defer utilruntime.HandleCrash()
	defer ctlr.resourceQueue.ShutDown()

	ctlr.StartInformers(ctlr.multiClusterHandler.LocalClusterName)

	if ctlr.ipamCli != nil {
		go ctlr.ipamCli.Start()
	}

	if ctlr.vxlanMgr != nil {
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		ctlr.vxlanMgr.ProcessAppmanagerEvents(clusterConfig.kubeClient)
	}

	stopChan := make(chan struct{})

	go wait.Until(ctlr.nextGenResourceWorker, time.Second, stopChan)

	<-stopChan
	ctlr.Stop()
}

// Stop the Controller
func (ctlr *Controller) Stop() {
	ctlr.StopInformers(ctlr.multiClusterHandler.LocalClusterName)
	ctlr.Agent.Stop()
	if ctlr.ipamCli != nil {
		ctlr.ipamCli.Stop()
	}
	if ctlr.Agent.EventChan != nil {
		close(ctlr.Agent.EventChan)
	}
}

func (ctlr *Controller) StartInformers(clusterName string) {
	informerStore := ctlr.multiClusterHandler.getInformerStore(clusterName)
	// start nsinformer in all modes
	for _, nsInf := range informerStore.nsInformers {
		nsInf.start()
	}

	// start nodeinformer in all modes
	informerStore.nodeInformer.start(false)

	// start comInformers for all modes
	for _, inf := range informerStore.comInformers {
		inf.start(ctlr.multiClusterHandler.LocalClusterName, false)
	}

	//start CNI informers if required
	if ctlr.StaticRoutingMode && ctlr.OrchestrationCNI == CALICO_K8S {
		// check if role permissions exists for calico crd
		roleCheck := authv1.SelfSubjectAccessReview{
			Spec: authv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authv1.ResourceAttributes{
					Resource:  BLOCKAFFINITIES,
					Verb:      "watch",
					Group:     "crd.projectcalico.org",
					Namespace: "",
				},
			},
		}
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		if clusterConfig != nil {
			resp, err := clusterConfig.kubeClient.AuthorizationV1().
				SelfSubjectAccessReviews().
				Create(context.TODO(), &roleCheck, metaV1.CreateOptions{})
			if err == nil {
				if resp.Status.Allowed {
					log.Debugf("RBAC present for blockaffinities watch: %v", resp)
					informerStore.dynamicInformers.start()
				} else {
					log.Warning("Role Permissions to watch blockaffinities resource for calico CNI is not provided.Informers are not created for blockaffinities resource.Create proper RBAC for blockaffinities watch for static routing to work properly")
				}
			} else {
				log.Errorf("Failed to create Self Subject Access Review for blockaffinities resource: %v.Skipping informer creation for blockaffinitoes resource", err)
			}
		}

	}
	switch ctlr.mode {
	case OpenShiftMode, KubernetesMode:
		// nrInformers only with openShiftMode
		for _, inf := range informerStore.nrInformers {
			inf.start()
		}
	default:
		// start customer resource informers in custom resource mode only
		for _, inf := range informerStore.crInformers {
			inf.start()
		}
	}
}

func (ctlr *Controller) StopInformers(clusterName string) {
	informerStore := ctlr.multiClusterHandler.getInformerStore(clusterName)
	switch ctlr.mode {
	case OpenShiftMode, KubernetesMode:
		// stop native resource informers
		for _, inf := range informerStore.nrInformers {
			inf.stop()
		}
	default:
		// stop custom resource informers
		for _, inf := range informerStore.crInformers {
			inf.stop()
		}
	}

	// stop common informers & namespace informers in all modes
	for _, inf := range informerStore.comInformers {
		inf.stop()
	}
	for _, nsInf := range informerStore.nsInformers {
		nsInf.stop()
	}
	// stop cni Informer
	if informerStore.dynamicInformers != nil {
		informerStore.dynamicInformers.stop()
	}
	// stop node Informer
	informerStore.nodeInformer.stop()
}

func (ctlr *Controller) CISHealthCheck() {
	// Expose cis health endpoint
	http.Handle("/ready", ctlr.CISHealthCheckHandler())
}

func (ctlr *Controller) CISHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clusterConfig := ctlr.multiClusterHandler.getClusterConfig(ctlr.multiClusterHandler.LocalClusterName)
		if clusterConfig.kubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := clusterConfig.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
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

func initInformerStore() *InformerStore {
	return &InformerStore{
		crInformers:  make(map[string]*CRInformer),
		nrInformers:  make(map[string]*NRInformer),
		nsInformers:  make(map[string]*NSInformer),
		comInformers: make(map[string]*CommonInformer),
	}
}

func newClusterConfig() *ClusterConfig {
	return &ClusterConfig{
		namespaces:    make(map[string]struct{}),
		eventNotifier: NewEventNotifier(nil),
	}
}

func (ctlr *Controller) handleNsInformersforCluster(clusterName string, startInf bool) {
	clusterConfig := ctlr.multiClusterHandler.getClusterConfig(clusterName)
	if clusterConfig.namespaceLabel == "" {
		if len(ctlr.multiClusterHandler.namespaces) == 0 {
			clusterConfig.namespaces[""] = struct{}{}
			log.Debugf("No namespaces provided. Watching all namespaces for cluster %s", clusterName)
		} else {
			for _, ns := range ctlr.multiClusterHandler.namespaces {
				clusterConfig.namespaces[ns] = struct{}{}
			}
		}
	} else {
		err2 := ctlr.createNamespaceLabeledInformerForCluster(clusterConfig.namespaceLabel, clusterName)
		if err2 != nil {
			log.Errorf("Unable to create the namespace-label informer for cluster %v: %v", clusterName, err2)
		} else {
			for _, nsInf := range clusterConfig.InformerStore.nsInformers {
				if startInf {
					nsInf.start()
				}
				namspaces := nsInf.nsInformer.GetIndexer().List()
				if len(namspaces) == 0 {
					nsList, err := clusterConfig.kubeClient.CoreV1().Namespaces().List(context.TODO(), metaV1.ListOptions{LabelSelector: clusterConfig.namespaceLabel})
					if err != nil {
						return
					}
					for _, ns := range nsList.Items {
						clusterConfig.namespaces[ns.ObjectMeta.Name] = struct{}{}
					}
				} else {
					for _, v := range namspaces {
						ns := v.(*v1.Namespace)
						clusterConfig.namespaces[ns.ObjectMeta.Name] = struct{}{}
					}
				}
			}
		}
	}
}
