package controller

import (
	"context"
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"strings"
)

func (ctlr *Controller) setupInformers() error {
	for n := range ctlr.namespaces {
		if err := ctlr.addNamespacedInformers(n, false); err != nil {
			log.Errorf("Unable to setup informer for namespace: %v, Error:%v", n, err)
			return err
		}
	}
	nodeInf := ctlr.getNodeInformer("")
	ctlr.multiClusterNodeInformers[""] = &nodeInf
	ctlr.addNodeEventUpdateHandler(&nodeInf)
	return nil
}

func (ctlr *Controller) initInformers() {
	// Initialize the controller with base resources in CIS config CR
	key := strings.Split(ctlr.CISConfigCRKey, "/")
	configCR, err := ctlr.clientsets.kubeCRClient.CisV1().DeployConfigs(key[0]).Get(context.TODO(), key[1], metaV1.GetOptions{})
	if err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
	ctlr.updateResourceSelectorConfig(configCR.Spec.BaseConfig)
	ctlr.updateBigIpConfigMap(configCR.Spec.BigIpConfig)
	// update the agent params
	ctlr.AgentParams.PostParams.AS3Config = configCR.Spec.AS3Config
	if ctlr.managedResources.ManageRoutes {
		// initialize the processed host-path map
		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metaV1.Time)
		ctlr.processedHostPath = &processedHostPath
	}
	// initialize the informer maps
	ctlr.comInformers = make(map[string]*CommonInformer)
	ctlr.multiClusterPoolInformers = make(map[string]map[string]*MultiClusterPoolInformer)
	ctlr.multiClusterNodeInformers = make(map[string]*NodeInformer)
	ctlr.nrInformers = make(map[string]*NRInformer)
	ctlr.crInformers = make(map[string]*CRInformer)
	ctlr.nsInformers = make(map[string]*NSInformer)
	ctlr.namespaces = make(map[string]bool)
	if ctlr.resourceSelectorConfig.NamespaceLabel == "" {
		ctlr.namespaces[""] = true
		log.Debug("No namespaces provided. Watching all namespaces")
	} else {
		err2 := ctlr.createNamespaceLabeledInformer(ctlr.resourceSelectorConfig.NamespaceLabel)
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
}

// Start the informers for controller
func (ctlr *Controller) startInformers() {
	// start nsinformer in all modes
	for _, nsInf := range ctlr.nsInformers {
		nsInf.start()
	}

	// start nodeinformer in all modes
	for _, nodeInf := range ctlr.multiClusterNodeInformers {
		nodeInf.start()
	}

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
}

// stop the informers for controller
func (ctlr *Controller) stopInformers() {
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
	for ns, inf := range ctlr.comInformers {
		inf.stop(ns)
	}
	for ns, nsInf := range ctlr.nsInformers {
		nsInf.stop(ns)
	}
	// stop node Informer
	for _, nodeInf := range ctlr.multiClusterNodeInformers {
		nodeInf.stop()
	}

	// stop multi cluster informers
	for _, poolInformers := range ctlr.multiClusterPoolInformers {
		for _, inf := range poolInformers {
			inf.stop()
		}
	}
}

func (ctlr *Controller) updateResourceSelectorConfig(config cisapiv1.BaseConfig) {
	ctlr.resourceSelectorConfig = ResourceSelectorConfig{
		NodeLabel:      config.NodeLabel,
		NamespaceLabel: config.NamespaceLabel,
		RouteLabel:     config.RouteLabel,
	}
	ctlr.resourceSelectorConfig.nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
	ctlr.resourceSelectorConfig.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
}

func (ctlr *Controller) updateBigIpConfigMap(config []cisapiv1.BigIpConfig) {
	for _, bigipconfig := range config {
		//initialize map with empty bigipconfig.will be updated after resource processing
		ctlr.bigIpMap[bigipconfig] = BigIpResourceConfig{}
	}
}

func (ctlr *Controller) resetControllerForNodeLabel() {
	for clusterName, inf := range ctlr.multiClusterNodeInformers {
		log.Debugf("Resetting node informer %v", getClusterLog(inf.clusterName))
		inf.stop()
		inf.oldNodes = []Node{}
		newInf := ctlr.getNodeInformer(clusterName)
		ctlr.multiClusterNodeInformers[clusterName] = &newInf
		ctlr.addNodeEventUpdateHandler(&newInf)
		newInf.start()
	}
}

func (ctlr *Controller) resetControllerForRouteLabel() {
	ctlr.resources.processedNativeResources = make(map[resourceRef]struct{})
	var processedHostPath ProcessedHostPath
	processedHostPath.processedHostPathMap = make(map[string]metaV1.Time)
	ctlr.processedHostPath = &processedHostPath
	for namespace, inf := range ctlr.nrInformers {
		inf.stop()
		newInf := ctlr.newNamespacedNativeResourceInformer(namespace)
		ctlr.addNativeResourceEventHandlers(newInf)
		ctlr.nrInformers[namespace] = newInf
		newInf.start()
	}
}

func (ctlr *Controller) resetControllerForNamespaceLabel() {
	// stop the older informers
	ctlr.stopInformers()
	// create new resource store
	ctlr.resources = NewResourceStore()
	// reinitialize the informers
	ctlr.initInformers()
	ctlr.setupInformers()
	ctlr.startInformers()
	// process the resources
	ctlr.initState = true
	ctlr.setInitialResourceCount()
	// process the DeployConfig CR if present
	if ctlr.CISConfigCRKey != "" {
		ctlr.processGlobalDeployConfigCR()
	}
	// process static routes after DeployConfig CR if present is processed, so as to support external cluster static routes during cis init
	if ctlr.StaticRoutingMode {
		clusterNodes := ctlr.getNodesFromAllClusters()
		ctlr.processStaticRouteUpdate(clusterNodes)
	}
}
