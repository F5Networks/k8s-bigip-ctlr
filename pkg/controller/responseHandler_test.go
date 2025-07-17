package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	crdfake "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/clientset/versioned/fake"
	cisinfv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/client/informers/externalversions/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var _ = Describe("Response Handler Tests", func() {
	var mockCtlr *mockController
	var postConfig *agentPostConfig
	var tenantResponseMap map[string]tenantResponse
	var vrt *cisapiv1.VirtualServer
	var ts *cisapiv1.TransportServer
	var il *cisapiv1.IngressLink
	var svc *v1.Service
	namespace := "default"

	BeforeEach(func() {
		// mockBaseAPIHandler = newMockBaseAPIHandler()
		vrt = test.NewVirtualServer(
			"SampleVS",
			namespace,
			cisapiv1.VirtualServerSpec{
				Host:                 "test.com",
				VirtualServerAddress: "1.2.3.5",
				Pools: []cisapiv1.VSPool{
					cisapiv1.VSPool{
						Path:        "/path",
						Service:     "svc",
						ServicePort: intstr.IntOrString{IntVal: 80},
					},
				},
			})
		ts = test.NewTransportServer(
			"SampleTS",
			namespace,
			cisapiv1.TransportServerSpec{
				SNAT:                 "auto",
				VirtualServerAddress: "1.2.3.6",
			},
		)
		label := make(map[string]string)
		label["app"] = "ingresslink"
		selector := &metav1.LabelSelector{
			MatchLabels: label,
		}
		iRules := []string{"dummyiRule"}
		il = test.NewIngressLink(
			"SampleIL",
			namespace,
			"1",
			cisapiv1.IngressLinkSpec{
				VirtualServerAddress: "1.2.3.4",
				Selector:             selector,
				IRules:               iRules,
			},
		)
		svc = test.NewService(
			"svc",
			"1",
			namespace,
			v1.ServiceTypeClusterIP,
			[]v1.ServicePort{
				{
					Port: 80,
					Name: "port0",
				},
			},
		)
		tenantDeclMap := make(map[string]as3Tenant)
		tenantResponseMap = make(map[string]tenantResponse)
		tenantResponseMap["test"] = tenantResponse{}
		tenantResponseMap["test1"] = tenantResponse{}
		tenantDeclMap["test"] = as3Tenant{
			"class":              "Tenant",
			"defaultRouteDomain": 0,
			as3SharedApplication: "shared",
			"label":              "cis2.x",
		}
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		mockWriter := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		mockCtlr.RequestHandler = newMockRequestHandler(mockWriter)
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
		mockCtlr.Partition = "test"
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = newClusterConfig()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].kubeClient = k8sfake.NewSimpleClientset(svc)
		mockCtlr.multiClusterHandler.ClusterConfigs[""].kubeCRClient = crdfake.NewSimpleClientset(vrt)
		mockCtlr.mode = CustomResourceMode
		mockCtlr.globalExtendedCMKey = "kube-system/global-cm"
		mockCtlr.multiClusterHandler.ClusterConfigs[""].InformerStore = initInformerStore()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].nativeResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		mockCtlr.multiClusterHandler.customResourceSelector, _ = createLabelSelector(DefaultCustomResourceLabel)
		_ = mockCtlr.addNamespacedInformers("default", false, "")
		mockCtlr.resourceQueue = workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(), "custom-resource-controller")
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				VirtualServer: make(map[string]int),
			},
		}
		mockCtlr.resources = NewResourceStore()
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].crInformers["default"].vsInformer = cisinfv1.NewFilteredVirtualServerInformer(
			mockCtlr.multiClusterHandler.ClusterConfigs[""].kubeCRClient,
			namespace,
			0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(options *metav1.ListOptions) {
				options.LabelSelector = mockCtlr.multiClusterHandler.ClusterConfigs[""].nativeResourceSelector.String()
			},
		)
		mockCtlr.multiClusterHandler.ClusterConfigs[""].crInformers["default"].ilInformer = cisinfv1.NewFilteredIngressLinkInformer(
			mockCtlr.multiClusterHandler.ClusterConfigs[""].kubeCRClient,
			namespace,
			0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(options *metav1.ListOptions) {
				options.LabelSelector = mockCtlr.multiClusterHandler.ClusterConfigs[""].nativeResourceSelector.String()
			},
		)
		mockCtlr.ResourceStatusVSAddressMap = make(map[resourceRef]string)
		mockCtlr.addVirtualServer(vrt)
		mockCtlr.addTransportServer(ts)
		mockCtlr.addIngressLink(il)
		postConfig = &agentPostConfig{
			reqMeta: requestMeta{
				id: 1,
			},
			as3APIURL:             "https://127.0.0.1/mgmt/shared/appsvcs/declare",
			data:                  `{"class": "AS3", "declaration": {"class": "ADC", "test": {"class": "Tenant", "testApp": {"class": "Application", "webcert":{"class": "Certificate", "certificate": "abc", "privateKey": "abc", "chainCA": "abc"}}}}}`,
			incomingTenantDeclMap: tenantDeclMap,
			tenantResponseMap:     make(map[string]tenantResponse),
			agentKind:             PrimaryBigIP,
		}
		postConfig.reqMeta.partitionMap = make(map[string]map[string]string)
		postConfig.reqMeta.partitionMap["test"] = make(map[string]string)
		postConfig.reqMeta.partitionMap["test"]["default/SampleVS"] = VirtualServer
		postConfig.reqMeta.partitionMap["test"]["default/SampleTS"] = TransportServer
		postConfig.reqMeta.partitionMap["test"]["default/SampleIL"] = IngressLink

	})
	It("Resource Status update tests for VS, TS and IL", func() {
		go mockCtlr.responseHandler()
		mockCtlr.respChan <- postConfig
	})
	It("Resource Status update tests for VS, TS and IL for failed tenants", func() {
		postConfig.failedTenants = make(map[string]tenantResponse)
		postConfig.timeout = 30
		mockCtlr.requestCounter = 1
		postConfig.failedTenants["test"] = tenantResponse{
			message:           "failed",
			agentResponseCode: 500,
		}
		go mockCtlr.responseHandler()
		mockCtlr.respChan <- postConfig
	})
	AfterEach(func() {
		close(mockCtlr.respChan)
	})
})
