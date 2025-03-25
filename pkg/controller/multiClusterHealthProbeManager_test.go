package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/teem"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"net/http"
)

var _ = Describe("Multi Cluster Health Probe", func() {
	var mockCtlr *mockController
	es := extendedSpec{}

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		mockWriter := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		mockCtlr.RequestHandler = newMockRequestHandler(mockWriter)
		mockCtlr.RequestHandler.PrimaryBigIPWorker.getPostManager().httpClient = &http.Client{
			Timeout: 1,
		}
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.mode = OpenShiftMode
		mockCtlr.globalExtendedCMKey = "kube-system/global-cm"
		mockCtlr.multiClusterHandler.ClusterConfigs[""] = newClusterConfig()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].kubeClient = k8sfake.NewSimpleClientset()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].routeClientV1 = fakeRouteClient.NewSimpleClientset().RouteV1()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].namespaces["default"] = struct{}{}
		mockCtlr.multiClusterHandler.ClusterConfigs[""].InformerStore = initInformerStore()
		mockCtlr.multiClusterHandler.ClusterConfigs[""].nativeResourceSelector, _ = createLabelSelector(DefaultNativeResourceLabel)
		mockCtlr.multiClusterHandler.ClusterConfigs[""].nrInformers["default"] = mockCtlr.newNamespacedNativeResourceInformer("default")
		mockCtlr.multiClusterHandler.ClusterConfigs[""].nrInformers["test"] = mockCtlr.newNamespacedNativeResourceInformer("test")
		mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers["test"] = mockCtlr.newNamespacedCommonResourceInformer("test", "")
		mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers["default"] = mockCtlr.newNamespacedCommonResourceInformer("default", "")
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()

		var processedHostPath ProcessedHostPath
		processedHostPath.processedHostPathMap = make(map[string]metav1.Time)
		mockCtlr.processedHostPath = &processedHostPath
		mockCtlr.TeemData = &teem.TeemsData{
			ResourceType: teem.ResourceTypes{
				RouteGroups:  make(map[string]int),
				NativeRoutes: make(map[string]int),
				ExternalDNS:  make(map[string]int),
			},
		}
		cmName := "ecm"
		cmNamespace := "kube-system"
		mockCtlr.globalExtendedCMKey = cmNamespace + "/" + cmName
		mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers[cmNamespace] = mockCtlr.newNamespacedCommonResourceInformer(cmNamespace, "")
		mockCtlr.multiClusterHandler.ClusterConfigs[""].comInformers[""] = mockCtlr.newNamespacedCommonResourceInformer("", "")
		mockCtlr.resources = NewResourceStore()
		data := make(map[string]string)

		data["extendedSpec"] = `
baseRouteSpec:
   tlsCipher:
     tlsVersion : 1.2
     ciphers: DEFAULT
     cipherGroup: /Common/f5-default
   defaultTLS:
      clientSSL: /Common/clientssl
      serverSSL: /Common/serverssl
      reference: bigip
highAvailabilityCIS:
     primaryEndPoint: http://10.145.72.114:8001
     probeInterval: 5
     retryInterval: 1
     primaryCluster:
       clusterName: cluster1
       secret: default/kubeconfig1
     secondaryCluster:
       clusterName: cluster2
       secret: default/kubeconfig2
externalClustersConfig:
   - clusterName: cluster3
     secret: default/kubeconfig3
   - clusterName: cluster4
     secret: default/kubeconfig4
extendedRouteSpec:
   - namespace: default
     vserverAddr: 10.8.3.11
     vserverName: nextgenroutes
     allowOverride: true
     policyCR : default/policy
`
		yaml.UnmarshalStrict([]byte(data["extendedSpec"]), &es)
	})

	It("Check Primary Cluster HealthProbe config", func() {

		mockCtlr.updateHealthProbeConfig(es.HAClusterConfig)
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPointType).To(BeEquivalentTo("http"), "endpoint type not set properly")
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval).To(BeEquivalentTo(5), "probe interval not set properly")
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval).To(BeEquivalentTo(1), "retry interval not set properly")
		Expect(mockCtlr.RequestHandler.checkPrimaryClusterHealthStatus()).To(BeFalse(), "incorrect primary cluster health status")
		es.HAClusterConfig.ProbeInterval = 0
		es.HAClusterConfig.RetryInterval = 0
		mockCtlr.updateHealthProbeConfig(es.HAClusterConfig)
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.probeInterval).To(BeEquivalentTo(DefaultProbeInterval), "probe interval not set properly")
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.retryInterval).To(BeEquivalentTo(DefaultRetryInterval), "retry interval not set properly")
		es.HAClusterConfig.PrimaryClusterEndPoint = "tcp://10.145.72.114"
		es.HAClusterConfig.ProbeInterval = 1
		es.HAClusterConfig.RetryInterval = 1
		mockCtlr.updateHealthProbeConfig(es.HAClusterConfig)
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPointType).To(BeEquivalentTo("tcp"), "endPoint type not set to tcp")
		Expect(mockCtlr.RequestHandler.checkPrimaryClusterHealthStatus()).To(BeFalse(), "incorrect primary cluster health status")
		// unsupported endpoint type
		es.HAClusterConfig.PrimaryClusterEndPoint = "https://10.145.72.114:8001"
		mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPointType = ""
		mockCtlr.firstPollPrimaryClusterHealthStatus()
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.statusRunning).To(BeFalse(), "incorrect primary cluster health status")
		mockCtlr.getPrimaryClusterHealthStatus()
		Expect(mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.statusRunning).To(BeFalse(), "incorrect primary cluster health status")

	})
	It("Check Primary Cluster HealthProbe with valid http endpoint", func() {
		server := ghttp.NewServer()
		statusCode := 200
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				ghttp.RespondWithJSONEncoded(statusCode, ""),
			))
		es.HAClusterConfig.PrimaryClusterEndPoint = "http://" + server.Addr()
		mockCtlr.updateHealthProbeConfig(es.HAClusterConfig)
		Expect(mockCtlr.RequestHandler.checkPrimaryClusterHealthStatus()).To(BeTrue(), "incorrect primary cluster health status")
		server.Close()
	})

	It("Check Primary Cluster HealthProbe with invalid http endpoint", func() {
		Expect(mockCtlr.RequestHandler.getPrimaryClusterHealthStatusFromHTTPEndPoint()).To(BeFalse())
		mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint = "https://0.0.0.0:80"
		Expect(mockCtlr.RequestHandler.getPrimaryClusterHealthStatusFromHTTPEndPoint()).To(BeFalse())
		mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint = "http://"
		Expect(mockCtlr.RequestHandler.getPrimaryClusterHealthStatusFromHTTPEndPoint()).To(BeFalse())
	})

	It("Check Primary Cluster HealthProbe with invalid tcp endpoint", func() {
		Expect(mockCtlr.RequestHandler.getPrimaryClusterHealthStatusFromTCPEndPoint()).To(BeFalse())
		mockCtlr.RequestHandler.PrimaryClusterHealthProbeParams.EndPoint = "tcp:/"
		Expect(mockCtlr.RequestHandler.getPrimaryClusterHealthStatusFromTCPEndPoint()).To(BeFalse())
	})
})
