package controller

import (
	"context"
	"fmt"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"net/http"
	"strings"
	"testing"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CR Manager Suite")
}

type (
	mockController struct {
		*Controller
		mockResources map[string][]interface{}
	}

	mockPostManager struct {
		*PostManager
		Responses []int
		RespIndex int
	}

	responseCtx struct {
		tenant string
		status float64
		body   io.ReadCloser
	}
)

func newMockController() *mockController {
	return &mockController{
		Controller: &Controller{
			respChan: make(chan *agentPostConfig, 1),
		},
		mockResources: make(map[string][]interface{}),
	}
}

func (m *mockController) shutdown() error {
	return nil
}

func newMockPostManger() *mockPostManager {
	mockPM := &mockPostManager{
		PostManager: &PostManager{
			postChan: make(chan *agentPostConfig, 1),
			respChan: make(chan *agentPostConfig, 1),
		},
		Responses: []int{},
		RespIndex: 0,
	}
	mockPM.firstPost = true
	return mockPM
}

func getMockHttpClient(responses []responseCtx, method string) (*http.Client, error) {
	responseMap := make(mockhc.ResponseConfigMap)
	responseMap[method] = &mockhc.ResponseConfig{}

	for _, resp := range responses {
		var bodyContent string
		if resp.body == nil {
			if resp.status == http.StatusOK {
				bodyContent = fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "%s"}], "declaration": {"%s": {"Shared": {"class": "application"}}}}`,
					int(resp.status), resp.tenant, resp.tenant)
			} else {
				bodyContent = fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "%s"}],"error":{"code":%d}}`,
					int(resp.status), resp.tenant, int(resp.status))
			}
		} else {
			bodyBytes, _ := io.ReadAll(resp.body)
			bodyContent = string(bodyBytes)
		}

		responseMap[method].Responses = append(responseMap[method].Responses, &http.Response{
			StatusCode: int(resp.status),
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(bodyContent)),
		})
	}

	return mockhc.NewMockHTTPClient(responseMap)
}

func (mockPM *mockPostManager) setResponses(responses []responseCtx, method string) {
	client, _ := getMockHttpClient(responses, method)
	mockPM.httpClient = client
}

func newMockRequestHandler(writer writer.Writer) *RequestHandler {
	pm := &PostManager{
		postChan: make(chan *agentPostConfig, 1),
		respChan: make(chan *agentPostConfig, 1),
		PostParams: PostParams{
			BIGIPURL: "https://127.0.0.1",
		},
	}
	return &RequestHandler{
		PrimaryBigIPWorker: &Agent{
			APIHandler: &APIHandler{LTM: &LTMAPIHandler{
				&BaseAPIHandler{
					PostManager: pm,
					APIHandler:  NewAS3Handler(pm, "test"),
				},
			}},
			Partition:       "test",
			ConfigWriter:    writer,
			EventChan:       make(chan interface{}),
			PythonDriverPID: 0,
			userAgent:       "",
		},
		PrimaryClusterHealthProbeParams: &PrimaryClusterHealthProbeParams{
			statusRunning: true,
		},
	}
}

func newMockBaseAPIHandler() *BaseAPIHandler {
	pm := &PostManager{
		postChan: make(chan *agentPostConfig, 1),
		respChan: make(chan *agentPostConfig, 1),
		PostParams: PostParams{
			BIGIPURL:      "https://127.0.0.1",
			BIGIPPassword: "password",
			BIGIPUsername: "username",
			LogRequest:    true,
			LogResponse:   true,
		},
		TokenManagerInterface: test.NewMockTokenManager("test-token"),
	}
	return &BaseAPIHandler{
		apiType:     AS3,
		PostManager: pm,
		APIHandler:  NewAS3Handler(pm, "test"),
	}
}

func (m *mockController) addEDNS(edns *cisapiv1.ExternalDNS) {
	appInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, edns.ObjectMeta.Namespace)
	appInf.ednsInformer.GetStore().Add(edns)
	if m.resourceQueue != nil {
		m.enqueueExternalDNS(edns, m.multiClusterHandler.LocalClusterName)
	}
}

func (m *mockController) deleteEDNS(edns *cisapiv1.ExternalDNS) {
	appInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, edns.ObjectMeta.Namespace)
	appInf.ednsInformer.GetStore().Delete(edns)
	if m.resourceQueue != nil {
		m.enqueueDeletedExternalDNS(edns, m.multiClusterHandler.LocalClusterName)
	}
}

func (m *mockController) addRoute(route *routeapi.Route) {
	appInf, _ := m.getNamespacedNativeInformer(route.ObjectMeta.Namespace)
	appInf.routeInformer.GetStore().Add(route)
	if m.resourceQueue != nil {
		m.enqueueRoute(route, Create)
	}
}

func (m *mockController) deleteRoute(route *routeapi.Route) {
	appInf, _ := m.getNamespacedNativeInformer(route.ObjectMeta.Namespace)
	appInf.routeInformer.GetStore().Delete(route)
	if m.resourceQueue != nil {
		m.enqueueDeletedRoute(route)
	}
}

func (m *mockController) updateRoute(route *routeapi.Route) {
	appInf, _ := m.getNamespacedNativeInformer(route.ObjectMeta.Namespace)
	appInf.routeInformer.GetStore().Update(route)
}
func (m *mockController) addService(svc *v1.Service, clusterName string) {
	if clusterName == "" {
		clusterName = m.multiClusterHandler.LocalClusterName
	}
	comInf, _ := m.getNamespacedCommonInformer(clusterName, svc.ObjectMeta.Namespace)
	comInf.svcInformer.GetStore().Add(svc)

	if m.resourceQueue != nil {
		m.enqueueService(svc, clusterName)
	}
}

func (m *mockController) updateService(svc *v1.Service, clusterName string) {
	if clusterName == "" {
		clusterName = m.multiClusterHandler.LocalClusterName
	}
	comInf, _ := m.getNamespacedCommonInformer(clusterName, svc.ObjectMeta.Namespace)
	comInf.svcInformer.GetStore().Update(svc)
}

func (m *mockController) deleteService(svc *v1.Service, clusterName string) {
	if clusterName == "" {
		clusterName = m.multiClusterHandler.LocalClusterName
	}
	comInf, _ := m.getNamespacedCommonInformer(clusterName, svc.ObjectMeta.Namespace)
	comInf.svcInformer.GetStore().Delete(svc)
	if m.resourceQueue != nil {
		m.enqueueDeletedService(svc, "")
	}
}

func (m *mockController) addEndpoints(ep *v1.Endpoints) {
	comInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, ep.ObjectMeta.Namespace)
	comInf.epsInformer.GetStore().Add(ep)

	if m.resourceQueue != nil {
		m.enqueueEndpoints(ep, Create, "")
	}
}

func (m *mockController) updateEndpoints(ep *v1.Endpoints) {
	comInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, ep.ObjectMeta.Namespace)
	comInf.epsInformer.GetStore().Update(ep)
}

func (m *mockController) deleteEndpoints(ep *v1.Endpoints) {
	comInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, ep.ObjectMeta.Namespace)
	comInf.epsInformer.GetStore().Delete(ep)
	if m.resourceQueue != nil {
		m.enqueueEndpoints(ep, Delete, "")
	}
}

func convertSvcPortsToEndpointPorts(svcPorts []v1.ServicePort) []v1.EndpointPort {
	eps := make([]v1.EndpointPort, len(svcPorts))
	for i, v := range svcPorts {
		eps[i].Name = v.Name
		eps[i].Port = v.Port
	}
	return eps
}

func (m *mockController) addVirtualServer(vs *cisapiv1.VirtualServer) {
	cusInf, _ := m.getNamespacedCRInformer(vs.ObjectMeta.Namespace, "")
	cusInf.vsInformer.GetStore().Add(vs)

	if m.resourceQueue != nil {
		m.enqueueVirtualServer(vs)
	}
}

func (m *mockController) updateVirtualServer(oldVS *cisapiv1.VirtualServer, newVS *cisapiv1.VirtualServer) {
	cusInf, _ := m.getNamespacedCRInformer(oldVS.ObjectMeta.Namespace, "")
	cusInf.vsInformer.GetStore().Update(newVS)

	if m.resourceQueue != nil {
		m.enqueueUpdatedVirtualServer(oldVS, newVS)
	}
}

func (m *mockController) deleteVirtualServer(vs *cisapiv1.VirtualServer) {
	cusInf, _ := m.getNamespacedCRInformer(vs.ObjectMeta.Namespace, "")
	cusInf.vsInformer.GetStore().Delete(vs)

	if m.resourceQueue != nil {
		m.enqueueDeletedVirtualServer(vs)
	}
}

func (m *mockController) addTransportServer(vs *cisapiv1.TransportServer) {
	cusInf, _ := m.getNamespacedCRInformer(vs.ObjectMeta.Namespace, "")
	cusInf.tsInformer.GetStore().Add(vs)

	if m.resourceQueue != nil {
		m.enqueueTransportServer(vs)
	}
}

func (m *mockController) updateTransportServer(oldVS *cisapiv1.TransportServer, newVS *cisapiv1.TransportServer) {
	cusInf, _ := m.getNamespacedCRInformer(oldVS.ObjectMeta.Namespace, "")
	cusInf.tsInformer.GetStore().Update(newVS)

	if m.resourceQueue != nil {
		m.enqueueUpdatedTransportServer(oldVS, newVS)
	}
}

func (m *mockController) deleteTransportServer(vs *cisapiv1.TransportServer) {
	cusInf, _ := m.getNamespacedCRInformer(vs.ObjectMeta.Namespace, "")
	cusInf.tsInformer.GetStore().Delete(vs)

	if m.resourceQueue != nil {
		m.enqueueDeletedTransportServer(vs)
	}
}

func (m *mockController) addPolicy(plc *cisapiv1.Policy) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, plc.ObjectMeta.Namespace)
	cusInf.plcInformer.GetStore().Add(plc)

	if m.resourceQueue != nil {
		m.enqueuePolicy(plc, Create, "")
	}
}

func (m *mockController) deletePolicy(plc *cisapiv1.Policy) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, plc.ObjectMeta.Namespace)
	cusInf.plcInformer.GetStore().Delete(plc)

	if m.resourceQueue != nil {
		m.enqueueDeletedPolicy(plc, "")
	}
}

func (m *mockController) addTLSProfile(prof *cisapiv1.TLSProfile) {
	cusInf, _ := m.getNamespacedCRInformer(prof.ObjectMeta.Namespace, "")
	cusInf.tlsInformer.GetStore().Add(prof)

	if m.resourceQueue != nil {
		m.enqueueTLSProfile(prof, Create)
	}
}

func (m *mockController) addSecret(secret *v1.Secret) {
	comInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, secret.ObjectMeta.Namespace)
	comInf.secretsInformer.GetStore().Add(secret)

	if m.resourceQueue != nil {
		m.enqueueSecret(secret, Create, m.multiClusterHandler.LocalClusterName)
	}
}

func (m *mockController) addIngressLink(il *cisapiv1.IngressLink) {
	cusInf, _ := m.getNamespacedCRInformer(il.ObjectMeta.Namespace, "")
	cusInf.ilInformer.GetStore().Add(il)

	if m.resourceQueue != nil {
		m.enqueueIngressLink(il)
	}
}

func (m *mockController) updateIngressLink(oldIL *cisapiv1.IngressLink, newIL *cisapiv1.IngressLink) {
	cusInf, _ := m.getNamespacedCRInformer(oldIL.ObjectMeta.Namespace, "")
	cusInf.ilInformer.GetStore().Update(newIL)

	if m.resourceQueue != nil {
		m.enqueueUpdatedIngressLink(oldIL, newIL)
	}
}

func (m *mockController) deleteIngressLink(il *cisapiv1.IngressLink) {
	cusInf, _ := m.getNamespacedCRInformer(il.ObjectMeta.Namespace, "")
	cusInf.ilInformer.GetStore().Delete(il)

	if m.resourceQueue != nil {
		m.enqueueDeletedIngressLink(il)
	}
}

func (m *mockController) addPod(pod *v1.Pod) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, pod.ObjectMeta.Namespace)
	cusInf.podInformer.GetStore().Add(pod)

	if m.resourceQueue != nil {
		m.enqueuePod(pod, "")
	}
}

func (m *mockController) updatePod(pod *v1.Pod) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, pod.ObjectMeta.Namespace)
	cusInf.podInformer.GetStore().Update(pod)

	if m.resourceQueue != nil {
		m.enqueuePod(pod, "")
	}
}

func (m *mockController) deletePod(pod v1.Pod) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, pod.ObjectMeta.Namespace)
	cusInf.podInformer.GetStore().Delete(pod)

	if m.resourceQueue != nil {
		m.enqueueDeletedPod(pod, "")
	}
}

func (m *mockController) addConfigMap(cm *v1.ConfigMap) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, cm.ObjectMeta.Namespace)
	cusInf.cmInformer.GetStore().Add(cm)

	if m.resourceQueue != nil {
		m.enqueueConfigmap(cm, Create, m.multiClusterHandler.LocalClusterName)
	}
}

func (m *mockController) updateConfigMap(cm *v1.ConfigMap) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, cm.ObjectMeta.Namespace)
	cusInf.cmInformer.GetStore().Update(cm)

	if m.resourceQueue != nil {
		m.enqueueConfigmap(cm, Update, m.multiClusterHandler.LocalClusterName)
	}
}

func (m *mockController) deleteConfigMap(cm *v1.ConfigMap) {
	cusInf, _ := m.getNamespacedCommonInformer(m.multiClusterHandler.LocalClusterName, cm.ObjectMeta.Namespace)
	cusInf.cmInformer.GetStore().Delete(cm)

	if m.resourceQueue != nil {
		m.enqueueDeletedConfigmap(cm, m.multiClusterHandler.LocalClusterName)
	}
}

func (m *mockController) addNode(node *v1.Node) {
	m.multiClusterHandler.ClusterConfigs[""].nodeInformer.nodeInformer.GetStore().Add(node)
	if m.resourceQueue != nil {
		m.SetupNodeProcessing("")
	}
}

func (m *mockController) updateNode(node *v1.Node, ns string) {
	m.multiClusterHandler.ClusterConfigs[""].nodeInformer.nodeInformer.GetStore().Update(node)
	if m.resourceQueue != nil {
		m.SetupNodeProcessing("")
	}
}

func (m *mockController) updateStatusNode(node *v1.Node, ns string) {
	m.multiClusterHandler.ClusterConfigs[""].nodeInformer.nodeInformer.GetStore().Update(node)
	if m.resourceQueue != nil {
		m.SetupNodeProcessing("")
	}
}

// addBlockAffinity adds a Calico BlockAffinity resource to the dynamic informer
func (m *mockController) addBlockAffinity(name, namespace, nodeName, cidr string, dynamicClient *dynamicfake.FakeDynamicClient) error {
	// Define the GVR for BlockAffinity
	blockAffinityGVR := schema.GroupVersionResource{
		Group:    "crd.projectcalico.org",
		Version:  "v1",
		Resource: "blockaffinities",
	}
	// Create unstructured BlockAffinity object
	ba := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "crd.projectcalico.org/v1",
			"kind":       "BlockAffinity",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"node": nodeName,
				"cidr": cidr,
			},
		},
	}
	// Add to store
	m.multiClusterHandler.ClusterConfigs[""].InformerStore.dynamicInformers.CalicoBlockAffinityInformer.Informer().GetStore().Add(ba)
	// Add to client
	_, err := dynamicClient.Resource(blockAffinityGVR).
		Namespace(namespace).
		Create(context.TODO(), ba, metav1.CreateOptions{})
	return err
}

//func (mockCtlr *mockController) getOrderedRoutes(resourceType, namespace string) []interface{} {
//	return mockCtlr.mockResources[namespace+"/"+resourceType]
//}
//
//func (mockCtlr *mockController) getServicePort(rt *routeapi.Route) (error, int32) {
//	if isSecureRoute(rt) {
//		return nil, 443
//	}
//	return nil, 80
//}
