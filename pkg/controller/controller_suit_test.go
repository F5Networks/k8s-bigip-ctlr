package controller

import (
	"bytes"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	routeapi "github.com/openshift/api/route/v1"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	"net/http"
	"testing"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CR Manager Suite")
}

var configPath = "../../test/configs/"

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

	responceCtx struct {
		tenant string
		status float64
		body   string
	}
)

func newMockController() *mockController {
	return &mockController{
		Controller:    &Controller{},
		mockResources: make(map[string][]interface{}),
	}
}

func (m *mockController) shutdown() error {
	return nil
}

func newMockPostManger() *mockPostManager {
	mockPM := &mockPostManager{
		PostManager: &PostManager{},
		Responses:   []int{},
		RespIndex:   0,
	}
	mockPM.tenantResponseMap = make(map[string]tenantResponse)
	mockPM.firstPost = true
	return mockPM
}

func (mockPM *mockPostManager) setResponses(responces []responceCtx, method string) {
	var body string

	responseMap := make(mockhc.ResponseConfigMap)
	responseMap[method] = &mockhc.ResponseConfig{}

	for _, resp := range responces {
		if resp.body == "" {
			if resp.status == http.StatusOK {
				body = fmt.Sprintf(`{"results":[{"code":%f,"message":"none", "tenant": "%s"}]}`,
					resp.status, resp.tenant)
			} else {
				body = fmt.Sprintf(`{"results":[{"code":%f,"message":"none", "tenant": "%s"}],"error":{"code":%f}}`,
					resp.status, resp.tenant, resp.status)
			}
		} else {
			body = resp.body
		}

		responseMap[method].Responses = append(responseMap[method].Responses, &http.Response{
			StatusCode: int(resp.status),
			Header:     http.Header{},
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(body))),
		})
	}

	client, _ := mockhc.NewMockHTTPClient(responseMap)
	mockPM.httpClient = client
}

func newMockAgent(writer writer.Writer) *Agent {
	return &Agent{
		PostManager:     nil,
		Partition:       "test",
		ConfigWriter:    writer,
		EventChan:       make(chan interface{}),
		postChan:        make(chan ResourceConfigRequest, 1),
		PythonDriverPID: 0,
		//cachedTenantDeclMap:   make(map[string]interface{}),
		//incomingTenantDeclMap: make(map[string]interface{}),
		userAgent: "",
	}
}

func (m *mockController) addRoute(route *routeapi.Route) {
	appInf, _ := m.getNamespacedNativeInformer(route.ObjectMeta.Namespace)
	appInf.routeInformer.GetStore().Add(route)
}

func (m *mockController) deleteRoute(route *routeapi.Route) {
	appInf, _ := m.getNamespacedNativeInformer(route.ObjectMeta.Namespace)
	appInf.routeInformer.GetStore().Delete(route)
}

func (m *mockController) updateRoute(route *routeapi.Route) {
	appInf, _ := m.getNamespacedNativeInformer(route.ObjectMeta.Namespace)
	appInf.routeInformer.GetStore().Update(route)
}
func (m *mockController) addService(svc *v1.Service) {
	comInf, _ := m.getNamespacedCommonInformer(svc.ObjectMeta.Namespace)
	comInf.svcInformer.GetStore().Add(svc)
}

func (m *mockController) updateService(svc *v1.Service) {
	comInf, _ := m.getNamespacedCommonInformer(svc.ObjectMeta.Namespace)
	comInf.svcInformer.GetStore().Update(svc)
}

func (m *mockController) deleteService(svc *v1.Service) {
	comInf, _ := m.getNamespacedCommonInformer(svc.ObjectMeta.Namespace)
	comInf.svcInformer.GetStore().Delete(svc)
}

func (m *mockController) addEndpoints(ep *v1.Endpoints) {
	comInf, _ := m.getNamespacedCommonInformer(ep.ObjectMeta.Namespace)
	comInf.epsInformer.GetStore().Add(ep)
}

func (m *mockController) updateEndpoints(ep *v1.Endpoints) {
	comInf, _ := m.getNamespacedCommonInformer(ep.ObjectMeta.Namespace)
	comInf.epsInformer.GetStore().Update(ep)
}

func (m *mockController) deleteEndpoints(ep *v1.Endpoints) {
	comInf, _ := m.getNamespacedCommonInformer(ep.ObjectMeta.Namespace)
	comInf.epsInformer.GetStore().Delete(ep)
}

func convertSvcPortsToEndpointPorts(svcPorts []v1.ServicePort) []v1.EndpointPort {
	eps := make([]v1.EndpointPort, len(svcPorts))
	for i, v := range svcPorts {
		eps[i].Name = v.Name
		eps[i].Port = v.Port
	}
	return eps
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
