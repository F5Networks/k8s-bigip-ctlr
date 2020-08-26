/*-
 * Copyright (c) 2016-2020, F5 Networks, Inc.
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

package appmanager

import (
	"fmt"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/agent/cccl"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/agent"
	. "github.com/F5Networks/k8s-bigip-ctlr/pkg/resource"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	fakeRouteClient "github.com/openshift/client-go/route/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

func NewFakeEventBroadcaster() record.EventBroadcaster {
	return &FakeEventBroadcaster{}
}

func NewFakeEvent(
	obj interface{},
	eventType string,
	reason string,
	message string,
) FakeEvent {

	namespace := ""
	name := ""
	var annotations map[string]string

	// Only Ingress objects are supported more, others added easily here.
	switch obj.(type) {
	case *v1beta1.Ingress:
		ing := obj.(*v1beta1.Ingress)
		namespace = ing.ObjectMeta.Namespace
		name = ing.ObjectMeta.Name
	default:
		// Set namespace and name to the error message
		namespace = fmt.Sprintf("NewFakeEvent: Unhandled object type: %T\n", obj)
		name = namespace
	}

	return FakeEvent{
		Namespace:   namespace,
		Name:        name,
		EventType:   eventType,
		Reason:      reason,
		Message:     message,
		Annotations: annotations,
	}
}

type FakeEventBroadcaster struct {
	EventRecorder FakeEventRecorder
}

type FakeEventRecorder struct {
	FEvent []FakeEvent
}

type FakeEvent struct {
	Namespace   string
	Name        string
	EventType   string
	Reason      string
	Message     string
	Annotations map[string]string
}

// record.EventBroadcaster interface methods
func (feb *FakeEventBroadcaster) StartEventWatcher(eventHandler func(*v1.Event)) watch.Interface {
	return nil
}

func (feb *FakeEventBroadcaster) StartRecordingToSink(sink record.EventSink) watch.Interface {
	return nil
}

func (feb *FakeEventBroadcaster) StartLogging(logf func(format string, args ...interface{})) watch.Interface {
	return nil
}

func (feb *FakeEventBroadcaster) NewRecorder(scheme *runtime.Scheme, source v1.EventSource) record.EventRecorder {
	return &feb.EventRecorder
}

// record.EventRecorder interface methods
func (fer *FakeEventRecorder) Event(obj runtime.Object, eventType, reason, message string) {
	ev := NewFakeEvent(obj, eventType, reason, message)
	fer.FEvent = append(fer.FEvent, ev)
}

func (fer *FakeEventRecorder) Eventf(obj runtime.Object, eventType, reason, messageFmt string, args ...interface{}) {
	ev := NewFakeEvent(obj, eventType, reason, fmt.Sprintf(messageFmt, args...))
	fer.FEvent = append(fer.FEvent, ev)
}

func (fer *FakeEventRecorder) PastEventf(obj runtime.Object, timestamp metav1.Time, eventType, reason, messageFmt string, args ...interface{}) {
	ev := NewFakeEvent(obj, eventType, reason, fmt.Sprintf(messageFmt, args...)+" @ "+timestamp.String())
	fer.FEvent = append(fer.FEvent, ev)
}

func (fer *FakeEventRecorder) AnnotatedEventf(obj runtime.Object, annotations map[string]string, eventType, reason, messageFmt string, args ...interface{}) {
	ev := NewFakeEvent(obj, eventType, reason, fmt.Sprintf(messageFmt, args...))
	ev.Annotations = annotations
	fer.FEvent = append(fer.FEvent, ev)
}

// Unit tests
var _ = Describe("Event Notifier Tests", func() {
	Describe("Using Mock Manager", func() {
		var mockMgr *mockAppManager
		var mw *test.MockWriter
		var namespaces []string
		BeforeEach(func() {
			RegisterBigIPSchemaTypes()

			mw = &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			mockMgr = newMockAppManager(&Params{
				KubeClient:             fakeClient,
				restClient:             test.CreateFakeHTTPClient(),
				RouteClientV1:          fakeRouteClient.NewSimpleClientset().RouteV1(),
				IsNodePort:             true,
				ManageIngress:          true,
				broadcasterFunc:        NewFakeEventBroadcaster,
				ManageIngressClassOnly: false,
				IngressClass:           "f5",
			})
			namespaces = []string{"ns0", "ns1", "ns2", "ns3", "ns4", "ns5"}
			mockMgr.appMgr.AgentCIS, _ = agent.CreateAgent(agent.CCCLAgent)
			mockMgr.appMgr.AgentCIS.Init(&cccl.Params{ConfigWriter: mw})
			err := mockMgr.startNonLabelMode(namespaces)
			Expect(err).To(BeNil())
		})
		AfterEach(func() {
			mockMgr.shutdown()
		})
		deployIngress := func(ingNbr int) {
			svcName := "service"
			var svcPort int32 = 80

			svcPorts := []v1.ServicePort{newServicePort("port0", svcPort)}
			svc := test.NewService(svcName, "1", namespaces[ingNbr],
				v1.ServiceTypeClusterIP, svcPorts)
			r := mockMgr.addService(svc)
			Expect(r).To(BeTrue(), "Service should be processed.")

			emptyIps := []string{}
			readyIps := []string{fmt.Sprintf("10.2.96.%d", ingNbr)}
			endpts := test.NewEndpoints(svcName, "1", "node0", namespaces[ingNbr],
				readyIps, emptyIps, convertSvcPortsToEndpointPorts(svcPorts))
			r = mockMgr.addEndpoints(endpts)
			Expect(r).To(BeTrue(), "Endpoints should be processed.")

			bindAddr := fmt.Sprintf("1.0.0.%d", ingNbr)
			ing := test.NewIngress("ingress", "1", namespaces[ingNbr],
				v1beta1.IngressSpec{
					Backend: &v1beta1.IngressBackend{
						ServiceName: svcName,
						ServicePort: intstr.IntOrString{IntVal: svcPort},
					},
				},
				map[string]string{
					F5VsBindAddrAnnotation:  bindAddr,
					F5VsPartitionAnnotation: "velcro",
				},
			)
			r = mockMgr.addIngress(ing)
			Expect(r).To(BeTrue(), "Ingress resource should be processed.")
		}

		It("multiple namespace ingress", func() {
			// Deploy a Service and Ingress in each namespace
			for i, _ := range namespaces {
				deployIngress(i)
			}

			// Make sure the ingress events are in the correct namespace.
			for _, ns := range namespaces {
				events := mockMgr.getFakeEvents(ns)
				// This use case currently creates 2 events
				// (ResourceConfigured and ServiceNotFound)
				Expect(len(events)).To(Equal(2))
				for _, event := range events {
					// Regardless of length test, make sure all events match ns.
					Expect(event.Namespace).To(Equal(ns))
				}
			}
		})
	})
})
