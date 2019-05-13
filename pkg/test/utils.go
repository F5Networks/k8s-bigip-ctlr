/*-
 * Copyright (c) 2017,2018,2019 F5 Networks, Inc.
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

package test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/pollers"

	routeapi "github.com/openshift/origin/pkg/route/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest/fake"
)

const (
	ImmediateFail = iota
	AsyncFail
	Timeout
	Success
)

type MockWriter struct {
	FailStyle    int
	WrittenTimes int
	Sections     map[string]interface{}
	File         string
	sync.Mutex
}

func (mw *MockWriter) GetOutputFilename() string {
	// Returns the File field if one exists, otherwise returns "mock-file"
	if len(mw.File) > 0 {
		return mw.File
	} else {
		return "mock-file"
	}
}

func (mw *MockWriter) Stop() {
}

func (mw *MockWriter) SendSection(
	name string,
	obj interface{},
) (<-chan struct{}, <-chan error, error) {
	mw.Lock()
	defer mw.Unlock()

	doneCh := make(chan struct{})
	errCh := make(chan error)

	mw.WrittenTimes++

	mw.Sections[name] = obj

	switch mw.FailStyle {
	case ImmediateFail:
		return nil, nil, fmt.Errorf("immediate test error")
	case AsyncFail:
		go func() {
			errCh <- fmt.Errorf("async test error")
		}()
	case Timeout:
		<-time.After(2 * time.Second)
	case Success:
		go func() {
			doneCh <- struct{}{}
		}()
	}

	return doneCh, errCh, nil
}

type MockPoller struct {
	FailStyle int
}

func (mp *MockPoller) Run() error {
	return nil
}

func (mp *MockPoller) Stop() error {
	return nil
}

func (mp *MockPoller) RegisterListener(p pollers.PollListener) error {
	switch mp.FailStyle {
	case ImmediateFail:
		return fmt.Errorf("immediate test error")
	case Success:
		return nil
	}
	return nil
}

// NewConfigMap returns a new configmap object
func NewConfigMap(id, rv, namespace string,
	keys map[string]string) *v1.ConfigMap {
	return &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
			Annotations:     make(map[string]string),
		},
		Data: keys,
	}
}

// NewIngress returns a new ingress object
func NewIngress(id, rv, namespace string,
	spec v1beta1.IngressSpec,
	annotations map[string]string) *v1beta1.Ingress {
	return &v1beta1.Ingress{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Ingress",
			APIVersion: "extensions/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
			Annotations:     annotations,
		},
		Spec: spec,
	}
}

// NewRoute returns a new route object
func NewRoute(
	id,
	rv,
	namespace string,
	spec routeapi.RouteSpec,
	annotations map[string]string,
) *routeapi.Route {
	return &routeapi.Route{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Route",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
			Annotations:     annotations,
		},
		Spec: spec,
	}
}

// NewNode returns a new node object
func NewNode(
	id string,
	rv string,
	unsched bool,
	addresses []v1.NodeAddress,
	taints []v1.Taint,
) *v1.Node {
	return &v1.Node{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
		},
		Spec: v1.NodeSpec{
			Unschedulable: unsched,
			Taints:        taints,
		},
		Status: v1.NodeStatus{
			Addresses: addresses,
		},
	}
}

// NewService returns a service
func NewService(id, rv, namespace string, serviceType v1.ServiceType,
	portSpecList []v1.ServicePort) *v1.Service {
	return &v1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
		},
		Spec: v1.ServiceSpec{
			Type:  serviceType,
			Ports: portSpecList,
		},
	}
}

//NewEndpoints returns an endpoints objects
func NewEndpoints(
	svcName,
	rv,
	node,
	namespace string,
	readyIps,
	notReadyIps []string,
	ports []v1.EndpointPort,
) *v1.Endpoints {
	ep := &v1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            svcName,
			Namespace:       namespace,
			ResourceVersion: rv,
		},
		Subsets: []v1.EndpointSubset{},
	}

	if 0 < len(readyIps) {
		ep.Subsets = append(
			ep.Subsets,
			v1.EndpointSubset{
				Addresses:         newEndpointAddress(readyIps, node),
				NotReadyAddresses: newEndpointAddress(notReadyIps, node),
				Ports:             ports,
			},
		)
	}

	return ep
}

func newEndpointAddress(ips []string, node string) []v1.EndpointAddress {
	eps := make([]v1.EndpointAddress, len(ips))
	for i, v := range ips {
		eps[i].IP = v
		eps[i].NodeName = &node
	}
	return eps
}

// CreateFakeHTTPClient returns a fake RESTClient which also satisfies rest.Interface
func CreateFakeHTTPClient() *fake.RESTClient {
	fakeClient := &fake.RESTClient{
		APIRegistry:          api.Registry,
		NegotiatedSerializer: &fakeNegotiatedSerializer{},
		Resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
		},
		Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			header := http.Header{}
			header.Set("Content-Type", runtime.ContentTypeJSON)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     header,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			}, nil
		}),
	}
	return fakeClient
}

// // Below here is all used to mock the client calls
type fakeNegotiatedSerializer struct{}

func (fns *fakeNegotiatedSerializer) SupportedMediaTypes() []runtime.SerializerInfo {
	info := runtime.SerializerInfo{
		MediaType:        runtime.ContentTypeJSON,
		EncodesAsText:    true,
		Serializer:       nil,
		PrettySerializer: nil,
		StreamSerializer: &runtime.StreamSerializerInfo{
			EncodesAsText: true,
			Serializer:    &fakeDecoder{IsWatching: true},
			Framer:        &fakeFrame{},
		},
	}
	return []runtime.SerializerInfo{info}
}

func (fns *fakeNegotiatedSerializer) EncoderForVersion(
	serializer runtime.Encoder,
	gv runtime.GroupVersioner,
) runtime.Encoder {
	return nil
}

func (fns *fakeNegotiatedSerializer) DecoderToVersion(
	serializer runtime.Decoder,
	gv runtime.GroupVersioner,
) runtime.Decoder {
	return &fakeDecoder{}
}

type fakeDecoder struct {
	IsWatching bool
}

func (fd *fakeDecoder) Decode(
	data []byte,
	defaults *schema.GroupVersionKind,
	into runtime.Object,
) (runtime.Object, *schema.GroupVersionKind, error) {
	if fd.IsWatching {
		return nil, nil, io.EOF
	}
	return &v1.ConfigMapList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMapList",
			APIVersion: "v1",
		},
		ListMeta: metav1.ListMeta{
			SelfLink:        "/api/v1/namespaces/potato/configmaps",
			ResourceVersion: "1403005",
		},
		Items: []v1.ConfigMap{},
	}, nil, nil
}

func (fd *fakeDecoder) Encode(obj runtime.Object, w io.Writer) error {
	return nil
}

type fakeFrame struct{}

func (ff *fakeFrame) NewFrameReader(r io.ReadCloser) io.ReadCloser {
	return r
}
func (ff *fakeFrame) NewFrameWriter(w io.Writer) io.Writer {
	return w
}

func NewNamespace(name, rv string, labels map[string]string) *v1.Namespace {
	ns := &v1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: rv,
			Labels:          labels,
		},
	}
	return ns
}
