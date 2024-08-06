// +gocover:ignore:file test utils
/*-
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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
	routeapi "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
			Name:              id,
			ResourceVersion:   rv,
			Namespace:         namespace,
			Annotations:       annotations,
			CreationTimestamp: metav1.Now(),
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
	conditions []v1.NodeCondition,
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
			Addresses:  addresses,
			Conditions: conditions,
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

// NewEndpoints returns an endpoints objects
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

// NewSecret returns a service
func NewSecret(name, namespace, cert, key string) *v1.Secret {
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"tls.crt": []byte(cert),
			"tls.key": []byte(key),
		},
	}
}

// NewPod return a pod
func NewPod(name, namespace string, podport int, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Ports: []v1.ContainerPort{
						{
							ContainerPort: int32(podport),
						},
					},
				},
			},
		},
	}
}

// NewService returns a service
func NewServicewithselectors(id, rv, namespace string, selector map[string]string, serviceType v1.ServiceType,
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
			Type:     serviceType,
			Ports:    portSpecList,
			Selector: selector,
		},
	}
}
