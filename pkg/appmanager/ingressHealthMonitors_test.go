/*-
 * Copyright (c) 2016,2017, F5 Networks, Inc.
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
	"testing"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/record"
)

func checkSingleServiceHealthMonitor(
	t *testing.T,
	rc *ResourceConfig,
	svcName string,
	svcPort int,
	expectSuccess bool,
) {
	require := require.New(t)
	assert := assert.New(t)

	require.True(len(rc.Pools) > 0)
	poolNdx := -1
	for i, pool := range rc.Pools {
		if pool.Partition == rc.Virtual.Partition &&
			pool.ServiceName == svcName &&
			pool.ServicePort == int32(svcPort) {
			poolNdx = i
		}
	}
	require.NotEqual(-1, poolNdx)
	monitorFound := false
	if expectSuccess {
		require.Equal(1, len(rc.Pools[poolNdx].MonitorNames))
		partition, monitorName := splitBigipPath(
			rc.Pools[poolNdx].MonitorNames[0], false)
		for _, monitor := range rc.Monitors {
			if monitor.Partition == partition && monitor.Name == monitorName {
				monitorFound = true
			}
		}
		assert.True(monitorFound)
	} else {
		require.Equal(0, len(rc.Pools[poolNdx].MonitorNames))
		partition := rc.Pools[poolNdx].Name
		poolName := rc.Pools[poolNdx].Name
		for _, monitor := range rc.Monitors {
			if monitor.Partition == partition && monitor.Name == poolName {
				monitorFound = true
			}
		}
		assert.False(monitorFound)
	}
}

func TestSingleServiceIngressHealthCheck(t *testing.T) {
	mw := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	require := require.New(t)
	assert := assert.New(t)
	fakeClient := fake.NewSimpleClientset()
	fakeRecorder := record.NewFakeRecorder(100)
	require.NotNil(fakeClient, "Mock client should not be nil")
	require.NotNil(fakeRecorder, "Mock recorder should not be nil")
	namespace := "default"

	appMgr := newMockAppManager(&Params{
		KubeClient:    fakeClient,
		ConfigWriter:  mw,
		restClient:    test.CreateFakeHTTPClient(),
		IsNodePort:    false,
		EventRecorder: fakeRecorder,
	})
	err := appMgr.startNonLabelMode([]string{namespace})
	require.Nil(err)
	defer appMgr.shutdown()

	svcName := "svc1"
	svcPort := 8080
	spec := v1beta1.IngressSpec{
		Backend: &v1beta1.IngressBackend{
			ServiceName: svcName,
			ServicePort: intstr.FromInt(svcPort),
		},
	}
	ing := test.NewIngress("ingress", "1", namespace, spec,
		map[string]string{
			"virtual-server.f5.com/ip":        "1.2.3.4",
			"virtual-server.f5.com/partition": "velcro",
			"virtual-server.f5.com/http-port": "443",
			"virtual-server.f5.com/health": `[
				{
					"path":     "svc1/",
					"send":     "HTTP GET /test1",
					"interval": 5,
					"timeout":  10
				}
			]`,
		})
	emptyIps := []string{}
	svcKey := serviceKey{
		Namespace:   namespace,
		ServiceName: svcName,
		ServicePort: int32(svcPort),
	}

	svcPorts := []v1.ServicePort{newServicePort(svcName, int32(svcPort))}
	fooSvc := test.NewService(svcName, "1", namespace, v1.ServiceTypeClusterIP,
		svcPorts)
	readyIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endpts := test.NewEndpoints(svcName, "1", namespace, readyIps, emptyIps,
		convertSvcPortsToEndpointPorts(svcPorts))

	r := appMgr.addIngress(ing)
	assert.True(r, "Ingress resource should be processed")

	r = appMgr.addService(fooSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts)
	assert.True(r, "Endpoints should be processed")
	resources := appMgr.resources()
	assert.Equal(1, resources.Count())

	// The first test uses an explicit server name
	assert.Equal(1, resources.CountOf(svcKey))
	vsCfgFoo, found := resources.Get(svcKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)
	checkSingleServiceHealthMonitor(t, vsCfgFoo, svcName, svcPort, true)

	// The second test uses a wildcard host name
	ing.ObjectMeta.Annotations[ingHealthMonitorAnnotation] = `[
		{
			"path":     "*/foo",
			"send":     "HTTP GET /test2",
			"interval": 5,
			"timeout":  10
		}]`
	r = appMgr.updateIngress(ing)
	assert.True(r, "Ingress resource should be processed")
	assert.Equal(1, resources.CountOf(svcKey))
	vsCfgFoo, found = resources.Get(svcKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)
	checkSingleServiceHealthMonitor(t, vsCfgFoo, svcName, svcPort, true)

	// The third test omits the host part of the path
	ing.ObjectMeta.Annotations[ingHealthMonitorAnnotation] = `[
		{
			"path":     "/",
			"send":     "HTTP GET /test3",
			"interval": 5,
			"timeout":  10
		}]`
	r = appMgr.updateIngress(ing)
	assert.True(r, "Ingress resource should be processed")
	assert.Equal(1, resources.CountOf(svcKey))
	vsCfgFoo, found = resources.Get(svcKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)
	checkSingleServiceHealthMonitor(t, vsCfgFoo, svcName, svcPort, true)

	// The fourth test omits the path entirely (error case)
	ing.ObjectMeta.Annotations[ingHealthMonitorAnnotation] = `[
		{
			"send":     "HTTP GET /test3",
			"interval": 5,
			"timeout":  10
		}]`
	r = appMgr.updateIngress(ing)
	assert.True(r, "Ingress resource should be processed")
	assert.Equal(1, resources.CountOf(svcKey))
	vsCfgFoo, found = resources.Get(svcKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)
	checkSingleServiceHealthMonitor(t, vsCfgFoo, svcName, svcPort, false)
}

func checkMultiServiceHealthMonitor(
	t *testing.T,
	rc *ResourceConfig,
	svcName string,
	svcPort int,
	expectSuccess bool,
) {
	require := require.New(t)
	assert := assert.New(t)

	require.True(len(rc.Policies) > 0)
	require.True(len(rc.Pools) > 0)
	policyNdx := -1
	for i, pol := range rc.Policies {
		if pol.Name == rc.Virtual.VirtualServerName &&
			pol.Partition == rc.Virtual.Partition {
			policyNdx = i
			break
		}
	}
	require.NotEqual(-1, policyNdx)

	poolNdx := -1
	for i, pool := range rc.Pools {
		if pool.Partition == rc.Virtual.Partition &&
			pool.ServiceName == svcName &&
			pool.ServicePort == int32(svcPort) {
			poolNdx = i
		}
	}
	require.NotEqual(-1, poolNdx)
	fullPoolName := joinBigipPath(
		rc.Pools[poolNdx].Partition, rc.Pools[poolNdx].Name)
	actionFound := false
	for _, rule := range rc.Policies[policyNdx].Rules {
		for _, action := range rule.Actions {
			if action.Pool == fullPoolName {
				actionFound = true
				assert.True(action.Forward)
				assert.Equal(fullPoolName, action.Pool)
			}
		}
	}
	assert.True(actionFound)

	monitorFound := false
	if expectSuccess {
		require.Equal(1, len(rc.Pools[poolNdx].MonitorNames))
		partition, monitorName := splitBigipPath(
			rc.Pools[poolNdx].MonitorNames[0], false)
		for _, monitor := range rc.Monitors {
			if monitor.Partition == partition && monitor.Name == monitorName {
				monitorFound = true
			}
		}
		assert.True(monitorFound)
	} else {
		require.Equal(0, len(rc.Pools[poolNdx].MonitorNames))
		partition := rc.Pools[poolNdx].Name
		poolName := rc.Pools[poolNdx].Name
		for _, monitor := range rc.Monitors {
			if monitor.Partition == partition && monitor.Name == poolName {
				monitorFound = true
			}
		}
		assert.False(monitorFound)
	}
}

func TestMultiServiceIngressHealthCheck(t *testing.T) {
	mw := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	require := require.New(t)
	assert := assert.New(t)
	fakeClient := fake.NewSimpleClientset()
	fakeRecorder := record.NewFakeRecorder(100)
	require.NotNil(fakeClient, "Mock client should not be nil")
	require.NotNil(fakeRecorder, "Mock recorder should not be nil")
	namespace := "default"

	appMgr := newMockAppManager(&Params{
		KubeClient:    fakeClient,
		ConfigWriter:  mw,
		restClient:    test.CreateFakeHTTPClient(),
		IsNodePort:    false,
		EventRecorder: fakeRecorder,
	})
	err := appMgr.startNonLabelMode([]string{namespace})
	require.Nil(err)
	defer appMgr.shutdown()

	host1Name := "svc1.bar.com"
	svc1Name := "svc1"
	svc1Port := 8080
	svc1Path := "/foo"
	host2Name := "svc2.bar.com"
	svc2Name := "svc2"
	svc2Port := 9090
	svc2Path := "/bar"
	svc3Name := "svc3"
	svc3Port := 8888
	svc3Path := "/baz"
	spec := v1beta1.IngressSpec{
		Rules: []v1beta1.IngressRule{
			{
				Host: host1Name,
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Path: svc1Path,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc1Name,
									ServicePort: intstr.FromInt(svc1Port),
								},
							},
						},
					},
				},
			}, {
				Host: host2Name,
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Path: svc2Path,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc2Name,
									ServicePort: intstr.FromInt(svc2Port),
								},
							}, {
								Path: svc3Path,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc3Name,
									ServicePort: intstr.FromInt(svc3Port),
								},
							},
						},
					},
				},
			},
		},
	}
	ing := test.NewIngress("ingress", "1", namespace, spec,
		map[string]string{
			ingressSslRedirect:                "true",
			"virtual-server.f5.com/ip":        "1.2.3.4",
			"virtual-server.f5.com/partition": "velcro",
			"virtual-server.f5.com/http-port": "443",
			"virtual-server.f5.com/health": `[
				{
					"path":     "svc2.bar.com/bar",
					"send":     "HTTP GET /health/bar",
					"interval": 5,
					"timeout":  5
				}, {
					"path":     "svc2.bar.com/baz",
					"send":     "HTTP GET /health/baz",
					"interval": 5,
					"timeout":  5
				}, {
					"path":     "svc1.bar.com/foo",
					"send":     "HTTP GET /health/foo",
					"interval": 5,
					"timeout":  10
				}
			]`,
		})
	emptyIps := []string{}

	svc1Ports := []v1.ServicePort{newServicePort(svc1Name, int32(svc1Port))}
	fooSvc := test.NewService(svc1Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc1Ports)
	ready1Ips := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endpts1 := test.NewEndpoints(svc1Name, "1", namespace, ready1Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc1Ports))

	r := appMgr.addIngress(ing)
	assert.True(r, "Ingress resource should be processed")

	r = appMgr.addService(fooSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts1)
	assert.True(r, "Endpoints should be processed")
	resources := appMgr.resources()
	assert.Equal(1, resources.Count())

	svc1Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc1Name,
		ServicePort: int32(svc1Port),
	}
	assert.Equal(1, resources.CountOf(svc1Key))
	vsCfgFoo, found := resources.Get(svc1Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)

	svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
	barSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc2Ports)
	ready2Ips := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
	endpts2 := test.NewEndpoints(svc2Name, "1", namespace, ready2Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc2Ports))

	r = appMgr.addService(barSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts2)
	assert.True(r, "Endpoints should be processed")
	assert.Equal(2, resources.Count())

	svc2Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc2Name,
		ServicePort: int32(svc2Port),
	}
	assert.Equal(1, resources.CountOf(svc2Key))
	vsCfgBar, found := resources.Get(svc2Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBar)

	svc3Ports := []v1.ServicePort{newServicePort(svc3Name, int32(svc3Port))}
	bazSvc := test.NewService(svc3Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc3Ports)
	ready3Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
	endpts3 := test.NewEndpoints(svc3Name, "1", namespace, ready3Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc3Ports))

	r = appMgr.addService(bazSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts3)
	assert.True(r, "Endpoints should be processed")
	assert.Equal(3, resources.Count())

	svc3Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc3Name,
		ServicePort: int32(svc3Port),
	}
	assert.Equal(1, resources.CountOf(svc3Key))
	vsCfgBaz, found := resources.Get(svc3Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBaz)

	checkMultiServiceHealthMonitor(t, vsCfgFoo, svc1Name, svc1Port, true)
	checkMultiServiceHealthMonitor(t, vsCfgBar, svc2Name, svc2Port, true)
	checkMultiServiceHealthMonitor(t, vsCfgBaz, svc3Name, svc3Port, true)
}

func TestMultiServiceIngressNoPathHealthCheck(t *testing.T) {
	mw := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	require := require.New(t)
	assert := assert.New(t)
	fakeClient := fake.NewSimpleClientset()
	fakeRecorder := record.NewFakeRecorder(100)
	require.NotNil(fakeClient, "Mock client should not be nil")
	require.NotNil(fakeRecorder, "Mock recorder should not be nil")
	namespace := "default"

	appMgr := newMockAppManager(&Params{
		KubeClient:    fakeClient,
		ConfigWriter:  mw,
		restClient:    test.CreateFakeHTTPClient(),
		IsNodePort:    false,
		EventRecorder: fakeRecorder,
	})
	err := appMgr.startNonLabelMode([]string{namespace})
	require.Nil(err)
	defer appMgr.shutdown()

	host1Name := "foo.bar.com"
	svc1aName := "nginx"
	svc1aPort := 80
	svc1aPath := "/foo"
	svc1bName := "nginx2"
	svc1bPort := 80
	svc1bPath := "/bar"
	host2Name := "bar.foo.com"
	svc2Name := "nginx3"
	svc2Port := 80
	spec := v1beta1.IngressSpec{
		Rules: []v1beta1.IngressRule{
			{
				Host: host1Name,
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Path: svc1aPath,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc1aName,
									ServicePort: intstr.FromInt(svc1aPort),
								},
							}, {
								Path: svc1bPath,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc1bName,
									ServicePort: intstr.FromInt(svc1bPort),
								},
							},
						},
					},
				},
			}, {
				Host: host2Name,
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Backend: v1beta1.IngressBackend{
									ServiceName: svc2Name,
									ServicePort: intstr.FromInt(svc2Port),
								},
							},
						},
					},
				},
			},
		},
	}
	ing := test.NewIngress("ingress", "1", namespace, spec,
		map[string]string{
			"virtual-server.f5.com/ip":        "172.16.3.2",
			"virtual-server.f5.com/partition": "velcro",
			"virtual-server.f5.com/health": `[
				{
					"path":     "foo.bar.com/foo",
					"send":     "HTTP GET /health/foo",
					"interval": 5,
					"timeout":  10
				}, {
					"path":     "foo.bar.com/bar",
					"send":     "HTTP GET /health/bar",
					"interval": 5,
					"timeout":  10
				}, {
					"path":     "bar.foo.com/",
					"send":     "HTTP GET /health",
					"interval": 5,
					"timeout":  10
				}
			]`,
		})
	emptyIps := []string{}

	svc1aPorts := []v1.ServicePort{newServicePort(svc1aName, int32(svc1aPort))}
	fooSvc := test.NewService(svc1aName, "1", namespace, v1.ServiceTypeClusterIP,
		svc1aPorts)
	ready1aIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endpts1a := test.NewEndpoints(svc1aName, "1", namespace, ready1aIps, emptyIps,
		convertSvcPortsToEndpointPorts(svc1aPorts))

	r := appMgr.addService(fooSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts1a)
	assert.True(r, "Endpoints should be processed")

	svc1bPorts := []v1.ServicePort{newServicePort(svc1bName, int32(svc1bPort))}
	barSvc := test.NewService(svc1bName, "1", namespace, v1.ServiceTypeClusterIP,
		svc1bPorts)
	ready1bIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
	endpts1b := test.NewEndpoints(svc1bName, "1", namespace, ready1bIps, emptyIps,
		convertSvcPortsToEndpointPorts(svc1bPorts))

	r = appMgr.addService(barSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts1b)
	assert.True(r, "Endpoints should be processed")

	svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
	bazSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc2Ports)
	ready2Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
	endpts2 := test.NewEndpoints(svc2Name, "1", namespace, ready2Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc2Ports))

	r = appMgr.addService(bazSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts2)
	assert.True(r, "Endpoints should be processed")

	r = appMgr.addIngress(ing)
	assert.True(r, "Ingress resource should be processed")

	resources := appMgr.resources()
	assert.Equal(3, resources.Count())

	svc1aKey := serviceKey{
		Namespace:   namespace,
		ServiceName: svc1aName,
		ServicePort: int32(svc1aPort),
	}
	assert.Equal(1, resources.CountOf(svc1aKey))
	vsCfgFoo, found := resources.Get(svc1aKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)

	svc1bKey := serviceKey{
		Namespace:   namespace,
		ServiceName: svc1bName,
		ServicePort: int32(svc1bPort),
	}
	assert.Equal(1, resources.CountOf(svc1bKey))
	vsCfgBar, found := resources.Get(svc1bKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBar)

	svc2Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc2Name,
		ServicePort: int32(svc2Port),
	}
	assert.Equal(1, resources.CountOf(svc2Key))
	vsCfgBaz, found := resources.Get(svc2Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBaz)

	checkMultiServiceHealthMonitor(t, vsCfgFoo, svc1aName, svc1aPort, true)
	checkMultiServiceHealthMonitor(t, vsCfgBar, svc1bName, svc1bPort, true)
	checkMultiServiceHealthMonitor(t, vsCfgBaz, svc2Name, svc2Port, true)
}

func TestMultiServiceIngressOneHealthCheck(t *testing.T) {
	mw := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	require := require.New(t)
	assert := assert.New(t)
	fakeClient := fake.NewSimpleClientset()
	fakeRecorder := record.NewFakeRecorder(100)
	require.NotNil(fakeClient, "Mock client should not be nil")
	require.NotNil(fakeRecorder, "Mock recorder should not be nil")
	namespace := "default"

	appMgr := newMockAppManager(&Params{
		KubeClient:    fakeClient,
		ConfigWriter:  mw,
		restClient:    test.CreateFakeHTTPClient(),
		IsNodePort:    false,
		EventRecorder: fakeRecorder,
	})
	err := appMgr.startNonLabelMode([]string{namespace})
	require.Nil(err)
	defer appMgr.shutdown()

	host1Name := "foo.bar.com"
	svc1aName := "nginx"
	svc1aPort := 80
	svc1aPath := "/foo"
	svc1bName := "nginx2"
	svc1bPort := 80
	svc1bPath := "/bar"
	host2Name := "svc2.bar.com"
	svc2Name := "nginx3"
	svc2Port := 80
	spec := v1beta1.IngressSpec{
		Rules: []v1beta1.IngressRule{
			{
				Host: host1Name,
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Path: svc1aPath,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc1aName,
									ServicePort: intstr.FromInt(svc1aPort),
								},
							}, {
								Path: svc1bPath,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc1bName,
									ServicePort: intstr.FromInt(svc1bPort),
								},
							},
						},
					},
				},
			}, {
				Host: host2Name,
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Backend: v1beta1.IngressBackend{
									ServiceName: svc2Name,
									ServicePort: intstr.FromInt(svc2Port),
								},
							},
						},
					},
				},
			},
		},
	}
	ing := test.NewIngress("ingress", "1", namespace, spec,
		map[string]string{
			ingressSslRedirect:                "true",
			"virtual-server.f5.com/ip":        "1.2.3.4",
			"virtual-server.f5.com/partition": "velcro",
			"virtual-server.f5.com/http-port": "443",
			"virtual-server.f5.com/health": `[
				{
					"path":     "foo.bar.com/foo",
					"send":     "HTTP GET /health/foo",
					"interval": 5,
					"timeout":  5
				}
			]`,
		})
	emptyIps := []string{}

	svc1aPorts := []v1.ServicePort{newServicePort(svc1aName, int32(svc1aPort))}
	fooSvc := test.NewService(svc1aName, "1", namespace, v1.ServiceTypeClusterIP,
		svc1aPorts)
	ready1aIps := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endpts1a := test.NewEndpoints(svc1aName, "1", namespace, ready1aIps, emptyIps,
		convertSvcPortsToEndpointPorts(svc1aPorts))

	r := appMgr.addIngress(ing)
	assert.True(r, "Ingress resource should be processed")

	r = appMgr.addService(fooSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts1a)
	assert.True(r, "Endpoints should be processed")
	resources := appMgr.resources()
	assert.Equal(1, resources.Count())

	svc1aKey := serviceKey{
		Namespace:   namespace,
		ServiceName: svc1aName,
		ServicePort: int32(svc1aPort),
	}
	assert.Equal(1, resources.CountOf(svc1aKey))
	vsCfgFoo, found := resources.Get(svc1aKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)

	svc1bPorts := []v1.ServicePort{newServicePort(svc1bName, int32(svc1bPort))}
	barSvc := test.NewService(svc1bName, "1", namespace, v1.ServiceTypeClusterIP,
		svc1bPorts)
	ready1bIps := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
	endpts1b := test.NewEndpoints(svc1bName, "1", namespace, ready1bIps, emptyIps,
		convertSvcPortsToEndpointPorts(svc1bPorts))

	r = appMgr.addService(barSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts1b)
	assert.True(r, "Endpoints should be processed")
	assert.Equal(2, resources.Count())

	svc1bKey := serviceKey{
		Namespace:   namespace,
		ServiceName: svc1bName,
		ServicePort: int32(svc1bPort),
	}
	assert.Equal(1, resources.CountOf(svc1bKey))
	vsCfgBar, found := resources.Get(svc1bKey, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBar)

	svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
	bazSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc2Ports)
	ready2Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
	endpts2 := test.NewEndpoints(svc2Name, "1", namespace, ready2Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc2Ports))

	r = appMgr.addService(bazSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts2)
	assert.True(r, "Endpoints should be processed")
	assert.Equal(3, resources.Count())

	svc2Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc2Name,
		ServicePort: int32(svc2Port),
	}
	assert.Equal(1, resources.CountOf(svc2Key))
	vsCfgBaz, found := resources.Get(svc2Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBaz)

	checkMultiServiceHealthMonitor(t, vsCfgFoo, svc1aName, svc1aPort, true)
	checkMultiServiceHealthMonitor(t, vsCfgBar, svc1bName, svc1bPort, false)
	checkMultiServiceHealthMonitor(t, vsCfgBaz, svc2Name, svc2Port, false)
}

func TestMultiServiceIngressHealthCheckNoHost(t *testing.T) {
	mw := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}
	require := require.New(t)
	assert := assert.New(t)
	fakeClient := fake.NewSimpleClientset()
	fakeRecorder := record.NewFakeRecorder(100)
	require.NotNil(fakeClient, "Mock client should not be nil")
	require.NotNil(fakeRecorder, "Mock recorder should not be nil")
	namespace := "default"

	appMgr := newMockAppManager(&Params{
		KubeClient:    fakeClient,
		ConfigWriter:  mw,
		restClient:    test.CreateFakeHTTPClient(),
		IsNodePort:    false,
		EventRecorder: fakeRecorder,
	})
	err := appMgr.startNonLabelMode([]string{namespace})
	require.Nil(err)
	defer appMgr.shutdown()

	svc1Name := "svc1"
	svc1Port := 8080
	svc1Path := "/foo"
	svc2Name := "svc2"
	svc2Port := 9090
	svc2Path := "/bar"
	svc3Name := "svc3"
	svc3Port := 8888
	svc3Path := "/baz"
	spec := v1beta1.IngressSpec{
		Rules: []v1beta1.IngressRule{
			{
				IngressRuleValue: v1beta1.IngressRuleValue{
					HTTP: &v1beta1.HTTPIngressRuleValue{
						Paths: []v1beta1.HTTPIngressPath{
							{
								Path: svc1Path,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc1Name,
									ServicePort: intstr.FromInt(svc1Port),
								},
							}, {
								Path: svc2Path,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc2Name,
									ServicePort: intstr.FromInt(svc2Port),
								},
							}, {
								Path: svc3Path,
								Backend: v1beta1.IngressBackend{
									ServiceName: svc3Name,
									ServicePort: intstr.FromInt(svc3Port),
								},
							},
						},
					},
				},
			},
		},
	}
	ing := test.NewIngress("ingress", "1", namespace, spec,
		map[string]string{
			ingressSslRedirect:                "true",
			"virtual-server.f5.com/ip":        "1.2.3.4",
			"virtual-server.f5.com/partition": "velcro",
			"virtual-server.f5.com/http-port": "443",
			"virtual-server.f5.com/health": `[
				{
					"path":     "*/bar",
					"send":     "HTTP GET /health/bar",
					"interval": 5,
					"timeout":  5
				}, {
					"path":     "*/baz",
					"send":     "HTTP GET /health/baz",
					"interval": 5,
					"timeout":  7
				}, {
					"path":     "*/foo",
					"send":     "HTTP GET /health/foo",
					"interval": 5,
					"timeout":  10
				}
			]`,
		})
	emptyIps := []string{}

	svc1Ports := []v1.ServicePort{newServicePort(svc1Name, int32(svc1Port))}
	fooSvc := test.NewService(svc1Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc1Ports)
	ready1Ips := []string{"10.2.96.0", "10.2.96.1", "10.2.96.2"}
	endpts1 := test.NewEndpoints(svc1Name, "1", namespace, ready1Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc1Ports))

	r := appMgr.addIngress(ing)
	assert.True(r, "Ingress resource should be processed")

	r = appMgr.addService(fooSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts1)
	assert.True(r, "Endpoints should be processed")
	resources := appMgr.resources()
	assert.Equal(1, resources.Count())

	svc1Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc1Name,
		ServicePort: int32(svc1Port),
	}
	assert.Equal(1, resources.CountOf(svc1Key))
	vsCfgFoo, found := resources.Get(svc1Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgFoo)

	svc2Ports := []v1.ServicePort{newServicePort(svc2Name, int32(svc2Port))}
	barSvc := test.NewService(svc2Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc2Ports)
	ready2Ips := []string{"10.2.96.3", "10.2.96.4", "10.2.96.5"}
	endpts2 := test.NewEndpoints(svc2Name, "1", namespace, ready2Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc2Ports))

	r = appMgr.addService(barSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts2)
	assert.True(r, "Endpoints should be processed")
	assert.Equal(2, resources.Count())

	svc2Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc2Name,
		ServicePort: int32(svc2Port),
	}
	assert.Equal(1, resources.CountOf(svc2Key))
	vsCfgBar, found := resources.Get(svc2Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBar)

	svc3Ports := []v1.ServicePort{newServicePort(svc3Name, int32(svc3Port))}
	bazSvc := test.NewService(svc3Name, "1", namespace, v1.ServiceTypeClusterIP,
		svc3Ports)
	ready3Ips := []string{"10.2.96.6", "10.2.96.7", "10.2.96.8"}
	endpts3 := test.NewEndpoints(svc3Name, "1", namespace, ready3Ips, emptyIps,
		convertSvcPortsToEndpointPorts(svc3Ports))

	r = appMgr.addService(bazSvc)
	assert.True(r, "Service should be processed")
	r = appMgr.addEndpoints(endpts3)
	assert.True(r, "Endpoints should be processed")
	assert.Equal(3, resources.Count())

	svc3Key := serviceKey{
		Namespace:   namespace,
		ServiceName: svc3Name,
		ServicePort: int32(svc3Port),
	}
	assert.Equal(1, resources.CountOf(svc3Key))
	vsCfgBaz, found := resources.Get(svc3Key, formatIngressVSName(ing, "http"))
	assert.True(found)
	require.NotNil(vsCfgBaz)

	checkMultiServiceHealthMonitor(t, vsCfgFoo, svc1Name, svc1Port, true)
	checkMultiServiceHealthMonitor(t, vsCfgBar, svc2Name, svc2Port, true)
	checkMultiServiceHealthMonitor(t, vsCfgBaz, svc3Name, svc3Port, true)
}
