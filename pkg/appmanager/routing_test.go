/*-
 * Copyright (c) 2017,2018, F5 Networks, Inc.
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

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Routing Tests", func() {
	It("orders routes", func() {
		mw := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}

		fakeClient := fake.NewSimpleClientset()
		Expect(fakeClient).ToNot(BeNil(), "Mock client should not be nil.")

		appMgr := newMockAppManager(&Params{
			KubeClient:    fakeClient,
			ConfigWriter:  mw,
			restClient:    test.CreateFakeHTTPClient(),
			RouteClientV1: test.CreateFakeHTTPClient(),
			IsNodePort:    true,
			ManageIngress: true,
		})
		err := appMgr.startNonLabelMode([]string{"test"})
		Expect(err).To(BeNil())
		defer appMgr.shutdown()

		namespace := "test"
		type testData struct {
			serviceName string
			hostName    string
			path        string
		}
		sortedTestData := []testData{
			{
				serviceName: "bar",
				hostName:    "barfoo.com",
				path:        "/bar",
			}, {
				serviceName: "foo",
				hostName:    "foobar.com",
				path:        "/foo",
			}, {
				serviceName: "foo",
				hostName:    "foobar.com",
				path:        "/foo/bar",
			}, {
				serviceName: "foo",
				hostName:    "foobar.com",
				path:        "/foo/bar/bay",
			}, {
				serviceName: "foo",
				hostName:    "foobar.com",
				path:        "/foo/bar/baz",
			},
		}

		unsortedTestData := []testData{
			sortedTestData[4],
			sortedTestData[1],
			sortedTestData[0],
			sortedTestData[3],
			sortedTestData[2],
		}

		for i, td := range unsortedTestData {
			routeName := fmt.Sprintf("route%d", i)
			spec := routeapi.RouteSpec{
				Host: td.hostName,
				Path: td.path,
				To: routeapi.RouteTargetReference{
					Kind: "Service",
					Name: td.serviceName,
				},
				TLS: &routeapi.TLSConfig{
					Termination: routeapi.TLSTerminationEdge,
				},
			}
			ok := appMgr.addRoute(test.NewRoute(routeName, "1", namespace, spec, nil))
			Expect(ok).To(BeTrue(), "Route resource should be processed.")
		}

		appInf, _ := appMgr.appMgr.getNamespaceInformer(namespace)
		routes, err := appInf.getOrderedRoutes(namespace)
		Expect(err).To(BeNil())
		Expect(len(routes)).To(Equal(len(sortedTestData)))
		for i, route := range routes {
			Expect(route.Spec.Host).To(Equal(sortedTestData[i].hostName))
			Expect(route.Spec.Path).To(Equal(sortedTestData[i].path))
		}
	})
})
