/*-
 * Copyright (c) 2016-2018, F5 Networks, Inc.
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
	"os"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/kubernetes/fake"
)

func init() {
	workingDir, _ := os.Getwd()
	schemaUrl = "file://" + workingDir + "/../../schemas/bigip-virtual-server_v0.1.7.json"
	namespace = "default"
	DEFAULT_PARTITION = "velcro"
}

var namespace string

var _ = Describe("As3Manager Tests", func() {

	Describe("Validating AS3 ConfigMap with AS3Manager", func() {
		var mockMgr *mockAppManager
		var mw *test.MockWriter
		BeforeEach(func() {
			RegisterBigIPSchemaTypes()

			mw = &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil())

			mockMgr = newMockAppManager(&Params{
				KubeClient:       fakeClient,
				ConfigWriter:     mw,
				restClient:       test.CreateFakeHTTPClient(),
				RouteClientV1:    test.CreateFakeHTTPClient(),
				IsNodePort:       true,
				broadcasterFunc:  NewFakeEventBroadcaster,
				ManageConfigMaps: true,
			})
		})
		AfterEach(func() {
			mockMgr.shutdown()
		})

		It("ConfigMap with AS3 true flag", func() {

			cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo})
			cfgFoo.ObjectMeta.Labels = make(map[string]string)
			cfgFoo.ObjectMeta.Labels["as3"] = "true"
			r := mockMgr.appMgr.checkAs3ConfigMap(cfgFoo)
			Expect(r).To(BeFalse(), "ConfigMap with AS3 TRUE be processed.")
		})
		It("ConfigMap with AS3 flase flag", func() {

			cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo})
			cfgFoo.ObjectMeta.Labels = make(map[string]string)
			cfgFoo.ObjectMeta.Labels["as3"] = "false"
			r := mockMgr.appMgr.checkAs3ConfigMap(cfgFoo)
			Expect(r).To(BeTrue(), "ConfigMap with AS3 FALSE not be processed.")
		})
		It("ConfigMap without AS3 flag", func() {

			cfgFoo := test.NewConfigMap("foomap", "1", namespace, map[string]string{
				"schema": schemaUrl,
				"data":   configmapFoo})
			r := mockMgr.appMgr.checkAs3ConfigMap(cfgFoo)
			Expect(r).To(BeTrue(), "ConfigMap without AS3 flag not be processed.")
		})
	})
})
