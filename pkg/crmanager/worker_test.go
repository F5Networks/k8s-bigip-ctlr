/*-
 * Copyright (c) 2016-2021, F5 Networks, Inc.
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

package crmanager

import (
	"sort"
	"time"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var configPath = "../../test/configs/"

type mockCRManager struct {
	*CRManager
}

func newMockCRManager() *mockCRManager {
	return &mockCRManager{
		&CRManager{},
	}
}

func (m *mockCRManager) shutdown() error {
	return nil
}

func newServicePort(name string, svcPort int32) v1.ServicePort {
	return v1.ServicePort{
		Port: svcPort,
		Name: name,
	}
}

// NewService returns a service
func NewIngressLink(id, rv, namespace string, virtualServerAddress string, iRules []string, selector *metav1.LabelSelector) *cisapiv1.IngressLink {
	return &cisapiv1.IngressLink{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            id,
			ResourceVersion: rv,
			Namespace:       namespace,
		},
		Spec: cisapiv1.IngressLinkSpec{
			virtualServerAddress,
			selector,
			iRules,
		},
	}
}

var _ = Describe("Worker Tests", func() {
	var namespace string
	BeforeEach(func() {
		namespace = "nginx-ingress"
	})
	AfterEach(func() {
	})

	Describe("Validating Ingress link functions", func() {
		It("Validating filterIngressLinkForService filters the correct ingresslink resource", func() {
			fooPorts := []v1.ServicePort{newServicePort("port0", 8080)}
			foo := test.NewService("foo", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
			label1 := make(map[string]string)
			label2 := make(map[string]string)
			label1["app"] = "ingresslink"
			label2["app"] = "dummy"
			foo.ObjectMeta.Labels = label1
			var (
				selctor = &metav1.LabelSelector{
					MatchLabels: label1,
				}
			)
			var iRules []string
			IngressLink1 := NewIngressLink("ingresslink1", "1", namespace, "", iRules, selctor)
			IngressLink2 := NewIngressLink("ingresslink2", "1", "dummy", "", iRules, selctor)
			var IngressLinks []*cisapiv1.IngressLink
			IngressLinks = append(IngressLinks, IngressLink1, IngressLink2)
			ingresslinksForService := filterIngressLinkForService(IngressLinks, foo)
			Expect(ingresslinksForService[0]).To(Equal(IngressLink1), "Should return the Ingresslink1 object")
		})
		It("Validating service are sorted properly", func() {
			fooPorts := []v1.ServicePort{newServicePort("port0", 8080)}
			foo := test.NewService("foo", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
			bar := test.NewService("bar", "1", namespace, v1.ServiceTypeClusterIP, fooPorts)
			bar.ObjectMeta.CreationTimestamp = metav1.NewTime(time.Now())
			time.Sleep(10 * time.Millisecond)
			foo.ObjectMeta.CreationTimestamp = metav1.NewTime(time.Now())
			var services Services
			services = append(services, *foo, *bar)
			sort.Sort(services)
			Expect(services[0].Name).To(Equal("bar"), "Should return the service name as bar")
		})
	})
})
