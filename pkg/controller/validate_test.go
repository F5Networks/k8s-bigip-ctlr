package controller

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"

	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
)

var _ = Describe("Validation Tests", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.multiClusterConfigs = NewClusterHandler()
	})

	Describe("Validating ExtendedServiceReference", func() {
		BeforeEach(func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			clusterConfigs := make(map[string]*ClusterConfig)
			clusterConfigs["cluster1"] = &ClusterConfig{}
			clusterConfigs["cluster2"] = &ClusterConfig{}
			mockCtlr.multiClusterConfigs = &ClusterHandler{
				ClusterConfigs:    clusterConfigs,
				HAPairClusterName: "cluster2",
				LocalClusterName:  "cluster1",
			}
		})

		It("Validating ExtendedServiceReference in non multiCluster mode", func() {
			mockCtlr.multiClusterMode = ""
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				SvcName:     "svc1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
				ClusterName: "cluster1",
			}, true)).Error().To(Equal(fmt.Errorf("CIS is not running in multiCluster mode")))
		})

		It("Validating ExtendedServiceReference for missing parameters", func() {
			// Check for missing cluster name
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				SvcName:     "svc1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(Equal(fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")))
			// Check for missing service name
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(Equal(fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")))
			// Check for missing ServicePort
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster1",
				Namespace:   "namespace1",
				SvcName:     "svc1",
			}, true)).Error().To(Equal(fmt.Errorf("some of the mandatory parameters (clusterName/namespace/service/servicePort) are missing")))
		})

		It("Validating ExtendedServiceReference running in HA and non-HA cluster", func() {
			// Service running in cluster3 which is not defined in extended configmap
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster3",
				SvcName:     "svc1",
				Namespace:   "namespace1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(Equal(fmt.Errorf("cluster config for the cluster cluster3 is not provided in extended configmap")))
			// Service running in non HA cluster
			mockCtlr.multiClusterConfigs.ClusterConfigs["cluster3"] = &ClusterConfig{}
			Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
				ClusterName: "cluster3",
				Namespace:   "namespace1",
				SvcName:     "svc1",
				ServicePort: intstr.IntOrString{IntVal: 80},
			}, true)).Error().To(BeNil())
			//// Service running in primary cluster
			//Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
			//	ClusterName: "cluster1",
			//	SvcName:     "svc1",
			//	Namespace:   "namespace1",
			//	ServicePort: intstr.IntOrString{IntVal: 80},
			//}, true)).Error().To(Equal(fmt.Errorf("service is running in HA cluster, currently CIS doesn't support services running in " +
			//	"HA clusters to be defined in checkValidMultiClusterService")))
			// Service running in secondary cluster
			//Expect(mockCtlr.checkValidMultiClusterService(cisapiv1.MultiClusterServiceReference{
			//	ClusterName: "cluster2",
			//	SvcName:     "svc1",
			//	Namespace:   "namespace1",
			//	ServicePort: intstr.IntOrString{IntVal: 80},
			//}, true)).Error().To(Equal(fmt.Errorf("service is running in HA cluster, currently CIS doesn't support services running in " +
			//	"HA clusters to be defined in extendedServiceReference")))
		})
	})
})
