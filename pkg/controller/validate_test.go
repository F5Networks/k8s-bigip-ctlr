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
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
	})

	Describe("Validating ExtendedServiceReference", func() {
		BeforeEach(func() {
			mockCtlr.multiClusterMode = PrimaryCIS
			clusterConfigs := make(map[string]*ClusterConfig)
			clusterConfigs["cluster1"] = &ClusterConfig{}
			clusterConfigs["cluster2"] = &ClusterConfig{}
			mockCtlr.multiClusterHandler = &ClusterHandler{
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
			mockCtlr.multiClusterHandler.ClusterConfigs["cluster3"] = &ClusterConfig{}
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

	Describe("getKeysFromSet", func() {
		It("should return an empty string for an empty map", func() {
			emptyMap := map[string]struct{}{}
			Expect(getKeysFromSet(emptyMap)).To(Equal(""))
		})

		It("should return the key for a single-entry map", func() {
			singleMap := map[string]struct{}{"partition1": {}}
			Expect(getKeysFromSet(singleMap)).To(Equal("partition1"))
		})

		It("should return comma-separated keys for a multi-entry map", func() {
			// Create map with multiple entries
			multiMap := map[string]struct{}{
				"partition1": {},
				"partition2": {},
				"partition3": {},
			}

			// Get the result
			result := getKeysFromSet(multiMap)

			// Since map iteration order is non-deterministic, we need to check all keys are present
			Expect(result).To(ContainSubstring("partition1"))
			Expect(result).To(ContainSubstring("partition2"))
			Expect(result).To(ContainSubstring("partition3"))
			Expect(result).To(HaveLen(len("partition1,partition2,partition3")))
		})
	})

	Describe("validateVSPartitionAccess", func() {
		var vsResource *cisapiv1.VirtualServer

		BeforeEach(func() {
			vsResource = &cisapiv1.VirtualServer{
				Spec: cisapiv1.VirtualServerSpec{
					Partition: "test-partition",
				},
			}
			mockCtlr.deniedPartitions = make(map[string]struct{})
			mockCtlr.allowedPartitions = make(map[string]struct{})
		})

		It("should return false for nil VirtualServer", func() {
			Expect(mockCtlr.validateVSPartitionAccess(nil, false)).To(BeFalse())
		})

		It("should allow when partition is empty", func() {
			vsResource.Spec.Partition = ""
			Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeTrue())
		})

		It("should allow when no allowed/denied partitions configured", func() {
			Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeTrue())
		})

		Context("with denied partitions", func() {
			BeforeEach(func() {
				mockCtlr.deniedPartitions = map[string]struct{}{
					"denied-partition": {},
				}
			})

			It("should deny when partition is in denied list", func() {
				vsResource.Spec.Partition = "denied-partition"
				Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeFalse())
			})

			It("should allow when partition is not in denied list", func() {
				Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeTrue())
			})

			It("should not update status when deleted flag is true", func() {
				vsResource.Spec.Partition = "denied-partition"
				// We can't directly test status updates, but we can verify the function behavior
				Expect(mockCtlr.validateVSPartitionAccess(vsResource, true)).To(BeFalse())
			})
		})

		Context("with allowed partitions", func() {
			BeforeEach(func() {
				mockCtlr.allowedPartitions = map[string]struct{}{
					"allowed-partition": {},
				}
			})

			It("should allow when partition is in allowed list", func() {
				vsResource.Spec.Partition = "allowed-partition"
				Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeTrue())
			})

			It("should deny when partition is not in allowed list", func() {
				Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeFalse())
			})
		})

		Context("with both allowed and denied partitions", func() {
			BeforeEach(func() {
				mockCtlr.deniedPartitions = map[string]struct{}{
					"denied-partition": {},
					"common-partition": {},
				}
				mockCtlr.allowedPartitions = map[string]struct{}{
					"allowed-partition": {},
					"common-partition":  {},
				}
			})

			It("should prioritize denied over allowed partitions", func() {
				vsResource.Spec.Partition = "common-partition"
				Expect(mockCtlr.validateVSPartitionAccess(vsResource, false)).To(BeFalse())
			})
		})
	})
})
