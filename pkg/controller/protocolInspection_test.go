package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v2/config/apis/cis/v1"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Protocol Inspection Tests", func() {
	var mockCtlr *mockController
	var rsCfg *ResourceConfig
	namespace := "default"

	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.multiClusterHandler = NewClusterHandler("")
		mockCtlr.multiClusterResources = newMultiClusterResourceStore()
		mockWriter := &test.MockWriter{
			FailStyle: test.Success,
			Sections:  make(map[string]interface{}),
		}
		mockCtlr.RequestHandler = newMockRequestHandler(mockWriter)
		mockCtlr.mode = CustomResourceMode
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()

		// Initialize resource config
		rsCfg = &ResourceConfig{}
		rsCfg.MetaData.ResourceType = VirtualServer
		rsCfg.Virtual.Enabled = true
		rsCfg.Virtual.Name = formatCustomVirtualServerName("TestVS", 80)
		rsCfg.IntDgMap = make(InternalDataGroupMap)
		rsCfg.IRulesMap = make(IRulesMap)
	})

	Describe("VirtualServer Protocol Inspection", func() {
		It("Should process profileProtocolInspection in VirtualServer", func() {
			vs := test.NewVirtualServer(
				"test-vs-protocol-inspection",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.example.com",
					VirtualServerAddress: "10.8.3.11",
					Profiles: cisapiv1.ProfileVSSpec{
						ProfileProtocolInspection: "/Common/protocol_inspection_profile",
					},
					Pools: []cisapiv1.VSPool{
						{
							Path:    "/",
							Service: "svc1",
							ServicePort: intstr.IntOrString{
								IntVal: 80,
							},
						},
					},
				},
			)

			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/protocol_inspection_profile"))
		})

		It("Should process TCP profiles with protocol inspection in VirtualServer", func() {
			vs := test.NewVirtualServer(
				"test-vs-tcp-protocol-inspection",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "test.example.com",
					VirtualServerAddress: "10.8.3.12",
					Profiles: cisapiv1.ProfileVSSpec{
						TCP: cisapiv1.ProfileTCP{
							Client: "/Common/tcp-client",
							Server: "/Common/tcp-server",
						},
						ProfileProtocolInspection: "/Common/protocol_inspection_profile",
					},
					Pools: []cisapiv1.VSPool{
						{
							Path:    "/",
							Service: "svc1",
							ServicePort: intstr.IntOrString{
								IntVal: 80,
							},
						},
					},
				},
			)

			err := mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to prepare Resource Config from VirtualServer")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/protocol_inspection_profile"))
			Expect(rsCfg.Virtual.TCP.Client).To(Equal("/Common/tcp-client"))
			Expect(rsCfg.Virtual.TCP.Server).To(Equal("/Common/tcp-server"))
		})
	})

	Describe("TransportServer Protocol Inspection", func() {
		BeforeEach(func() {
			// Update rsCfg for TransportServer type
			rsCfg.MetaData.ResourceType = TransportServer
		})

		It("Should process profileProtocolInspection in TransportServer", func() {
			ts := test.NewTransportServer(
				"test-ts-protocol-inspection",
				namespace,
				cisapiv1.TransportServerSpec{
					VirtualServerAddress: "10.8.3.13",
					VirtualServerPort:    8080,
					Type:                 "tcp",
					Mode:                 "standard",
					Profiles: cisapiv1.ProfileTSSpec{
						ProfileProtocolInspection: "/Common/protocol_inspection_profile",
					},
					Pool: cisapiv1.TSPool{
						Service: "tcp-svc",
						ServicePort: intstr.IntOrString{
							IntVal: 8080,
						},
					},
				},
			)

			err := mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to prepare Resource Config from TransportServer")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/protocol_inspection_profile"))
		})

		It("Should process TCP profiles with protocol inspection in TransportServer", func() {
			ts := test.NewTransportServer(
				"test-ts-tcp-protocol-inspection",
				namespace,
				cisapiv1.TransportServerSpec{
					VirtualServerAddress: "10.8.3.14",
					VirtualServerPort:    9090,
					Type:                 "tcp",
					Mode:                 "standard",
					Profiles: cisapiv1.ProfileTSSpec{
						TCP: cisapiv1.ProfileTCP{
							Client: "/Common/tcp-optimized",
							Server: "/Common/tcp-optimized",
						},
						ProfileProtocolInspection: "/Common/protocol_inspection_profile",
					},
					Pool: cisapiv1.TSPool{
						Service: "tcp-svc",
						ServicePort: intstr.IntOrString{
							IntVal: 9090,
						},
					},
				},
			)

			err := mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to prepare Resource Config from TransportServer")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/protocol_inspection_profile"))
			Expect(rsCfg.Virtual.TCP.Client).To(Equal("/Common/tcp-optimized"))
			Expect(rsCfg.Virtual.TCP.Server).To(Equal("/Common/tcp-optimized"))
		})
	})

	Describe("Policy Protocol Inspection", func() {
		It("Should apply Policy profileProtocolInspection to VirtualServer", func() {
			policy := test.NewPolicy(
				"test-policy-protocol-inspection",
				namespace,
				cisapiv1.PolicySpec{
					Profiles: cisapiv1.ProfileSpec{
						ProfileProtocolInspection: "/Common/policy_protocol_inspection",
						TCP: cisapiv1.ProfileTCP{
							Client: "/Common/policy-tcp",
							Server: "/Common/policy-tcp",
						},
					},
				},
			)

			// Test policy application to VirtualServer ResourceConfig
			err := mockCtlr.handleVSResourceConfigForPolicy(rsCfg, policy)
			Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/policy_protocol_inspection"))
			Expect(rsCfg.Virtual.TCP.Client).To(Equal("/Common/policy-tcp"))
			Expect(rsCfg.Virtual.TCP.Server).To(Equal("/Common/policy-tcp"))
		})

		It("Should apply Policy profileProtocolInspection to TransportServer", func() {
			// Update rsCfg for TransportServer type
			rsCfg.MetaData.ResourceType = TransportServer

			policy := test.NewPolicy(
				"test-policy-ts-protocol-inspection",
				namespace,
				cisapiv1.PolicySpec{
					Profiles: cisapiv1.ProfileSpec{
						ProfileProtocolInspection: "/Common/ts_policy_protocol_inspection",
					},
				},
			)

			// Test policy application to TransportServer ResourceConfig
			err := mockCtlr.handleTSResourceConfigForPolicy(rsCfg, policy)
			Expect(err).To(BeNil(), "Failed to handle TransportServer for policy")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/ts_policy_protocol_inspection"))
		})

		It("Should prioritize VirtualServer profileProtocolInspection over Policy", func() {
			// First apply policy
			policy := test.NewPolicy(
				"test-policy-override",
				namespace,
				cisapiv1.PolicySpec{
					Profiles: cisapiv1.ProfileSpec{
						ProfileProtocolInspection: "/Common/policy_protocol_inspection",
					},
				},
			)

			err := mockCtlr.handleVSResourceConfigForPolicy(rsCfg, policy)
			Expect(err).To(BeNil(), "Failed to handle VirtualServer for policy")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/policy_protocol_inspection"))

			// Then apply VirtualServer with its own profile - should override policy
			vs := test.NewVirtualServer(
				"test-vs-override-policy",
				namespace,
				cisapiv1.VirtualServerSpec{
					Host:                 "override.example.com",
					VirtualServerAddress: "10.8.3.17",
					PolicyName:           "test-policy-override",
					Profiles: cisapiv1.ProfileVSSpec{
						ProfileProtocolInspection: "/Common/vs_protocol_inspection", // Should override policy
					},
					Pools: []cisapiv1.VSPool{
						{
							Path:    "/",
							Service: "svc1",
							ServicePort: intstr.IntOrString{
								IntVal: 80,
							},
						},
					},
				},
			)

			err = mockCtlr.prepareRSConfigFromVirtualServer(rsCfg, vs, false, "")
			Expect(err).To(BeNil(), "Failed to prepare Resource Config from VirtualServer")
			// VirtualServer should take precedence over Policy
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/vs_protocol_inspection"))
		})

		It("Should prioritize TransportServer profileProtocolInspection over Policy", func() {
			// Update rsCfg for TransportServer type
			rsCfg.MetaData.ResourceType = TransportServer

			// First apply policy
			policy := test.NewPolicy(
				"test-policy-ts-override",
				namespace,
				cisapiv1.PolicySpec{
					Profiles: cisapiv1.ProfileSpec{
						ProfileProtocolInspection: "/Common/policy_protocol_inspection",
					},
				},
			)

			err := mockCtlr.handleTSResourceConfigForPolicy(rsCfg, policy)
			Expect(err).To(BeNil(), "Failed to handle TransportServer for policy")
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/policy_protocol_inspection"))

			// Then apply TransportServer with its own profile - should override policy
			ts := test.NewTransportServer(
				"test-ts-override-policy",
				namespace,
				cisapiv1.TransportServerSpec{
					VirtualServerAddress: "10.8.3.18",
					VirtualServerPort:    6060,
					Type:                 "tcp",
					Mode:                 "standard",
					PolicyName:           "test-policy-ts-override",
					Profiles: cisapiv1.ProfileTSSpec{
						ProfileProtocolInspection: "/Common/ts_protocol_inspection", // Should override policy
					},
					Pool: cisapiv1.TSPool{
						Service: "tcp-svc",
						ServicePort: intstr.IntOrString{
							IntVal: 6060,
						},
					},
				},
			)

			err = mockCtlr.prepareRSConfigFromTransportServer(rsCfg, ts)
			Expect(err).To(BeNil(), "Failed to prepare Resource Config from TransportServer")
			// TransportServer should take precedence over Policy
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/ts_protocol_inspection"))
		})
	})
})
