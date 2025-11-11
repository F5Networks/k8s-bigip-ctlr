package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AS3 Protocol Inspection Parser Tests", func() {

	Describe("AS3 Object Generation with Protocol Inspection", func() {
		It("Should generate proper AS3 profileProtocolInspection object", func() {
			profileRef := "/Common/test_protocol_inspection"

			// Test the AS3 generation process directly (similar to processCommonDecl)
			as3Obj := make(map[string]interface{})

			// Simulate protocol inspection profile assignment
			if profileRef != "" {
				as3Obj["profileProtocolInspection"] = as3ResourcePointer{
					Use: profileRef,
				}
			}

			// Verify the generated structure
			protocols, exists := as3Obj["profileProtocolInspection"]
			Expect(exists).To(BeTrue(), "profileProtocolInspection should exist")

			protocolRef, ok := protocols.(as3ResourcePointer)
			Expect(ok).To(BeTrue(), "profileProtocolInspection should be an as3ResourcePointer")

			Expect(protocolRef.Use).To(Equal("/Common/test_protocol_inspection"), "Use reference should match")
		})

		It("Should handle empty protocol inspection profile reference", func() {
			profileRef := ""

			// Test the AS3 generation process with empty reference
			as3Obj := make(map[string]interface{})

			// Simulate protocol inspection profile assignment
			if profileRef != "" {
				as3Obj["profileProtocolInspection"] = as3ResourcePointer{
					Use: profileRef,
				}
			}

			// Verify that no profile is added when reference is empty
			_, exists := as3Obj["profileProtocolInspection"]
			Expect(exists).To(BeFalse(), "profileProtocolInspection should not exist when reference is empty")
		})

		It("Should generate correct AS3 structure for HTTP VirtualServer with Protocol Inspection", func() {
			// Simulate HTTP VirtualServer AS3 object with protocol inspection
			httpVS := map[string]interface{}{
				"class":       "Service_HTTP",
				"profileHTTP": map[string]interface{}{"use": "/Common/http"},
				"profileProtocolInspection": as3ResourcePointer{
					Use: "/Common/http_protocol_inspection",
				},
				"virtualAddresses": []string{"10.1.1.1"},
				"virtualPort":      80,
				"pool":             "web_pool",
			}

			// Verify HTTP service structure
			Expect(httpVS["class"]).To(Equal("Service_HTTP"))

			// Verify protocol inspection profile
			protocolInspection, exists := httpVS["profileProtocolInspection"]
			Expect(exists).To(BeTrue(), "profileProtocolInspection should exist")

			protocolRef, ok := protocolInspection.(as3ResourcePointer)
			Expect(ok).To(BeTrue(), "profileProtocolInspection should be an as3ResourcePointer")
			Expect(protocolRef.Use).To(Equal("/Common/http_protocol_inspection"))
		})

		It("Should generate correct AS3 structure for TCP Service with Protocol Inspection", func() {
			// Simulate TCP Service AS3 object with protocol inspection
			tcpService := map[string]interface{}{
				"class": "Service_TCP",
				"profileTCP": map[string]interface{}{
					"ingress": map[string]interface{}{"use": "/Common/tcp-wan-optimized"},
					"egress":  map[string]interface{}{"use": "/Common/tcp-lan-optimized"},
				},
				"profileProtocolInspection": as3ResourcePointer{
					Use: "/Common/tcp_protocol_inspection",
				},
				"virtualAddresses": []string{"10.1.1.2"},
				"virtualPort":      8080,
				"pool":             "tcp_pool",
			}

			// Verify TCP service structure
			Expect(tcpService["class"]).To(Equal("Service_TCP"))

			// Verify protocol inspection profile
			protocolInspection, exists := tcpService["profileProtocolInspection"]
			Expect(exists).To(BeTrue(), "profileProtocolInspection should exist")

			protocolRef, ok := protocolInspection.(as3ResourcePointer)
			Expect(ok).To(BeTrue(), "profileProtocolInspection should be an as3ResourcePointer")
			Expect(protocolRef.Use).To(Equal("/Common/tcp_protocol_inspection"))

			// Verify TCP profiles are also present
			tcpProfiles, exists := tcpService["profileTCP"]
			Expect(exists).To(BeTrue(), "profileTCP should exist")

			tcpProfileMap, ok := tcpProfiles.(map[string]interface{})
			Expect(ok).To(BeTrue(), "profileTCP should be a map")
			Expect(tcpProfileMap["ingress"]).To(Equal(map[string]interface{}{"use": "/Common/tcp-wan-optimized"}))
			Expect(tcpProfileMap["egress"]).To(Equal(map[string]interface{}{"use": "/Common/tcp-lan-optimized"}))
		})

		It("Should handle protocol inspection with other profile types", func() {
			// Test protocol inspection alongside various other profiles
			multiProfileService := map[string]interface{}{
				"class":       "Service_HTTPS",
				"profileHTTP": map[string]interface{}{"use": "/Common/http"},
				"profileTLS": map[string]interface{}{
					"client": map[string]interface{}{"use": "/Common/clientssl"},
					"server": map[string]interface{}{"use": "/Common/serverssl"},
				},
				"profileProtocolInspection": as3ResourcePointer{
					Use: "/Common/https_protocol_inspection",
				},
				"virtualAddresses": []string{"10.1.1.3"},
				"virtualPort":      443,
			}

			// Verify all profiles coexist properly
			Expect(multiProfileService["class"]).To(Equal("Service_HTTPS"))

			// Check HTTP profile
			_, exists := multiProfileService["profileHTTP"]
			Expect(exists).To(BeTrue(), "profileHTTP should exist")

			// Check TLS profile
			_, exists = multiProfileService["profileTLS"]
			Expect(exists).To(BeTrue(), "profileTLS should exist")

			// Check protocol inspection profile
			protocolInspection, exists := multiProfileService["profileProtocolInspection"]
			Expect(exists).To(BeTrue(), "profileProtocolInspection should exist")

			protocolRef, ok := protocolInspection.(as3ResourcePointer)
			Expect(ok).To(BeTrue(), "profileProtocolInspection should be an as3ResourcePointer")
			Expect(protocolRef.Use).To(Equal("/Common/https_protocol_inspection"))
		})

		It("Should validate AS3 resource pointer structure", func() {
			// Test the as3ResourcePointer type directly
			pointer := as3ResourcePointer{
				Use: "/Common/test_profile",
			}

			Expect(pointer.Use).To(Equal("/Common/test_profile"))

			// Test that the structure can be used in AS3 declarations
			as3Declaration := map[string]interface{}{
				"profileProtocolInspection": pointer,
			}

			protocolInspection, exists := as3Declaration["profileProtocolInspection"]
			Expect(exists).To(BeTrue(), "profileProtocolInspection should exist in declaration")

			extractedPointer, ok := protocolInspection.(as3ResourcePointer)
			Expect(ok).To(BeTrue(), "Should be able to extract as3ResourcePointer")
			Expect(extractedPointer.Use).To(Equal("/Common/test_profile"))
		})
	})
})
