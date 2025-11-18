package controller

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Profile", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
		mockCtlr.resources = NewResourceStore()
		mockCtlr.multiClusterHandler = NewClusterHandler("cluster-1")
		go mockCtlr.multiClusterHandler.ResourceEventWatcher()
		// Handles the resource status updates
		go mockCtlr.multiClusterHandler.ResourceStatusUpdater()
		mockCtlr.mode = CustomResourceMode
		mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher = TLSCipher{
			"1.2",
			"",
			"",
			[]string{"1.1"}}

	})

	It("Client SSL", func() {
		rsCfg := &ResourceConfig{
			MetaData: metaData{
				ResourceType: VirtualServer,
			},
			Virtual: Virtual{
				Name:      "crd_virtual_server",
				Partition: "test",
				Profiles:  ProfileRefs{},
			},
			customProfiles: make(map[SecretKey]CustomProfile),
		}

		secret := &v1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind: Secret,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "SampleSecret",
				Namespace: "default",
			},
			Immutable:  nil,
			Data:       make(map[string][]byte),
			StringData: nil,
			Type:       "",
		}
		secret.Data["tls.key"] = []byte("fawiueh9wuan;kasjf;")
		secret.Data["tls.crt"] = []byte("ahfa;osejfn;kahse;ha")

		secrets := []*v1.Secret{secret}
		tlsCipher := mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher

		err, updated := mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).To(BeNil(), "Failed to Create Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Client SSL")

		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).To(BeNil(), "Failed to Create Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Client SSL")

		secret.Data["tls.crt"] = []byte("dfaf")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).To(BeNil(), "Failed to Update Client SSL")
		Expect(updated).To(BeTrue(), "Failed to Update Client SSL")

		// Negative Cases
		delete(secret.Data, "tls.crt")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).ToNot(BeNil(), "Failed to Validate Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Client SSL")

		delete(secret.Data, "tls.key")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).ToNot(BeNil(), "Failed to Validate Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Client SSL")

	})

	It("Server SSL", func() {
		rsCfg := &ResourceConfig{
			MetaData: metaData{
				ResourceType: VirtualServer,
			},
			Virtual: Virtual{
				Name:      "crd_virtual_server",
				Partition: "test",
				Profiles:  ProfileRefs{},
			},
			customProfiles: make(map[SecretKey]CustomProfile),
		}

		secret := &v1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind: Secret,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "SampleSecret",
				Namespace: "default",
			},
			Immutable:  nil,
			Data:       make(map[string][]byte),
			StringData: nil,
			Type:       "",
		}
		secret.Data["tls.crt"] = []byte("ahfa;osejfn;kahse;ha")
		secrets := []*v1.Secret{secret}
		tlsCipher := mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher
		renegotaiationEnabled := true
		err, updated := mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside", &renegotaiationEnabled)
		skey := SecretKey{
			Name:         fmt.Sprintf("default-%s-%s", "clientside", rsCfg.GetName()),
			ResourceName: rsCfg.GetName(),
		}
		Expect(rsCfg.customProfiles[skey].RenegotiationEnabled).To(Equal(&renegotaiationEnabled), "Failed to Update renegotiationEnabled")
		Expect(err).To(BeNil(), "Failed to Create Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Server SSL")
		err, updated = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).To(BeNil(), "Failed to Create Server SSL")
		Expect(updated).To(BeTrue(), "Failed to Create Server SSL")

		secret.Data["tls.crt"] = []byte("dfaf")
		err, updated = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).To(BeNil(), "Failed to Update Server SSL")
		Expect(updated).To(BeTrue(), "Failed to Update Server SSL")

		// Negative Cases
		delete(secret.Data, "tls.crt")
		err, updated = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside", nil)
		Expect(err).ToNot(BeNil(), "Failed to Validate Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Server SSL")

	})

	Describe("Protocol Inspection Profile Tests", func() {
		It("Should set ProfileProtocolInspection in Virtual structure", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Name = "test-vs"

			// Test setting protocol inspection profile
			profileRef := "/Common/test_protocol_inspection"
			rsCfg.Virtual.ProfileProtocolInspection = profileRef

			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal(profileRef))
		})

		It("Should handle empty ProfileProtocolInspection", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Name = "test-vs"

			// Test with empty protocol inspection profile
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal(""))
		})

		It("Should work with different profile path formats", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Name = "test-vs"

			testCases := []string{
				"/Common/protocol_inspection_profile",
				"/tenant/protocol_inspection_profile",
				"/partition/app/protocol_inspection_profile",
				"protocol_inspection_profile",
			}

			for _, profilePath := range testCases {
				rsCfg.Virtual.ProfileProtocolInspection = profilePath
				Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal(profilePath))
			}
		})

		It("Should coexist with other profiles in Virtual structure", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Name = "test-vs"

			// Set multiple profiles including protocol inspection
			rsCfg.Virtual.ProfileProtocolInspection = "/Common/protocol_inspection"
			rsCfg.Virtual.TCP.Client = "/Common/tcp-client"
			rsCfg.Virtual.TCP.Server = "/Common/tcp-server"
			rsCfg.Virtual.WAF = "/Common/waf"

			// Verify all profiles are set correctly
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/protocol_inspection"))
			Expect(rsCfg.Virtual.TCP.Client).To(Equal("/Common/tcp-client"))
			Expect(rsCfg.Virtual.TCP.Server).To(Equal("/Common/tcp-server"))
			Expect(rsCfg.Virtual.WAF).To(Equal("/Common/waf"))
		})

		It("Should validate ProfileProtocolInspection field type", func() {
			rsCfg := &ResourceConfig{}
			rsCfg.Virtual.Name = "test-vs"

			// Protocol inspection should be a string field
			var profileRef interface{} = "/Common/test_profile"
			profileStr, ok := profileRef.(string)

			Expect(ok).To(BeTrue(), "ProfileProtocolInspection should be a string type")
			Expect(profileStr).To(Equal("/Common/test_profile"))

			rsCfg.Virtual.ProfileProtocolInspection = profileStr
			Expect(rsCfg.Virtual.ProfileProtocolInspection).To(Equal("/Common/test_profile"))
		})
	})

})
