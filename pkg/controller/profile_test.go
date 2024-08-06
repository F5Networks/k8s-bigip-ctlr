package controller

import (
	cisapiv1 "github.com/F5Networks/k8s-bigip-ctlr/v3/config/apis/cis/v1"
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
		mockCtlr.managedResources.ManageCustomResources = true
		mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher = cisapiv1.TLSCipher{
			TLSVersion: "1.2",
		}

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

		err, updated := mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Client SSL")

		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Client SSL")

		secret.Data["tls.crt"] = []byte("dfaf")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Update Client SSL")
		Expect(updated).To(BeTrue(), "Failed to Update Client SSL")

		// Negative Cases
		delete(secret.Data, "tls.crt")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).ToNot(BeNil(), "Failed to Validate Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Client SSL")

		delete(secret.Data, "tls.key")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
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
		err, updated := mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Server SSL")

		err, updated = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Server SSL")

		secret.Data["tls.crt"] = []byte("dfaf")
		err, updated = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Update Server SSL")
		Expect(updated).To(BeTrue(), "Failed to Update Server SSL")

		// Negative Cases
		delete(secret.Data, "tls.crt")
		err, updated = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).ToNot(BeNil(), "Failed to Validate Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Server SSL")

	})

})
