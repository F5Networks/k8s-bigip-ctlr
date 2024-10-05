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

	It("Client SSL Multiple Secrets", func() {
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

		secret1 := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "SampleSecret1",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.key": []byte("key1"),
				"tls.crt": []byte("cert1"),
			},
		}

		secret2 := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "SampleSecret2",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.key": []byte("key2"),
				"tls.crt": []byte("cert2"),
			},
		}

		secrets := []*v1.Secret{secret1}
		tlsCipher := mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher

		err, updated := mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Client SSL with first secret")
		Expect(updated).To(BeFalse(), "Expected no update for first Client SSL creation")

		secrets = []*v1.Secret{secret2}
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Client SSL with second secret")
		Expect(updated).To(BeFalse(), "Expected no update for second Client SSL creation")

		secret2.Data["tls.crt"] = []byte("newcert2")
		err, updated = mockCtlr.createSecretClientSSLProfile(rsCfg, secrets, tlsCipher, "clientside")
		Expect(err).To(BeNil(), "Failed to Update Client SSL with modified second secret")
		Expect(updated).To(BeTrue(), "Expected update for modified second Client SSL")

	})

	It("Server SSL with empty secrets list", func() {
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

		var secrets []*v1.Secret
		tlsCipher := mockCtlr.resources.supplementContextCache.baseRouteConfig.TLSCipher

		Expect(func() {
			_, _ = mockCtlr.createSecretServerSSLProfile(rsCfg, secrets, tlsCipher, "serverside")
		}).To(Panic(), "Expected panic due to empty secrets list")
	})
})
