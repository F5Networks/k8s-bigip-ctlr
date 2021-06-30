package crmanager

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Profile", func() {
	var mockCRM *mockCRManager
	BeforeEach(func() {
		mockCRM = newMockCRManager()
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
			customProfiles: CustomProfileStore{
				Profs: make(map[SecretKey]CustomProfile),
			},
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

		err, updated := mockCRM.createSecretClientSSLProfile(rsCfg, secret, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Client SSL")

		err, updated = mockCRM.createSecretClientSSLProfile(rsCfg, secret, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Client SSL")

		secret.Data["tls.crt"] = []byte("dfaf")
		err, updated = mockCRM.createSecretClientSSLProfile(rsCfg, secret, "clientside")
		Expect(err).To(BeNil(), "Failed to Update Client SSL")
		Expect(updated).To(BeTrue(), "Failed to Update Client SSL")

		// Negative Cases
		delete(secret.Data, "tls.crt")
		err, updated = mockCRM.createSecretClientSSLProfile(rsCfg, secret, "clientside")
		Expect(err).ToNot(BeNil(), "Failed to Validate Client SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Client SSL")

		delete(secret.Data, "tls.key")
		err, updated = mockCRM.createSecretClientSSLProfile(rsCfg, secret, "clientside")
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
			customProfiles: CustomProfileStore{
				Profs: make(map[SecretKey]CustomProfile),
			},
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

		err, updated := mockCRM.createSecretServerSSLProfile(rsCfg, secret, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Server SSL")

		err, updated = mockCRM.createSecretServerSSLProfile(rsCfg, secret, "clientside")
		Expect(err).To(BeNil(), "Failed to Create Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Create Server SSL")

		secret.Data["tls.crt"] = []byte("dfaf")
		err, updated = mockCRM.createSecretServerSSLProfile(rsCfg, secret, "clientside")
		Expect(err).To(BeNil(), "Failed to Update Server SSL")
		Expect(updated).To(BeTrue(), "Failed to Update Server SSL")

		// Negative Cases
		delete(secret.Data, "tls.crt")
		err, updated = mockCRM.createSecretServerSSLProfile(rsCfg, secret, "clientside")
		Expect(err).ToNot(BeNil(), "Failed to Validate Server SSL")
		Expect(updated).To(BeFalse(), "Failed to Validate Server SSL")

	})

})
