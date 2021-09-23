module github.com/F5Networks/k8s-bigip-ctlr

go 1.16

require (
	github.com/F5Networks/f5-ipam-controller v0.1.5-0.20210813064837-de4b96f0e82c
	github.com/f5devcentral/go-bigip/f5teem v0.0.0-20210918163638-28fdd0579913
	github.com/f5devcentral/mockhttpclient v0.0.0-20210630101009-cc12e8b81051
	github.com/google/uuid v1.3.0
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/miekg/dns v1.1.42
	github.com/onsi/ginkgo v1.16.2
	github.com/onsi/gomega v1.12.0
	github.com/openshift/api v0.0.0-20210315202829-4b79815405ec
	github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47
	github.com/prometheus/client_golang v1.7.1
	github.com/spf13/pflag v1.0.5
	github.com/xeipuuv/gojsonpointer v0.0.0-20151027082146-e0fe6f683076 // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20150808065054-e02fc20de94c // indirect
	github.com/xeipuuv/gojsonschema v1.1.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/mod v0.4.2
	golang.org/x/net v0.0.0-20210520170846-37e1c6afe023 // indirect
	k8s.io/api v0.21.2
	k8s.io/apiextensions-apiserver v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
	k8s.io/klog/v2 v2.9.0
)
