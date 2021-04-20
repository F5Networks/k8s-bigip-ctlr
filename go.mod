module github.com/F5Networks/k8s-bigip-ctlr

go 1.15

require (
	github.com/F5Networks/f5-ipam-controller v0.1.2-0.20210416093847-f0eeef5171d9
	github.com/miekg/dns v1.0.14
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.4
	github.com/openshift/api v0.0.0-20210315202829-4b79815405ec
	github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47
	github.com/prometheus/client_golang v1.7.1
	github.com/spf13/pflag v1.0.5
	github.com/xeipuuv/gojsonpointer v0.0.0-20151027082146-e0fe6f683076 // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20150808065054-e02fc20de94c // indirect
	github.com/xeipuuv/gojsonschema v0.0.0-20190108114628-f971f3cd73b2
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	k8s.io/api v0.20.4
	k8s.io/apiextensions-apiserver v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
	k8s.io/klog/v2 v2.4.0
)
