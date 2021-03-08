module github.com/F5Networks/k8s-bigip-ctlr

go 1.15

require (
	github.com/F5Networks/f5-ipam-controller v0.1.2-0.20210308133217-973939b92f66
	github.com/evanphx/json-patch v4.2.0+incompatible // indirect
	github.com/golang/groupcache v0.0.0-20170421005642-b710c8433bd1 // indirect
	github.com/googleapis/gnostic v0.0.0-20190828010002-635450e9295f // indirect
	github.com/miekg/dns v0.0.0-20170818131442-e4205768578d
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.4
	github.com/openshift/api v3.9.1-0.20190927132434-86c3b775619d+incompatible
	github.com/openshift/client-go v0.0.0-20190923180330-3b6373338c9b
	github.com/prometheus/client_golang v0.9.2
	github.com/spf13/pflag v1.0.5
	github.com/xeipuuv/gojsonpointer v0.0.0-20151027082146-e0fe6f683076 // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20150808065054-e02fc20de94c // indirect
	github.com/xeipuuv/gojsonschema v0.0.0-20190108114628-f971f3cd73b2
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	k8s.io/api v0.16.14
	k8s.io/apiextensions-apiserver v0.16.14
	k8s.io/apimachinery v0.16.14
	k8s.io/client-go v0.16.14
)
