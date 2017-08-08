package openshift_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestOpenshift(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Openshift Suite")
}
