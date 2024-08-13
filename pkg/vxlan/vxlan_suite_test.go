package vxlan_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestVxlan(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Vxlan Suite")
}
