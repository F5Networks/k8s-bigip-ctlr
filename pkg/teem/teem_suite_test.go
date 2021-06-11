package teem_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTeem(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Teem Suite")
}
