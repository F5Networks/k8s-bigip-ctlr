package pollers_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestPollers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pollers Suite")
}
