package crmanager

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCustomResource(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CR Manager Suite")
}
