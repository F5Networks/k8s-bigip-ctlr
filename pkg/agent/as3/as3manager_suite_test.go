package as3_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestAS3(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AS3 Suite")
}
