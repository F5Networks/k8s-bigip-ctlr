package statusmanager

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestK8sBigipCtlr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "StatusManager Suite")
}
