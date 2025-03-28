package tokenmanager

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"testing"
)

func TestK8sBigipCtlr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TokenManagerInterface Suite")
}
