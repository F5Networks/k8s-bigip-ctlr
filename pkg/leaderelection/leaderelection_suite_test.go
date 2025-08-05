package leaderelection

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLeaderElection(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Leader Election Suite")
}
