package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestK8sBigipCtlr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "K8sBigipCtlr Suite")
}
