package appmanager_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestAppmanager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Appmanager Suite")
}
