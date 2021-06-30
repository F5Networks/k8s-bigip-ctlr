package crmanager

import (
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sync"
)

var _ = Describe("Python Driver Tests", func() {
	It("Initialize", func() {
		cw := &test.MockWriter{
			FailStyle:    test.Success,
			WrittenTimes: 0,
			Sections:     make(map[string]interface{}),
			File:         "",
			Mutex:        sync.Mutex{},
		}

		err := initializeDriverConfig(
			cw,
			globalSection{GTM: true},
			bigIPSection{},
			gtmBigIPSection{},
		)
		Expect(err).To(BeNil(), "Failed to Initialize Python Driver")

		// Negative Cases
		err = initializeDriverConfig(
			nil,
			globalSection{GTM: true},
			bigIPSection{},
			gtmBigIPSection{},
		)
		Expect(err).NotTo(BeNil(), "Failed to Validate Initializaton of Python Driver")

		cw.FailStyle = test.ImmediateFail
		err = initializeDriverConfig(
			cw,
			globalSection{GTM: true},
			bigIPSection{},
			gtmBigIPSection{},
		)
		Expect(err).NotTo(BeNil(), "Failed to Validate Initializaton of Python Driver")

		cw.FailStyle = test.AsyncFail
		err = initializeDriverConfig(
			cw,
			globalSection{GTM: true},
			bigIPSection{},
			gtmBigIPSection{},
		)
		Expect(err).NotTo(BeNil(), "Failed to Validate Initializaton of Python Driver")

		cw.FailStyle = test.Timeout
		err = initializeDriverConfig(
			cw,
			globalSection{GTM: true},
			bigIPSection{},
			gtmBigIPSection{},
		)
		Expect(err).To(BeNil(), "Failed to Validate Initializaton of Python Driver")

	})

	It("Command", func() {
		cmd := createDriverCmd("python", "bigipconfigdriver.py")
		Expect(cmd).NotTo(BeNil(), "Failed to create Command")

		cmd = createDriverCmd("python", "configdriver.py")
		Expect(cmd).NotTo(BeNil(), "Failed to create Command")

	})

})
