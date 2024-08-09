package controller

import (
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
	. "github.com/onsi/ginkgo/v2"
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

	It("Start Python Driver", func() {
		//var mockCtlr *mockController
		//mockCtlr = newMockController()
		//
		//mockCtlr.Agent = &Agent{}
		//
		//cw := &test.MockWriter{
		//	FailStyle:    test.Success,
		//	WrittenTimes: 0,
		//	Sections:     make(map[string]interface{}),
		//	File:         "",
		//	Mutex:        sync.Mutex{},
		//}
		//mockCtlr.Agent.ConfigWriter = cw
		//
		////mockCtlr.Agent.startPythonDriver(
		////	globalSection{GTM: true},
		////	bigIPSection{},
		////	gtmBigIPSection{},
		////	"/Users/k.meka/go/src/github.com/F5Networks/k8s-bigip-ctlr/cmd/k8s-bigip-ctlr/test")
		//
		//mockCtlr.Agent.PythonDriverPID = 1
		//go mockCtlr.Agent.healthCheckPythonDriver()
		//time.Sleep(1 * time.Second)
		//mockCtlr.Agent.stopPythonDriver()
	})

})
