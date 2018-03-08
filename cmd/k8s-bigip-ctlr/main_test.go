/*-
 * Copyright (c) 2017,2018, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"

	"k8s.io/client-go/kubernetes/fake"
)

type MockOut struct{}

func (mo MockOut) Write(p []byte) (n int, err error) {
	return
}

var _ = Describe("Main Tests", func() {
	Describe("Main Tests", func() {
		It("sets up the config", func() {
			configWriter := &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}

			type ConfigTest struct {
				Global globalSection `json:"global"`
				BigIP  bigIPSection  `json:"bigip"`
			}

			expected := ConfigTest{
				BigIP: bigIPSection{
					BigIPUsername: "colonel atari",
					BigIPPassword: "dexter",
					BigIPURL:      "https://bigip.example.com",
					BigIPPartitions: []string{
						"k8s",
						"openshift",
						"marathon",
					},
				},
				Global: globalSection{
					LogLevel:       "WARNING",
					VerifyInterval: 10101,
				},
			}

			err := initializeDriverConfig(nil, expected.Global, expected.BigIP)
			Expect(err).ToNot(BeNil())

			err = initializeDriverConfig(
				configWriter,
				expected.Global,
				expected.BigIP,
			)
			Expect(err).To(BeNil())

			configWriter.Lock()
			Expect(configWriter.Sections).To(HaveKey("bigip"))
			Expect(configWriter.Sections).To(HaveKey("global"))

			actual := ConfigTest{
				configWriter.Sections["global"].(globalSection),
				configWriter.Sections["bigip"].(bigIPSection),
			}
			configWriter.Unlock()

			Expect(actual).To(Equal(expected))

			// test error states
			configWriter = &test.MockWriter{
				FailStyle: test.ImmediateFail,
				Sections:  make(map[string]interface{}),
			}
			err = initializeDriverConfig(
				configWriter,
				expected.Global,
				expected.BigIP,
			)
			Expect(err).ToNot(BeNil())

			configWriter = &test.MockWriter{
				FailStyle: test.AsyncFail,
				Sections:  make(map[string]interface{}),
			}
			err = initializeDriverConfig(
				configWriter,
				expected.Global,
				expected.BigIP,
			)
			Expect(err).ToNot(BeNil())
			// This will not error out but does print to the logs so verify the correct
			// number of calls we expect to the writer
			configWriter = &test.MockWriter{
				FailStyle: test.Timeout,
				Sections:  make(map[string]interface{}),
			}
			err = initializeDriverConfig(
				configWriter,
				expected.Global,
				expected.BigIP,
			)
			Expect(err).To(BeNil())
			Expect(configWriter.WrittenTimes).To(Equal(2))
		})

		It("sets up the driver command", func() {
			pyDriver := "bigipconfigdriver.py"
			configFile := fmt.Sprintf("/tmp/k8s-bigip-ctlr.config.%d.json",
				os.Getpid())
			driverPath, err := exec.LookPath("bigipconfigdriver.py")
			Expect(err).To(BeNil(), "We should find the driver.")

			args := []string{
				pyDriver,
				"--config-file", configFile,
				"--ctlr-prefix", "k8s",
			}
			cmd := createDriverCmd(
				configFile,
				pyDriver,
			)

			Expect(cmd.Path).To(Equal(driverPath))
			Expect(cmd.Args).To(Equal(args))

			pyDriver = "/path/to/python/bigipconfigdriver.py"
			pythonPath, err := exec.LookPath("python")
			Expect(err).To(BeNil(), "We should find the driver.")

			args = []string{
				"python",
				pyDriver,
				"--config-file", configFile,
				"--ctlr-prefix", "k8s",
			}
			cmd = createDriverCmd(
				configFile,
				pyDriver,
			)

			Expect(cmd.Path).To(Equal(pythonPath))
			Expect(cmd.Args).To(Equal(args))
		})

		It("verifies cli arguments", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin"}

			nameVar := []string{"testing"}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).To(BeNil())
			Expect(*namespaces).To(Equal(nameVar))
			Expect(*bigIPURL).To(Equal("https://bigip.example.com"))
			Expect(*bigIPUsername).To(Equal("admin"))
			Expect(*bigIPPassword).To(Equal("admin"))
			Expect(*bigIPPartitions).To(Equal([]string{"velcro1", "velcro2"}))
			Expect(*logLevel).To(Equal("INFO"))

			// Test url variations
			os.Args[5] = "--bigip-url=fail://bigip.example.com"
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil(), "BIGIP-URL should fail with incorrect scheme 'fail://'.")

			os.Args[5] = "--bigip-url=https://bigip.example.com/some/path"
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil(), "BIGIP-URL should fail with invalid path.")

			// Test empty required args
			allArgs := map[string]*string{
				"bigipUrl":      bigIPURL,
				"bigipUsername": bigIPUsername,
				"bigipPassword": bigIPPassword,
				"logLevel":      logLevel,
			}

			for argName, arg := range allArgs {
				holder := *arg
				*arg = ""
				argError = verifyArgs()
				Expect(argError).ToNot(BeNil(), fmt.Sprintf(
					"Argument %s is required, and should not allow an empty string.", argName))
				*arg = holder
			}

			// Test bigIPPartitions seperatly as it's a string array
			holder := *bigIPPartitions
			*bigIPPartitions = []string{}
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil(),
				"Argument bigIPPartitions is required, and should not allow an empty string.")
			*bigIPPartitions = holder

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=cluster",
			}

			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).To(BeNil())
			Expect(isNodePort).To(BeFalse())

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=invalid",
			}

			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())
			Expect(isNodePort).To(BeFalse())
		})

		It("verifies args labels", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=cluster",
				"--openshift-sdn-name=vxlan500",
				"--namespace=testing",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())
			Expect(watchAllNamespaces).To(BeFalse())

			// No namespace or label sets watchAllNamespaces to true
			var ns []string
			*namespaces = ns
			err = verifyArgs()
			Expect(err).To(BeNil())
			Expect(watchAllNamespaces).To(BeTrue())

			*namespaceLabel = "addLabel"
			err = verifyArgs()
			Expect(err).To(BeNil())
			Expect(watchAllNamespaces).To(BeFalse())

			// Fail case, can only specify a namespace or label, not both
			ns = []string{"fail"}
			*namespaces = ns
			err = verifyArgs()
			Expect(err).ToNot(BeNil())
		})

		It("verifies SDN args", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=cluster",
				"--openshift-sdn-name=vxlan500",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			*openshiftSDNName = ""
			err = verifyArgs()
			Expect(err).ToNot(BeNil())
		})

		It("sets up the node poller", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=nodeport",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			fake := fake.NewSimpleClientset()
			Expect(fake).ToNot(BeNil(), "Mock client cannot be nil.")

			configWriter := &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			Expect(configWriter).ToNot(BeNil(), "Mock writer cannot be nil.")

			nodePoller := &test.MockPoller{
				FailStyle: test.Success,
			}
			Expect(nodePoller).ToNot(BeNil(), "Mock poller cannot be nil.")

			vsm := appmanager.NewManager(&appmanager.Params{
				KubeClient:   fake,
				ConfigWriter: configWriter,
				IsNodePort:   true,
			})
			err = setupNodePolling(vsm, nodePoller, nil, nil)
			Expect(err).To(BeNil())

			nodePoller = &test.MockPoller{
				FailStyle: test.ImmediateFail,
			}
			Expect(nodePoller).ToNot(BeNil(), "Mock poller cannot be nil.")

			err = setupNodePolling(vsm, nodePoller, nil, nil)
			Expect(err).ToNot(BeNil())
		})

		It("sets up node poller - Cluster", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=cluster",
				"--openshift-sdn-name=vxlan500",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			fakeClient := fake.NewSimpleClientset()
			Expect(fakeClient).ToNot(BeNil(), "Mock client cannot be nil.")

			configWriter := &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			Expect(configWriter).ToNot(BeNil(), "Mock writer cannot be nil.")
			// Success case
			nodePoller := &test.MockPoller{
				FailStyle: test.Success,
			}
			Expect(nodePoller).ToNot(BeNil(), "Mock poller cannot be nil.")

			vsm := appmanager.NewManager(&appmanager.Params{
				KubeClient:   fakeClient,
				ConfigWriter: configWriter,
			})
			err = setupNodePolling(vsm, nodePoller, nil, nil)
			Expect(err).To(BeNil())
			// Fail case from config writer
			nodePoller = &test.MockPoller{
				FailStyle: test.ImmediateFail,
			}
			Expect(nodePoller).ToNot(BeNil(), "Mock poller cannot be nil.")

			err = setupNodePolling(vsm, nodePoller, nil, nil)
			Expect(err).ToNot(BeNil())
			// Fail case from NewOpenshiftSDNMgr
			vxlanName = ""
			nodePoller = &test.MockPoller{
				FailStyle: test.Success,
			}
			Expect(nodePoller).ToNot(BeNil(), "Mock poller cannot be nil.")

			err = setupNodePolling(vsm, nodePoller, nil, nil)
			Expect(err).ToNot(BeNil())
		})

		It("handles vxlan flags", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			Expect(len(vxlanMode)).To(Equal(0), "Mode variable should not be set.")
			Expect(len(*openshiftSDNName)).To(Equal(0),
				"Openshift sdn name variable should not be set.")
			Expect(len(*flannelName)).To(Equal(0), "Flannel name variable should not be set.")

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--openshift-sdn-name=vxlan500",
				"--pool-member-type=cluster",
			}

			flags.Parse(os.Args)
			err = verifyArgs()
			Expect(err).To(BeNil())

			Expect(vxlanMode).To(Equal("maintain"))
			Expect(*openshiftSDNName).To(Equal("vxlan500"))

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--openshift-sdn-name=vxlan500",
				"--flannel-name=vxlan500",
			}

			flags.Parse(os.Args)
			err = verifyArgs()
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal("Cannot have both openshift-sdn-name and flannel-name specified."))
		})

		It("handles empty vxlan flags", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--openshift-sdn-name",
			}

			var called bool
			oldUsage := flags.Usage
			defer func() {
				flags.Usage = oldUsage
			}()
			flags.Usage = func() {
				called = true
			}

			flags.SetOutput(MockOut{})
			defer flags.SetOutput(os.Stderr)

			err := flags.Parse(os.Args)
			Expect(err).ToNot(BeNil())
			Expect(called).To(BeTrue())
			Expect(len(*openshiftSDNName)).To(Equal(0))
		})

		It("sets up watches for all namespaces", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			vsm := appmanager.NewManager(&appmanager.Params{
				KubeClient: fake.NewSimpleClientset(),
			})

			namespaces := vsm.GetWatchedNamespaces()
			Expect(len(namespaces)).To(Equal(0))
			setupWatchers(vsm, 0)
			namespaces = vsm.GetWatchedNamespaces()
			Expect(len(namespaces)).To(Equal(1))
			Expect(namespaces[0]).To(Equal(""))
		})

		It("sets up watchers for multiple namespaces", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--namespace=default",
				"--namespace=test",
				"--namespace=test2",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			vsm := appmanager.NewManager(&appmanager.Params{
				KubeClient: fake.NewSimpleClientset(),
			})

			namespaces := vsm.GetWatchedNamespaces()
			Expect(len(namespaces)).To(Equal(0))
			setupWatchers(vsm, 0)
			namespaces = vsm.GetWatchedNamespaces()
			Expect(len(namespaces)).To(Equal(3))
			sort.Strings(namespaces)
			Expect(namespaces[0]).To(Equal("default"))
			Expect(namespaces[1]).To(Equal("test"))
			Expect(namespaces[2]).To(Equal("test2"))
		})

		It("sets up watches for labels", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--namespace-label=prod",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())

			vsm := appmanager.NewManager(&appmanager.Params{
				KubeClient: fake.NewSimpleClientset(),
			})

			namespaces := vsm.GetWatchedNamespaces()
			Expect(len(namespaces)).To(Equal(0))
			setupWatchers(vsm, 0)
			namespaces = vsm.GetWatchedNamespaces()
			Expect(len(namespaces)).To(Equal(0))
			nsInf := vsm.GetNamespaceLabelInformer()
			Expect(nsInf).ToNot(BeNil())
		})
	})

	Describe("Mock driver subprocess tests", func() {
		var pid int
		BeforeEach(func() {
			configWriter := &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
			}
			gs := globalSection{
				LogLevel:       "INFO",
				VerifyInterval: 30,
				VXLANPartition: "Common",
			}
			bs := bigIPSection{
				BigIPUsername:   "admin",
				BigIPPassword:   "admin",
				BigIPURL:        "url",
				BigIPPartitions: []string{},
			}
			subPidCh, _ := startPythonDriver(configWriter, gs, bs, "test")
			pid = <-subPidCh

		})
		AfterEach(func() {
			killDriverCmd := exec.Command("kill", []string{"-2", strconv.Itoa(pid)}...)
			Start(killDriverCmd, GinkgoWriter, GinkgoWriter)
		})
		It("runs the driver subprocess", func() {

			Expect(pid).ToNot(Equal(0), "Pid should be set and not nil value.")

			proc, err := os.FindProcess(pid)
			Expect(err).To(BeNil())
			Expect(proc).ToNot(BeNil(), "Should have process object.")

			cmd := exec.Command("bash", []string{"test/testBigipconfigdriver.sh"}...)
			session, _ := Start(cmd, GinkgoWriter, GinkgoWriter)
			Eventually(session, 30*time.Second).Should(Exit(0))
		})
	})
})
