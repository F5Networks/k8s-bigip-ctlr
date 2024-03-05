/*-
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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
	"context"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/as3"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/agent/cccl"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/appmanager"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/test"
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
	BeforeEach(func() {
		watchAllNamespaces = false
	})
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
			//driverPath, err := exec.LookPath("bigipconfigdriver.py")
			//if err != nil {
			// Set path for local runs
			//	driverPath = "bigipconfigdriver.py"
			//}

			args := []string{
				pyDriver,
				"--config-file", configFile,
				"--ctlr-prefix", "k8s",
			}
			cmd := createDriverCmd(
				configFile,
				pyDriver,
			)

			//Expect(cmd.Path).To(Equal(driverPath))
			Expect(cmd.Args).To(Equal(args))

			pyDriver = "/path/to/python/bigipconfigdriver.py"
			//pythonPath, err := exec.LookPath("./python")
			//Expect(err).To(BeNil(), "We should find the driver.")

			args = []string{
				"python3",
				pyDriver,
				"--config-file", configFile,
				"--ctlr-prefix", "k8s",
			}
			cmd = createDriverCmd(
				configFile,
				pyDriver,
			)

			//Expect(cmd.Path).To(Equal(pythonPath))
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
				"--bigip-username=admin",
				"--vs-snat-pool-name=test-snat-pool"}

			nameVar := []string{"testing"}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).To(BeNil())
			Expect(*namespaces).To(Equal(nameVar))
			Expect(*bigIPURL).To(Equal("bigip.example.com"))
			Expect(*bigIPUsername).To(Equal("admin"))
			Expect(*bigIPPassword).To(Equal("admin"))
			Expect(*bigIPPartitions).To(Equal([]string{"velcro1", "velcro2"}))
			Expect(*vsSnatPoolName).To(Equal("test-snat-pool"))
			Expect(*logLevel).To(Equal("INFO"))

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

			// Verify if bigIPPartition is Common
			os.Args = []string{
				"--bigip-partition=Common",
			}
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())

			// Invalid static route mode with nodeport mode
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=nodeport",
				"--static-routing-mode=true",
			}
			*bigIPPartitions = []string{}
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())

			// Invalid static route mode with openshiftSDNName
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--openshift-sdn-name=flannel-vxlan",
				"--static-routing-mode=true",
				"--pool-member-type=cluster",
			}
			*bigIPPartitions = []string{}
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())

			// Invalid override-as3-declaration
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--pool-member-type=cluster",
				"--override-as3-declaration=invalid",
			}
			*bigIPPartitions = []string{}
			*openshiftSDNName = ""
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())

			// Invalid controller mode
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--pool-member-type=cluster",
				"--controller-mode=invalid",
			}
			*bigIPPartitions = []string{}
			*overriderAS3CfgmapName = ""
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())

			// Invalid route spec configmap in openshift mode
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--pool-member-type=cluster",
				"--controller-mode=openshift",
				"--route-spec-configmap=invalid",
			}
			*bigIPPartitions = []string{}
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).ToNot(BeNil())

			// Valid route spec configmap in openshift mode
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--pool-member-type=cluster",
				"--controller-mode=openshift",
				"--route-spec-configmap=kube-config/ecm",
				"--route-label=systest",
			}
			*bigIPPartitions = []string{}
			*overriderAS3CfgmapName = ""
			*routeSpecConfigmap = ""
			*routeLabel = ""
			flags.Parse(os.Args)
			argError = verifyArgs()
			Expect(argError).To(BeNil())
		})

		It("verifies Common not in list of partitions", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--vs-snat-pool-name=test-snat-pool"}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).To(BeNil())
			hasCommon := hasCommonPartition(*bigIPPartitions)
			Expect(hasCommon).To(BeFalse())

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-partition=Common",
				"--bigip-partition=velcro2",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--vs-snat-pool-name=test-snat-pool"}
			flags.Parse(os.Args)
			hasCommon = hasCommonPartition(*bigIPPartitions)
			Expect(hasCommon).To(BeTrue())
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

		It("gets credentials from a file", func() {
			defer _init()
			defer os.RemoveAll("/tmp/k8s-test-creds")

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--credentials-directory=/tmp/k8s-test-creds",
				"--bigip-partition=velcro1",
				"--bigip-url=bigip.example.com",
				"--pool-member-type=nodeport",
				"--trusted-certs-cfgmap=default/foomap",
			}
			flags.Parse(os.Args)
			os.Mkdir("/tmp/k8s-test-creds", 0755)
			err := os.WriteFile("/tmp/k8s-test-creds/username", []byte("user"), 0755)
			Expect(err).ToNot(HaveOccurred())
			err = os.WriteFile("/tmp/k8s-test-creds/password", []byte("pass"), 0755)
			Expect(err).ToNot(HaveOccurred())

			err = getCredentials()
			Expect(err).ToNot(HaveOccurred())
			Expect(*bigIPURL).To(Equal("https://bigip.example.com"))
			Expect(*bigIPUsername).To(Equal("user"))
			Expect(*bigIPPassword).To(Equal("pass"))
			kubeClient = fake.NewSimpleClientset()
			cfgFoo := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foomap", Namespace: "default"}, Data: map[string]string{"data": "foo"}}
			_, err = kubeClient.CoreV1().ConfigMaps("default").Create(context.TODO(), cfgFoo, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			cfgFoo, err = getConfigMapUsingNamespaceAndName("default", "foomap")
			Expect(err).ToNot(HaveOccurred())
			Expect(cfgFoo.Data["data"]).To(Equal("foo"))
			//check for invlaid configmap
			_, err = getConfigMapUsingNamespaceAndName("default", "invalid")
			Expect(err).ToNot(BeNil())
			//check for valid bigip trusted certs
			os.Args[6] = "--trusted-certs-cfgmap=default/foomap"
			out := getBIGIPTrustedCerts()
			Expect(strings.TrimSpace(out)).To(Equal("foo"))
			//check for invalid bigip trusted certs
			os.Args[6] = "--trusted-certs-cfgmap= "
			flags.Parse(os.Args)
			out = getBIGIPTrustedCerts()
			Expect(out).To(Equal(""))
			os.Args[6] = "--trusted-certs-cfgmap=default"
			flags.Parse(os.Args)
			out = getBIGIPTrustedCerts()
			Expect(out).To(Equal(""))

			// Test url variations
			os.Args[4] = "--bigip-url=fail://bigip.example.com"
			flags.Parse(os.Args)
			err = getCredentials()
			Expect(err).ToNot(BeNil(), "BIGIP-URL should fail with incorrect scheme 'fail://'.")

			os.Args[4] = "--bigip-url=https://bigip.example.com/some/path"
			flags.Parse(os.Args)
			err = getCredentials()
			Expect(err).ToNot(BeNil(), "BIGIP-URL should fail with invalid path.")
		})

		It("uses credentials file over CLI args", func() {
			defer _init()
			defer os.RemoveAll("/tmp/k8s-test-creds")

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--credentials-directory=/tmp/k8s-test-creds",
				"--gtm-credentials-directory=/tmp/k8s-test-gtm-creds",
				"--bigip-partition=velcro1",
				"--bigip-url=bigip.example.com",
				"--bigip-username=cli-user",
				"--bigip-password=cli-pass",
				"--gtm-bigip-url=bigip1.example.com",
				"--gtm-bigip-username=cli-user-gtm",
				"--gtm-bigip-password=cli-pass-gtm",
				"--pool-member-type=nodeport",
			}
			flags.Parse(os.Args)
			os.Mkdir("/tmp/k8s-test-creds", 0755)
			err := os.WriteFile("/tmp/k8s-test-creds/username", []byte("user"), 0755)
			Expect(err).ToNot(HaveOccurred())
			err = os.WriteFile("/tmp/k8s-test-creds/password", []byte("pass"), 0755)
			Expect(err).ToNot(HaveOccurred())
			os.Mkdir("/tmp/k8s-test-gtm-creds", 0755)
			err = os.WriteFile("/tmp/k8s-test-gtm-creds/username", []byte("user-gtm"), 0755)
			Expect(err).ToNot(HaveOccurred())
			err = os.WriteFile("/tmp/k8s-test-gtm-creds/password", []byte("pass-gtm"), 0755)
			Expect(err).ToNot(HaveOccurred())

			err = getCredentials()
			Expect(err).ToNot(HaveOccurred())
			// get gtm credentials
			getGTMCredentials()
			Expect(*bigIPURL).To(Equal("https://bigip.example.com"))
			Expect(*bigIPUsername).To(Equal("user"))
			Expect(*bigIPPassword).To(Equal("pass"))
			Expect(*gtmBigIPURL).To(Equal("https://bigip1.example.com"))
			Expect(*gtmBigIPUsername).To(Equal("user-gtm"))
			Expect(*gtmBigIPPassword).To(Equal("pass-gtm"))

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
			Expect(len(*ciliumTunnelName)).To(Equal(0), "Cilium name variable should not be set.")
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
				"--cilium-name=vxlan500",
			}

			flags.Parse(os.Args)
			err = verifyArgs()
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal("Cannot have openshift-sdn-name,cilium-name specified"))
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
			defer func() {
				Expect(called).To(BeTrue())
			}()
			defer flags.SetOutput(os.Stderr)
			defer func() {
				if r := recover(); r != nil {
					return
				}
			}()
			err := flags.Parse(os.Args)
			Expect(err).ToNot(BeNil())

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
		It("Fetch parameters for CCCL", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--route-label=test2",
				"--openshift-sdn-name=vxlan500",
				"--pool-member-type=cluster",
				"--default-client-ssl=clientssl",
				"--default-server-ssl=serverssl",
				"--route-vserver-addr=192.168.1.1",
				"--agent=cccl",
				"--trusted-certs-cfgmap=default/foomap",
			}
			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())
			appManagerParams := getAppManagerParams()
			Expect(appManagerParams.RouteConfig.RouteVSAddr).To(Equal("192.168.1.1"))
			Expect(appManagerParams.RouteConfig.ServerSSL).To(Equal("serverssl"))
			Expect(appManagerParams.RouteConfig.ClientSSL).To(Equal("clientssl"))
			Expect(appManagerParams.RouteConfig.RouteLabel).To(Equal("test2"))
			Expect(appManagerParams.RouteConfig.HttpVs).To(Equal("ose-vserver"))
			Expect(appManagerParams.RouteConfig.HttpsVs).To(Equal("https-ose-vserver"))
			cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
				"key": "testkey"})
			kubeClient = fake.NewSimpleClientset(cfgFoo)
			Expect(kubeClient).ToNot(BeNil(), "Mock client cannot be nil.")
			params := getAgentParams(*agent)
			ccclParams := params.(*cccl.Params)
			Expect(ccclParams.BIGIPURL).To(Equal("bigip.example.com"))
			Expect(ccclParams.BIGIPPassword).To(Equal("admin"))
			Expect(ccclParams.BIGIPUsername).To(Equal("admin"))
			Expect(ccclParams.SSLInsecure).To(BeFalse())
			Expect(ccclParams.ConfigWriter).ToNot(BeNil())
			Expect(ccclParams.EventChan).To(BeNil())
			Expect(ccclParams.TrustedCerts).To(Equal("testkey\n"))
		})
		It("Fetch parameters for AS3", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--route-label=test2",
				"--openshift-sdn-name=vxlan500",
				"--pool-member-type=cluster",
				"--default-client-ssl=clientssl",
				"--default-server-ssl=serverssl",
				"--route-vserver-addr=192.168.1.1",
				"--trusted-certs-cfgmap=default/foomap",
			}
			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())
			appManagerParams := getAppManagerParams()
			Expect(appManagerParams.RouteConfig.RouteVSAddr).To(Equal("192.168.1.1"))
			Expect(appManagerParams.RouteConfig.ServerSSL).To(Equal("serverssl"))
			Expect(appManagerParams.RouteConfig.ClientSSL).To(Equal("clientssl"))
			Expect(appManagerParams.RouteConfig.RouteLabel).To(Equal("test2"))
			Expect(appManagerParams.RouteConfig.HttpVs).To(Equal("ose-vserver"))
			Expect(appManagerParams.RouteConfig.HttpsVs).To(Equal("https-ose-vserver"))
			cfgFoo := test.NewConfigMap("foomap", "1", "default", map[string]string{
				"key": "testkey"})
			kubeClient = fake.NewSimpleClientset(cfgFoo)
			Expect(kubeClient).ToNot(BeNil(), "Mock client cannot be nil.")
			params := getAgentParams(*agent)
			as3Params := params.(*as3.Params)
			Expect(as3Params.BIGIPURL).To(Equal("bigip.example.com"))
			Expect(as3Params.BIGIPPassword).To(Equal("admin"))
			Expect(as3Params.BIGIPUsername).To(Equal("admin"))
			Expect(as3Params.SSLInsecure).To(BeFalse())
			Expect(as3Params.ConfigWriter).ToNot(BeNil())
			Expect(as3Params.EventChan).To(BeNil())
			Expect(as3Params.TrustedCerts).To(Equal("testkey\n"))
			Expect(as3Params.EnableTLS).To(Equal("1.2"))
			Expect(as3Params.TLS13CipherGroupReference).To(Equal("/Common/f5-default"))
			Expect(as3Params.Ciphers).To(Equal("DEFAULT"))
			Expect(as3Params.AS3PostDelay).To(Equal(0))
			Expect(as3Params.PoolMemberType).To(Equal("cluster"))
		})

		It("Verify GetNamespaces", func() {
			// Get watching namespaces when both namespaces and namespaceLabel not used
			appMngr := appmanager.Manager{}
			GetNamespaces(&appMngr)
			Expect(len(appMngr.WatchedNS.Namespaces)).To(Equal(0))
			Expect(len(appMngr.WatchedNS.NamespaceLabel)).To(Equal(0))

			// Get watching namespaces when namespaces are used
			namespaces = &[]string{"ns1", "ns2"}
			GetNamespaces(&appMngr)
			Expect(len(appMngr.WatchedNS.Namespaces)).To(Equal(2))
			Expect(len(appMngr.WatchedNS.NamespaceLabel)).To(Equal(0))

			// Get watching namespaces when both namespaces and namespaceLabel are used
			appMngr = appmanager.Manager{}
			nsLabel := "env=test"
			namespaceLabel = &nsLabel
			GetNamespaces(&appMngr)
			Expect(len(appMngr.WatchedNS.Namespaces)).To(Equal(0))
			Expect(len(appMngr.WatchedNS.NamespaceLabel)).To(Equal(0))

			// Get watching namespaces when namespaceLabel is used
			namespaces = &[]string{}
			GetNamespaces(&appMngr)
			Expect(len(appMngr.WatchedNS.Namespaces)).To(Equal(0))
			Expect(len(appMngr.WatchedNS.NamespaceLabel)).NotTo(Equal(0))

		})

		It("Verify pool member type auto", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=auto",
			}

			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).ToNot(BeNil())

			Expect(len(vxlanMode)).To(Equal(0), "Mode variable should not be set.")
			Expect(len(*openshiftSDNName)).To(Equal(0),
				"Openshift sdn name variable should not be set.")
			Expect(len(*flannelName)).To(Equal(0), "Flannel name variable should not be set.")
			Expect(len(*ciliumTunnelName)).To(Equal(0), "Cilium name variable should not be set.")

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--namespace=testing",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--openshift-sdn-name=vxlan500",
				"--custom-resource-mode=true",
				"--pool-member-type=auto",
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
				"--cilium-name=vxlan500",
			}

			flags.Parse(os.Args)
			err = verifyArgs()
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal("Cannot have openshift-sdn-name,cilium-name specified"))
		})
	})

	Describe("Mock driver subprocess tests", func() {
		var pid int
		tmpFilename := string("configdriverOutput.tmp")
		tmpFilepath := string("test/" + tmpFilename)
		BeforeEach(func() {
			configWriter := &test.MockWriter{
				FailStyle: test.Success,
				Sections:  make(map[string]interface{}),
				File:      "configdriverOutput.tmp",
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
			// Call kill command once the file exists and the message is received
			killDriverCmd := exec.Command("kill", []string{"-2", strconv.Itoa(pid)}...)
			session, _ := Start(killDriverCmd, GinkgoWriter, GinkgoWriter)
			Eventually(session, 30*time.Second).Should(Exit(0))

			// Clean up file
			os.RemoveAll(tmpFilepath)
			_, err := os.Stat(tmpFilepath)
			Expect(err).ToNot(BeNil())
		})

		It("runs the driver subprocess", func() {
			Expect(pid).ToNot(Equal(0), "Pid should be set and not nil value.")

			proc, err := os.FindProcess(pid)
			Expect(err).To(BeNil())
			Expect(proc).ToNot(BeNil(), "Should have process object.")

			// Runs script verifying the creation of the Python process
			cmd := exec.Command("bash", []string{"test/testBigipconfigdriver.sh"}...)
			session, _ := Start(cmd, GinkgoWriter, GinkgoWriter)
			Eventually(session, 30*time.Second).Should(Exit(0))

			// Check if configdriverOutput.tmp file exists
			timeCount := 1000
			for timeCount > 0 {
				if _, err = os.Stat(tmpFilepath); err == nil {
					break
				}
				time.Sleep(time.Millisecond)
				timeCount--
			}
			// Timed out waiting for the creation of a temp file
			Expect(timeCount).ToNot(Equal(0), "Timed out waiting for the creation of a temp file")

			// Check if configdriverOutput.tmp file contains message
			f, fileError := os.Open(tmpFilepath)
			Expect(fileError).To(BeNil(), "The configdriverOutput.tmp file should be present.")

			fileMsg := make([]byte, 27)
			f.Read(fileMsg)
			timeCount = 1000
			for (string(fileMsg) != string("Ready for KeyboardInterrupt")) &&
				(timeCount > 0) {
				time.Sleep(time.Millisecond)
				f.Read(fileMsg)
				timeCount--
			}
			// Timed out waiting for a ready message in the temp file
			Expect(timeCount).ToNot(Equal(0), "Timed out waiting for a ready message in the temp file")
		})
	})
	Describe("Check the SDNType", func() {
		It("Check the SDNType nodeport", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--pool-member-type=nodeport",
			}
			flags.Parse(os.Args)
			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())
			config := &rest.Config{}
			Expect(getSDNType(config)).To(Equal("nodeport-mode"), "SDNType should be nodeport-mode")
		})
		It("Check the SDNType flannel", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--flannel-name=vxlan500",
				"--pool-member-type=cluster",
			}
			flags.Parse(os.Args)
			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())
			config := &rest.Config{}
			Expect(getSDNType(config)).To(Equal("flannel"), "SDNType should be flannel")
		})
		It("Check the SDNType other", func() {
			config := &rest.Config{}
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--bigip-partition=velcro1",
				"--bigip-password=admin",
				"--bigip-url=bigip.example.com",
				"--bigip-username=admin",
				"--openshift-sdn-name=vxlan500",
				"--pool-member-type=cluster",
			}
			flags.Parse(os.Args)
			flags.Parse(os.Args)
			err := verifyArgs()
			Expect(err).To(BeNil())
			Expect(getSDNType(config)).To(Equal("openshiftSDN"), "SDNType should be other")
		})
	})
})
