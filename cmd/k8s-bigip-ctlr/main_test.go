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
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/controller"
	"github.com/spf13/pflag"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Main Tests", func() {
	Describe("Main Tests", func() {
		It("verifies cli arguments", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
				"--log-level=INFO",
				"--disable-teems=true",
				"--no-verify-ssl=true",
				"--trusted-certs-cfgmap=default/foomap",
				"--kubeconfig=/tmp/kubeconfig",
				"--credentials-directory=/tmp/k8s-test-creds",
				"--log-file=/tmp/k8s-bigip-ctlr.log",
			}

			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).To(BeNil())
			Expect(*cmURL).To(Equal("cm.example.com"))
			Expect(*cmUsername).To(Equal("admin"))
			Expect(*cmPassword).To(Equal("admin"))
			Expect(*logLevel).To(Equal("INFO"))
			Expect(*CISConfigCR).To(Equal("default/testcr"))
			Expect(*disableTeems).To(Equal(true))
			Expect(*sslInsecure).To(Equal(true))
			Expect(*trustedCertsCfgmap).To(Equal("default/foomap"))
			Expect(*kubeConfig).To(Equal("/tmp/kubeconfig"))
			Expect(*credsDir).To(Equal("/tmp/k8s-test-creds"))
			Expect(*logFile).To(Equal("/tmp/k8s-bigip-ctlr.log"))
		})
		It("Test empty required args ", func() {
			defer _init()
			allArgs := map[string]*string{
				"cmUrl":       cmURL,
				"cmUsername":  cmUsername,
				"cmPassword":  cmPassword,
				"logLevel":    logLevel,
				"cisConfigCR": CISConfigCR,
			}

			for argName, arg := range allArgs {
				holder := *arg
				*arg = ""
				argError := verifyArgs()
				Expect(argError).ToNot(BeNil(), fmt.Sprintf(
					"Argument %s is required, and should not allow an empty string.", argName))
				*arg = holder
			}
		})
		It("verifies with missing all required CLI parameters", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
			}

			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).To(BeNil())

		})

		It("verifies with missing --cm-password required CLI parameter", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
			}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())
		})
		It("verifies with missing all required CLI parameters", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
			}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())
		})
		It("verifies with missing --deploy-config-cr required CLI parameter", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
			}
			flags.Init("", pflag.ContinueOnError)
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())
		})
		It("verifies with missing --cm-url required CLI parameter", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
			}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())
		})
		It("verifies with missing --cm-username required CLI parameter", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--deploy-config-cr=default/testcr",
			}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())
		})
		It("verifies with all required CLI parameter ", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
			}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).To(BeNil())

		})
		It("invalid CLI argument", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default"}
			flags.Parse(os.Args)
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())

		})
		It("invalid CLI3 argument  ", func() {
			defer _init()
			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-username1=admin",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
			}
			argError := verifyArgs()
			Expect(argError).ToNot(BeNil())
		})

		It("gets credentials from a file", func() {
			defer _init()
			defer os.RemoveAll("/tmp/k8s-test-creds")

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--credentials-directory=/tmp/k8s-test-creds",
				"--cm-url=cm.example.com",
				"--deploy-config-cr=default/testcr",
				"--disable-teems=true",
			}
			flags.Parse(os.Args)
			os.Mkdir("/tmp/k8s-test-creds", 0755)
			err := os.WriteFile("/tmp/k8s-test-creds/username", []byte("user"), 0755)
			Expect(err).ToNot(HaveOccurred())
			err = os.WriteFile("/tmp/k8s-test-creds/password", []byte("pass"), 0755)
			Expect(err).ToNot(HaveOccurred())

			err = getCredentials()
			Expect(err).ToNot(HaveOccurred())
			Expect(*cmURL).To(Equal("https://cm.example.com"))
			Expect(*cmUsername).To(Equal("user"))
			Expect(*cmPassword).To(Equal("pass"))
			// Test url variations
			os.Args[4] = "--cm-url=fail://cm.example.com"
			flags.Parse(os.Args)
			err = getCredentials()
			Expect(err).ToNot(BeNil(), "cm-url should fail with incorrect scheme 'fail://'.")

			os.Args[4] = "--cm-url=https://cm.example.com/some/path"
			flags.Parse(os.Args)
			err = getCredentials()
			Expect(err).ToNot(BeNil(), "cm-url should fail with invalid path.")
		})

		It("uses credentials file over CLI args", func() {
			defer _init()
			defer os.RemoveAll("/tmp/k8s-test-creds")

			os.Args = []string{
				"./bin/k8s-bigip-ctlr",
				"--credentials-directory=/tmp/k8s-test-creds",
				"--cm-url=cm.example.com",
				"--cm-username=cli-user",
				"--cm-password=cli-pass",
				"--deploy-config-cr=default/testcr",
				"--trusted-certs-cfgmap=default/foomap",
			}
			flags.Parse(os.Args)
			os.Mkdir("/tmp/k8s-test-creds", 0755)
			err := os.WriteFile("/tmp/k8s-test-creds/username", []byte("user"), 0755)
			Expect(err).ToNot(HaveOccurred())
			err = os.WriteFile("/tmp/k8s-test-creds/password", []byte("pass"), 0755)

			err = getCredentials()
			Expect(err).ToNot(HaveOccurred())

			Expect(*cmURL).To(Equal("https://cm.example.com"))
			Expect(*cmUsername).To(Equal("user"))
			Expect(*cmPassword).To(Equal("pass"))
			clientSets = controller.ClientSets{
				KubeClient: fake.NewSimpleClientset(),
			}
			cfgFoo := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foomap", Namespace: "default"}, Data: map[string]string{"data": "foo"}}
			_, err = clientSets.KubeClient.CoreV1().ConfigMaps("default").Create(context.TODO(), cfgFoo, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			cfgFoo, err = getConfigMapUsingNamespaceAndName("default", "foomap")
			Expect(err).ToNot(HaveOccurred())
			Expect(cfgFoo.Data["data"]).To(Equal("foo"))
			//check for invlaid configmap
			_, err = getConfigMapUsingNamespaceAndName("default", "invalid")
			Expect(err).ToNot(BeNil())
			//check for valid bigip trusted certs
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
		})
	})
})
