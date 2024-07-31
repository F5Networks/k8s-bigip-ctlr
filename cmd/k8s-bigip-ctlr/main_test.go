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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/config/client/clientset/versioned"
	"github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/controller"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/spf13/pflag"
	"io"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	restFake "k8s.io/client-go/rest/fake"
	"net/http"
	"os"
	"strings"
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

var _ = Describe("GetUserAgentInfo", func() {
	var (
		clientSet *fake.Clientset
		rc        *restFake.RESTClient
	)

	BeforeEach(func() {
		clientSet = fake.NewSimpleClientset()
		rc = &restFake.RESTClient{}
		clientSets.KubeClient = clientSet
		version = "1.0.0" // example version
	})

	It("should return CIS version with OCP < 3.11", func() {
		versionInfo := map[string]string{"gitVersion": "v3.10.0"}
		vInfo, _ := json.Marshal(versionInfo)
		rc.Resp = &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(vInfo)),
		}

		info := getUserAgentInfo(rc)
		Expect(info).To(Equal(fmt.Sprintf("CIS/v%v OCP/v3.10.0", version)))
	})
	// TODO - Fix these test
	//It("should return CIS version with OCP > 4.0", func() {
	//	ocp4 := Ocp4Version{
	//		Status: ClusterVersionStatus{
	//			History: []UpdateHistory{
	//				{Version: "4.1.0"},
	//			},
	//		},
	//	}
	//	vInfo, _ := json.Marshal(ocp4)
	//	rc.Resp = &http.Response{
	//		StatusCode: http.StatusOK,
	//		Body:       io.NopCloser(bytes.NewReader(vInfo)),
	//	}
	//
	//	info := getUserAgentInfo(rc)
	//	Expect(info).To(Equal(fmt.Sprintf("CIS/v%v OCP/v4.1.0", version)))
	//})
	//
	//It("should return CIS version with K8S version", func() {
	//	versionInfo := map[string]string{"gitVersion": "v1.18.0"}
	//	vInfo, _ := json.Marshal(versionInfo)
	//	rc.Resp = &http.Response{
	//		StatusCode: http.StatusOK,
	//		Body:       io.NopCloser(bytes.NewReader(vInfo)),
	//	}
	//
	//	info := getUserAgentInfo(rc)
	//	Expect(info).To(Equal(fmt.Sprintf("CIS/v%v K8S/v1.18.0", version)))
	//})

	It("should return CIS version when unable to fetch details", func() {
		rc.Resp = &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		}

		info := getUserAgentInfo(rc)
		Expect(info).To(Equal(fmt.Sprintf("CIS/v%v", version)))
	})
})

var _ = Describe("GetKubeConfig", func() {
	var (
		mockInClusterConfig func() (*rest.Config, error)
	)

	Context("when InClusterConfig succeeds", func() {
		BeforeEach(func() {
			mockInClusterConfig = func() (*rest.Config, error) {
				return &rest.Config{}, nil
			}
		})

		It("should return a non-nil config and no error", func() {
			config, err := getKubeConfig(mockInClusterConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(config).NotTo(BeNil())
		})
	})

	Context("when InClusterConfig fails", func() {
		BeforeEach(func() {
			mockInClusterConfig = func() (*rest.Config, error) {
				return nil, errors.New("mock error")
			}
		})

		It("should return an error", func() {
			config, err := getKubeConfig(mockInClusterConfig)
			Expect(err).To(HaveOccurred())
			Expect(config).To(BeNil())
		})
	})
})

var _ = Describe("InitClientSets", func() {
	var (
		config                   *rest.Config
		mockKubeClient           *kubernetes.Clientset
		mockKubeCRClient         *versioned.Clientset
		mockRouteClient          *routeclient.RouteV1Client
		mockKubeClientFunction   func(*rest.Config) (*kubernetes.Clientset, error)
		mockKubeCRClientfunction func(*rest.Config) (*versioned.Clientset, error)
		mockRouteClientFunction  func(*rest.Config) (*routeclient.RouteV1Client, error)
		trueValue                bool
		falseValue               bool
	)

	BeforeEach(func() {
		// Initialize the config and clientSets
		config = &rest.Config{}
		manageCustomResources = new(bool)
		manageRoutes = new(bool)
		clientSets = controller.ClientSets{}
	})

	Context("Creating clientsets", func() {
		BeforeEach(func() {
			mockKubeClient = &kubernetes.Clientset{}
			mockKubeCRClient = &versioned.Clientset{}
			mockRouteClient = &routeclient.RouteV1Client{}
			trueValue = true
			falseValue = false
			manageCustomResources = &falseValue
			manageRoutes = &falseValue
		})
		It("KubeClient fails", func() {
			mockKubeClientFunction = func(*rest.Config) (*kubernetes.Clientset, error) {
				return nil, errors.New("mock error")
			}
			err := initClientSets(config, mockKubeClientFunction, mockKubeCRClientfunction, mockRouteClientFunction)
			Expect(err).To(HaveOccurred())
			Expect(clientSets.KubeClient).To(BeNil())
		})
		It("KubeClient Succeeds", func() {
			mockKubeClientFunction = func(*rest.Config) (*kubernetes.Clientset, error) {
				return mockKubeClient, nil
			}
			err := initClientSets(config, mockKubeClientFunction, mockKubeCRClientfunction, mockRouteClientFunction)
			Expect(err).NotTo(HaveOccurred())
			Expect(clientSets.KubeClient).To(Equal(mockKubeClient))
			Expect(clientSets.KubeCRClient).To(BeNil())
			Expect(clientSets.RouteClientV1).To(BeNil())
		})
		It("KubeCRClient fails", func() {
			mockKubeClientFunction = func(*rest.Config) (*kubernetes.Clientset, error) {
				return mockKubeClient, nil
			}
			mockKubeCRClientfunction = func(*rest.Config) (*versioned.Clientset, error) {
				return nil, errors.New("mock error")
			}
			manageCustomResources = &trueValue
			err := initClientSets(config, mockKubeClientFunction, mockKubeCRClientfunction, mockRouteClientFunction)
			Expect(err).To(HaveOccurred())
			Expect(clientSets.KubeClient).To(Equal(mockKubeClient))
			Expect(clientSets.KubeCRClient).To(BeNil())
			Expect(clientSets.RouteClientV1).To(BeNil())
		})
		It("KubeCRClient succeeds", func() {
			mockKubeClientFunction = func(*rest.Config) (*kubernetes.Clientset, error) {
				return mockKubeClient, nil
			}
			mockKubeCRClientfunction = func(*rest.Config) (*versioned.Clientset, error) {
				return mockKubeCRClient, nil
			}
			manageCustomResources = &trueValue
			err := initClientSets(config, mockKubeClientFunction, mockKubeCRClientfunction, mockRouteClientFunction)
			Expect(err).NotTo(HaveOccurred())
			Expect(clientSets.KubeClient).To(Equal(mockKubeClient))
			Expect(clientSets.KubeCRClient).To(Equal(mockKubeCRClient))
			Expect(clientSets.RouteClientV1).To(BeNil())
		})
		It("Route Client fails", func() {
			mockKubeClientFunction = func(*rest.Config) (*kubernetes.Clientset, error) {
				return mockKubeClient, nil
			}
			mockKubeCRClientfunction = func(*rest.Config) (*versioned.Clientset, error) {
				return mockKubeCRClient, nil
			}
			mockRouteClientFunction = func(*rest.Config) (*routeclient.RouteV1Client, error) {
				return nil, errors.New("mock error")
			}
			manageRoutes = &trueValue
			err := initClientSets(config, mockKubeClientFunction, mockKubeCRClientfunction, mockRouteClientFunction)
			Expect(err).To(HaveOccurred())
			Expect(clientSets.KubeClient).To(Equal(mockKubeClient))
			Expect(clientSets.KubeCRClient).To(BeNil())
			Expect(clientSets.RouteClientV1).To(BeNil())
		})
		It("Route Client succeeds", func() {
			mockKubeClientFunction = func(*rest.Config) (*kubernetes.Clientset, error) {
				return mockKubeClient, nil
			}
			mockKubeCRClientfunction = func(*rest.Config) (*versioned.Clientset, error) {
				return mockKubeCRClient, nil
			}
			mockRouteClientFunction = func(*rest.Config) (*routeclient.RouteV1Client, error) {
				return mockRouteClient, nil
			}
			manageRoutes = &trueValue
			err := initClientSets(config, mockKubeClientFunction, mockKubeCRClientfunction, mockRouteClientFunction)
			Expect(err).NotTo(HaveOccurred())
			Expect(clientSets.KubeClient).To(Equal(mockKubeClient))
			Expect(clientSets.KubeCRClient).To(BeNil())
			Expect(clientSets.RouteClientV1).To(Equal(mockRouteClient))
		})
	})

})

var _ = Describe("Run", func() {
	var (
		args       []string
		trueValue  bool
		falseValue bool
	)

	BeforeEach(func() {
		args = []string{"cmd"}
		trueValue = true
		falseValue = false
		printVersion = new(bool)
		printVersion = &falseValue
	})

	Context("when flags.Parse returns an error", func() {
		It("should return an error", func() {
			mockParseFlags := func([]string) error {
				return errors.New("flags parse error")
			}
			err := run(args, mockParseFlags)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("flags parse error"))
		})
	})

	Context("when printVersion is true", func() {
		BeforeEach(func() {
			printVersion = &trueValue
		})

		It("should print version and return nil", func() {
			err := run(args, flags.Parse)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when verifyArgs returns an error", func() {

		It("should return an error with invalid multi-cluster mode", func() {
			defer _init()
			args = []string{
				"./bin/k8s-bigip-ctlr",
				"--cm-password=admin",
				"--cm-url=cm.example.com",
				"--cm-username=admin",
				"--deploy-config-cr=default/testcr",
				"--multi-cluster-mode=invalid",
			}
			err := run(args, flags.Parse)
			Expect(err).To(HaveOccurred())
			Expect(fmt.Sprintf(err.Error())).To(ContainSubstring("is not a valid multi cluster mode"))
		})
	})

	Context("when getCredentials returns an error", func() {
		BeforeEach(func() {

		})

		It("should return an error", func() {
			defer _init()
			args = []string{
				"./bin/k8s-bigip-ctlr",
				"--credentials-directory=/tmp/k8s-test-creds/",
				"--deploy-config-cr=default/testcr",
			}
			err := run(args, flags.Parse)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("CentralManager username not specified"))
		})
	})

	Context("when getKubeConfig returns an error", func() {
		defer _init()
		args = []string{
			"./bin/k8s-bigip-ctlr",
			"--cm-password=admin",
			"--cm-url=cm.example.com",
			"--cm-username=admin",
			"--deploy-config-cr=default/testcr",
		}
		err := run(args, flags.Parse)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined"))
	})
})

var _ = Describe("initTeems", func() {
	var (
		ctlr *controller.Controller
	)

	BeforeEach(func() {
		ctlr = &controller.Controller{
			PoolMemberType:   "nodeport",
			OrchestrationCNI: "calico",
		}
		disableTeems = new(bool)
		version = "1.0.0"
		userAgentInfo = "TestUserAgent"
	})

	Context("when disableTeems is true", func() {
		BeforeEach(func() {
			*disableTeems = true
		})

		It("should disable AccessEnabled and not set SDNType", func() {
			initTeems(ctlr)
			Expect(ctlr.TeemData).NotTo(BeNil())
			Expect(ctlr.TeemData.AccessEnabled).To(BeFalse())
			Expect(ctlr.TeemData.SDNType).To(BeEmpty())
		})
	})
})
