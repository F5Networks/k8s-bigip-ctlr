package controller

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"io/ioutil"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"time"
)

var _ = Describe("Metrics", func() {
	var mockCtlr *mockController
	BeforeEach(func() {
		mockCtlr = newMockController()
	})
	It("Enable the metrics without http", func() {
		// Create a mock Kubernetes API server
		server := ghttp.NewServer()
		defer server.Close()
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/readyz"),
				ghttp.RespondWithJSONEncoded(http.StatusOK, Ok),
			))
		// Override the base URL of the client to point to the mock server
		config := &rest.Config{
			Host: server.URL(),
		}
		client, err := kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())
		mockCtlr.clientsets.KubeClient = client
		go mockCtlr.enableHttpEndpoint("0.0.0.0:8080")
		time.Sleep(3 * time.Second)
		resp, err := makeHTTPRequest("http://0.0.0.0:8080/health")
		Expect(err).To(BeNil())
		Expect(resp).To(Equal(Ok))
	})
})

func makeHTTPRequest(url string) (string, error) {
	// Make the HTTP GET request
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("Error making HTTP request: %v\n", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error reading response body: %v\n", err)
	}
	// Print the response body
	return string(body), nil
}
