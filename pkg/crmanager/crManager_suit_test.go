package crmanager

import (
	"bytes"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestCustomResource(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CR Manager Suite")
}

var configPath = "../../test/configs/"

type mockCRManager struct {
	*CRManager
}

type mockPostManager struct {
	*PostManager
	Responses []int
	RespIndex int
}

func newMockCRManager() *mockCRManager {
	return &mockCRManager{
		&CRManager{},
	}
}

func (mockCRM *mockCRManager) shutdown() error {
	return nil
}

func newMockPostManger() *mockPostManager {
	mockPM := &mockPostManager{
		PostManager: &PostManager{},
		Responses:   []int{},
		RespIndex:   0,
	}

	mockPM.postChan = make(chan agentConfig, 1)

	return mockPM
}

func (mockPM *mockPostManager) setResponses(respCodes []int, responseBody, method string) {
	var body string

	responseMap := make(mockhc.ResponseConfigMap)
	responseMap[method] = &mockhc.ResponseConfig{}
	for _, statusCode := range respCodes {
		if responseBody == "" {
			if statusCode == http.StatusOK {
				body = fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "none"}]}`,
					statusCode)
			} else {
				body = fmt.Sprintf(`{"results":[{"code":%d,"message":"none", "tenant": "none"}],"error":{"code":%d}}`,
					statusCode, statusCode)
			}
		} else {
			body = responseBody
		}

		responseMap[method].Responses = append(responseMap[method].Responses, &http.Response{
			StatusCode: statusCode,
			Header:     http.Header{},
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(body))),
		})
	}
	client, _ := mockhc.NewMockHTTPClient(responseMap)
	mockPM.httpClient = client
}

func newMockAgent(writer writer.Writer) *Agent {
	return &Agent{
		PostManager:     nil,
		Partition:       "test",
		ConfigWriter:    writer,
		EventChan:       make(chan interface{}),
		PythonDriverPID: 0,
		activeDecl:      "",
		userAgent:       "",
	}
}
