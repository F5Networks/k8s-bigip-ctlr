package controller

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/F5Networks/k8s-bigip-ctlr/pkg/writer"
	mockhc "github.com/f5devcentral/mockhttpclient"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CR Manager Suite")
}

var configPath = "../../test/configs/"

type (
	mockController struct {
		*Controller
	}

	mockPostManager struct {
		*PostManager
		Responses []int
		RespIndex int
	}
)

func newMockController() *mockController {
	return &mockController{
		&Controller{},
	}
}

func (mockCtlr *mockController) shutdown() error {
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
		activeDecl:      make(map[string]interface{}),
		newDecl:         make(map[string]interface{}),
		userAgent:       "",
	}
}
