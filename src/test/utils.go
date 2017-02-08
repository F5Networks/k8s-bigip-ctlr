package test

import (
	"fmt"
	"sync"
	"time"
)

const (
	ImmediateFail = iota
	AsyncFail
	Timeout
	Success
)

type MockWriter struct {
	FailStyle    int
	WrittenTimes int
	Sections     map[string]interface{}
	sync.Mutex
}

func (mw *MockWriter) GetOutputFilename() string {
	return "mock-file"
}

func (mw *MockWriter) Stop() {
}

func (mw *MockWriter) SendSection(
	name string,
	obj interface{},
) (<-chan struct{}, <-chan error, error) {
	mw.Lock()
	defer mw.Unlock()

	doneCh := make(chan struct{})
	errCh := make(chan error)

	mw.WrittenTimes++

	mw.Sections[name] = obj

	switch mw.FailStyle {
	case ImmediateFail:
		return nil, nil, fmt.Errorf("immediate test error")
	case AsyncFail:
		go func() {
			errCh <- fmt.Errorf("async test error")
		}()
	case Timeout:
		<-time.After(2 * time.Second)
	case Success:
		go func() {
			doneCh <- struct{}{}
		}()
	}

	return doneCh, errCh, nil
}
