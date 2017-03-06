/*-
 * Copyright (c) 2017, F5 Networks, Inc.
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
