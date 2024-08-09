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

package writer

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	failLock = iota
	failUnlock
	failTruncate
	failWrite
	failShortWrite
)

type pseudoFile struct {
	FailStyle int
	RealFile  *os.File
	BadFd     uintptr
}

func newPseudoFile(failure int) *pseudoFile {
	f, err := ioutil.TempFile("/tmp", "config-writer-unit-test")
	Expect(err).To(BeNil())
	Expect(f).ToNot(BeNil())

	pf := &pseudoFile{
		FailStyle: failure,
		RealFile:  f,
		BadFd:     uintptr(10101001),
	}
	return pf
}

func (pf *pseudoFile) Close() error {
	return nil
}

func (pf *pseudoFile) Fd() uintptr {
	switch pf.FailStyle {
	case failLock:
		return pf.BadFd
	case failUnlock:
		return pf.BadFd
	default:
		return pf.RealFile.Fd()
	}
}

func (pf *pseudoFile) Truncate(size int64) error {
	switch pf.FailStyle {
	case failTruncate:
		return errors.New("mock file truncate error")
	default:
		return nil
	}
}

func (pf *pseudoFile) Write(b []byte) (n int, err error) {
	switch pf.FailStyle {
	case failWrite:
		n = 0
		err = errors.New("mock file write error")
	case failShortWrite:
		n = 1
		err = errors.New("mock file short write")
	default:
		n = 100
		err = nil
	}
	return n, err
}

type testSubSection struct {
	SubField1 string `json:"sub-field1-str,omitempty"`
	SubField2 int    `json:"sub-field2-int,omitempty"`
}
type testSection struct {
	Field1 string          `json:"field1-str,omitempty"`
	Field2 int             `json:"field2-int,omitempty"`
	Field3 *testSubSection `json:"field3-struct,omitempty"`
}

type simpleTest struct {
	Test testSection `json:"simple-test"`
}

var _ = Describe("Config Writer Tests", func() {
	Context("General functionality", func() {
		pollError := func(doneCh <-chan struct{}, errCh <-chan error) {
			ticks := 0
			tickLimit := 100
			ticker := time.NewTicker(100 * time.Millisecond)

		loop:
			for {
				select {
				case e := <-errCh:
					Expect(e).ToNot(BeNil())
					break loop
				case <-ticker.C:
				}
				ticks++
				if tickLimit == ticks {
					Fail("Did not receive expected error in 10s.")
					break loop
				}
			}
			select {
			case <-doneCh:
				Fail("Received unexpected done signal.")
			default:
			}
		}

		pollDone := func(doneCh <-chan struct{}, errCh <-chan error) {
			ticks := 0
			tickLimit := 100
			ticker := time.NewTicker(100 * time.Millisecond)

		loop:
			for {
				select {
				case <-doneCh:
					break loop
				case <-ticker.C:
				}
				ticks++
				if tickLimit == ticks {
					Fail("Did not receive expected error in 10s.")
					break loop
				}
			}
			select {
			case e := <-errCh:
				Expect(e).To(BeNil(), "Received unexpected error from good transaction.")
			default:
			}
		}

		testFile := func(f string, shouldExist bool) {
			_, err := os.Stat(f)

			if false == shouldExist {
				Expect(err).ToNot(BeNil())
				Expect(os.IsNotExist(err)).To(BeTrue())
			} else {
				Expect(err).To(BeNil())
				if nil != err {
					Expect(os.IsNotExist(err)).To(BeFalse())
				}
			}
		}

		var cw Writer
		var err error
		var f string

		BeforeEach(func() {
			cw, err = NewConfigWriter()
			Expect(err).To(BeNil())
			Expect(cw).ToNot(BeNil())

			f = cw.GetOutputFilename()
		})

		AfterEach(func() {
			cw.Stop()
			_, err = os.Stat(f)
			Expect(os.IsExist(err)).To(BeFalse())
		})

		It("has functional getters", func() {
			dir := filepath.Dir(f)
			_, err = os.Stat(dir)
			Expect(err).To(BeNil())
		})

		It("doesn't write when stopped", func() {
			testFile(f, false)

			doneCh, errCh, err := cw.SendSection("write-after-start", struct{}{})
			Expect(err).To(BeNil())

			pollDone(doneCh, errCh)
			testFile(f, true)

			cw.Stop()
			testFile(f, false)

			// Maybe overdone here but stopping and writing multiple times to ensure
			// there isn't a deadlock lurking in the Stop functionality.
			cw.SendSection("write-after-stop", struct{}{})
			cw.Stop()
			cw.SendSection("write-after-stop", struct{}{})
			cw.Stop()
			cw.SendSection("write-after-stop", struct{}{})
			testFile(f, false)
		})

		It("doesn't write bad json", func() {
			badJSON := map[struct{ key string }]string{
				struct{ key string }{
					key: "one",
				}: "something goes here",
				struct{ key string }{
					key: "two",
				}: "some more here",
				struct{ key string }{
					key: "three",
				}: "this really shouldn't marshal",
			}

			doneCh, errCh, err := cw.SendSection("bad", badJSON)
			Expect(err).To(BeNil())

			pollError(doneCh, errCh)
		})

		It("handles simple writes", func() {
			testData := simpleTest{
				Test: testSection{
					Field1: "test-field1",
					Field2: 121232343,
					Field3: &testSubSection{
						SubField1: "test-sub-field1",
						SubField2: 42,
					},
				},
			}

			testFile(f, false)

			doneCh, errCh, err := cw.SendSection("", testData.Test)
			Expect(doneCh).To(BeNil())
			Expect(errCh).To(BeNil())
			Expect(err).ToNot(BeNil())

			testFile(f, false)

			doneCh, errCh, err = cw.SendSection("simple-test", testData.Test)
			Expect(err).To(BeNil())

			pollDone(doneCh, errCh)
			testFile(f, true)

			expected, err := json.Marshal(testData)
			Expect(err).To(BeNil())

			written, err := ioutil.ReadFile(f)
			Expect(err).To(BeNil())
			Expect(written).To(Equal(expected))

			// test empty section and overwrite
			empty := struct {
				Section struct {
					Field string `json:"field,omitempty"`
				} `json:"simple-test"`
			}{Section: struct {
				Field string `json:"field,omitempty"`
			}{
				Field: "",
			},
			}
			doneCh, errCh, err = cw.SendSection("simple-test", empty.Section)
			Expect(err).To(BeNil())

			pollDone(doneCh, errCh)
			testFile(f, true)

			expected, err = json.Marshal(empty)
			Expect(err).To(BeNil())

			written, err = ioutil.ReadFile(f)
			Expect(err).To(BeNil())
			Expect(written).To(Equal(expected))

			// add section back
			doneCh, errCh, err = cw.SendSection("simple-test", testData.Test)
			Expect(err).To(BeNil())

			pollDone(doneCh, errCh)
			testFile(f, true)

			expected, err = json.Marshal(testData)
			Expect(err).To(BeNil())

			written, err = ioutil.ReadFile(f)
			Expect(err).To(BeNil())
			Expect(written).To(Equal(expected))
		})

		It("can write concurrently", func() {
			testData := map[string]testSection{
				"concurrent-1": testSection{
					Field1: "concur1-field1",
					Field2: 121232343,
					Field3: &testSubSection{
						SubField1: "concur1-sub-field1",
						SubField2: 42,
					},
				},
				"concurrent-2": testSection{
					Field1: "concur2-field1",
					Field2: 9999,
					Field3: &testSubSection{
						SubField1: "concur2-sub-field1",
						SubField2: 1111,
					},
				},
				"concurrent-3": testSection{
					Field1: "concur3-field1",
					Field2: 2222,
					Field3: &testSubSection{
						SubField1: "concur3-sub-field1",
						SubField2: 10101,
					},
				},
				"concurrent-4": testSection{
					Field1: "concur4-field1",
					Field2: 333444,
					Field3: &testSubSection{
						SubField1: "concur4-sub-field1",
						SubField2: 222211114,
					},
				},
				"concurrent-5": testSection{
					Field1: "concur5-field1",
					Field2: 1,
					Field3: &testSubSection{
						SubField1: "concur5-sub-field1",
						SubField2: 2,
					},
				},
			}

			var wg sync.WaitGroup
			for k, v := range testData {
				wg.Add(1)
				go func(field string, data interface{}) {
					defer GinkgoRecover()
					doneCh, errCh, err := cw.SendSection(field, data)
					Expect(err).To(BeNil())

					pollDone(doneCh, errCh)
					testFile(f, true)

					wg.Done()
				}(k, v)
			}
			wg.Wait()

			expected, err := json.Marshal(testData)
			Expect(err).To(BeNil())

			written, err := ioutil.ReadFile(f)
			Expect(err).To(BeNil())

			Expect(written).To(Equal(expected))
		})
	})

	Context("Failures", func() {
		var cw *configWriter
		BeforeEach(func() {
			cw = &configWriter{
				configFile: "/this-file/really/probably/will/not/exist",
				stopCh:     make(chan struct{}),
				dataCh:     make(chan configSection),
				sectionMap: make(map[string]interface{}),
			}
		})

		Context("No file", func() {
			It("fails to open non-existent files", func() {
				var wrote bool
				var err error
				Expect(func() {
					wrote, err = cw.lockAndWrite([]byte("hello"))
				}).ToNot(Panic())
				Expect(wrote).To(BeFalse())
				Expect(err).ToNot(BeNil())

				expected := "open /this-file/really/probably/will/not/exist: no such file or directory"
				Expect(err.Error()).To(Equal(expected))
			})
		})

		Context("With file", func() {
			var mockFile *pseudoFile

			AfterEach(func() {
				err := mockFile.RealFile.Close()
				Expect(err).To(BeNil())

				os.Remove(mockFile.RealFile.Name())
			})

			It("FailLock ", func() {
				// go does not have an idea of a File interface, doing the best
				// we can to try and create some negative behaviors
				mockFile = newPseudoFile(failLock)
				Expect(mockFile).ToNot(BeNil())

				var wrote bool
				var err error
				Expect(func() {
					wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
				}).ToNot(Panic())
				Expect(wrote).To(BeFalse())
				Expect(err).ToNot(BeNil())

				expected := "bad file descriptor"
				Expect(err.Error()).To(Equal(expected))
			})

			It("FailUnlock", func() {
				// go does not have an idea of a File interface, doing the best
				// we can to try and create some negative behaviors
				mockFile = newPseudoFile(failUnlock)
				Expect(mockFile).ToNot(BeNil())

				var wrote bool
				var err error
				Expect(func() {
					wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
				}).ToNot(Panic())
				Expect(wrote).To(BeFalse())
				Expect(err).ToNot(BeNil())

				expected := "bad file descriptor"
				Expect(err.Error()).To(Equal(expected))
			})

			It("FailTrunc", func() {
				// go does not have an idea of a File interface, doing the best
				// we can to try and create some negative behaviors
				mockFile = newPseudoFile(failTruncate)
				Expect(mockFile).ToNot(BeNil())

				var wrote bool
				var err error
				Expect(func() {
					wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
				}).ToNot(Panic())
				Expect(wrote).To(BeFalse())
				Expect(err).ToNot(BeNil())

				expected := "mock file truncate error"
				Expect(err.Error()).To(Equal(expected))
			})

			It("FailWrite", func() {
				// go does not have an idea of a File interface, doing the best
				// we can to try and create some negative behaviors
				mockFile = newPseudoFile(failWrite)
				Expect(mockFile).ToNot(BeNil())

				var wrote bool
				var err error
				Expect(func() {
					wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
				}).ToNot(Panic())
				Expect(wrote).To(BeFalse())
				Expect(err).ToNot(BeNil())

				expected := "mock file write error"
				Expect(err.Error()).To(Equal(expected))
			})

			It("FailWrite", func() {
				// go does not have an idea of a File interface, doing the best
				// we can to try and create some negative behaviors
				mockFile = newPseudoFile(failShortWrite)
				Expect(mockFile).ToNot(BeNil())

				var wrote bool
				var err error
				Expect(func() {
					wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
				}).ToNot(Panic())
				Expect(wrote).To(BeTrue())
				Expect(err).ToNot(BeNil())

				expected := "mock file short write"
				Expect(err.Error()).To(Equal(expected))
			})
		})
	})
})
