package writer

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newPseudoFile(t *testing.T, failure int) *pseudoFile {
	f, err := ioutil.TempFile("/tmp", "config-writer-unit-test")
	require.NoError(t, err)
	require.NotNil(t, f)

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

func checkGoroutines(t *testing.T, expectedRoutines int) {
	ticks := 0
	tickLimit := 100
	ticker := time.NewTicker(100 * time.Millisecond)

	if expectedRoutines == runtime.NumGoroutine() {
		assert.Equal(t, expectedRoutines, runtime.NumGoroutine())
	} else {
		for _ = range ticker.C {
			runtime.Gosched()

			if expectedRoutines == runtime.NumGoroutine() {
				assert.Equal(t, expectedRoutines, runtime.NumGoroutine())
				return
			}

			ticks++
			if tickLimit == ticks {
				assert.FailNow(t, "Did not exit go routines in 10s")
			}
		}
	}
}

func pollError(t *testing.T, doneCh <-chan struct{}, errCh <-chan error) {
	ticks := 0
	tickLimit := 100
	ticker := time.NewTicker(100 * time.Millisecond)

loop:
	for {
		select {
		case e := <-errCh:
			assert.NotNil(t, e)
			break loop
		case <-ticker.C:
		}
		ticks++
		if tickLimit == ticks {
			assert.FailNow(t, "Did not receive expected error in 10s")
			break loop
		}
	}
	select {
	case <-doneCh:
		assert.False(t, true, "Received unexpected done signal")
	default:
	}
}

func pollDone(t *testing.T, doneCh <-chan struct{}, errCh <-chan error) {
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
			assert.FailNow(t, "Did not receive expected error in 10s")
			break loop
		}
	}
	select {
	case e := <-errCh:
		assert.Nil(t, e, "Received unexpected error from good transaction")
	default:
	}
}

func testFile(t *testing.T, f string, shouldExist bool) {
	_, err := os.Stat(f)

	if false == shouldExist {
		assert.NotNil(t, err)
		assert.True(t, os.IsNotExist(err))
	} else {
		assert.Nil(t, err)
		if nil != err {
			assert.False(t, os.IsNotExist(err))
		}
	}
}

func TestConfigWriterGetters(t *testing.T) {
	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	defer cw.Stop()

	f := cw.GetOutputFilename()

	dir := filepath.Dir(f)
	_, err = os.Stat(dir)
	assert.NoError(t, err)
}

func TestConfigWriterCreateStop(t *testing.T) {
	curGoroutines := runtime.NumGoroutine()

	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	f := cw.GetOutputFilename()
	testFile(t, f, false)

	checkGoroutines(t, curGoroutines+1)

	cw.Stop()
	checkGoroutines(t, curGoroutines)

	// Maybe overdone here but stopping and writing multiple times to ensure
	// there isn't a deadlock lurking in the Stop functionality.
	cw.SendSection("write-after-stop", struct{}{})
	cw.Stop()
	cw.SendSection("write-after-stop", struct{}{})
	cw.Stop()
	cw.SendSection("write-after-stop", struct{}{})
	checkGoroutines(t, curGoroutines)
}

func TestConfigWriterBadJson(t *testing.T) {
	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	f := cw.GetOutputFilename()

	defer func() {
		cw.Stop()
		_, err := os.Stat(f)
		assert.False(t, os.IsExist(err))
	}()

	badJson := map[struct{ key string }]string{
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

	doneCh, errCh, err := cw.SendSection("bad", badJson)
	assert.Nil(t, err)

	pollError(t, doneCh, errCh)
}

func TestConfigWriterSimpleWrite(t *testing.T) {
	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	f := cw.GetOutputFilename()

	defer func() {
		cw.Stop()
		_, err := os.Stat(f)
		assert.False(t, os.IsExist(err))
	}()

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

	testFile(t, f, false)

	doneCh, errCh, err := cw.SendSection("", testData.Test)
	assert.Nil(t, doneCh)
	assert.Nil(t, errCh)
	assert.NotNil(t, err)

	testFile(t, f, false)

	doneCh, errCh, err = cw.SendSection("simple-test", testData.Test)
	assert.Nil(t, err)

	pollDone(t, doneCh, errCh)

	testFile(t, f, true)

	expected, err := json.Marshal(testData)
	assert.Nil(t, err)

	written, err := ioutil.ReadFile(f)
	assert.Nil(t, err)

	assert.EqualValues(t, expected, written)

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
	assert.Nil(t, err)

	pollDone(t, doneCh, errCh)

	testFile(t, f, true)

	expected, err = json.Marshal(empty)
	assert.Nil(t, err)

	written, err = ioutil.ReadFile(f)
	assert.Nil(t, err)

	assert.EqualValues(t, expected, written)

	// add section back
	doneCh, errCh, err = cw.SendSection("simple-test", testData.Test)
	assert.Nil(t, err)

	pollDone(t, doneCh, errCh)

	testFile(t, f, true)

	expected, err = json.Marshal(testData)
	assert.Nil(t, err)

	written, err = ioutil.ReadFile(f)
	assert.Nil(t, err)

	assert.EqualValues(t, expected, written)
}

func TestConfigWriterConcurrentWrite(t *testing.T) {
	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	f := cw.GetOutputFilename()

	defer func() {
		cw.Stop()
		_, err := os.Stat(f)
		assert.True(t, os.IsNotExist(err))
	}()

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
			doneCh, errCh, err := cw.SendSection(field, data)
			assert.Nil(t, err)

			pollDone(t, doneCh, errCh)

			testFile(t, f, true)

			wg.Done()
		}(k, v)
	}
	wg.Wait()

	expected, err := json.Marshal(testData)
	assert.Nil(t, err)

	written, err := ioutil.ReadFile(f)
	assert.Nil(t, err)

	assert.EqualValues(t, expected, written)
}

func TestConfigWriterWriteFailOpen(t *testing.T) {
	cw := &configWriter{
		configFile: "/this-file/really/probably/will/not/exist",
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	var wrote bool
	var err error
	require.NotPanics(t, func() {
		wrote, err = cw.lockAndWrite([]byte("hello"))
	})
	assert.False(t, wrote)
	assert.Error(t, err)

	expected := "open /this-file/really/probably/will/not/exist: no such file or directory"
	assert.Equal(t, expected, err.Error())
}

func TestConfigWriterFailLock(t *testing.T) {
	cw := &configWriter{
		configFile: "/this-file/really/probably/will/not/exist",
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	// go does not have an idea of a File interface, doing the best
	// we can to try and create some negative behaviors
	mockFile := newPseudoFile(t, failLock)
	require.NotNil(t, mockFile)
	defer func() {
		err := mockFile.RealFile.Close()
		assert.NoError(t, err)

		os.Remove(mockFile.RealFile.Name())
	}()

	var wrote bool
	var err error
	require.NotPanics(t, func() {
		wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
	})
	assert.False(t, wrote)
	assert.Error(t, err)

	expected := "bad file descriptor"
	assert.Equal(t, expected, err.Error())
}

func TestConfigWriterFailUnlock(t *testing.T) {
	cw := &configWriter{
		configFile: "/this-file/really/probably/will/not/exist",
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	// go does not have an idea of a File interface, doing the best
	// we can to try and create some negative behaviors
	mockFile := newPseudoFile(t, failUnlock)
	require.NotNil(t, mockFile)
	defer func() {
		err := mockFile.RealFile.Close()
		assert.NoError(t, err)

		os.Remove(mockFile.RealFile.Name())
	}()

	var wrote bool
	var err error
	require.NotPanics(t, func() {
		wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
	})
	assert.False(t, wrote)
	assert.Error(t, err)

	expected := "bad file descriptor"
	assert.Equal(t, expected, err.Error())
}

func TestConfigWriterFailTrunc(t *testing.T) {
	cw := &configWriter{
		configFile: "/this-file/really/probably/will/not/exist",
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	// go does not have an idea of a File interface, doing the best
	// we can to try and create some negative behaviors
	mockFile := newPseudoFile(t, failTruncate)
	require.NotNil(t, mockFile)
	defer func() {
		err := mockFile.RealFile.Close()
		assert.NoError(t, err)

		os.Remove(mockFile.RealFile.Name())
	}()

	var wrote bool
	var err error
	require.NotPanics(t, func() {
		wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
	})
	assert.False(t, wrote)
	assert.Error(t, err)

	expected := "mock file truncate error"
	assert.Equal(t, expected, err.Error())
}

func TestConfigWriterFailWrite(t *testing.T) {
	cw := &configWriter{
		configFile: "/this-file/really/probably/will/not/exist",
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	// go does not have an idea of a File interface, doing the best
	// we can to try and create some negative behaviors
	mockFile := newPseudoFile(t, failWrite)
	require.NotNil(t, mockFile)
	defer func() {
		err := mockFile.RealFile.Close()
		assert.NoError(t, err)

		os.Remove(mockFile.RealFile.Name())
	}()

	var wrote bool
	var err error
	require.NotPanics(t, func() {
		wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
	})
	assert.False(t, wrote)
	assert.Error(t, err)

	expected := "mock file write error"
	assert.Equal(t, expected, err.Error())
}

func TestConfigWriterFailShortWrite(t *testing.T) {
	cw := &configWriter{
		configFile: "/this-file/really/probably/will/not/exist",
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	// go does not have an idea of a File interface, doing the best
	// we can to try and create some negative behaviors
	mockFile := newPseudoFile(t, failShortWrite)
	require.NotNil(t, mockFile)
	defer func() {
		err := mockFile.RealFile.Close()
		assert.NoError(t, err)

		os.Remove(mockFile.RealFile.Name())
	}()

	var wrote bool
	var err error
	require.NotPanics(t, func() {
		wrote, err = cw._lockAndWrite(mockFile, []byte("hello"))
	})
	assert.True(t, wrote)
	assert.Error(t, err)

	expected := "mock file short write"
	assert.Equal(t, expected, err.Error())
}
