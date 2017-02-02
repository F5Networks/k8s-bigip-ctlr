package writer

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestSubSection struct {
	SubField1 string `json:"sub-field1-str,omitempty"`
	SubField2 int    `json:"sub-field2-int,omitempty"`
}
type TestSection struct {
	Field1 string          `json:"field1-str,omitempty"`
	Field2 int             `json:"field2-int,omitempty"`
	Field3 *TestSubSection `json:"field3-struct,omitempty"`
}

type SimpleTest struct {
	Test TestSection `json:"simple-test"`
}

func checkStop(t *testing.T, expectedRoutines int) {
	ticks := 0
	tickLimit := 10
	ticker := time.NewTicker(100 * time.Millisecond)

	if expectedRoutines == runtime.NumGoroutine() {
		assert.Equal(t, expectedRoutines, runtime.NumGoroutine())
	} else {
		for _ = range ticker.C {
			runtime.Gosched()

			if expectedRoutines == runtime.NumGoroutine() {
				break
			}

			ticks++
			if tickLimit == ticks {
				break
			}
		}
	}
	assert.Equal(t, expectedRoutines, runtime.NumGoroutine())
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
	expect := "/tmp/f5-k8s-controller.config." + strconv.Itoa(os.Getpid()) + ".json"

	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	cw.configFile = expect

	f := cw.GetOutputFilename()

	assert.Equal(t, expect, f)
}

func TestConfigWriterCreateStop(t *testing.T) {
	curGoroutines := runtime.NumGoroutine()

	cw, err := NewConfigWriter()
	assert.Nil(t, err)
	require.NotNil(t, cw)

	f := cw.GetOutputFilename()
	testFile(t, f, false)

	assert.Equal(t, curGoroutines+1, runtime.NumGoroutine())

	cw.Stop()
	checkStop(t, curGoroutines)

	// Maybe overdone here but stopping multiple times to ensure there isn't
	// a deadlock lurking in the Stop functionality.
	cw.Stop()
	cw.Stop()
	checkStop(t, curGoroutines)
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

	select {
	case e := <-errCh:
		assert.NotNil(t, e)
	case <-time.After(time.Second):
		assert.False(t, true, "Timed out expecting an error")
	}

	select {
	case <-doneCh:
		assert.False(t, true, "Received unexpected done signal")
	case <-time.After(time.Second):
	}
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

	testData := SimpleTest{
		Test: TestSection{
			Field1: "test-field1",
			Field2: 121232343,
			Field3: &TestSubSection{
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

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		assert.False(t, true, "Timed out expecting a done signal")
	}

	select {
	case e := <-errCh:
		assert.Nil(t, e, "Received unexpected error from good transaction")
	case <-time.After(time.Second):
	}

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

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		assert.False(t, true, "Timed out expecting a done signal")
	}

	select {
	case e := <-errCh:
		assert.Nil(t, e, "Received unexpected error from good transaction")
	case <-time.After(time.Second):
	}

	testFile(t, f, true)

	expected, err = json.Marshal(empty)
	assert.Nil(t, err)

	written, err = ioutil.ReadFile(f)
	assert.Nil(t, err)

	assert.EqualValues(t, expected, written)

	// add section back
	doneCh, errCh, err = cw.SendSection("simple-test", testData.Test)
	assert.Nil(t, err)

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		assert.False(t, true, "Timed out expecting a done signal")
	}

	select {
	case e := <-errCh:
		assert.Nil(t, e, "Received unexpected error from good transaction")
	case <-time.After(time.Second):
	}

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

	testData := map[string]TestSection{
		"concurrent-1": TestSection{
			Field1: "concur1-field1",
			Field2: 121232343,
			Field3: &TestSubSection{
				SubField1: "concur1-sub-field1",
				SubField2: 42,
			},
		},
		"concurrent-2": TestSection{
			Field1: "concur2-field1",
			Field2: 9999,
			Field3: &TestSubSection{
				SubField1: "concur2-sub-field1",
				SubField2: 1111,
			},
		},
		"concurrent-3": TestSection{
			Field1: "concur3-field1",
			Field2: 2222,
			Field3: &TestSubSection{
				SubField1: "concur3-sub-field1",
				SubField2: 10101,
			},
		},
		"concurrent-4": TestSection{
			Field1: "concur4-field1",
			Field2: 333444,
			Field3: &TestSubSection{
				SubField1: "concur4-sub-field1",
				SubField2: 222211114,
			},
		},
		"concurrent-5": TestSection{
			Field1: "concur5-field1",
			Field2: 1,
			Field3: &TestSubSection{
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

			select {
			case <-doneCh:
			case <-time.After(time.Second):
				assert.False(t, true, "Timed out expecting a done signal")
			}

			select {
			case e := <-errCh:
				assert.Nil(t, e, "Received unexpected error from good transaction")
			case <-time.After(time.Second):
			}

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
