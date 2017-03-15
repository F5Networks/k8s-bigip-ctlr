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

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockOut struct{}

func (mo MockOut) Write(p []byte) (n int, err error) {
	return
}

func resetFlags() {
	pythonBaseDir = new(string)
	logLevel = new(string)
	verifyInterval = new(int)

	namespace = new(string)
	useNodeInternal = new(bool)
	poolMemberType = new(string)
	inCluster = new(bool)
	kubeConfig = new(string)

	bigIPURL = new(string)
	bigIPUsername = new(string)
	bigIPPassword = new(string)
	bigIPPartitions = &[]string{}

	openshiftSDNMode = ""
	openshiftSDNName = new(string)

	// package variables
	isNodePort = false
}

func TestConfigSetup(t *testing.T) {
	configWriter := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}

	type ConfigTest struct {
		Global globalSection `json:"global"`
		BigIP  bigIPSection  `json:"bigip"`
	}

	expected := ConfigTest{
		BigIP: bigIPSection{
			BigIPUsername: "colonel atari",
			BigIPPassword: "dexter",
			BigIPURL:      "https://bigip.example.com",
			BigIPPartitions: []string{
				"k8s",
				"openshift",
				"marathon",
			},
		},
		Global: globalSection{
			LogLevel:       "WARNING",
			VerifyInterval: 10101,
		},
	}

	err := initializeDriverConfig(nil, expected.Global, expected.BigIP)
	assert.Error(t, err)

	err = initializeDriverConfig(
		configWriter,
		expected.Global,
		expected.BigIP,
	)
	assert.NoError(t, err)

	configWriter.Lock()
	assert.Contains(t, configWriter.Sections, "bigip")
	assert.Contains(t, configWriter.Sections, "global")

	actual := ConfigTest{
		configWriter.Sections["global"].(globalSection),
		configWriter.Sections["bigip"].(bigIPSection),
	}
	configWriter.Unlock()

	assert.EqualValues(t, expected, actual)
}

func TestDriverCmd(t *testing.T) {
	pyDriver := "/tmp/some-dir/test-driver.py"

	configFile := fmt.Sprintf("/tmp/k8s-bigip-ctlr.config.%d.json",
		os.Getpid())

	pythonPath, err := exec.LookPath("python")
	assert.NoError(t, err, "We should find python")

	cmd := createDriverCmd(
		configFile,
		pyDriver,
	)

	require.NotNil(t, cmd, "Command should not be nil")
	require.NotNil(t, cmd.Path, "Path should not be nil")
	require.Equal(t, cmd.Path, pythonPath, "The command path should be python")

	args := []string{
		"python",
		pyDriver,
		"--config-file", configFile,
	}
	require.EqualValues(t, cmd.Args, args, "We should get expected args list")
}

func TestDriverSubProcess(t *testing.T) {
	configWriter := &test.MockWriter{
		FailStyle: test.Success,
		Sections:  make(map[string]interface{}),
	}

	type ConfigTest struct {
		Global globalSection `json:"global"`
		BigIP  bigIPSection  `json:"bigip"`
	}

	expected := ConfigTest{
		BigIP: bigIPSection{
			BigIPUsername: "admin",
			BigIPPassword: "test",
			BigIPURL:      "https://bigip.example.com",
			BigIPPartitions: []string{
				"velcro1",
				"velcro2",
			},
		},
		Global: globalSection{
			LogLevel:       "INFO",
			VerifyInterval: 30,
		},
	}

	err := initializeDriverConfig(
		configWriter,
		expected.Global,
		expected.BigIP,
	)
	assert.NoError(t, err)

	configWriter.Lock()
	assert.Contains(t, configWriter.Sections, "bigip")
	assert.Contains(t, configWriter.Sections, "global")

	actual := ConfigTest{
		configWriter.Sections["global"].(globalSection),
		configWriter.Sections["bigip"].(bigIPSection),
	}
	configWriter.Unlock()

	assert.EqualValues(t, expected, actual)

	subPidCh := make(chan int)

	pyDriver := "./test/pyTest.py"

	configFile := configWriter.GetOutputFilename()

	cmd := createDriverCmd(
		configFile,
		pyDriver,
	)
	go runBigIPDriver(subPidCh, cmd)
	pid := <-subPidCh

	time.Sleep(time.Second)

	assert.NotEqual(t, pid, 0, "Pid should be set and not nil value")

	proc, err := os.FindProcess(pid)
	assert.NoError(t, err)
	assert.NotNil(t, proc, "Should have process object")

	done := make(chan error)

	go func() {
		count := 0
		var testErr error
	forever:
		for {
			count++
			cmd := exec.Command("bash", []string{"test/testPyTest.sh"}...)
			err = cmd.Start()
			if err != nil {
				testErr = errors.New("Should not error starting bash command")
				break forever
			}
			err = cmd.Wait()
			if _, ok := err.(*exec.ExitError); ok {
				break forever
			}

			if count == 30 {
				testErr = errors.New("Timed out waiting for process to stop")
				break forever
			}

			<-time.After(time.Second)
		}

		done <- testErr
	}()

	err = proc.Signal(os.Interrupt)
	require.NoError(t, err)

	err = <-done
	require.NoError(t, err)
}

func TestVerifyArgs(t *testing.T) {
	os.Args = []string{
		"./bin/k8s-bigip-ctlr",
		"--namespace=testing",
		"--bigip-partition=velcro1",
		"--bigip-partition=velcro2",
		"--bigip-password=admin",
		"--bigip-url=bigip.example.com",
		"--bigip-username=admin"}

	flags.Parse(os.Args)
	argError := verifyArgs()
	assert.Nil(t, argError, "there should not be an error")
	assert.Equal(t, "testing", *namespace, "namespace flag not parsed correctly")
	assert.Equal(t, "https://bigip.example.com", *bigIPURL, "bigipUrl flag not parsed correctly")
	assert.Equal(t, "admin", *bigIPUsername, "bigipUsername flag not parsed correctly")
	assert.Equal(t, "admin", *bigIPPassword, "bigipPassword flag not parsed correctly")
	assert.Equal(t, []string{"velcro1", "velcro2"}, *bigIPPartitions, "bigipPartitions flag not parsed correctly")
	assert.Equal(t, "INFO", *logLevel, "logLevel flag not parsed correctly")

	// Test url variations
	os.Args[5] = "--bigip-url=fail://bigip.example.com"
	flags.Parse(os.Args)
	argError = verifyArgs()
	assert.Error(t, argError, fmt.Sprintf("BIGIP-URL should fail with incorrect scheme 'fail://'"))

	os.Args[5] = "--bigip-url=https://bigip.example.com/some/path"
	flags.Parse(os.Args)
	argError = verifyArgs()
	assert.Error(t, argError, fmt.Sprintf("BIGIP-URL should fail with invalid path'"))

	// Test empty required args
	allArgs := map[string]*string{
		"namespace":     namespace,
		"bigipUrl":      bigIPURL,
		"bigipUsername": bigIPUsername,
		"bigipPassword": bigIPPassword,
		"logLevel":      logLevel,
	}

	for argName, arg := range allArgs {
		holder := *arg
		*arg = ""
		argError = verifyArgs()
		assert.Error(t, argError, fmt.Sprintf("Argument %s is required, and should not allow an empty string", argName))
		*arg = holder
	}

	// Test bigIPPartitions seperatly as it's a string array
	holder := *bigIPPartitions
	*bigIPPartitions = []string{}
	argError = verifyArgs()
	assert.Error(t, argError, "Argument bigIPPartitions is required, and should not allow an empty string")
	*bigIPPartitions = holder
}

func TestOpenshiftSDNFlags(t *testing.T) {
	os.Args = []string{
		"./bin/k8s-bigip-ctlr",
		"--namespace=testing",
		"--bigip-partition=velcro1",
		"--bigip-partition=velcro2",
		"--bigip-password=admin",
		"--bigip-url=bigip.example.com",
		"--bigip-username=admin",
	}

	flags.Parse(os.Args)
	err := verifyArgs()
	assert.NoError(t, err)

	assert.Equal(t, 0, len(openshiftSDNMode),
		"Mode variable should not be set")
	assert.Equal(t, 0, len(*openshiftSDNName),
		"Name variable should not be set")

	os.Args = []string{
		"./bin/k8s-bigip-ctlr",
		"--namespace=testing",
		"--bigip-partition=velcro1",
		"--bigip-partition=velcro2",
		"--bigip-password=admin",
		"--bigip-url=bigip.example.com",
		"--bigip-username=admin",
		"--openshift-sdn-name=vxlan500",
	}

	flags.Parse(os.Args)
	err = verifyArgs()
	assert.NoError(t, err)

	assert.Equal(t, "maintain", openshiftSDNMode,
		"Mode variable should be set to maintain")
	assert.Equal(t, "vxlan500", *openshiftSDNName,
		"VxLAN name should be set")
}

func TestOpenshiftSDNFlagEmpty(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"./bin/k8s-bigip-ctlr",
		"--namespace=testing",
		"--bigip-partition=velcro1",
		"--bigip-partition=velcro2",
		"--bigip-password=admin",
		"--bigip-url=bigip.example.com",
		"--bigip-username=admin",
		"--openshift-sdn-name",
	}

	var called bool
	oldUsage := flags.Usage
	defer func() {
		flags.Usage = oldUsage
	}()
	flags.Usage = func() {
		called = true
	}

	flags.SetOutput(MockOut{})
	defer flags.SetOutput(os.Stderr)

	err := flags.Parse(os.Args)
	assert.Error(t, err)
	assert.True(t, called)

	assert.Equal(t, 0, len(*openshiftSDNName))
}
