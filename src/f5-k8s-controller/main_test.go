package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDriverCmd(t *testing.T) {
	username := "admin"
	password := "test"
	partitions := []string{"velcro1", "velcro2"}
	url := "https://bigip.example.com"
	verify := "30"
	log := "INFO"
	pyDriver := "/tmp/some-dir/test-driver.py"

	configFile := fmt.Sprintf("/tmp/f5-k8s-controller.config.%d.json",
		os.Getpid())

	pythonPath, err := exec.LookPath("python")
	assert.Nil(t, err, "We should find python")

	cmd := createDriverCmd(
		partitions,
		username,
		password,
		url,
		configFile,
		verify,
		log,
		pyDriver,
	)

	require.NotNil(t, cmd, "Command should not be nil")
	require.NotNil(t, cmd.Path, "Path should not be nil")
	require.Equal(t, cmd.Path, pythonPath, "The command path should be python")

	args := []string{
		"python",
		pyDriver,
		"--username", username,
		"--password", password,
		"--url", url,
		"--config-file", configFile,
		"--verify-interval", "30",
		"--log-level", log,
		strings.Join(partitions, " ")}
	require.EqualValues(t, cmd.Args, args, "We should get expected args list")
}

func TestDriverSubProcess(t *testing.T) {
	subPidCh := make(chan int)

	username := "admin"
	password := "test"
	partitions := []string{"velcro1", "velcro2"}
	url := "https://bigip.example.com"
	verify := "30"
	log := "INFO"
	pyDriver := "./test/pyTest.py"

	configFile := fmt.Sprintf("/tmp/f5-k8s-controller.config.%d.json",
		os.Getpid())

	cmd := createDriverCmd(
		partitions,
		username,
		password,
		url,
		configFile,
		verify,
		log,
		pyDriver,
	)
	go runBigIpDriver(subPidCh, cmd)
	pid := <-subPidCh

	time.Sleep(time.Second)

	assert.NotEqual(t, pid, 0, "Pid should be set and not nil value")

	proc, err := os.FindProcess(pid)
	assert.NoError(t, err)
	assert.NotNil(t, proc, "Should have process object")

	done := make(chan error)

	go func() {
		count := 0
		var testErr error = nil
	forever:
		for {
			count += 1
			cmd := exec.Command("bash", []string{"test/testPyTest.sh"}...)
			err := cmd.Start()
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
		"./bin/f5-k8s-controller",
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
	assert.Equal(t, "https://bigip.example.com", *bigipUrl, "bigipUrl flag not parsed correctly")
	assert.Equal(t, "admin", *bigipUsername, "bigipUsername flag not parsed correctly")
	assert.Equal(t, "admin", *bigipPassword, "bigipPassword flag not parsed correctly")
	assert.Equal(t, []string{"velcro1", "velcro2"}, *bigipPartitions, "bigipPartitions flag not parsed correctly")
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
		"bigipUrl":      bigipUrl,
		"bigipUsername": bigipUsername,
		"bigipPassword": bigipPassword,
		"logLevel":      logLevel,
	}

	for argName, arg := range allArgs {
		holder := *arg
		*arg = ""
		argError = verifyArgs()
		assert.Error(t, argError, fmt.Sprintf("Argument %s is required, and should not allow an empty string", argName))
		*arg = holder
	}

	// Test bigipPartitions seperatly as it's a string array
	holder := *bigipPartitions
	*bigipPartitions = []string{}
	argError = verifyArgs()
	assert.Error(t, argError, "Argument bigipPartitions is required, and should not allow an empty string")
	*bigipPartitions = holder
}
