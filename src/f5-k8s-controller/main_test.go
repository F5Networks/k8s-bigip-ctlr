package main

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDriverCmd(t *testing.T) {
	username := "admin"
	password := "test"
	partitions := []string{"velcro1", "velcro2"}
	url := "bigip.example.com"
	verify := "30"
	log := "INFO"
	pyDriver := "/tmp/some-dir/test-driver.py"

	configFile := fmt.Sprintf("/tmp/f5-k8s-controller.config.%d.json",
		os.Getpid())

	pythonPath, err := exec.LookPath("python")
	assert.Nil(t, err, "We should find python")

	cmd := createDriverCmd(partitions, username, password, url, verify, log, pyDriver)

	require.NotNil(t, cmd, "Command should not be nil")
	require.NotNil(t, cmd.Path, "Path should not be nil")
	require.Equal(t, cmd.Path, pythonPath, "The command path should be python")

	args := []string{
		"python",
		pyDriver,
		"--username", username,
		"--password", password,
		"--hostname", url,
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
	url := "bigip.example.com"
	verify := "30"
	log := "INFO"
	pyDriver := "./test/pyTest.py"

	cmd := createDriverCmd(partitions, username, password, url, verify, log, pyDriver)
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
