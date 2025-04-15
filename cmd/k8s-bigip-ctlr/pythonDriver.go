/*-
 * Copyright (c) 2019-2021, F5 Networks, Inc.
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
	"bufio"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/securecreds"
	"os/exec"
	"strings"
	"syscall"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"
)

func initializeDriverConfig(
	configWriter writer.Writer,
	global globalSection,
	bigIP bigIPSection,
) error {
	if nil == configWriter {
		return fmt.Errorf("config writer argument cannot be nil")
	}

	sectionNames := []string{"global", "bigip"}
	for i, v := range []interface{}{global, bigIP} {
		doneCh, errCh, err := configWriter.SendSection(sectionNames[i], v)
		if nil != err {
			return fmt.Errorf("failed writing global config section: %v", err)
		}
		select {
		case <-doneCh:
		case e := <-errCh:
			return fmt.Errorf("failed writing section %s - %v: %v",
				sectionNames[i], e, v)
		case <-time.After(1000 * time.Millisecond):
			log.Warning("Did not receive config write response in 1 second")
		}
	}

	return nil
}

func createDriverCmd(
	configFilename string,
	pyCmd string,
) *exec.Cmd {
	var cmd *exec.Cmd

	if pyCmd == "bigipconfigdriver.py" {
		cmdArgs := []string{
			"--config-file", configFilename,
			"--ctlr-prefix", "k8s"}
		cmd = exec.Command(pyCmd, cmdArgs...)
	} else {
		cmdName := "python3"
		cmdArgs := []string{
			pyCmd,
			"--config-file", configFilename,
			"--ctlr-prefix", "k8s"}
		cmd = exec.Command(cmdName, cmdArgs...)
	}

	return cmd
}

func runBigIPDriver(pid chan<- int, cmd *exec.Cmd) {
	defer close(pid)

	// the config driver python logging goes to stderr by default
	cmdOut, _ := cmd.StderrPipe()
	go func() {
		bufsize := bufio.MaxScanTokenSize
		for {
			scanOut := bufio.NewScanner(cmdOut)
			scanOut.Buffer(make([]byte, 0, bufsize), bufsize)
			for scanOut.Scan() {
				if strings.Contains(scanOut.Text(), "DEBUG]") {
					log.Debug(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "WARNING]") {
					log.Warning(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "ERROR]") {
					log.Error(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "CRITICAL]") {
					log.Critical(scanOut.Text())
				} else {
					log.Info(scanOut.Text())
				}
			}
			if scanOut.Err() == bufio.ErrTooLong {
				bufsize *= 2
				log.Infof("Double the bufsize to %d", bufsize)
			} else {
				if scanOut.Err() != nil {
					log.Errorf("unexpected error: %s", scanOut.Err().Error())
				}
				break
			}
		}
	}()

	err := cmd.Start()
	if nil != err {
		log.Fatalf("Internal error: failed to start config driver: %v", err)
	}
	log.Infof("Started config driver sub-process at pid: %d", cmd.Process.Pid)

	pid <- cmd.Process.Pid

	err = cmd.Wait()
	var waitStatus syscall.WaitStatus
	if exitError, ok := err.(*exec.ExitError); ok {
		waitStatus = exitError.Sys().(syscall.WaitStatus)
		if waitStatus.Signaled() {
			log.Fatalf("Config driver signaled to stop: %d - %s",
				waitStatus.Signal(), waitStatus.Signal())
		} else {
			log.Fatalf("Config driver exited: %d", waitStatus.ExitStatus())
		}
	} else if nil != err {
		log.Fatalf("Config driver exited with error: %v", err)
	} else {
		waitStatus = cmd.ProcessState.Sys().(syscall.WaitStatus)
		log.Warningf("Config driver exited normally: %d", waitStatus.ExitStatus())
	}
}

// Start called to run the python driver
func startPythonDriver(
	configWriter writer.Writer,
	global globalSection,
	bigIP bigIPSection,
	bigIPUserName string,
	bigIPPassword string,
	pythonBaseDir string,
) (<-chan int, error) {
	var pyCmd string

	// Start a goroutine to handle credential requests from the Python driver
	go securecreds.HandleCredentialsRequest(bigIPUserName, bigIPPassword, "", "")

	err := initializeDriverConfig(configWriter, global, bigIP)
	if nil != err {
		return nil, err
	}

	subPidCh := make(chan int)
	if len(pythonBaseDir) != 0 && pythonBaseDir != "/app/python" {
		log.Warning("DEPRECATED: python-basedir: option may no longer work as expected.")
		pyCmd = fmt.Sprintf("%s/bigipconfigdriver.py", pythonBaseDir)
	} else {
		pyCmd = "bigipconfigdriver.py"
	}
	cmd := createDriverCmd(
		configWriter.GetOutputFilename(),
		pyCmd,
	)

	go runBigIPDriver(subPidCh, cmd)

	return subPidCh, nil
}
