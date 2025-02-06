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

package controller

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/health"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/writer"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
)

func initializeDriverConfig(
	configWriter writer.Writer,
	global globalSection,
	bigIP bigIPSection,
	gtm gtmBigIPSection,
) error {
	if nil == configWriter {
		return fmt.Errorf("config writer argument cannot be nil")
	}

	sections := make(map[string]interface{})

	sections["global"] = global
	sections["bigip"] = bigIP
	if global.GTM {
		sections["gtm_bigip"] = gtm
	}
	if global.MultiClusterMode == SecondaryCIS {
		//Initially set the primary cluster status as true before init
		sections["primary-cluster-status"] = true
	}
	for k, v := range sections {
		doneCh, errCh, err := configWriter.SendSection(k, v)
		if nil != err {
			return fmt.Errorf("failed writing global config section: %v", err)
		}
		select {
		case <-doneCh:
		case e := <-errCh:
			return fmt.Errorf("failed writing section %s - %v: %v",
				k, e, v)
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
		cmdName := "python"
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
	cmdOut, err := cmd.StderrPipe()
	scanOut := bufio.NewScanner(cmdOut)
	go func() {
		for true {
			if scanOut.Scan() {
				if strings.Contains(scanOut.Text(), "DEBUG]") {
					log.Debug(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "WARNING]") {
					log.Warning(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "ERROR]") {
					log.Error(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "CRITICAL]") {
					log.Critical(scanOut.Text())
				} else if strings.Contains(scanOut.Text(), "INFO]") && (strings.Contains(scanOut.Text(), "Creating") ||
					strings.Contains(scanOut.Text(), "Updating") ||
					strings.Contains(scanOut.Text(), "Deleting")) {
					log.Info(scanOut.Text())
				} else {
					// moving cccl info level logs to debug
					log.Debug(scanOut.Text())
				}
			} else {
				break
			}
		}
	}()

	err = cmd.Start()
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
func (agent *Agent) startPythonDriver(
	global globalSection,
	bigIP bigIPSection,
	gtmBigIP gtmBigIPSection,
	pythonBaseDir string,
) {
	var pyCmd string

	err := initializeDriverConfig(agent.ConfigWriter, global, bigIP, gtmBigIP)
	if nil != err {
		log.Fatalf("Could not initialize subprocess configuration: %v", err)
		return
	}

	subPidCh := make(chan int)
	if len(pythonBaseDir) != 0 && pythonBaseDir != "/app/python" {
		log.Warning("DEPRECATED: python-basedir: option may no longer work as expected.")
		pyCmd = fmt.Sprintf("%s/bigipconfigdriver.py", pythonBaseDir)
	} else {
		pyCmd = "bigipconfigdriver.py"
	}
	cmd := createDriverCmd(
		agent.ConfigWriter.GetOutputFilename(),
		pyCmd,
	)
	go runBigIPDriver(subPidCh, cmd)

	subPid := <-subPidCh
	agent.PythonDriverPID = subPid
	//Enable "/health" and "/metrics" endpoint with controller
	go agent.healthCheckPythonDriver()

	return
}

func (agent *Agent) stopPythonDriver() {
	if 0 != agent.PythonDriverPID {
		var proc *os.Process
		proc, err := os.FindProcess(agent.PythonDriverPID)
		if nil != err {
			log.Warningf("Failed to find sub-process on exit: %v", err)
		}
		err = proc.Signal(os.Interrupt)
		if nil != err {
			log.Warningf("Could not stop sub-process on exit: %d - %v", agent.PythonDriverPID, err)
		}
	}
}

func (agent *Agent) healthCheckPythonDriver() {
	// Expose Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	// Add health check to track whether Python process still alive
	hc := &health.HealthChecker{
		SubPID: agent.PythonDriverPID,
	}
	http.Handle("/health", hc.HealthCheckHandler())
	bigIPPrometheus.RegisterMetrics(agent.PostManager.HTTPClientMetrics)
	log.Fatal(http.ListenAndServe(agent.HttpAddress, nil).Error())
}

func (agent *Agent) enableMetrics() {
	// Expose Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	bigIPPrometheus.RegisterMetrics(agent.PostManager.HTTPClientMetrics)
	log.Fatal(http.ListenAndServe(agent.HttpAddress, nil).Error())
}
