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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	pyCmd string,
) *exec.Cmd {
	var cmd *exec.Cmd

	if pyCmd == "bigipconfigdriver.py" {
		cmdArgs := []string{
			"--ctlr-prefix", "k8s"}
		cmd = exec.Command(pyCmd, cmdArgs...)
	} else {
		cmdName := "python"
		cmdArgs := []string{
			pyCmd,
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

// can you write a func for opening a unix socket which is used by python driver to request the credentials
func openUnixSocket(socketPath string) (*net.UnixListener, error) {
	// Create the Unix socket
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Unix address: %v", err)
	}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on Unix socket: %v", err)
	}

	// Set permissions on the socket file
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set permissions on socket file: %v", err)
	}

	return listener, nil
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
	cmd := createDriverCmd(pyCmd)

	// Start a goroutine to handle credential requests from the Python driver
	go agent.handleCredentialsRequest()

	go runBigIPDriver(subPidCh, cmd)

	subPid := <-subPidCh
	agent.PythonDriverPID = subPid
	//Enable "/health" and "/metrics" endpoint with controller
	go agent.healthCheckPythonDriver()

	return
}

// handleCredentialsRequest listens on a Unix socket for incoming connections,
// processes credential requests, and sends encrypted responses back to the Python driver.
// It uses AES-GCM encryption to securely transmit sensitive information.
func (agent *Agent) handleCredentialsRequest() {
	listener, err := openUnixSocket("/tmp/cis_socket")
	if err != nil {
		log.Fatalf("Failed to open Unix socket: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			log.Errorf("Failed to accept connection: %v", err)
			continue
		}
		handleConnection(conn)
	}
}

// handleConnection processes incoming connections on the Unix socket.
// It generates a dynamic key, encrypts credentials using AES-GCM,
// and sends the encrypted data along with the key back to the pythonDriver.
// This function ensures secure transmission of sensitive information
// between the CIS controller and the Python driver.
func handleConnection(conn *net.UnixConn) {
	defer conn.Close()

	key := generateDynamicKey()
	encryptedData, err := encryptCredentials(key)
	if err != nil {
		log.Errorf("Failed to encrypt credentials: %v", err)
		return
	}

	response := map[string]string{
		"key":            base64.StdEncoding.EncodeToString(key),
		"encrypted_data": base64.StdEncoding.EncodeToString(encryptedData),
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Failed to marshal response: %v", err)
		return
	}

	_, err = conn.Write(jsonResponse)
	if err != nil {
		log.Errorf("Failed to send response: %v", err)
		return
	}

	log.Debug("Successfully sent encrypted credentials")
}

// generateDynamicKey creates a random 32-byte key for AES encryption
// It returns the generated key or nil if there's an error
func generateDynamicKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Errorf("Failed to generate dynamic key: %v", err)
		return nil
	}
	return key
}

// encryptCredentials encrypts the credentials using AES-GCM
// and returns the encrypted data as a byte slice
func encryptCredentials(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to create nonce: %v", err)
	}

	credentials := getCredentials()
	plaintext, err := json.Marshal(credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credentials: %v", err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func getCredentials() struct {
	Username string
	Password string
} {
	return struct {
		Username string
		Password string
	}{
		Username: "your_username",
		Password: "*************",
	}
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
