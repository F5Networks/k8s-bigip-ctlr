// +gocover:ignore:file logging package
// Copyright (c) 2019-2021, F5 Networks, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// log.go:
//
//	This module provides the generic interface that end-user libraries and apps should program to.
package vlogger

import (
	"fmt"
	"log/syslog" // For LOG level definitions
	"os"
	"strings"
)

// LogLevel is used for global (package-level) filtering of log messages based on their priority
// (this filtering is applied before all other filtering which might be provided by the concrete logger).
type LogLevel int

const (
	// Must be in sequential ascending order based on priority
	// (higher priorities have higher numeric values)
	LL_DEBUG = iota
	LL_INFO
	LL_WARNING
	LL_ERROR
	LL_CRITICAL
	LL_LOGLEVEL_SIZE

	LL_MIN_LEVEL = LL_DEBUG
	LL_MAX_LEVEL = LL_LOGLEVEL_SIZE - 1
)

// String converts a LogLevel to a string for serializing.
func (ll LogLevel) String() string {
	switch ll {
	case LL_DEBUG:
		return "debug"
	case LL_INFO:
		return "info"
	case LL_WARNING:
		return "warning"
	case LL_ERROR:
		return "error"
	case LL_CRITICAL:
		return "critical"
	default:
		return "invalid"
	}
}

// NewLogLevel converts a string to a log level.
func NewLogLevel(s string) *LogLevel {
	var r LogLevel
	s = strings.ToLower(s)
	switch s {
	case "":
		return nil
	case "as3debug":
		r = LL_DEBUG
	case "debug":
		r = LL_DEBUG
	case "info":
		r = LL_INFO
	case "warning":
		r = LL_WARNING
	case "error":
		r = LL_ERROR
	case "critical":
		r = LL_CRITICAL
	default:
		return nil
	}
	return &r
}

// MarshalJSON converts a LogLevel to a quoted string for JSON output.
func (ll LogLevel) MarshalJSON() ([]byte, error) {
	s := ll.String()
	return []byte("\"" + s + "\""), nil
}

func (ll *LogLevel) UnmarshalJSON(data []byte) error {
	s := string(data)
	s = strings.Trim(s, "\"")
	newll := NewLogLevel(s)
	if newll == nil {
		return fmt.Errorf("Unable to unmarshal %s to Log Level.", string(data))
	}
	*ll = *newll
	return nil
}

// Generic interface that all concrete loggers must implement.  Using this interface directly
// isolates user code from a particular logger implementation.
type (
	Logger interface {
		Debug(string)
		Debugf(string, ...interface{})
		Info(string)
		Infof(string, ...interface{})
		Warning(string)
		Warningf(string, ...interface{})
		Error(string)
		Errorf(string, ...interface{})
		Critical(string)
		Criticalf(string, ...interface{})
		GetLogLevel() syslog.Priority
		SetLogLevel(syslog.Priority)
		Close()
	}
)

var (
	// vlog specifies loggers associated with each log level (could all be the same logger).
	vlog [LL_LOGLEVEL_SIZE]Logger

	// logLevel indicates the current package-level filtering being applied
	// (may be further restricted by specific concrete loggers).
	logLevel LogLevel = LL_DEBUG

	// logLevelToSyslogLevel maps vlogger log levels to the internal representation used
	// by the implementations (which use syslog's definitions).
	logLevelToSyslogLevel = [LL_LOGLEVEL_SIZE]syslog.Priority{
		syslog.LOG_DEBUG,
		syslog.LOG_INFO,
		syslog.LOG_WARNING,
		syslog.LOG_ERR,
		syslog.LOG_CRIT,
	}
)

// RegisterLogger must be called to map a concrete logger object with each log level.
func RegisterLogger(minLogLevel, maxLogLevel LogLevel, log Logger) {
	for level := minLogLevel; level <= maxLogLevel; level++ {
		vlog[level] = log
	}
}

// Debug sends a message to the logger object to record debug/trace level statements
func Debug(msg string) {
	vlog[LL_DEBUG].Debug(msg)
}

// Debugf formats a message before sending it to the logger object to record
// debug/trace level statements
func Debugf(format string, params ...interface{}) {
	vlog[LL_DEBUG].Debugf(format, params...)
}

// Info sends a message to the logger object to record informational level statements
// (these should be statements that can normally be logged without causing performance
// issues).
func Info(msg string) {
	vlog[LL_INFO].Info(msg)
}

// Infof formats a message before sending it to the logger object to record
// informational level statements (there should be statements that can normally
// be logged without causing performance issues).
func Infof(format string, params ...interface{}) {
	vlog[LL_INFO].Infof(format, params...)
}

// Warning sends a message to the logger object to record warning level statements
// (these indication conditions that are unexpected or may cause issues but are not
// normally going to affect the program execution).
func Warning(msg string) {
	vlog[LL_WARNING].Warning(msg)
}

// Warningf formats a message before sending it to the logger object to record
// warning level statements (these indication conditions that are unexpected or
// may cause issues but are not normally going to affect the program execution).
func Warningf(format string, params ...interface{}) {
	vlog[LL_WARNING].Warningf(format, params...)
}

// Error sends a message to the logger object to record error level statements
// (these indicate conditions that should not occur and may indicate a failure
// in performing the requested action).
func Error(msg string) {
	vlog[LL_ERROR].Error(msg)
}

// Errorf formats a message before sending it to the logger object to record
// error level statements (these indicate conditions that should not occur
// and may indicate a failure in performing the requested action).
func Errorf(format string, params ...interface{}) {
	vlog[LL_ERROR].Errorf(format, params...)
}

// Critical sends a message to the logger object to record critical level statements
// (these indicate conditions that should never occur and might cause a failure/crash
// of the executing program or unexpected outcome from the requested action).
func Critical(msg string) {
	vlog[LL_CRITICAL].Critical(msg)
}

// Criticalf formats a message before sending it to the logger object to record
// critical level statements (these indicate conditions that should never occur
// and might cause a failure/crash of the executing program or unexpected
// outcome from the requested action).
func Criticalf(format string, params ...interface{}) {
	vlog[LL_CRITICAL].Criticalf(format, params...)
}

// Fatal sends a CRITICAL message to the logger object and then exits.
// NOTE: This call should not be made in packages that are meant to serve
// as libraries for other developers.
func Fatal(msg string) {
	vlog[LL_CRITICAL].Critical(msg)
	Close()
	os.Exit(1)
}

// Fatalf sends a formatted CRITICAL message to the logger object and then exits.
// NOTE: This call should not be made in packages that are meant to serve
// as libraries for other developers.
func Fatalf(format string, params ...interface{}) {
	vlog[LL_CRITICAL].Criticalf(format, params...)
	Close()
	os.Exit(1)
}

// Panic sends a CRITICAL message to the logger object and then calls panic.
// NOTE: This call should not be made in packages that are meant to serve
// as libraries for other developers.
func Panic(msg string) {
	vlog[LL_CRITICAL].Critical(msg)
	panic(msg)
}

// Panicf sends a formatted CRITICAL message to the logger object and then calls panic.
// NOTE: This call should not be made in packages that are meant to serve
// as libraries for other developers.
func Panicf(format string, params ...interface{}) {
	msg := fmt.Sprintf(format, params...)
	vlog[LL_CRITICAL].Critical(msg)
	panic(msg)
}

// SetLogLevel sets the current package-level filtering
func SetLogLevel(level LogLevel) {
	logLevel = level

	// Update all loggers to the new level
	slLogLevel := logLevelToSyslogLevel[logLevel]
	for i, _ := range vlog {
		if vlog[i] != nil {
			vlog[i].SetLogLevel(slLogLevel)
		}
	}
}

// GetLogLevel returns the current package-level filtering
func GetLogLevel() LogLevel {
	return logLevel
}

// Close informs the configured loggers that they are being closed and
// should cleanup (for instance, flushing any queued log messages)
func Close() {
	for i, _ := range vlog {
		if vlog[i] != nil {
			vlog[i].Close()
		}
	}
}
