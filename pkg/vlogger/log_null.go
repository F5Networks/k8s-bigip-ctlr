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

// log_null.go:
//
//	Turns off all logging.
package vlogger

import "log/syslog"

type (
	nullLogger struct {
		slLogLevel syslog.Priority
	}
)

// newNullLogger creates a logger object that drops all log messages.
func newNullLogger() *nullLogger {
	return &nullLogger{
		slLogLevel: syslog.LOG_DEBUG,
	}
}

func init() {
	// Keeps the global interface from starting out with an
	// undefined implementation.
	RegisterLogger(LL_MIN_LEVEL, LL_MAX_LEVEL, newNullLogger())
}

func (cl *nullLogger) Debug(msg string)                               {}
func (cl *nullLogger) Debugf(format string, params ...interface{})    {}
func (cl *nullLogger) Info(msg string)                                {}
func (cl *nullLogger) Infof(format string, params ...interface{})     {}
func (cl *nullLogger) Warning(msg string)                             {}
func (cl *nullLogger) Warningf(format string, params ...interface{})  {}
func (cl *nullLogger) Error(msg string)                               {}
func (cl *nullLogger) Errorf(format string, params ...interface{})    {}
func (cl *nullLogger) Critical(msg string)                            {}
func (cl *nullLogger) Criticalf(format string, params ...interface{}) {}
func (cl *nullLogger) Close()                                         {}
func (cl *nullLogger) SetLogLevel(slLogLevel syslog.Priority) {
	cl.slLogLevel = slLogLevel
}
func (cl *nullLogger) GetLogLevel() syslog.Priority {
	return cl.slLogLevel
}
