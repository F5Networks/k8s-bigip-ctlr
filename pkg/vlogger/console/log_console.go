// Copyright 2018 F5 Networks
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

//log_console.go:
//  Provides console logging through the common interface.
//  To use, create the logger object with the following syntax:
//    NewConsoleLogger()
//
package console

import (
	"fmt"
	"log"
	"log/syslog"
)

type (
	consoleLogger struct {
		// slLogLevel uses syslog's definitions which have higher priority
		// levels defined in descending order (0 is highest)
		slLogLevel syslog.Priority
	}
)

// NewConsoleLogger creates a default logger object that prints log messages
// to the console.
func NewConsoleLogger() *consoleLogger {
	return &consoleLogger{
		slLogLevel: syslog.LOG_DEBUG,
	}
}

// NewConsoleLoggerExt() allows the user to create a customized logger
// that will then be used by the vlogger interface.
func NewConsoleLoggerExt(prefix string, flags int) *consoleLogger {
	log.SetPrefix(prefix)
	log.SetFlags(flags)
	return NewConsoleLogger()
}

func (cl *consoleLogger) Debug(msg string) {
	if cl.slLogLevel >= syslog.LOG_DEBUG {
		log.Println("[DEBUG]", msg)
	}
}

func (cl *consoleLogger) Debugf(format string, params ...interface{}) {
	if cl.slLogLevel >= syslog.LOG_DEBUG {
		msg := fmt.Sprintf(format, params...)
		log.Println("[DEBUG]", msg)
	}
}

func (cl *consoleLogger) Info(msg string) {
	if cl.slLogLevel >= syslog.LOG_INFO {
		log.Println("[INFO]", msg)
	}
}

func (cl *consoleLogger) Infof(format string, params ...interface{}) {
	if cl.slLogLevel >= syslog.LOG_INFO {
		msg := fmt.Sprintf(format, params...)
		log.Println("[INFO]", msg)
	}
}

func (cl *consoleLogger) Warning(msg string) {
	if cl.slLogLevel >= syslog.LOG_WARNING {
		log.Println("[WARNING]", msg)
	}
}

func (cl *consoleLogger) Warningf(format string, params ...interface{}) {
	if cl.slLogLevel >= syslog.LOG_WARNING {
		msg := fmt.Sprintf(format, params...)
		log.Println("[WARNING]", msg)
	}
}

func (cl *consoleLogger) Error(msg string) {
	if cl.slLogLevel >= syslog.LOG_ERR {
		log.Println("[ERROR]", msg)
	}
}

func (cl *consoleLogger) Errorf(format string, params ...interface{}) {
	if cl.slLogLevel >= syslog.LOG_ERR {
		msg := fmt.Sprintf(format, params...)
		log.Println("[ERROR]", msg)
	}
}

func (cl *consoleLogger) Critical(msg string) {
	if cl.slLogLevel >= syslog.LOG_CRIT {
		log.Println("[CRITICAL]", msg)
	}
}

func (cl *consoleLogger) Criticalf(format string, params ...interface{}) {
	if cl.slLogLevel >= syslog.LOG_CRIT {
		msg := fmt.Sprintf(format, params...)
		log.Println("[CRITICAL]", msg)
	}
}

func (cl *consoleLogger) SetLogLevel(slLogLevel syslog.Priority) {
	cl.slLogLevel = slLogLevel
}

func (cl *consoleLogger) GetLogLevel() syslog.Priority {
	return cl.slLogLevel
}

func (cl *consoleLogger) Close() {
}
