// Copyright (c) 2019-2020, F5 Networks, Inc.
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

/*
Package vlogger implements an interface around basic logging features
so that end-user and library writers can code to the interface without
worrying about the specific type of logging package that is being used.

LIBRARY USAGE

To support logging in a user-defined library, you need to include the
vlogger package.  Once that is included, you can simply call one of the
following package-level functions:

  func Debug(msg string)
  func Debugf(format string, params ... interface{})
  func Info(msg string)
  func Infof(format string, params ... interface{})
  func Warning(msg string)
  func Warningf(format string, params ... interface{})
  func Error(msg string)
  func Errorf(format string, params ... interface{})
  func Critical(msg string)
  func Criticalf(format string, params ... interface{})
  func Fatal(msg string)
  func Fatalf(format string, params ... interface{})
  func Panic(msg string)
  func Panicf(format string, params ... interface{})

APPLICATION USAGE

Logging in the main application is similar to logging in a library.  However,
additional steps must be taken to setup and breakdown the vlogger.

When creating an application, you should specify the concrete vlogger that
you would like to use in your main module's init function. This will
guarantee that the vlogger will be available for any library that supports
vlogger (otherwise logging will default to the console).

The following types of loggers are currently provided as subpackages:

    func NewConsoleLogger() Logger
    func NewSyslogLogger(facility syslog.Priority, progname string) Logger
    func NewSeelogLogger(filename string) Logger
    func NewLogrusLogger() Logger

The first two use standard GO packages to implement logging. The last two
uses more sophisticated third-party library that supports features such
as multiple logging streams and various levels of filtering. Logging using
these last two packages can be directed to any combination of outputs including
syslog.  Users can provide their own implementations by adhering to the
vlogger interface.

Some logging subpackages have an extended version of the New function that
provides additional customization of that particular logger.  These functions
end with an 'Ext' suffix (for instance, NewConsoleLoggerExt).

Logger types need to be registered for use by the vlogger package-level
functions using the following call:

    func RegisterLogger(minLogLevel, maxLogLevel, Logger)

The RegisterLogger function allows you to use different loggers for
different log levels (for instance, sending critical messages to a
blocking logger while sending all other messages to a non-blocking version).

For proper cleanup, the main routine should have a defer statement that calls the
vlogger Close() function:

  func Close()

LOG LEVELS

To control the global logging level, several package level functions are provided:

  SetLogLevel(level LogLevel)
  GetLogLevel() LogLevel

The following log levels are currently defined (do not make an assumption of the
values assigned to these constants):

  LL_DEBUG
  LL_INFO
  LL_WARNING
  LL_ERROR
  LL_CRITICAL

Two related defines can also be used (mainly as a convenience for logger registration):

  LL_MIN_LEVEL
  LL_MAX_LEVEL

Note that certain concrete packages will have their own fine-grained filtering for
logging.  However, the package-level controls will supercede these finer controls.

COMPATIBILITY ISSUES

Log levels do not always map 1-to-1 with the underlying 3rd-party logging library.
The issues mainly involve the LL_CRITICAL level.  Packages that do not provide this
level will be mapped to LL_ERROR.

EXAMPLE

The following is a simple example of an application that sends several log statements
to the console:

  package main

  import (
    log  "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
    "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger/console"

  func init() {
    // Log all messages to the user's console
    log.RegisterLogger(log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, console.NewConsoleLogger())
    // only report errors at the LL_INFO level and above
    log.SetLogLevel(log.LL_INFO)
  }

  func main() {
    defer log.Close()

    log.Debug("This debug message won't print");
    log.Info("This is an info message")
    log.Warning("This is a warning message")
    log.Errorf("This is an error message with %v", "formatting")
    log.Criticalf("This is a critical message %v formatting", "with")
    log.Fatal("This is a fatal message")
    log.Info("This will never print due to log.Fatal() causing the application to exit")
  }

MODULES

*/
package vlogger
