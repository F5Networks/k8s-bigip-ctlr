# vlogger

    import "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"

Package vlogger implements an interface around basic logging features so that
end-user and library writers can code to the interface without worrying about
the specific type of logging package that is being used.


### LIBRARY USAGE

To support logging in a user-defined library, you need to include the vlogger
package. Once that is included, you can simply call one of the following
package-level functions:

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


### APPLICATION USAGE

Logging in the main application is similar to logging in a library. However,
additional steps must be taken to setup and breakdown the vlogger.

When creating an application, you should specify the concrete vlogger that you
would like to use in your main module's init function. This will guarantee that
the vlogger will be available for any library that supports vlogger (otherwise
logging will default to the console).

The following types of loggers are currently provided as subpackages:

    func NewConsoleLogger() Logger
    func NewSyslogLogger(facility syslog.Priority, progname string) Logger
    func NewSeelogLogger(filename string) Logger
    func NewLogrusLogger() Logger

The first two use standard GO packages to implement logging. The last two
uses more sophisticated third-party library that supports features such
as multiple logging streams and various levels of filtering. Logging using
these last two packages can be directed to any combination of outputs including
syslog.  Users can also provide their own implementations by adhering to the
vlogger interface.

Some logging subpackages have an extended version of the New function that
provides additional customization of that particular logger.  These functions
end with an 'Ext' suffix (for instance, NewConsoleLoggerExt).

Logger types need to be registered for use by the vlogger package-level
functions using the following call:

    func RegisterLogger(minLogLevel, maxLogLevel, Logger)

The RegisterLogger function allows you to use different loggers for different
log levels (for instance, sending critical messages to a blocking logger while
sending all other messages to a non-blocking version).

For proper cleanup, the main routine should have a defer statement that calls
the vlogger Close() function:

    func Close()


### LOG LEVELS

To control the global logging level, several package level functions are
provided:

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

Note that certain concrete packages will have their own fine-grained filtering
for logging. However, the package-level controls will supercede these finer
controls.


### COMPATIBILITY ISSUES

Log levels do not always map 1-to-1 with the underlying 3rd-party logging library.
The issues mainly involve the LL_CRITICAL level.  Packages that do not provide this
level will be mapped to LL_ERROR.


### EXAMPLE

The following is a simple example of an application that sends several log
statements to the console:

```go
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
```


### MODULES

log.go:

    This module provides the generic interface that end-user libraries and apps should program to.

## Usage

#### func  RegisterLogger

```go
func RegisterLogger(minLogLevel, maxLogLevel LogLevel, log Logger)
```
RegisterLogger must be called to map a concrete logger object with each log
level.

#### func  Close

```go
func Close()
```
Close informs the configured loggers that they are being closed and should
cleanup (for instance, flushing any queued log messages)

#### func  Panic

```go
func Panic(msg string)
```
Panic sends a CRITICAL message to the logger object and then calls panic. **NOTE:
This call should not be made in packages that are meant to serve as libraries
for other developers.**

#### func  Panicf

```go
func Panicf(format string, params ...interface{})
```
Panicf sends a formatted CRITICAL message to the logger object and then calls
panic. **NOTE: This call should not be made in packages that are meant to serve as
libraries for other developers.**

#### func  Fatal

```go
func Fatal(msg string)
```
Fatal sends a CRITICAL message to the logger object and then exits. **NOTE: This
call should not be made in packages that are meant to serve as libraries for
other developers.**

#### func  Fatalf

```go
func Fatalf(format string, params ...interface{})
```
Fatalf sends a formatted CRITICAL message to the logger object and then exits.
**NOTE: This call should not be made in packages that are meant to serve as
libraries for other developers.**

#### func  Critical

```go
func Critical(msg string)
```
Critical sends a message to the logger object to record critical level
statements (these indicate conditions that should never occur and might cause a
failure/crash of the executing program or unexpected outcome from the
requested action).

#### func  Criticalf

```go
func Criticalf(format string, params ...interface{})
```
Criticalf formats a message before sending it to the logger object to record
critical level statements (these indicate conditions that should never occur and
might cause a failure/crash of the executing program or unexpected outcome
from the requested action).

#### func  Error

```go
func Error(msg string)
```
Error sends a message to the logger object to record error level statements
(these indicate conditions that should not occur and may indicate a failure in
performing the requested action).

#### func  Errorf

```go
func Errorf(format string, params ...interface{})
```
Errorf formats a message before sending it to the logger object to record error
level statements (these indicate conditions that should not occur and may
indicate a failure in performing the requested action).

#### func  Warning

```go
func Warning(msg string)
```
Warning sends a message to the logger object to record warning level statements
(these indication conditions that are unexpected or may cause issues but are not
normally going to affect the program execution).

#### func  Warningf

```go
func Warningf(format string, params ...interface{})
```
Warningf formats a message before sending it to the logger object to record
warning level statements (these indication conditions that are unexpected or may
cause issues but are not normally going to affect the program execution).

#### func  Info

```go
func Info(msg string)
```
Info sends a message to the logger object to record informational level
statements (these should be statements that can normally be logged without
causing performance issues).

#### func  Infof

```go
func Infof(format string, params ...interface{})
```
Infof formats a message before sending it to the logger object to record
informational level statements (there should be statements that can normally be
logged without causing performance issues).

#### func  Debug

```go
func Debug(msg string)
```
Debug sends a message to the logger object to record debug/trace level
statements

#### func  Debugf

```go
func Debugf(format string, params ...interface{})
```
Debugf formats a message before sending it to the logger object to record
debug/trace level statements

#### func  SetLogLevel

```go
func SetLogLevel(level LogLevel)
```
SetLogLevel sets the current package-level filtering

#### func  GetLogLevel

```go
func GetLogLevel() LogLevel
```
GetLogLevel returns the current package-level filtering

#### type LogLevel

```go
type LogLevel int
```

LogLevel is used for global (package-level) filtering of log messages based on
their priority (this filtering is applied before all other filtering which might
be provided by the concrete logger).

```go
const (
	// Must be in sequential ascending order based on priority
	// (higher priorities have higher numeric values)
	LL_DEBUG LogLevel = iota
	LL_INFO
	LL_WARNING
	LL_ERROR
	LL_CRITICAL
	LL_LOGLEVEL_SIZE
	LL_MIN_LEVEL = LL_DEBUG
	LL_MAX_LEVEL = LL_LOGLEVEL_SIZE - 1
)
```

#### type Logger

```go
type Logger interface {
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
```

Generic interface that all concrete loggers must implement. Using this interface
directly isolates user code from a particular logger implementation.

