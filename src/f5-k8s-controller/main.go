package main

import (
	"time"
	log "velcro/vlogger"
	clog "velcro/vlogger/console"
)

func initLogger() {
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, clog.NewConsoleLogger())
	log.SetLogLevel(log.LL_DEBUG)
}

func main() {
	initLogger()
	for {
		log.Errorf("Hello there!")
		time.Sleep(5 * time.Second)
	}
}
