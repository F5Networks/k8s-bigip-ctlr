package writer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	log "velcro/vlogger"
)

type ConfigWriter struct {
	configFile string
	stopCh     chan struct{}
	dataCh     chan configSection
	sectionMap map[string]interface{}
}

type configSection struct {
	name    string
	data    interface{}
	doneCh  chan struct{}
	errorCh chan error
}

func NewConfigWriter() (*ConfigWriter, error) {
	dir, err := ioutil.TempDir("", "f5-k8s-controller.config")
	if nil != err {
		return nil, fmt.Errorf("could not create unique config directory: %v", err)
	}

	tmpfn := filepath.Join(dir, "config.json")

	cw := &ConfigWriter{
		configFile: tmpfn,
		stopCh:     make(chan struct{}),
		dataCh:     make(chan configSection),
		sectionMap: make(map[string]interface{}),
	}

	go cw.waitData()

	log.Infof("ConfigWriter started: %p", cw)
	return cw, nil
}

func (cw *ConfigWriter) GetOutputFilename() string {
	return cw.configFile
}

func (cw *ConfigWriter) Stop() {
	defer func() {
		if r := recover(); r != nil {
			log.Warningf("ConfigWriter (%p) stop called after already stopped", cw)
		}
	}()

	cw.stopCh <- struct{}{}
	close(cw.stopCh)
	os.RemoveAll(filepath.Dir(cw.configFile))

	log.Infof("ConfigWriter stopped: %p", cw)
}

func (cw *ConfigWriter) SendSection(
	name string,
	obj interface{},
) (<-chan struct{}, <-chan error, error) {
	if 0 == len(name) {
		return nil, nil, fmt.Errorf("cannot marshal section without name")
	}

	done := make(chan struct{})
	err := make(chan error)
	cw.dataCh <- configSection{
		name:    name,
		data:    obj,
		doneCh:  done,
		errorCh: err,
	}

	log.Debugf("ConfigWriter (%p) writing section name %s", cw, name)
	return done, err, nil
}

func (cw *ConfigWriter) waitData() {
	respondDone := func(d chan<- struct{}) {
		select {
		case d <- struct{}{}:
		case <-time.After(time.Second):
		}
	}
	respondErr := func(e chan<- error, err error) {
		select {
		case e <- err:
		case <-time.After(time.Second):
		}
	}
	for {
		select {
		case <-cw.stopCh:
			log.Debugf("ConfigWriter (%p) received stop signal", cw)
			return
		case cs := <-cw.dataCh:
			// check if this section will marshal
			_, err := json.Marshal(cs.data)
			if nil != err {
				log.Warningf("ConfigWriter (%p) received bad json for section %s: %v",
					cw, cs.name, err)
				go respondErr(cs.errorCh, err)
			} else {
				cw.sectionMap[cs.name] = cs.data

				output, err := json.Marshal(cw.sectionMap)
				if nil != err {
					log.Warningf("ConfigWriter (%p) received marshal error: %v",
						cw, cs.name)
					go respondErr(cs.errorCh, err)
				}

				err = ioutil.WriteFile(cw.configFile, output, 0644)
				if nil != err {
					log.Warningf("ConfigWriter (%p) received io error: %v",
						cw, cs.name)
					go respondErr(cs.errorCh, err)
				} else {
					log.Debugf("ConfigWriter (%p) successfully wrote config")
					go respondDone(cs.doneCh)
				}
			}
		}
	}
}
