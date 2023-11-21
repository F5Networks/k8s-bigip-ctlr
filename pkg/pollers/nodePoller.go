/*-
 * Copyright (c) 2017-2021 F5 Networks, Inc.
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

package pollers

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
)

type pollData struct {
	nl  []v1.Node
	err error
}

type pollListener struct {
	l chan pollData
	s chan struct{}
}

type nodePoller struct {
	kubeClient   kubernetes.Interface
	pollInterval time.Duration
	stopCh       chan struct{}
	addCh        chan pollListener
	running      bool
	runningLock  *sync.Mutex
	regListeners []PollListener
	nodeCache    []v1.Node
	lastError    error
	nodeLabel    string
}

func NewNodePoller(
	kubeClient kubernetes.Interface,
	pollInterval time.Duration,
	nodeLabel string,
) Poller {
	np := &nodePoller{
		kubeClient:   kubeClient,
		pollInterval: pollInterval,
		stopCh:       make(chan struct{}),
		addCh:        make(chan pollListener),
		running:      false,
		runningLock:  &sync.Mutex{},
		nodeLabel:    nodeLabel,
	}

	log.Debugf("[CORE] NodePoller object created: %p", np)
	return np
}

func (np *nodePoller) Run() error {
	np.runningLock.Lock()
	defer np.runningLock.Unlock()

	if false == np.running {
		np.running = true
		go np.poller()
		for _, pl := range np.regListeners {
			log.Debugf("[CORE] NodePoller (%p) registering cached listener: %p\n",
				np, pl)
			np.runListener(pl)
		}
	} else {
		return fmt.Errorf("NodePoller Run method called while running")
	}

	log.Infof("[CORE] NodePoller started: (%p)", np)
	return nil
}

func (np *nodePoller) Stop() error {
	np.runningLock.Lock()
	defer np.runningLock.Unlock()

	if true == np.running {
		np.running = false
		np.stopCh <- struct{}{}
	} else {
		return fmt.Errorf("NodePoller Stop method called while stopped")
	}

	log.Infof("[CORE] NodePoller stopped: %p", np)
	return nil
}

func (np *nodePoller) RegisterListener(p PollListener) error {
	np.runningLock.Lock()
	defer np.runningLock.Unlock()

	log.Infof("[CORE] NodePoller (%p) registering new listener: %p", np, p)

	np.regListeners = append(np.regListeners, p)
	if false == np.running {
		log.Debugf("[CORE] NodePoller (%p) caching listener %p, poller is not running",
			np, p)
		return nil
	}

	np.runListener(p)
	return nil
}

func (np *nodePoller) runListener(p PollListener) {
	listener := make(chan pollData)
	stopCh := make(chan struct{})

	np.addCh <- pollListener{
		l: listener,
		s: stopCh,
	}

	go func() {
		log.Debugf("[CORE] NodePoller (%p) listener goroutine started: %p", np, p)
		for {
			select {
			case <-stopCh:
				log.Debugf("[CORE] NodePoller (%p) listener stopped: %p", np, p)
				return
			case pd := <-listener:
				log.Debugf("[CORE] NodePoller (%p) listener callback - num items: %v err: %v",
					np, len(pd.nl), pd.err)
				p(pd.nl, pd.err)
			}
		}
	}()

	return
}

func (np *nodePoller) stopListeners(listeners []pollListener) {
	for _, pl := range listeners {
		pl.s <- struct{}{}
	}
}

func (np *nodePoller) poller() {
	doPoll := true
	var listeners []pollListener
	var loopTime time.Time
	remainingInterval := np.pollInterval

	log.Debugf("[CORE] NodePoller (%p) poller goroutine started", np)

	for {
		select {
		case <-np.stopCh:
			log.Debugf("[CORE] NodePoller (%p) stopping poller goroutine", np)
			np.stopListeners(listeners)
			return
		default:
		}

		if true == doPoll {
			doPoll = false

			// LabelSelector
			nodes, err := np.kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: np.nodeLabel})
			bigIPPrometheus.MonitoredNodes.WithLabelValues(np.nodeLabel).Set(float64(len(nodes.Items)))
			np.nodeCache = nodes.Items
			np.lastError = err

			for _, listener := range listeners {
				log.Debugf("[CORE] NodePoller (%p) notifying listener: %+v", np, listener)
				select {
				case listener.l <- pollData{
					nl:  np.nodeCache,
					err: np.lastError,
				}:
				default:
				}
			}
		}

		loopTime = time.Now()
		select {
		case <-np.stopCh:
			log.Debugf("[CORE] NodePoller (%p) stopping poller goroutine", np)
			np.stopListeners(listeners)
			return
		case pl := <-np.addCh:
			log.Debugf("[CORE] NodePoller (%p) poller goroutine adding listener: %+v",
				np, pl)

			pl.l <- pollData{
				nl:  np.nodeCache,
				err: np.lastError,
			}

			since := time.Since(loopTime)
			remainingInterval = remainingInterval - since
			log.Debugf("[CORE] NodePoller (%p) listener add wake up - next poll in %v\n",
				np, remainingInterval)
			if 0 > remainingInterval {
				remainingInterval = 0
			}

			listeners = append(listeners, pl)
		case <-time.After(remainingInterval):
			log.Debugf("[CORE] NodePoller (%p) ready to poll, last wait: %v\n",
				np, remainingInterval)
			remainingInterval = np.pollInterval
			doPoll = true
		}
	}
}
