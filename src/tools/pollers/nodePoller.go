package pollers

import (
	"fmt"
	"sync"
	"time"

	log "velcro/vlogger"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/v1"
)

type pollData struct {
	nl  []v1.Node
	err error
}

type pollListener struct {
	l chan pollData
	s chan struct{}
}

type NodePoller struct {
	kubeClient   kubernetes.Interface
	pollInterval time.Duration
	stopCh       chan struct{}
	addCh        chan pollListener
	running      bool
	runningLock  *sync.Mutex
	regListeners []PollListener
	nodeCache    []v1.Node
	lastError    error
}

func NewNodePoller(
	kubeClient kubernetes.Interface,
	pollInterval time.Duration,
) *NodePoller {
	np := &NodePoller{
		kubeClient:   kubeClient,
		pollInterval: pollInterval,
		stopCh:       make(chan struct{}),
		addCh:        make(chan pollListener),
		running:      false,
		runningLock:  &sync.Mutex{},
	}

	log.Debugf("NodePoller object created: %p", np)
	return np
}

func (np *NodePoller) Run() error {
	np.runningLock.Lock()
	defer np.runningLock.Unlock()

	if false == np.running {
		np.running = true
		go np.poller()
		for _, pl := range np.regListeners {
			log.Debugf("NodePoller (%p) registering cached listener: %p\n",
				np, pl)
			np.runListener(pl)
		}
	} else {
		return fmt.Errorf("NodePoller Run method called while running")
	}

	log.Infof("NodePoller started: (%p)", np)
	return nil
}

func (np *NodePoller) Stop() error {
	np.runningLock.Lock()
	defer np.runningLock.Unlock()

	if true == np.running {
		np.running = false
		np.stopCh <- struct{}{}
	} else {
		return fmt.Errorf("NodePoller Stop method called while stopped")
	}

	log.Debugf("NodePoller stopped: %p", np)
	return nil
}

func (np *NodePoller) RegisterListener(p PollListener) error {
	np.runningLock.Lock()
	defer np.runningLock.Unlock()

	log.Infof("NodePoller (%p) registering new listener: %p", np, p)

	np.regListeners = append(np.regListeners, p)
	if false == np.running {
		log.Debugf("NodePoller (%p) caching listener %p, poller is not running",
			np, p)
		return nil
	}

	np.runListener(p)
	return nil
}

func (np *NodePoller) runListener(p PollListener) {
	listener := make(chan pollData)
	stopCh := make(chan struct{})

	np.addCh <- pollListener{
		l: listener,
		s: stopCh,
	}

	go func() {
		log.Debugf("NodePoller (%p) listener goroutine started: %p", np, p)
		for {
			select {
			case <-stopCh:
				log.Debugf("NodePoller (%p) listener stopped: %p", np, p)
				return
			case pd := <-listener:
				log.Debugf("NodePoller (%p) listener callback - num items: %v err: %v",
					np, len(pd.nl), pd.err)
				p(pd.nl, pd.err)
			}
		}
	}()

	return
}

func (np *NodePoller) stopListeners(listeners []pollListener) {
	for _, pl := range listeners {
		pl.s <- struct{}{}
	}
}

func (np *NodePoller) poller() {
	doPoll := true
	var listeners []pollListener
	var loopTime time.Time
	remainingInterval := np.pollInterval

	log.Debugf("NodePoller (%p) poller goroutine started", np)

	for {
		select {
		case <-np.stopCh:
			log.Debugf("NodePoller (%p) stopping poller goroutine", np)
			np.stopListeners(listeners)
			return
		default:
		}

		if true == doPoll {
			doPoll = false
			nodes, err := np.kubeClient.Core().Nodes().List(api.ListOptions{})
			np.nodeCache = nodes.Items
			np.lastError = err

			for _, listener := range listeners {
				log.Debugf("NodePoller (%p) notifying listener: %+v", np, listener)
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
			log.Debugf("NodePoller (%p) stopping poller goroutine", np)
			np.stopListeners(listeners)
			return
		case pl := <-np.addCh:
			log.Debugf("NodePoller (%p) poller goroutine adding listener: %+v",
				np, pl)

			pl.l <- pollData{
				nl:  np.nodeCache,
				err: np.lastError,
			}

			since := time.Since(loopTime)
			remainingInterval = remainingInterval - since
			log.Debugf("NodePoller (%p) listener add wake up - next poll in %v\n",
				np, remainingInterval)
			if 0 > remainingInterval {
				remainingInterval = 0
			}

			listeners = append(listeners, pl)
		case <-time.After(remainingInterval):
			log.Debugf("NodePoller (%p) ready to poll, last wait: %v\n",
				np, remainingInterval)
			remainingInterval = np.pollInterval
			doPoll = true
		}
	}
}
