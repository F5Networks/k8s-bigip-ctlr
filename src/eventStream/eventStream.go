package eventStream

import (
	"time"

	v1core "k8s.io/client-go/1.4/kubernetes/typed/core/v1"
	"k8s.io/client-go/1.4/pkg/api"
	"k8s.io/client-go/1.4/pkg/api/v1"
	"k8s.io/client-go/1.4/pkg/fields"
	"k8s.io/client-go/1.4/pkg/labels"
	"k8s.io/client-go/1.4/pkg/runtime"
	"k8s.io/client-go/1.4/pkg/watch"
	"k8s.io/client-go/1.4/tools/cache"
)

// Interface for external operations on an EventStream
type EventStreamRunner interface {
	Store() *EventStore
	Run()
	Stop()
}

// Internal data required for cached events
type EventStream struct {
	reflector *cache.Reflector // reflects events to the EventStore
	store     *EventStore      // our event store
	stopChan  chan struct{}    // channel to tell goroutine to stop
}

// Implementations for EventStreamRunner interface for EventStream
func (es *EventStream) Store() *EventStore {
	return es.store
}
func (es *EventStream) Run() {
	es.reflector.RunUntil(es.stopChan)
}
func (es *EventStream) Stop() {
	close(es.stopChan)
}

// Extension of cacheListerWatcher that also requires OnChangeFunc
type EventListerWatcher interface {
	cache.ListerWatcher                              // provides listing and watching of k8s objects
	OnChange(changeType ChangeType, obj interface{}) // triggered on changes after they have been applied to the store
}

// Holds callbacks to handle list/watch/change events from k8s
type EventListWatch struct {
	ListFunc     cache.ListFunc
	WatchFunc    cache.WatchFunc
	OnChangeFunc OnChangeFunc
}

// Implementations for EventListWatcher interface for EventListWatch
func (lw *EventListWatch) List(options api.ListOptions) (runtime.Object, error) {
	return lw.ListFunc(options)
}
func (lw *EventListWatch) Watch(options api.ListOptions) (watch.Interface, error) {
	return lw.WatchFunc(options)
}
func (lw *EventListWatch) OnChange(changeType ChangeType, obj interface{}) {
	lw.OnChangeFunc(changeType, obj)
}

// Creates a new EventStream
func NewEventStream(eventListWatch *EventListWatch, dataType interface{}, resyncPeriod time.Duration) *EventStream {
	store := NewEventStore(cache.MetaNamespaceKeyFunc, eventListWatch.OnChangeFunc)
	eventStream := &EventStream{
		reflector: cache.NewReflector(eventListWatch, dataType, store, resyncPeriod),
		store:     store,
		stopChan:  make(chan struct{}),
	}
	return eventStream
}

// Creates a new EventStream for *v1.Service
func NewServiceEventStream(core v1core.CoreInterface, namespace string, resyncPeriod time.Duration, onChangeFunc OnChangeFunc, labelSelector labels.Selector, fieldSelector fields.Selector) *EventStream {
	return NewEventStream(
		&EventListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return core.Services(namespace).List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return core.Services(namespace).Watch(options)
			},
			OnChangeFunc: onChangeFunc,
		},
		&v1.Service{},
		resyncPeriod)
}

// Creates a new EventStream for *v1.ConfigMap
func NewConfigMapEventStream(core v1core.CoreInterface, namespace string, resyncPeriod time.Duration, onChangeFunc OnChangeFunc, labelSelector labels.Selector, fieldSelector fields.Selector) *EventStream {
	return NewEventStream(
		&EventListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				// add the specified labelSelector and fieldSelector object to the options list
				opts := options
				opts.LabelSelector = labelSelector
				opts.FieldSelector = fieldSelector
				return core.ConfigMaps(namespace).List(opts)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				// add the specified labelSelector and fieldSelector object to the options list
				opts := options
				opts.LabelSelector = labelSelector
				opts.FieldSelector = fieldSelector
				return core.ConfigMaps(namespace).Watch(opts)
			},
			OnChangeFunc: onChangeFunc,
		},
		&v1.ConfigMap{},
		resyncPeriod)
}
