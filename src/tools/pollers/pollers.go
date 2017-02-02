package pollers

type PollListener func(interface{}, error)

type Poller interface {
	Run() error
	Stop() error
	RegisterListener(p PollListener) error
}
