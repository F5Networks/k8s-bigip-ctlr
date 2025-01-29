package controller

import "time"

func (req *RequestHandler) EnqueueRequestConfig(rsConfig ResourceConfigRequest) {
	// Always push latest activeConfig to channel
	// Case1: Put latest config into the channel
	// Case2: If channel is blocked because of earlier config, pop out earlier config and push latest config
	// Either Case1 or Case2 executes, which ensures the above

	select {
	case req.reqChan <- rsConfig:
	case <-time.After(3 * time.Millisecond):
	}
}
