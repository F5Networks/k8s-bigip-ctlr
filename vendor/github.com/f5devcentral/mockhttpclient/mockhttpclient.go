/*
   Copyright 2021, Subba Reddy Veeramreddy

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specsific language governing permissions and
   limitations under the License.
*/

package mockhttpclient

import (
	"errors"
	"net/http"
)

type roundTripHandler struct {
	context *roundTripperContext
}

type roundTripperContext struct {
	respCfg ResponseConfigMap
}

// ResponseConfigMap needs to be composed in order to utilise this Package
// It is map where the Key is HTTP Method, that would be enclosed in HTTP request
type ResponseConfigMap map[string]*ResponseConfig

// ResponseConfig wraps a List of Responses
type ResponseConfig struct {
	// Responses that would be fetched by mock client for a series of requests
	Responses []*http.Response
	// Max number of times that the client fetches response
	// If MaxRun is greater than Length of Responses,
	// then Responses will be cycled until MaxRus is elapsed
	MaxRun int
	cursor int
}

func (rc *ResponseConfig) handler() (*http.Response, error) {
	if rc.cursor >= rc.MaxRun {
		return nil, errors.New("client exhausted")
	}

	index := rc.cursor % len(rc.Responses)
	rc.cursor++

	if rc.Responses[index] == nil {
		return nil, errors.New("http: nil Request")
	}

	return rc.Responses[index], nil
}

func (rtc *roundTripperContext) Handler(req *http.Request) (*http.Response, error) {
	respCfg, ok := rtc.respCfg[req.Method]
	if !ok {
		return nil, errors.New("No Responses for HTTP Method: " + req.Method)
	}

	return respCfg.handler()
}

// PutContext Validates the input and updates the roundTripperContext
func (rtc *roundTripperContext) PutContext(responseMap ResponseConfigMap) error {
	if len(responseMap) == 0 {
		return errors.New("empty map of responses")
	}

	for k, v := range responseMap {
		if v == nil || len(v.Responses) == 0 {
			return errors.New("Empty Response list for HTTP Method: " + k)
		}
		if v.MaxRun < 0 {
			return errors.New("Invalid MaxRun for HTTP Method: " + k)
		}
		if v.MaxRun == 0 {
			v.MaxRun = len(v.Responses)
		}
	}
	rtc.respCfg = responseMap

	return nil
}

// RoundTrip is the implementation of http.RoundTripper interface
func (rth roundTripHandler) RoundTrip(req *http.Request) (*http.Response, error) {
	return rth.context.Handler(req)
}

// NewMockHTTPClient returns a mock http client with the behaviour as configured in ResponseConfigMap
func NewMockHTTPClient(responseMap ResponseConfigMap) (*http.Client, error) {
	rtc := &roundTripperContext{}
	if err := rtc.PutContext(responseMap); err != nil {
		return nil, err
	}

	client := &http.Client{}
	client.Transport = roundTripHandler{
		context: rtc,
	}

	return client, nil
}
