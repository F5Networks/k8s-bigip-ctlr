[![GoDoc](https://pkg.go.dev/badge/github.com/f5devcentral/mockhttpclient?utm_source=godoc)](https://pkg.go.dev/github.com/f5devcentral/mockhttpclient)
[![Go Report Card](https://goreportcard.com/badge/github.com/f5devcentral/mockhttpclient)](https://goreportcard.com/report/github.com/f5devcentral/mockhttpclient)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Mock HTTP Client

(Originally imported from: https://github.com/subbuv26/mockhttpclient.git)

A Mock HTTP Client package for efficient testing of REST Client response handling scenarios. 
Mock HTTP client acts as an HTTP client and serves requests as per the needs of tests.
This mock HTTP client simply responds with preconfigured HTTP responses when ever http requests are made.

To test the code that handles different http responses, this mock client comes very useful,
as the client responds with desired responses, the code that gets tested receives the expected responses in the expected order.

## Installation

```
go get github.com/f5devcentral/mockhttpclient
```

## Usage
### Example 1:
The function to be tested (createAndVerifyResource) has the below functionality
1. CREATE resource using POST call, which returns http OK
2. GET the resource using GET call, which returns http Service Unavailable (Server Busy)
3. retry to GET the resource, which returns http OK
4. On Success return true, otherwise false


```go

import mockhc "github.com/f5devcentral/mockhttpclient"

resp1 := &http.Response{
    StatusCode: 200,
    Header:     http.Header{},
    Body:       ioutil.NopCloser(bytes.NewReader([]byte("body"))),
}

resp2 := &http.Response{
    StatusCode: 503,
    Header:     http.Header{},
    Body:       ioutil.NopCloser(bytes.NewReader([]byte("body"))),
}

responseMap := make(mockhc.ResponseConfigMap)

responseMap[http.MethodPost] = &ResponseConfig{}
responseMap[http.MethodPost].Responses = []*http.Response{resp1}
responseMap[http.MethodGet] = &ResponseConfig{}
responseMap[http.MethodGet].Responses = []*http.Response{resp2, resp1}

// Create Client
client, _ := NewMockHTTPClient(responseMap)

// myRESTClient is the client that is going to be tested
myRESTClient.client = client

// createAndVerifyResource creates a resource  with POST and verifies with GET
// with myRESTClient.client
ok := myRESTClient.createAndVerifyResource(Resource{})
if ok {
	// Success 
} else {
	// Failed
}

```

### Example 2
The function to be tested (createResources) creates N number of resources by calling continuous POST calls

```go
import mockhc "github.com/f5devcentral/mockhttpclient"

N := 5

resp1 := &http.Response{
    StatusCode: 200,
    Header:     http.Header{},
    Body:       ioutil.NopCloser(bytes.NewReader([]byte("body"))),
}

responseMap := make(mockhc.ResponseConfigMap)

responseMap[http.MethodPost] = &ResponseConfig{}
responseMap[http.MethodPost].Responses = []*http.Response{resp1}
responseMap[http.MethodPost].MaxRun = N

// Create Client
client, _ := NewMockHTTPClient(responseMap)

// myRESTClient is the client that is going to be tested
myRESTClient.client = client

// createResources makes post calls using myRESTClient.client
ok := myRESTClient.createResources([]Resources)
if ok {
    // Success 
} else {
    // Failed
}

```
