
[//]: # (Original work Copyright © 2015 Scott Ware)
[//]: # (Modifications Copyright 2019 F5 Networks Inc)
[//]: # (Licensed under the Apache License, Version 2.0 [the "License"];)
[//]: # (You may not use this file except in compliance with the License.)
[//]: # (You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0)
[//]: # (Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,)
[//]: # (WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.)
[//]: # (See the License for the specific language governing permissions and limitations under the License.)

## go-bigip
[![GoDoc](https://godoc.org/github.com/f5devcentral/go-bigip?status.svg)](https://godoc.org/github.com/f5devcentral/go-bigip) [![Travis-CI](https://travis-ci.org/f5devcentral/go-bigip.svg?branch=master)](https://travis-ci.org/f5devcentral/go-bigip)
[![Go Report Card](https://goreportcard.com/badge/github.com/f5devcentral/go-bigip)](https://goreportcard.com/report/github.com/f5devcentral/go-bigip)
[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/f5devcentral/go-bigip/master/LICENSE)

A Go package that interacts with F5 BIG-IP systems using the REST API.

Some of the tasks you can do are as follows:

* Get a detailed list of all nodes, pools, vlans, routes, trunks, route domains, self IP's, virtual servers, monitors on the BIG-IP system.
* Create/delete nodes, pools, vlans, routes, trunks, route domains, self IP's, virtual servers, monitors, etc.
* Modify individual settings for all of the above.
* Change the status of nodes and individual pool members (enable/disable).

> **Note**: You must be on version 11.4+! For the features that deal with internal data groups, you must be running version 11.6+!

### Examples & Documentation
Visit the [GoDoc][godoc-go-bigip] page for package documentation and examples.

Here's a [blog post][blog] that goes a little more in-depth.

### Contributors
A very special thanks to the following who have helped contribute to this software, especially:

* [Adam Burnett](https://github.com/aburnett)
* [Michael D. Ivey](https://github.com/ivey)

[godoc-go-bigip]: http://godoc.org/github.com/f5devcentral/go-bigip
[license]: https://github.com/f5devcentral/go-bigip/blob/master/LICENSE
[blog]: http://sdubs.org/go-big-ip-or-go-home/
