[![Build Status](https://travis-ci.org/F5Networks/k8s-bigip-ctlr.svg?branch=master)](https://travis-ci.org/F5Networks/k8s-bigip-ctlr) [![Coverage Status](https://coveralls.io/repos/github/F5Networks/k8s-bigip-ctlr/badge.svg?branch=HEAD)](https://coveralls.io/github/F5Networks/k8s-bigip-ctlr?branch=HEAD)

F5 Container Ingress Services for Kubernetes & OpenShift
========================================================

The F5 Container Ingress Services for [Kubernetes](https://kubernetes.io/) and [OpenShift](https://www.openshift.com/) makes F5 [BIG-IP](https://www.f5.com/products/big-ip-services) services available to applications running in Kubernetes and OpenShift.

Documentation
-------------

For instruction on how to use this component, see the
[docs](https://clouddocs.f5.com/containers/latest/)
for F5 Container Ingress Services for Kubernetes & OpenShift.

For guides on this and other solutions for Kubernetes, see the
[F5 Solution Guides for Kubernetes](https://clouddocs.f5.com/containers/latest/userguide/kubernetes/).

What's New?
-----------
Support for Custom Resource Definitions [Documentation](https://github.com/F5Networks/k8s-bigip-ctlr/tree/master/docs/config_examples/crd/CustomResource.md)

Getting Help
------------

We encourage you to use the cis-kubernetes channel in our [f5CloudSolutions Slack workspace](https://f5cloudsolutions.herokuapp.com/) for discussion and assistance on this
controller. This channel is typically monitored Monday-Friday 9am-5pm MST by F5
employees who will offer best-effort support.

Contact F5 Technical support via your typical method for more time sensitive
changes and other issues requiring immediate support.


Running
-------

The official docker image is `f5networks/k8s-bigip-ctlr`.

Usually, the controller is deployed in Kubernetes. However, the controller can be run locally for development testing.

```shell
docker run f5networks/k8s-bigip-ctlr /app/bin/k8s-bigip-ctlr <args>
```


Building
--------

The official images are built using docker, but the adventurous can use standard go build tools.

### Official Build

Prerequisites:
- Docker

```shell
git clone https://github.com/F5Networks/k8s-bigip-ctlr.git 
cd  k8s-bigip-ctlr

# Use docker to build the release artifacts, into a local "_docker_workspace" directory, then put into docker images
# Debian image
make prod

OR

# RHEL7 image
make prod BASE_OS=rhel7
```


### Alternate, unofficial build

A normal go toolchain can be used as well

Prerequisites:
- go 1.15
- $GOPATH pointing at a valid go workspace
- python
- virtualenv

```shell
mkdir -p $GOPATH/src/github.com/F5Networks
cd $GOPATH/src/github.com/F5Networks
git clone https://github.com/f5networks/k8s-bigip-ctlr.git
cd k8s-bigip-ctlr

# Build all packages, and run unit tests
make all test
```

To make changes to vendor dependencies, see [Devel](DEVEL.md)
