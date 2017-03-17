F5 Kubernetes BIG-IP Controller
===============================

The F5 BIG-IP Controller for [Kubernetes](http://kubernetes.io/) makes F5 BIG-IP
[Local Traffic Manager](<https://f5.com/products/big-ip/local-traffic-manager-ltm)
services available to applications running in Kubernetes.

Documentation
-------------

For instruction on how to use this component, see the
[F5 Kubernetes BIG-IP Controller docs](http://clouddocs.f5.com/products/connectors/k8s-bigip-ctlr/latest/).

For guides on this and other solutions for Kubernetes, see the
[F5 Kubernetes Solution Guides](http://clouddocs.f5.com/containers/latest/kubernetes).


Running
-------

The official docker image is `f5networks/k8s-bigip-ctlr`.

Usually, the controller is deployed in Kubernetes. However, the controller can be run locally for development testing.

```shell
docker run f5networks/k8s-bigip-ctlr /app/bin/k8s-bigip-ctlr <args>
```


Building
--------

Note that these instructions will only work for internal users.

To checkout and build:

```shell
git clone https://github.com/f5networks/k8s-bigip-ctlr.git
cd  k8s-bigip-ctlr
git submodule sync
git submodule update --init
```

The official images are built using a docker image. To use this, first build it:

```shell
make devel-image
```

Then, to mount your working tree into a build container and run the build commands:
```shell
./build-tools/run-in-docker.sh make release
```

### Alternate Manual Build - Ubuntu

To build locally, you'll need the following build dependencies:

```shell
# Install build dependencies
sudo apt-get update
sudo apt-get install devscripts equivs git golang golang-go.tools m4 \
  make python python-dev python-pip

# Install gb tool into PATH
export GOPATH=$HOME/go
mkdir -p $GOPATH
export PATH=$PATH:$GOPATH/bin
sudo go install -v -race runtime/race
git clone https://bldr-git.int.lineratesystems.com/mirror/gb.git \
  $GOPATH/src/github.com/constabulary/gb
git -C $GOPATH/src/github.com/constabulary/gb checkout 2b9e9134
go install -v github.com/constabulary/gb/...
go get -v github.com/wadey/gocovmerge

# Install python requirements using sudo or create a virtualenv workspace.
pip install -r python/*-requirements.txt
```

Then to build:

```shell
# Build with debug options like race detection
make debug

# Build with release options
make release
```
