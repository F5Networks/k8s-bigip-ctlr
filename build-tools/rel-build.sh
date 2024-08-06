#!/bin/bash

set -ex

if [[ $BUILD_VERSION == "" ]]; then
  echo "Must set BUILD_VERSION"
  false
fi
if [[ $BUILD_INFO == "" ]]; then
  echo "Must set BUILD_INFO"
  false
fi

go mod download

CGO_ENABLED=0
GOOS=linux
GOARCH=amd64
go build -v -ldflags "-extldflags \"-static\" -X main.version=${BUILD_VERSION} -X main.buildInfo=${BUILD_INFO}" -o /bin/k8s-bigip-ctlr $REPOPATH/cmd/k8s-bigip-ctlr
