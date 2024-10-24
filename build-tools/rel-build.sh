#!/bin/bash

set -ex

go mod download

CGO_ENABLED=0
GOOS=linux
GOARCH=amd64
go build -gcflags="all=-N -l" -v -ldflags "-extldflags \"-static\" -X main.version=${BUILD_VERSION} -X main.buildInfo=${BUILD_INFO}" -o /bin/k8s-bigip-ctlr $REPOPATH/cmd/k8s-bigip-ctlr

RUN_TESTS=${RUN_TESTS:-1}

. $REPOPATH/build-tools/_build-lib.sh

if [ $RUN_TESTS -eq 1 ]; then
    go install github.com/onsi/ginkgo/v2/ginkgo
    go install github.com/onsi/gomega
    go install github.com/wadey/gocovmerge@latest
    go install github.com/mattn/goveralls@latest
    echo "Gathering unit test code coverage for 'release' build..."
    ginkgo_test_with_coverage
    # push coverage data to coveralls if F5 repo or if configured for fork.
    if [ "$COVERALLS_TOKEN" ]; then
      echo "Pushing coverage data to coveralls"
      goveralls -coverprofile=./coverage.out -service=azure
    fi
fi
