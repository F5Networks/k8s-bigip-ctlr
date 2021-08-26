#!/bin/bash

set -ex

CURDIR="$(dirname $BASH_SOURCE)"
RUN_TESTS=${RUN_TESTS:-1}

. $CURDIR/_build-lib.sh

if [ $RUN_TESTS -eq 1 ]; then
    echo "Gathering unit test code coverage for 'release' build..."
    ginkgo_test_with_coverage
fi

if [ $RUN_TESTS -eq 1 ]; then
    # push coverage data to coveralls if F5 repo or if configured for fork.
    if [ "$COVERALLS_TOKEN" ]; then
      goveralls \
        -coverprofile=./coverage/coverage.out \
        -service=azure
    fi
fi
