#!/bin/bash

#
# This is the common environment for building the runtime image, and the
# reusable developer image
#
# The build uses two docker container types:
#  - Builder container: We build this container with all the build tools and
#  dependencies need to build and test everything. The source can be mounted as
#  a volume, and run any build command needed.
#  The built artifacts can then be added to the runtime container without any
#  build deps
#  - Runtime container: This container is just the minimum base runtime
#      environment plus any artifacts from the builder that we need to actually
#      run the proxy.  We leave all the tooling behind.

set -e

if [[ $BUILD_VERSION == "" ]]; then
  echo "Must set BUILD_VERSION"
  false
fi
if [[ $BUILD_INFO == "" ]]; then
  echo "Must set BUILD_INFO"
  false
fi

ginkgo_test_with_coverage () {
    ginkgo -r --procs=4 --compilers=1 --randomize-all --randomize-suites --fail-on-pending --keep-going --trace --junit-report=report.xml --timeout=300s --flake-attempts=3 --succinct -cover -coverprofile coverage.out
    echo "Gathering unit test code coverage for 'release' build..."
    gather_coverage $WKDIR
}

ginkgo_test_with_profile () {
    ginkgo -r -compilers 1 -keepGoing -randomizeAllSpecs -progress --nodes 4 \
            ${BUILD_VARIANT_FLAGS} -- \
            -test.cpuprofile profile.cpu \
            -test.blockprofile profile.block \
            -test.memprofile profile.mem
}

gather_coverage() {
    go tool cover -html=coverage.out -o coverage.html
    go tool cover -func=coverage.out
    # Total coverage for CI
    go tool cover -func=coverage.out | grep "^total:" | awk 'END { print "Total coverage:", $3, "of statements" }'
}