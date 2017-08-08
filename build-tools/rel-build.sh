#!/bin/bash


set -ex

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh
BUILDDIR=$(get_builddir)

export BUILDDIR=$BUILDDIR

go_install $(all_cmds)

echo "Gathering unit test code coverage for 'release' build..."
ginkgo_test_with_coverage

# reset GOPATH after using temp directories
export GOPATH=/build

# run python tests
./build-tools/python-tests.sh

# push coverage data to coveralls if F5 repo or if configured for fork.
if [ "$COVERALLS_TOKEN" ]; then
  cat $BUILDDIR/coverage/merged-coverage.out >> $BUILDDIR/merged-coverage.out
  cat $BUILDDIR/python-coverage.txt >> $BUILDDIR/merged-coverage.out
  goveralls \
    -coverprofile=$BUILDDIR/merged-coverage.out \
    -service=travis-ci
fi
