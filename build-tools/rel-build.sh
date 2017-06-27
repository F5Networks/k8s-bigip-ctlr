#!/bin/bash


set -ex

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh
BUILDDIR=$(get_builddir)

export BUILDDIR=$BUILDDIR

for pkg in $(all_cmds) $(all_pkgs); do
  test_pkg "$pkg"
done

go_install $(all_cmds)

echo "Gathering unit test code coverage for 'release' build..."
gather_coverage

# run python tests
./build-tools/python-tests.sh

# push coverage data to coveralls if F5 repo or if configured for fork.
if [ "$COVERALLS_TOKEN" ]; then
  cat $BUILDDIR/test/merged-coverage.out >> $BUILDDIR/merged-coverage.out
  cat $BUILDDIR/python-coverage.txt >> $BUILDDIR/merged-coverage.out
  goveralls \
    -coverprofile=$BUILDDIR/merged-coverage.out \
    -service=travis-ci
fi
