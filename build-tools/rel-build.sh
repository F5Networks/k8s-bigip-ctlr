#!/bin/bash


set -ex

CURDIR="$(dirname $BASH_SOURCE)"
RUN_TESTS=${RUN_TESTS:-1}
DEBUG=${DEBUG:-1}

. $CURDIR/_build-lib.sh
BUILDDIR=$(get_builddir)
export BUILDDIR=$BUILDDIR

# Licensee need this path to generate attributions
vendor_dir="$CURDIR/../../k8s-bigip-ctlr/vendor"
. $CURDIR/attributions-generator.sh
# Run the attributions and save the content to a local file.
generate_attributions_licensee $vendor_dir >> /build/all_attributions.txt

DEBUG=$DEBUG go_install $(all_cmds)

if [ $RUN_TESTS -eq 1 ]; then
    echo "Gathering unit test code coverage for 'release' build..."
    ginkgo_test_with_coverage
fi

# reset GOPATH after using temp directories
export GOPATH=/build

if [ $RUN_TESTS -eq 1 ]; then
    # push coverage data to coveralls if F5 repo or if configured for fork.
    if [ "$COVERALLS_TOKEN" ]; then
      cat $BUILDDIR/coverage/coverage.out >> $BUILDDIR/coverage.out
      goveralls \
        -coverprofile=$BUILDDIR/coverage.out \
        -service=travis-ci
    fi
fi
#Copying the build directory to volume
cp -rf $BUILDDIR /build/mnt/
