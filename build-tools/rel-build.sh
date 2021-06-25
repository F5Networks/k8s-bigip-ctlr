#!/bin/bash

set -ex

CURDIR="$(dirname $BASH_SOURCE)"
RUN_TESTS=${RUN_TESTS:-1}
LICENSE=${LICENSE:-0}

. $CURDIR/_build-lib.sh

if [ $LICENSE == 1 ]; then
  # Licensee need this path to generate attributions
  vendor_dir="$CURDIR/../../k8s-bigip-ctlr/vendor"
  . $CURDIR/attributions-generator.sh
  # Run the attributions and save the content to a local file.
  generate_attributions_licensee $vendor_dir > /build/all_attributions.txt
fi

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
