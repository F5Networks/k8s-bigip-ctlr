#!/bin/bash

# This script builds and uses a docker container to produce official artifacts

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Build the builder image.
$CURDIR/build-devel-image.sh

# Build artifacts using the build image
export build_img=$BUILD_DBG_IMG_TAG
$CURDIR/run-in-docker.sh ./build-tools/dbg-build.sh

if $CLEAN_BUILD; then
  docker rmi $build_img
fi

# Now ready to run ./build-debug-images.sh

