#!/bin/bash

# This script builds and uses a docker container to produce official artifacts

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Build artifacts using the build image
$CURDIR/run-in-docker.sh ./build-tools/rel-build.sh

if $CLEAN_BUILD; then
  docker rmi $BUILD_IMG_TAG
fi

# Now ready to run ./build-release-images.sh
