#!/bin/bash

# This script builds and uses a docker container to produce official artifacts

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"
mkdir -p  _docker_workspace
. $CURDIR/_build-lib.sh
build_dir=/build/out/
# Build artifacts using the build image
$CURDIR/run-in-docker.sh ./build-tools/rel-build.sh
if $CLEAN_BUILD; then
  docker rmi $BUILD_IMG_TAG
fi

# Now ready to run ./build-release-images.sh
