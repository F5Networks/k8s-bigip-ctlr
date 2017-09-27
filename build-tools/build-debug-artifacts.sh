#!/bin/bash

# This script builds and uses a docker container to produce official artifacts

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Build artifacts using the build image
export build_img=$BUILD_DBG_IMG_TAG
$CURDIR/run-in-docker.sh make verify
$CURDIR/run-in-docker.sh ./build-tools/dbg-build.sh
