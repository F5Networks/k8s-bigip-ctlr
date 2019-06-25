#!/bin/bash

# Create a go workspace in a container, and run any command
#
# $PWD is mounted into the correct go workspace loaction
# All output artifacts are placed in $PWD/_docker_workspace
#

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

: ${build_img:=${BUILD_IMG_TAG}}

# Need to make the directory before docker, to keep it owned by local user
srcdir=/build/src/github.com/F5Networks/k8s-bigip-ctlr/
#wkspace=${PWD}/_docker_workspace
#mkdir -p $wkspace/$srcdir
#LOCAL_USER_ID=$(id -u)
LOCAL_USER_ID=9001
if [ "$GITLAB_CI" == true ]; then
  TRAVIS_REPO_SLUG=$CI_PROJECT_PATH
  LOCAL_USER_ID=9001
fi
RUN_ARGS=( \
  --rm
#  -v $wkspace:/build:Z
#  -v $PWD:/build/$srcdir:ro,Z
  -v workspace_vol:/build/
  --workdir  $srcdir
  -e GOPATH=/build
  -e CLEAN_BUILD=$CLEAN_BUILD
  -e IMG_TAG=$IMG_TAG
  -e BUILD_IMG_TAG=$BUILD_IMG_TAG
  -e BUILD_VERSION=$BUILD_VERSION
  -e BUILD_INFO=$BUILD_INFO
  -e LOCAL_USER_ID=$LOCAL_USER_ID
  -e TRAVIS_REPO_SLUG=$TRAVIS_REPO_SLUG
  -e COVERALLS_TOKEN=$COVERALLS_REPO_TOKEN
  -e RUN_TESTS=$RUN_TESTS
  -e BASE_OS=$BASE_OS
)

# Add -it if caller is a terminal
if [ -t 0 ]; then
  RUN_ARGS+=( "-it" )
fi
# Run the user provided args
docker run "${RUN_ARGS[@]}" "$build_img" "$@"
