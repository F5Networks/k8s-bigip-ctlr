#!/bin/bash

# This script builds and uses a docker container to produce official artifacts

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

# Making changes to user docker volume as workspace
#mkdir -p  _docker_workspace
docker volume create workspace_vol
WORKSPACE=/build/src/github.com/F5Networks/
# adding logic for copying the code repository to newly created volume
docker run -v workspace_vol:/build --rm -d alpine mkdir -p $WORKSPACE
# Removing cp-temp container if already exist
if docker ps -a | grep cp-temp ; then docker rm -f cp-temp ; fi
docker run -v workspace_vol:/build -d --name cp-temp alpine tail -f /dev/null
# copying CIS code to volume
docker cp $CURDIR/../../k8s-bigip-ctlr cp-temp:$WORKSPACE
#Removing the temporory container
docker rm -f cp-temp

. $CURDIR/_build-lib.sh

# Build artifacts using the build image
$CURDIR/run-in-docker.sh ./build-tools/rel-build.sh

if $CLEAN_BUILD; then
  docker rmi $BUILD_IMG_TAG
fi

# Now ready to run ./build-release-images.sh
