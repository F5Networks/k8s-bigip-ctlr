#!/bin/bash

# This script packages up artifacts produced by ./build-release-artifacts.sh
# into an official container.

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Setup a temp docker build context dir
WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.runtime $WKDIR

# Hard code the platform dir here
cp $CURDIR/../_docker_workspace/out/$RELEASE_PLATFORM/bin/* $WKDIR/
mkdir -p $WKDIR/python
cp python/*.py $WKDIR/python/
cp python/k8s-runtime-requirements.txt $WKDIR/
cp schemas/bigip-virtual-server_v*.json $WKDIR/

echo "Docker build context:"
ls -la $WKDIR

docker build --force-rm ${NO_CACHE_ARGS} \
  -t $IMG_TAG \
  -f $WKDIR/Dockerfile.runtime \
  $WKDIR

docker history $IMG_TAG
echo "Built docker image $IMG_TAG"

rm -rf docker-build.????
