#!/bin/bash

# This script packages up artifacts produced by ./build-runtime-artifacts.sh
# into an official container.

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/build-env.sh

# Setup a temp docker build context dir
WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.runtime $WKDIR
cp bin/f5-k8s-controller $WKDIR/
cp -R -l python $WKDIR/
cp --remove-destination vendor/src/velcro/f5-marathon-lb/_f5.py $WKDIR/python/_f5.py
cp --remove-destination vendor/src/velcro/f5-marathon-lb/common.py $WKDIR/python/common.py
cp vendor/src/velcro/schemas/bigip-virtual-server_v*.json $WKDIR/

echo "Docker build context:"
ls -la $WKDIR

docker build --force-rm ${NO_CACHE_ARGS} \
  -t $IMG_TAG \
  -f $WKDIR/Dockerfile.runtime \
  $WKDIR

docker history $IMG_TAG
echo "Built docker image $IMG_TAG"

rm -rf docker-build.????
