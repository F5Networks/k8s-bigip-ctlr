#!/bin/bash

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Build the builder image.
#
# This may download many build tools,
# build dependencies and so on.
#
# Adding editing tools is discouraged, since the pattern is to edit files
# outside a conatiner.
#
# Runtime Dockerfile will add only the runtime dependencies


WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.$BASE_OS.builder $WKDIR/Dockerfile.builder
cp $CURDIR/entrypoint.builder.sh $WKDIR
cp $CURDIR/../requirements.txt $WKDIR
cp $CURDIR/../requirements.docs.txt $WKDIR
# GOLANG patches
cp $CURDIR/golang/17847.patch $WKDIR/
cp $CURDIR/golang/no-pic.patch $WKDIR/

docker build --pull --force-rm ${NO_CACHE_ARGS} \
  -t $BUILD_IMG_TAG \
  -f $WKDIR/Dockerfile.builder \
  $WKDIR

# Repeat for debug builder  (To enable -race)
WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.builder.dbg $WKDIR
cp $CURDIR/entrypoint.builder.debian.sh $WKDIR
#cp $CURDIR/../python/k8s-*-requirements.txt $WKDIR/
#cp $CURDIR/../requirements.docs.txt $WKDIR

docker build --pull --force-rm ${NO_CACHE_ARGS} \
  -t $BUILD_DBG_IMG_TAG \
  -f $WKDIR/Dockerfile.builder.dbg \
  $WKDIR

rm -rf docker-build.????

docker history $BUILD_IMG_TAG
echo "Built docker image $BUILD_IMG_TAG"

docker history $BUILD_DBG_IMG_TAG
echo "Built docker image $BUILD_DBG_IMG_TAG"
