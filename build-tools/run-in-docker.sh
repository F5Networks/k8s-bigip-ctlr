#!/bin/bash

# Run any command in the devel image

set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/build-env.sh

RUN_ARGS=( \
  --rm
  -v $PWD:$PWD:z
  --workdir $PWD
  -e CLEAN_BUILD="${CLEAN_BUILD}"
  -e IMG_TAG="${IMG_TAG}"
  -e BUILD_IMG_TAG="${BUILD_IMG_TAG}"
  -e LOCAL_USER_ID=$(id -u)
)

# Add -it if caller is a terminal
if [ -t 0 ]; then
  RUN_ARGS+=( "-it" )
fi

# Run the user provided args
docker run "${RUN_ARGS[@]}" "$BUILD_IMG_TAG" "$@"
