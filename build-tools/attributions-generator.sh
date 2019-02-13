#!/bin/bash

#
# Run the arrtibutions generator container
#

set -e
set -x

ATTR_GEN_IMG=f5networksdevel/attributions-generator:latest
docker pull ${ATTR_GEN_IMG}

RUN_ARGS=( \
  --rm
  -v $PWD:$PWD
  -e LOCAL_USER_ID=$(id -u)
)

docker run "${RUN_ARGS[@]}" ${ATTR_GEN_IMG}  "$@"
