#!/bin/bash

#
# Run the arrtibutions generator container
#

set -e
set -x

ATTR_GEN_IMG=f5networksdevel/attributions-generator:latest
docker pull ${ATTR_GEN_IMG}

LOCAL_USER_ID=$(id -u)
if [ "$GITLAB_CI" == true ]; then
  LOCAL_USER_ID=9001
fi

RUN_ARGS=( \
  --rm
  -v $PWD:$PWD
  -e LOCAL_USER_ID=$LOCAL_USER_ID
)

docker run "${RUN_ARGS[@]}" ${ATTR_GEN_IMG}  "$@"
