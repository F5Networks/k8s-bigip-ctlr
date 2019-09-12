#!/bin/bash

#
# Run the arrtibutions generator container
#

set -e
set -x

# ATTR_GEN_IMG=f5networksdevel/attributions-generator:latest
# FIXME: Includes a fix for processing "sigs.k8s.io" repos which is modified directly in the container image.
# This change needs to go in the source.

ATTR_GEN_IMG=cisbot/attributions-generator:latest

docker pull ${ATTR_GEN_IMG}

RUN_ARGS=( \
  --rm
  -v $PWD:$PWD
  -e LOCAL_USER_ID=$(id -u)
)

docker run "${RUN_ARGS[@]}" ${ATTR_GEN_IMG}  "$@"
