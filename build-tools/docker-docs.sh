#!/usr/bin/env bash

set -x

: ${DOC_IMG:=docker-registry.pdbld.f5net.com/tools/containthedocs:master}
 
exec docker run --rm -it \
  -v $PWD:$PWD --workdir $PWD \
  ${DOCKER_RUN_ARGS} \
  -e "LOCAL_USER_ID=$(id -u)" \
  ${DOC_IMG} "$@"
