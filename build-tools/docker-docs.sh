#!/usr/bin/env bash

set -x

: ${DOC_IMG:=docker-registry.pdbld.f5net.com/tools/containthedocs:master}
 
RUN_ARGS=( \
  --rm
  -v $PWD:$PWD
  --workdir $PWD
  ${DOCKER_RUN_ARGS}
  -e "LOCAL_USER_ID=$(id -u)"
)

# Add -it if caller is a terminal
if [ -t 0 ]; then
  RUN_ARGS+=( "-it" )
fi

# Run the user provided args
docker run "${RUN_ARGS[@]}" ${DOC_IMG} "$@"
