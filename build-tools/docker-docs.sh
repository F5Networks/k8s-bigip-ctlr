#!/usr/bin/env bash

set -x

: ${DOC_IMG:=f5devcentral/containthedocs:latest}

RUN_ARGS=( \
  --rm
  -v $PWD:$PWD
  --workdir $PWD
  ${DOCKER_RUN_ARGS}
  -e "LOCAL_USER_ID=$(id -u)"
  -e TRAVIS=$TRAVIS
)

if [[ $TRAVIS_BRANCH == *"-stable" || "$TRAVIS_BRANCH" =~ ^v[0-9]+\.[0-9]+\.[0-9]* ]]; then
  release="$(git describe --tags --abbrev=0)"
  RUN_ARGS+=( -e DOCS_RELEASE=$release )
  va=( ${release//./ } ) # replace decimals and split into array
  version="${va[0]}.${va[1]}"
  RUN_ARGS+=( -e DOCS_VERSION=$version )
fi

# Add -it if caller is a terminal
if [ -t 0 ]; then
  RUN_ARGS+=( "-it" )
fi

# Run the user provided args
docker run "${RUN_ARGS[@]}" ${DOC_IMG} "$@"
