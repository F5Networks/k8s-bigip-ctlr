#!/bin/bash

# This script packages up artifacts produced by ./build-release-artifacts.sh
# into an official container.


set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Setup a temp docker build context dir
WKDIR=$(mktemp -d docker-build.XXXX)
cp $CURDIR/Dockerfile.$BASE_OS.runtime $WKDIR/Dockerfile.runtime

BUILD_INFO=$(${CURDIR}/version-tool build-info)
VERSION_INFO=$(${CURDIR}/version-tool version)

# Hard code the platform dir here
cp $CURDIR/../_docker_workspace/out/$RELEASE_PLATFORM/bin/* $WKDIR/
cp requirements.txt $WKDIR/
cp schemas/bigip-virtual-server_v*.json $WKDIR/
cp schemas/as3-schema-3.11.0-3-cis.json $WKDIR/
cp LICENSE $WKDIR/
cp $CURDIR/help.md $WKDIR/help.md
echo "{\"version\": \"${VERSION_INFO}\", \"build\": \"${BUILD_INFO}\"}" \
  > $WKDIR/VERSION_BUILD.json

echo "Docker build context:"
ls -la $WKDIR

if [[ $BASE_OS == "rhel7" ]]; then
  PULL_FLAG="--pull"
fi

VERSION_BUILD_ARGS=$(${CURDIR}/version-tool docker-build-args)
docker build $PULL_FLAG --force-rm ${NO_CACHE_ARGS} \
  -t $IMG_TAG \
  --label BUILD_STAMP=$BUILD_STAMP \
  ${VERSION_BUILD_ARGS} \
  -f $WKDIR/Dockerfile.runtime \
  $WKDIR

docker history $IMG_TAG
docker inspect -f '{{ range $k, $v := .ContainerConfig.Labels -}}
{{ $k }}={{ $v }}
{{ end -}}' "$IMG_TAG"

echo "Built docker image $IMG_TAG"

rm -rf docker-build.????
