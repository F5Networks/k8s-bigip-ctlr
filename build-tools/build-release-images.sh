#!/bin/bash

# This script packages up artifacts produced by ./build-release-artifacts.sh
# into an official container.


set -e
set -x

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh

# Setup a temp docker build context dir
WKDIR=$(mktemp -d docker-build.XXXX)
DEBUG=${DEBUG:-1}

cp $CURDIR/Dockerfile.$BASE_OS.runtime $WKDIR/Dockerfile.runtime

if [ $DEBUG == 0 ]
then
  cp $CURDIR/Dockerfile.debug.runtime $WKDIR/Dockerfile.runtime
fi

BUILD_INFO=$(${CURDIR}/version-tool build-info)
VERSION_INFO=$(${CURDIR}/version-tool version)

# adding logic for copying the code repository to newly created volume
docker run -v workspace_vol:/build -d --name cp-temp alpine tail -f /dev/null
# copying CIS binary to local
docker cp cp-temp:/build/out/$RELEASE_PLATFORM/bin/k8s-bigip-ctlr $WKDIR/
#Removing the temporory container
docker rm -f cp-temp

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
# Removing the workspace volume
docker volume rm -f workspace_vol
rm -rf docker-build.???? _docker_workspace
