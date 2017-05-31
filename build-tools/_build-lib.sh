#!/bin/bash

#
# This is the common enviromnent for building the runtime image, and the
# reusable developer image
#
# The build uses two docker container types:
#  - Builder container: We build this container with all the build tools and
#  dependencies need to build and test everything. The source can be mounted as
#  a volume, and run any build command needed.
#  The built artifacts can then be added to the runtime container without any
#  build deps
#  - Runtime container: This container is just the minimum base runtime
#      environment plus any artifacts from the builder that we need to actually
#      run the proxy.  We leave all the tooling behind.

set -e

# CI Should set these variables
: ${CLEAN_BUILD:=false}
: ${IMG_TAG:=k8s-bigip-ctlr:latest}
: ${BUILD_IMG_TAG:=k8s-bigip-ctlr-devel:latest}
: ${BUILD_DBG_IMG_TAG:=${BUILD_IMG_TAG}-debug}
: ${BUILD_VARIANT:=release}
: ${BUILD_VARIANT_FLAGS:=}

PKGIMPORT="github.com/F5Networks/k8s-bigip-ctlr"


# Defer calculating build dir until actualy in the build environment
get_builddir() {
# Ensure PWD starts with GOPATH
  if [ "${PWD##$GOPATH}" == "${PWD}" ]; then
    echo '$PWD is not in $GOPATH. Refusing to continue.'
    exit 1
  fi

  local platform="$(go env GOHOSTOS)-$(go env GOHOSTARCH)-${BUILD_VARIANT}"
  local govers=$(go version  | awk '{print $3}')

  echo "${GOPATH}/out/$platform-$govers"
}

# This is the expected output location, from the release build container
RELEASE_PLATFORM=linux-amd64-release-go1.7.5

NO_CACHE_ARGS=""
if $CLEAN_BUILD; then
  NO_CACHE_ARGS="--no-cache"
fi


echodo() {
  printf " + %s\n" "$*" >&2
  "$@"
}


#TODO: Should GOBIN be set too?
go_install () {
  local pkg="$1"
  local BUILDDIR=$(get_builddir)


  mkdir -p "$BUILDDIR"
  (
    export GOBIN="$BUILDDIR/bin"
    echodo cd "$BUILDDIR"
    echodo go install $BUILD_VARIANT_FLAGS -v "$pkg"
  )
}

test_pkg () {
  local pkg="$1"
  local BUILDDIR=$(get_builddir)

  mkdir -p "$BUILDDIR/test/$pkg"
  (
    export GOBIN="$BUILDDIR/bin"
    echodo cd "$BUILDDIR/test/$pkg"
    echodo go test -v -covermode=count -coverprofile=coverage.out "$pkg"
  )
}

test_pkg_cover () {
  local pkg="$1"
  local BUILDDIR=$(get_builddir)

  mkdir -p "$BUILDDIR"
  (
    export GOBIN="$BUILDDIR/bin"
    echodo cd "$BUILDDIR"
    echodo go test -v "$pkg"
  )
}

test_pkg_profile () {
  local pkg="$1"
  local BUILDDIR=$(get_builddir)

  mkdir -p "$BUILDDIR/test/$pkg"
  (
    export GOBIN="$BUILDDIR/bin"
    echodo cd "$BUILDDIR/test/$pkg"
    echodo go test -v  \
            ${BUILD_VARIANT_FLAGS} \
            -test.benchmem \
            -test.cpuprofile profile.cpu \
            -test.blockprofile profile.block \
            -test.memprofile profile.mem \
            "$pkg"
  )
}

all_cmds() {
  echodo go list ./cmd/...
}
all_pkgs() {
  echodo go list ./pkg/...
}

gather_coverage() {
  local BUILDDIR=$(get_builddir)

  (
    cd $BUILDDIR/test
    gocovmerge `find . -name coverage.out` > merged-coverage.out
    go tool cover -html=merged-coverage.out -o coverage.html
    go tool cover -func=merged-coverage.out
    # Total coverage for CI
    go tool cover -func=merged-coverage.out | grep "^total:" | awk 'END { print "Total coverage:", $3, "of statements" }'
  )

}
