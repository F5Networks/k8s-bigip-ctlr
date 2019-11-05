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
: ${BUILD_VARIANT:=release}
: ${BUILD_VARIANT_FLAGS:=}

PKGIMPORT="github.com/F5Networks/k8s-bigip-ctlr"


if [[ $BUILD_VERSION == "" ]]; then
  echo "Must set BUILD_VERSION"
  false
fi
if [[ $BUILD_INFO == "" ]]; then
  echo "Must set BUILD_INFO"
  false
fi


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
RELEASE_PLATFORM=linux-amd64-release-go1.13.4

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
  # Declare seperate from assign, so failures aren't maked by local
  local BUILDDIR
  BUILDDIR=$(get_builddir)
  local GO_BUILD_FLAGS=( -v -ldflags "-extldflags \"-static\" -X main.version=${BUILD_VERSION} -X main.buildInfo=${BUILD_INFO}" )

  if [ $DEBUG == 0 ]
  then
    GO_BUILD_FLAGS+=( -gcflags "all=-N -l" )
  fi

  mkdir -p "$BUILDDIR"
  (
    export GOBIN="$BUILDDIR/bin"
    echodo cd "$BUILDDIR"
    export GO111MODULE=on
    echodo go install $BUILD_VARIANT_FLAGS "${GO_BUILD_FLAGS[@]}" -v "$@"
  )
}

ginkgo_test_with_coverage () {
  local WKDIR=$(tmpdir_for_test)
  BUILDDIR=$(get_builddir)
  # Set our gopath to the tmp dir for package import resolution
  export GOPATH=$WKDIR

  (
    export GOBIN="$BUILDDIR/bin"
    cd "$WKDIR/src/$PKGIMPORT"
    ginkgo -r -compilers 1 -keepGoing -trace -randomizeAllSpecs -progress --nodes 4 -cover
    echo "Gathering unit test code coverage for 'release' build..."
    gather_coverage $WKDIR
    rm -rf $WKDIR
    export GOPATH=/build
  )
}

ginkgo_test_with_profile () {
  local WKDIR=$(tmpdir_for_test)
  BUILDDIR=$(get_builddir)
  mkdir -p $BUILDDIR/profile
  export GOPATH=$WKDIR
  (
    export GOBIN="$BUILDDIR/bin"
    cd "$WKDIR/src/$PKGIMPORT"
    ginkgo -r -compilers 1 -keepGoing -randomizeAllSpecs -progress --nodes 4 \
            ${BUILD_VARIANT_FLAGS} -- \
            -test.cpuprofile profile.cpu \
            -test.blockprofile profile.block \
            -test.memprofile profile.mem
    rsync -a -f"+ */" -f"+ profile.cpu" -f"+ profile.block" -f"+ profile.mem" -f"- *" . $BUILDDIR/profile
    rm -rf $WKDIR
    export GOPATH=/build
  )
}

all_cmds() {
  echodo go list ./cmd/...
}
all_pkgs() {
  echodo go list ./pkg/...
}

gather_coverage() {
	local WKDIR="$1"
	mkdir -p $BUILDDIR/coverage

  (
    cd $WKDIR/src/github.com/F5Networks
    gocovmerge `find . -name *.coverprofile` > coverage.out
    go tool cover -html=coverage.out -o coverage.html
    go tool cover -func=coverage.out
    # Total coverage for CI
    go tool cover -func=coverage.out | grep "^total:" | awk 'END { print "Total coverage:", $3, "of statements" }'
    rsync -a -f"+ */" -f"+ *.coverprofile" -f"+ coverage.html" -f"+ coverage.out" -f"- *" . $BUILDDIR/coverage
  )
}

# Create a tmp dir with go src files in a writable location
tmpdir_for_test() {
  BUILDDIR=$(get_builddir)
  mkdir -p $BUILDDIR
  # Create a temp dir we can write to
  local WKDIR=$(mktemp -d $BUILDDIR/tmpXXXXXX)
  # src dir to follow gopath convention
  mkdir -p $WKDIR/src
  # Copy over mounted src to our writable src
  rsync -a --exclude '.git' --exclude '_docker_workspace' $GOPATH/src/ $WKDIR/src
  echo $WKDIR
}
