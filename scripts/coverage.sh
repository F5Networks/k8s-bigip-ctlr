#!/bin/sh
# Generate test coverage statistics for Go packages.
#
# Works around the fact that `go test -coverprofile` currently does not work
# with multiple packages, see https://code.google.com/p/go/issues/detail?id=6909
#

set -e

PROJECT=$PWD
profile="coverage.out"
mode=count

generate_cover_data() {
    for pkg in "$@"; do
        f="$(echo $pkg | tr / -).cover"
        env GOPATH=$PROJECT:$PROJECT/vendor go test -covermode="$mode" -coverprofile="$f" "$pkg"
    done

    echo "mode: $mode" > "$profile"
    NUM_COVERAGE_FILES=`find . -name "*.cover" | wc -l`
    if [ 0 -eq $NUM_COVERAGE_FILES ]; then
	echo "No coverage analysis performed."
	exit 0
    fi
    grep -h -v "^mode:" *.cover >> "$profile"
    env GOPATH=$PROJECT:$PROJECT/vendor go tool cover -html="$profile" -o coverage.html
    rm -f *.cover
}

generate_cover_data $(gb list ./...)
