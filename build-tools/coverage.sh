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
coverage=0

generate_cover_data() {
    for pkg in "$@"; do
        # This will generate a .cover file for each package
        f="$(echo $pkg | tr / -).cover"
        env GOPATH=$PROJECT:$PROJECT/vendor go test -covermode="$mode" -coverprofile="$f" "$pkg"
    done

    NUM_COVERAGE_FILES=`find . -name "*.cover" | wc -l`
    if [ 0 -eq $NUM_COVERAGE_FILES ]; then
	echo "No coverage analysis performed."
	exit 0
    fi
    # Merge all .cover files into one. The tool will handle overlaps correctly
    gocovmerge $(find . -name \*.cover) > $profile
    # Generate the total coverage % and also the detailed html
    env GOPATH=$PROJECT:$PROJECT/vendor go tool cover -func="$profile" | grep "^total:" | awk 'END { print "Total coverage:", $3, "of statements" }'
    env GOPATH=$PROJECT:$PROJECT/vendor go tool cover -html="$profile" -o coverage.html
    rm -f *.cover
}

generate_cover_data $(gb list ./...)
