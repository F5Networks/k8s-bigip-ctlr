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

do_sum() {
  out=$1

  cur=$(echo $out | sed -e 's/^ok.*coverage:\s*//' -e 's/%.*$//')
  coverage=$(echo "$coverage $cur" | awk '{ SUM = $1 + $2 } END { print SUM }')
}

generate_cover_data() {
    for pkg in "$@"; do
        f="$(echo $pkg | tr / -).cover"
        out=$(env GOPATH=$PROJECT:$PROJECT/vendor go test -covermode="$mode" -coverprofile="$f" "$pkg")
        echo $out
        echo $out | grep -q "no test files" || do_sum "$out"
    done

    echo "mode: $mode" > "$profile"
    NUM_COVERAGE_FILES=`find . -name "*.cover" | wc -l`
    if [ 0 -eq $NUM_COVERAGE_FILES ]; then
	echo "No coverage analysis performed."
	exit 0
    fi
    coverage_mean=$(echo "$coverage $NUM_COVERAGE_FILES" | awk '{ MEAN = $1 / $2 } END { printf "%.2f", MEAN }')
    echo "mean coverage: ${coverage_mean}% of statements"
    grep -h -v "^mode:" *.cover >> "$profile"
    env GOPATH=$PROJECT:$PROJECT/vendor go tool cover -html="$profile" -o coverage.html
    rm -f *.cover
}

generate_cover_data $(gb list ./...)
