#!/bin/bash

# run python style and unit tests
# simplified to run in build-devel-image

set -ex

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh
BUILDDIR=$(get_builddir)

echo "BUILDDIR: as seen from python-tests -- $BUILDDIR"

(cd python && flake8 . --exclude src,lib,go,bin,docs,cmd)
(cd python && pytest . -slvv --ignore=src/ -p no:cacheprovider)
