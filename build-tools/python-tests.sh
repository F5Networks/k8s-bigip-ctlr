#!/bin/bash

# run python style and unit tests
# simplified to run in build-devel-image

set -ex

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh
BUILDDIR=$(get_builddir)

export BUILDDIR=$BUILDDIR

flake8 ./build-tools/version-tool
(cd python && flake8 . --exclude src,lib,go,bin,docs,cmd)
(cd python && pytest . -slvv --ignore=src/ -p no:cacheprovider --cov)
# Don't run bandit from python directory, doing so issues warnings.
(bandit python/*.py)

if [ "$TRAVIS_REPO_SLUG" != "" ]; then
  if [ "$COVERALLS_TOKEN" ]; then
    echo "Converting python coverage to goveralls format..."
    (cd python && coveralls --output=$BUILDDIR/coverage.json)
    python build-tools/python-coverage.py $BUILDDIR/coverage.json $BUILDDIR/python-coverage.txt
  else
    echo "[INFO] Not an 'F5Networks' commit, coverage optional."
    echo "[INFO] See README.md section 'build' to configure travis with coveralls."
  fi
fi
