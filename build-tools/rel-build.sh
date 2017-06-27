#!/bin/bash


set -ex

CURDIR="$(dirname $BASH_SOURCE)"

. $CURDIR/_build-lib.sh
BUILDDIR=$(get_builddir)

for pkg in $(all_cmds) $(all_pkgs); do
  test_pkg "$pkg"
done

go_install $(all_cmds)

echo "Gathering unit test code coverage for 'release' build..."
gather_coverage

# run python tests
./build-tools/python-tests.sh
