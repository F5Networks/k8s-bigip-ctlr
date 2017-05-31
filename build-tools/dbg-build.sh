#!/bin/bash


set -e

CURDIR="$(dirname $BASH_SOURCE)"
BUILD_VARIANT=debug

# TODO: Fix races first...
#BUILD_VARIANT_FLAGS="-race"

. $CURDIR/_build-lib.sh

go_install $(all_cmds)

for pkg in $(all_cmds) $(all_pkgs); do
  test_pkg_profile "$pkg"
done
