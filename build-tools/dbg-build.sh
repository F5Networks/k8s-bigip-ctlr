#!/bin/bash


set -e

CURDIR="$(dirname $BASH_SOURCE)"
BUILD_VARIANT=debug

# TODO: Fix races first...
#BUILD_VARIANT_FLAGS="-race"

. $CURDIR/_build-lib.sh

go_install $(all_cmds)

ginkgo_test_with_profile
