#!/bin/bash

set -e
set -x

git submodule sync
git submodule update --init

# Generate vendors.txt, recording the current versions of all vendors
# Keep this to verify godep versions later
git submodule -q foreach sh -c 'd=$PWD && echo $d $(cd $d && git remote get-url origin) $(cd $d && git rev-parse HEAD)' \
  | sed -e "s,^$PWD/vendor/src/,," \
  | egrep -v "^(f5/|$PWD)" \
  > vendors.txt

while read d r s; do
  git rm -rf vendor/src/$d
done < vendors.txt
git rm -rf vendor
rm -rf vendor
git rm -rf gb-pkgs
rm -rf gb-pkgs

git commit -m 'Remove old vendor submodules

Godep save will only pull in the code that is actually imported. Remove the code
from the old vendor directroy to keep it from getting confused

The exact versions of these modules will be checked out into the go workspace
for godep to find,

./godep-fixup/02-remove-old-vendor.sh
'
