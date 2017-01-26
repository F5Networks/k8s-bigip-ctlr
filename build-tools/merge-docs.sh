#!/bin/bash

: ${GIT_STAGE:=true}

set -x
set -e

usage() {
  cat <<EOF
Usage: $0 <dst-dir>

Copy the local docs into a parent project.
The include and static paths will be fixed so that their absolute paths do not
change.

The dst-dir is assumed to be a git repo, and all changes will be staged.
To skip this, set GIT_STAGE=false
EOF
}

dst="$1"
shift

if ! [ -d "${dst}" ]; then
  usage
  exit 1
fi

self=f5-csi_k

rm -rf "${dst}"/docs/${self}
cp -R docs "${dst}"/docs/${self}
rm -rf "${dst}"/docs/${self}/_build

# These directories are includes using absolute paths.
# When they are copied into the parent project, they should maintain the same
# absolute path
for dir in includes static; do
  if ! [ -d docs/${dir} ]; then
    continue;
  fi
  rm -rf "${dst}/docs/${dir}/${self}"
  mkdir -p "${dst}/docs/${dir}"
  mv "${dst}/docs/${self}/${dir}/${self}" "${dst}/docs/${dir}/${self}"
  # There should be no other files in the old path. rmdir will fail if there are
  rmdir "${dst}/docs/${self}/${dir}"
  if ${GIT_STAGE}; then
    git -C "${dst}" add "docs/${dir}/${self}"
  fi
done

if ${GIT_STAGE}; then
  git -C "${dst}" add "docs/${self}"
  git -C "${dst}" status
fi
