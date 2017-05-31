#!/bin/bash

set -x

# Use 'go fmt' to find all the files that do not comply, modify them,
# and then collect the diff as an artifact.
CHANGED_FILES=$(go fmt ./cmd/... ./pkg/...)
if [ "$CHANGED_FILES" != "" ]; then
    printf "\n\n\nFiles requiring modification:\n\n$CHANGED_FILES\n\n\n";
fi

# FIXME(lenny) When Gitlab CI will upload artifacts even on build then
# write the diff to a file and upload it instead of writing the diff
# only to the logs.
git diff --exit-code
exit $?
