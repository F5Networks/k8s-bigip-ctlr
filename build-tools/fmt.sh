#!/bin/bash

set -x

# Use 'go fmt' to find all the files that do not comply, modify them,
# and then collect the diff as an artifact.
CHANGED_FILES=$(go fmt ./cmd/... ./pkg/...)
if [ "$CHANGED_FILES" != "" ]; then
    printf "\n\n\nFiles requiring modification:\n\n$CHANGED_FILES\n\n\n";
fi

git diff --exit-code
exit $?
