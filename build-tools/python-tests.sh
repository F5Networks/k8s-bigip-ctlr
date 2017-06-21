#!/bin/bash

# run python style and unit tests
# simplified to run in build-devel-image

set -e
set -x

cd python
flake8 . --exclude src
pytest . -slvv --ignore=src/ -p no:cacheprovider
