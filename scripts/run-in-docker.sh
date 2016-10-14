#!/bin/bash

IMGNAME=f5-k8s-ctrl-devel

set -x 

exec docker run --rm -it -v $PWD:$PWD --workdir $PWD ${IMGNAME} "$@"
