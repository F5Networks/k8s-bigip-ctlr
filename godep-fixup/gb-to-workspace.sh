#!/bin/bash

set -e
set -x


mkdir pkg cmd
git mv src/k8s-bigip-ctlr cmd/k8s-bigip-ctlr
git mv src/* pkg/
git mv pkg/tools/* pkg/

