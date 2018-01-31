#!/bin/bash

set -x
set -e

go tool vet -all -shadow ./cmd ./pkg

exit $?
