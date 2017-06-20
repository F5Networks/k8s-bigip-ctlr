#!/bin/bash

testFiles=`find $PWD/schemas/test -name 'test-*' -type f -not -path '*/node_modules/*'`

NODE_ENV="test" $PWD/node_modules/nodeunit/bin/nodeunit $testFiles
