#!/bin/bash

# expects node:6.11.0-slim and k8s-bigip-ctlr as volume

set -e

npm install jsonschema nodeunit
schemas/scripts/run-tests.sh
rm -rf node_modules/
