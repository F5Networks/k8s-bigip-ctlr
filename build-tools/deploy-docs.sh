#!/usr/bin/env bash

# Don't set -x
# we need to keep the secrets AWS variables out of the logs

exec docker run --rm -it -v $PWD:$PWD --workdir $PWD -e  AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY -e AWS_S3_BUCKET=$AWS_S3_BUCKET f5devcentral/containthedocs "$@"
