#!/bin/bash

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or
# fallback

USER_ID=${LOCAL_USER_ID:-9001}

echo "Starting with UID : $USER_ID"
export HOME=/home/user

if [ -v GOSU_VERSION ]; then
    adduser -s /bin/bash -u $USER_ID user
    su_binary=gosu
    source scl_source enable python27
else
    adduser -D -s /bin/bash -u $USER_ID user
    su_binary=/sbin/su-exec
fi

exec $su_binary user "$@"