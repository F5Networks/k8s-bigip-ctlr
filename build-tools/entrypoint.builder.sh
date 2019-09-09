#!/bin/bash

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or
# fallback
chmod -R 755 /build
USER_ID=${LOCAL_USER_ID:-9001}

echo "Starting with UID : $USER_ID"
export HOME=/home/user

echo "BASE_OS=$BASE_OS"
if [[ $BASE_OS == "debian" ]]; then
  ADDUSER_FLAG='--disabled-password --gecos ""'
fi

if [ -x /sbin/su-exec ]; then
    adduser -D --shell /bin/bash --uid $USER_ID ${ADDUSER_FLAG} user
    su_binary=/sbin/su-exec
else
    adduser --shell /bin/bash --uid $USER_ID ${ADDUSER_FLAG} user
    su_binary=gosu
    source scl_source enable python27
fi
chmod -R 755 /build
chown -R user:user /build
exec $su_binary user "$@"
