#!/bin/bash -x

# Format of version tag in git must match RELEASE_VERSION_REGEX
DEB_TAG_FMT="v%(version)s"
RELEASE_VERSION_REGEX="^v(([0-9]+\.){2}([0-9]+)(~([0-9A-Za-z\.~])*){0,1}$)"

