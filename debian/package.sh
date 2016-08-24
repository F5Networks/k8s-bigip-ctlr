#!/bin/bash -x

source "$(dirname "$0")/common.sh"

function show_help() {
    cat <<-END
usage: configure [OPTIONS] DISTRO

Configure the Debian packaging system.

OPTIONS:
    -C <path>  Directory containing the rules.m4 and control.m4 files.
    -R <ver>   Build the package with a specific version.
    --debug    Build without optimization.
    --help     Show this help.

DISTRO:
    The distro for which the package is to be built, such as "wily" or "jessie".
END
    exit $1
}

RELEASE_BUILD="RELEASE_BUILD"

function write_build_script() {
    SCRIPT_DIR=$1
    VERSION=$2
    GIT_EMAIL=$(git config user.email)
    GIT_USER=$(git config user.name)
    cat > ${SCRIPT_DIR}/dobuild.sh <<EOF
set -e
set -x

# Setup git
git config user.email ${GIT_EMAIL}
git config user.name ${GIT_USER}

# Install Build-Depends
${SUDO} apt-get update
${SUDO} mk-build-deps --tool "apt-get -y --no-install-recommends" \
  --install debian/control

if [ "${VERSION}" != "${RELEASE_BUILD}" ]; then
    # Update the changelog with the correct version. Version numbers used with
    # automated or developer builds will sort lower than released versions, so
    # we need to set an appropriate variable in ~/.devscripts to allow that.
    echo -e DEBCHANGE_LOWER_VERSION_PATTERN=${VERSION} > ~/.devscripts
    gbp dch --verbose --no-multimaint --auto --ignore-branch \
        --debian-tag="${DEB_TAG_FMT}" --new-version=${VERSION}
else
    # Update the changelog with status 'released' and the correct distribution.
    dch --verbose --release --distribution ${DISTRO} --nomultimaint
fi

# NOTE(garyr): The order that parameters are passed to debuild is important!
# In particular, the -D (check build dependencies)  MUST be first or the build
# dependencies will not be checked during the build. This is not as easy to do
# as it sounds, as gbp-buildpackage will reorder parameters incorrectly, such
# as when it applies default parameters like '-rfakeroot' and puts them at the
# beginning of the debuild command line and breaks build dependency checking.
DEBUILD_CMD='debuild -D --prepend-path="\${GOPATH}/bin" \
    -uc -us -j`nproc` -rfakeroot -I -Ibin -Ipkg -Ibuild'
gbp buildpackage \
  --git-verbose \
  --git-force-create \
  --git-ignore-new \
  --git-ignore-branch \
  --git-purge \
  --git-builder=\${DEBUILD_CMD}
EOF
}

# Extract the project name from git.
PROJECT_NAME=`git remote show -n origin | grep "Fetch URL:" | sed -e 's#\(.*\)\.git$#\1#' -e 's#^.*/\(.*\)#\1#'`
BUILD_TYPE="release"
BUILD_NAME_EXT=""
CONFLICTS_UNOPT="-unoptimized"
ORIG_DIR="${PWD}"
WORK_DIR="${PWD}"
PROJECT_DIR=`${GOPATH}/bin/gb env GB_PROJECT_DIR`
PROJECT_ROOT=`dirname ${PROJECT_DIR}`
if [ -n "${CI_BUILD_REF_NAME}" ]; then
    GIT_BRANCH=${CI_BUILD_REF_NAME}
else
    GIT_BRANCH=$(git symbolic-ref --short HEAD)
    if [ "$?" -ne "0" ]; then
        echo "ERROR: Unable to determine git branch!"
        exit 1
    fi
fi
GIT_REMOTE=$(git remote show -n origin | grep "Fetch URL")
GIT_REMOTE_REGEX="^\s*Fetch URL:\s*(.*)$"
if [[ ${GIT_REMOTE} =~ ${GIT_REMOTE_REGEX} ]]; then
    # Format the Vcs-Git field according to:
    # https://www.debian.org/doc/debian-policy/ch-controlfields.html
    # It also needs special treatment in the m4 command below.
    VCS_GIT="${BASH_REMATCH[1]} -b ${GIT_BRANCH}"
else
    echo "ERROR: Unable to determine value for Vcs-Git!"
    exit 1
fi
GIT_TAG=$(git describe --tags --always)
if [ -z "${GIT_TAG}" ]; then
    echo "ERROR: Unable to determine latest commit tag!"
    exit 1
fi
source "${PROJECT_DIR}/version.txt"
if [ -z "${VERSION_BRANCH}" ]; then
    echo "ERROR: Unable to determine version branch!"
    exit 1
fi

args=`getopt --options hdC:R: --longoptions help,debug -n "$0" -- "$@"`
if [ $? != 0 ] ; then
    show_help 2
fi

eval set -- "${args}"

while true; do
    case "$1" in
        -h|--help) show_help 0 ; exit 0 ;;
        --) shift; break ;;

        -C)
            WORK_DIR=`echo "$2" | xargs`
            shift 2
            ;;
        -R)
            # Check RELEASE_VERSION_TAG against RELEASE_VERSION_REGEX.
            RELEASE_VERSION_TAG="$2"
            if [[ ${RELEASE_VERSION_TAG} =~ ${RELEASE_VERSION_REGEX} ]]; then
                # RELEASE_VERSION has the 'v' stripped off.
                RELEASE_VERSION=${BASH_REMATCH[1]}
            else
                echo "ERROR: bad version tag format"
                # Dump out capture information to help identify the problem.
                i=0
                n=${#BASH_REMATCH[*]}
                while [[ $i -lt $n ]]; do
                    echo "  capture[$i]: ${BASH_REMATCH[$i]}"
                    let i++
                done
                exit 1
            fi
            shift 2
            ;;
        -d|--debug)
            BUILD_TYPE="debug"
            BUILD_NAME_EXT="-unoptimized"
            CONFLICTS_UNOPT=""
            shift 1
            ;;

        *) echo "Internal error: found $1" ; exit 1 ;;
    esac
done

# There should be one more item left and it is the distro. Anything else is an
# error. Help will be shown.
if [ "$#" -ne "1" ]; then
    echo "Distro specified. 1 and only 1 distro."
    show_help 3
else
    DISTRO=$1
    echo "Building for ${DISTRO}"
fi

# Create *.install files for each of the new packages being created for the
# build type requested.
if [ "" != "${BUILD_NAME_EXT}" ]; then
    for file in ${WORK_DIR}/*.install; do
        cp --force \
           "${file}" \
           "${file/\.install/${BUILD_NAME_EXT}\.install}"
    done
fi

# Generate the extended name.
EXTENDED_PROJECT_NAME=${PROJECT_NAME}${BUILD_NAME_EXT}

# Enter the project workspace.
cd ${PROJECT_ROOT}/${PROJECT_NAME}

# debuild doesn't allow us to specify the path for the output files, need to do
# that ourselves. It needs to be within $PROJECT_ROOT for gitlab-CI.
mkdir -p ${PROJECT_DIR}/build/${DISTRO}

# Need to determine if we are running containerized or (assume) under vagrant
if [ "$CI_BUILD_ID" != "" ]; then
    # Running on CI server
    echo "Running on CI server with build id: ${CI_BUILD_ID}"
    CONTAINER_ENV=1
else
    command -v docker >> /dev/null
    if [ "$?" -ne "0" ]; then 
        echo "Running within a Docker container"
        CONTAINER_ENV=1
        SUDO=sudo
    else
        # Our vagrant environment has docker installed
        echo "Running as a Vagrant VM"
        CONTAINER_ENV=0
    fi
fi

if [ "${CONTAINER_ENV}" -eq "1" ]; then
    PKG_DIR=${PROJECT_ROOT}

    # Use Builder's information in gitlab-ci
    git config user.email "builder@lineratesystems.com"
    git config user.name "Builder"

    BUILD_SCRIPT_DIR=${PROJECT_ROOT}
    BUILD_CMD="bash ${BUILD_SCRIPT_DIR}/dobuild.sh"

    # This will create a package with the debian revsion == CI_BUILD_ID
    VERSION="${PROJECT_VERSION}~${CI_BUILD_ID}.gitlab"
else
    # Running locally
    echo "Running on local vagrant instance"
    LOCAL_BUILD_DIR=/tmp/build/${DISTRO}
    DOCKER_BUILD_DIR=/build
    PKG_DIR=${LOCAL_BUILD_DIR}
    DOCKER_IMAGE=local:${DISTRO}

    # Ignore this package script as it is not run from the build tree.
    if [ ! -z "$(git status -su | grep -v debian/package.sh)" ]; then
        # Fail build if workspace has uncommitted files, as they
        # will not be included during 'git clone', which is not obvious.
        echo "ERROR: Your workspace contains uncommitted changes. " \
            "Please commit them before building release packages."
        exit 1
    fi

    FOUND_TAG=""
    if [ -z "${RELEASE_VERSION}" ]; then
        # Developer build, run dch in docker, don't keep changes
        VERSION=${PROJECT_VERSION}"~$(date '+%Y%m%d.%H%M%S').local"
    else
        # Release build, check to make sure there's a matching tag.
        VERSION=${RELEASE_BUILD}
        for tag in $(git tag --sort=-v:refname); do
            if [ "$tag" == "${RELEASE_VERSION_TAG}" ]; then
                FOUND_TAG=$tag
                break
            fi
        done
        if [ -z "${FOUND_TAG}" ]; then
            echo "ERROR: Required tag ${RELEASE_VERSION_TAG} not found!"
            exit 1
        fi
    fi

    # Create an area under /tmp/build where we will have docker build
    mkdir -p ${LOCAL_BUILD_DIR}
    sudo rm -rf ${LOCAL_BUILD_DIR}/*

    # Create a clone of our local workspace. This is required to workaround
    # the symlinks to /vagrant/.git and also to preserve tags.
    git clone --local --no-hardlinks --recursive \
        ${PROJECT_DIR} ${LOCAL_BUILD_DIR}/${PROJECT_NAME}
    if [ -n "${FOUND_TAG}" ]; then
        cd ${LOCAL_BUILD_DIR}/${PROJECT_NAME}
        git checkout ${FOUND_TAG}
        # Re-parse the project version and make sure it matches.
        PROJECT_VERSION=`dpkg-parsechangelog --show-field Version`
        cd -
        if [ "${PROJECT_VERSION}" != "${RELEASE_VERSION}" ]; then
            echo "ERROR: Expected changelog version of ${RELEASE_VERSION}, " \
                "but found ${PROJECT_VERSION}."
            exit 1
        fi
        PROJECT_DISTRO=`dpkg-parsechangelog --show-field Distribution`
        if [ "${PROJECT_DISTRO}" != "UNRELEASED" ]; then
            echo "ERROR: changelog status must be 'UNRELEASED'."
            exit 1
        fi
    fi

    # Ensure our docker image is built. See Dockerfile for image details.
    docker build -f debian/Dockerfile.${DISTRO} -t ${DOCKER_IMAGE} .
    if [ "$?" -ne "0" ]; then
        exit 1
    fi

    # Run build script
    BUILD_SCRIPT_DIR=${LOCAL_BUILD_DIR}
    BUILD_CMD="docker run --rm \
        --volume=${LOCAL_BUILD_DIR}:${DOCKER_BUILD_DIR} \
        --workdir=/build/${PROJECT_NAME} \
        ${DOCKER_IMAGE} \
        bash ${DOCKER_BUILD_DIR}/dobuild.sh"
fi

# Create the rules and control files from the M4.
for f in ${BUILD_SCRIPT_DIR}/${PROJECT_NAME}/debian/*.m4; do
    m4 \
        -Dm4_BUILD_TYPE=${BUILD_TYPE} \
        -Dm4_BUILD_NAME_EXT=${BUILD_NAME_EXT} \
        -Dm4_CONFLICTS_UNOPT=${CONFLICTS_UNOPT} \
        -Dm4_VCS_GIT="${VCS_GIT}" \
        -Dm4_GIT_TAG=${GIT_TAG} \
        -Dm4_VERSION_BRANCH="${VERSION_BRANCH}" \
        "${f}" > "${f%.m4}"
done
chmod a+x ${BUILD_SCRIPT_DIR}/${PROJECT_NAME}/debian/rules

# Run build script
write_build_script ${BUILD_SCRIPT_DIR} ${VERSION}
${BUILD_CMD}
if [ "$?" -ne "0" ]; then
    exit 1
fi

# Move build artifacts to the expected location.
mv -f ${PKG_DIR}/*.build ${PKG_DIR}/*.changes ${PKG_DIR}/*.deb \
    ${PKG_DIR}/*.dsc ${PKG_DIR}/*.xz ${PROJECT_DIR}/build/${DISTRO}/
if [ "$?" -ne "0" ]; then
    exit 1
fi

