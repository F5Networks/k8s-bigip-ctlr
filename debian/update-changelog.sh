#!/bin/bash

DEBIAN_DIR="$(dirname $0)"
PROJECT_DIR="$(dirname ${DEBIAN_DIR})"
source "${DEBIAN_DIR}/common.sh"
source "${PROJECT_DIR}/version.txt"

function show_help {
    cat <<-END
Usage: $0 [OPTIONS]

Update the Debian changelog. See the dch man page for more information.

OPTIONS:
    -h|--help           Show this help.
    -d|--debug          Script will emit copious debug output.
    -r|--dry-run        Do not actually update the changelog or commit to git.
    -l|--last-tag <tag> Use git commits since the specified tag or SHA.
END
    exit $1
}

# Add any new title exclusion regexes here, delimited by a space.
COMMIT_EXCLUDE_REGEXES=('^\[?WIP\]?')

function should_exclude_title {
    i=0
    ct=${#COMMIT_EXCLUDE_REGEXES[@]}
    while [ "$i" -lt "$ct" ]; do
        if [[ $1 =~ ${COMMIT_EXCLUDE_REGEXES[$i]} ]]; then
            return 1
        fi
        i=$((i+1))
    done
    return 0
}

function ask_yes_or_no {
    while true; do
        read -p "$1 (y/n) " yn
        case $yn in
            [Yy]*)
                return 1
                ;;
            [Nn]*)
                return 0
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

VERSION_FILE="${PROJECT_DIR}/version.txt"
NEW_VERSION_TAG="v${PROJECT_VERSION}"
NEW_VERSION_NBR=""
TAG_OR_SHA=""
OLD_VERSION_NBR=""
GBP_DCH_OPTIONS=""
DRY_RUN=0

args=`getopt --options hdrl: --longoptions help,debug,dry-run,last-tag: -n "$0" -- "$@"`
if [ $? != 0 ] ; then
    show_help 1
fi

eval set -- "${args}"

while true; do
    case "$1" in
        -h|--help)
            show_help 0
            ;;
        -d|--debug)
            set -x
            shift
            ;;
        -r|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -l|--last-tag)
            TAG_OR_SHA=`echo "$2" | xargs`
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error: found $1"
            show_help 1
            ;;
    esac
done

# Make sure the version number is of the correct format.
# RELEASE_VERSION_REGEX is defined in common.sh
if [[ ${NEW_VERSION_TAG} =~ ${RELEASE_VERSION_REGEX} ]]; then
    # NEW_VERSION_NBR has the 'v' stripped off.
    NEW_VERSION_NBR=${BASH_REMATCH[1]}
else
    echo "ERROR: bad version tag format specified for new-version"
    # Dump out capture information to help identify the problem.
    show_help 1
fi

# Make sure last-tag is either a valid tag or a valid sha..
if [ -n "${TAG_OR_SHA}" ]; then
    if [[ ${TAG_OR_SHA} =~ ${RELEASE_VERSION_REGEX} ]]; then
        # OLD_VERSION_NBR has the 'v' stripped off.
        OLD_VERSION_NBR=${BASH_REMATCH[1]}
        # Make sure new version is >= old version
        dpkg --compare-versions ${NEW_VERSION_NBR} ge ${OLD_VERSION_NBR}
        if [ "$?" -ne 0 ]; then
            echo "ERROR: ${NEW_VERSION_NBR} must be >= ${OLD_VERSION_NBR}"
            show_help 1
        fi
    else
        # Not a tag, must be a SHA
        git cat-file -e ${TAG_OR_SHA}
        if [ "$?" -ne 0 ]; then
            echo "ERROR: ${TAG_OR_SHA} is not a git tag or SHA!"
            show_help 1
        fi
    fi
    COMMIT_RANGE="${TAG_OR_SHA}^...HEAD"
else
    # Try to find the correct tag automatically
    FOUND_TAG=""
    while IFS= read -r TAG; do
        if [[ ${TAG} =~ ${RELEASE_VERSION_REGEX} ]]; then
            dpkg --compare-versions ${NEW_VERSION_NBR} gt ${BASH_REMATCH[1]}
            if [ "$?" -eq 0 ]; then
                FOUND_TAG=${TAG}
                break
            fi
        fi
    done < <(stdbuf -oL git tag --sort=-v:refname)

    if [ -n "${FOUND_TAG}" ]; then
        COMMIT_RANGE="${FOUND_TAG}^...HEAD"
    fi
fi

if [ -n "${COMMIT_RANGE}" ]; then
    echo "Using commits in the range ${COMMIT_RANGE}"
else
    # Will be true for the first release.
    echo "Using entire git history..."
fi
echo

DEBEMAIL="builder@lineratesystems.com"
DEBFULLNAME="Builder"
TMPFILE=$(mktemp --tmpdir=/tmp)
DCH_OPTIONS="--nomultimaint --noquery --changelog ${TMPFILE}"
GIT_LOG_REGEX='^(.*)\s"(.*)"$'
TICKET_REGEX='^F5 [Ii]ssues?:\s([Rr]esolves\s)?(TK-[[:digit:]]+.*)+$'

# Do all work on a temporary changelog.
cp "${DEBIAN_DIR}/changelog" "${TMPFILE}"
TMPFILE_MTIME_BEFORE=$(stat --printf=%Y "${TMPFILE}")

while IFS= read -r LINE; do
    if [[ ${LINE} =~ ${GIT_LOG_REGEX} ]]; then
        SHA=${BASH_REMATCH[1]}
        TITLE=${BASH_REMATCH[2]}
        echo "Commit ${SHA}: ${TITLE}"
        should_exclude_title "${TITLE}"
        if [ $? -ne 0 ]; then
            echo "  Excluding commit."
            continue
        fi

        # Build up a space-delimited string of ticket ids.
        TICKET_STR=""
        while IFS= read -r BODY_LINE; do
            # LINE must start with 'F5 issue', may contain 'Resolves'.
            # All ticket ids on matching LINEs are captured.
            if [[ ${BODY_LINE} =~ ${TICKET_REGEX} ]]; then
                TICKET_LINE="${BASH_REMATCH[2]//,/ }"
                if [ -z "${TICKET_STR}" ]; then
                    TICKET_STR="${TICKET_LINE}"
                else
                    TICKET_STR="${TICKET_STR} ${TICKET_LINE}"
                fi
            fi
        done < <(stdbuf -oL git log --pretty=format:'%b' ${SHA}^!)

        # Normalize the spaces in the ticket string.
        TICKET_STR=$(echo ${TICKET_STR} | xargs)

        # Add any commit with at least 1 Bug ID to the changelog.
        if [ -z "${TICKET_STR}" ]; then
            echo "  No Bug IDs found, ignoring commit."
            continue
        fi
        echo "  Bug IDs: ${TICKET_STR}"
        dch ${DCH_OPTIONS} --newversion ${NEW_VERSION_NBR} \
            "${TICKET_STR}: ${TITLE}"
        # dch always exits with 0
    fi
done < <(stdbuf -oL git log --pretty=format:'%h "%s"' --no-merges ${COMMIT_RANGE})

TMPFILE_MTIME_AFTER=$(stat --printf=%Y "${TMPFILE}")

echo
if [ "${DRY_RUN}" -ne 0 ]; then
    # Optionally show the would-be changelog to the user in their editor.
    ask_yes_or_no "Display proposed changelog in your editor?"
    if [ "$?" -eq 1 ]; then
        dch ${DCH_OPTIONS} --edit
    fi
    echo "'--dry-run' specified, exiting without updating changelog."
    rm -fv "${TMPFILE}"
    exit 0
fi

if [ "${TMPFILE_MTIME_BEFORE}" == "${TMPFILE_MTIME_AFTER}" ]; then
    echo "Debian changelog file was not modified."
    rm -fv "${TMPFILE}"
    exit 0
fi

# Give the user a chance to edit the changelog. If the user did not change
dch ${DCH_OPTIONS} --edit
ask_yes_or_no "Do you wish to use this changelog?"
case $? in
    1)  # Yes
        mv -fv "${TMPFILE}" "${DEBIAN_DIR}/changelog"
        ;;
    0)  # No
        rm -fv "${TMPFILE}"
        exit 0
        ;;
esac

# See if we need to commit the changelog
git ls-files -m | grep "${DEBIAN_DIR}/changelog"
if [ "$?" -ne 0 ]; then
    echo "Debian changelog file has not been changed."
    exit 1
fi

# Commit the changelog
git add "${PROJECT_DIR}/debian/changelog"
echo git commit -m "Update changelog for ${NEW_VERSION_NBR} release."
git commit -m "Update changelog for ${NEW_VERSION_NBR} release."
if [ $? != 0 ]; then
    exit 1
fi

# Tag the changelog commit with the new version tag
git tag -f ${NEW_VERSION_TAG}

