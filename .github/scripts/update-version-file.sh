#!/usr/bin/env bash
set -ue

BIN="xeol"
DISTDIR=$1
VERSION=$2

# the source of truth as to whether we want to notify users of an update is if the release just created is NOT
# flagged as a pre-release on github
if [[ "$(curl -SsL https://api.github.com/repos/xeol-io/${BIN}/releases/tags/${VERSION} | jq .prerelease)" == "true" ]] ; then
   echo "skipping publishing a version file (this is a pre-release: ${VERSION})"
   exit 0
fi

echo "creating and publishing version file"

# create a version file for version-update checks
VERSION_FILE="${DISTDIR}/VERSION"
echo "${VERSION}" | tee "${VERSION_FILE}"

# upload the version file that supports the application version update check
export AWS_DEFAULT_REGION=us-east-1
aws s3 cp "${VERSION_FILE}" s3://data.xeol.io/${BIN}/releases/latest/VERSION
