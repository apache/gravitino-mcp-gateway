#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Publishes a release candidate whose vote has passed: tags the release,
# moves its files from dist/dev to dist/release, uploads the voted wheel and
# sdist to PyPI, and removes the previous release from dist/release.
#
# Each step is skipped if it is already done, so the script can be run again
# after a failure. twine reads the PyPI token from TWINE_PASSWORD, ~/.pypirc
# or the keyring.

source "$(dirname "$0")/common.sh"

USAGE="usage: $0 [-n] <version> <rc>   e.g. $0 0.1.0 1   (-n: don't publish)"
parse_args "$USAGE" true "$@"
require git svn gpg curl twine

STAGE_URL="$DIST_DEV/$VERSION-rc$RC"
RELEASE_URL="$DIST_RELEASE/$VERSION"
FILES_DIR="$WORK_ROOT/$VERSION-rc$RC/publish"
PYTHON_PACKAGES=("$FILES_DIR/$PYTHON_NAME-$VERSION.tar.gz" "$FILES_DIR/$PYTHON_NAME-$VERSION-py3-none-any.whl")

exists() { svn info "$1" >/dev/null 2>&1; }

if exists "$RELEASE_URL"; then
  SOURCE_URL="$RELEASE_URL"
elif exists "$STAGE_URL"; then
  SOURCE_URL="$STAGE_URL"
else
  die "neither $STAGE_URL nor $RELEASE_URL exists"
fi

info "Checking the files in $SOURCE_URL against $KEYS_URL"
rm -rf "$FILES_DIR"
svn export --quiet "$SOURCE_URL" "$FILES_DIR"
check_files "$FILES_DIR" "$VERSION"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
use_keys_keyring "$TEMP_DIR"
(
  cd "$FILES_DIR"
  for signature in *.asc; do
    gpg --batch --verify "$signature" "${signature%.asc}" 2>/dev/null || die "$signature doesn't verify against KEYS"
  done
  sha512 --check --status ./*.sha512 || die "a checksum doesn't match"
)

confirm "Has the vote on dev@ for $RC_TAG passed, with at least three binding +1s?"

if [[ -n "$(git ls-remote --tags "$GIT_REPO" "refs/tags/$RELEASE_TAG")" ]]; then
  info "$RELEASE_TAG already exists"
else
  info "Tagging $RELEASE_TAG on the commit of $RC_TAG"
  TAG_DIR="$TEMP_DIR/git"
  git init --quiet "$TAG_DIR"
  use_checkout_identity "$TAG_DIR"
  git -C "$TAG_DIR" fetch --quiet --depth 1 "$GIT_REPO" "refs/tags/$RC_TAG:refs/tags/$RC_TAG"
  git -C "$TAG_DIR" tag --annotate "$RELEASE_TAG" --message "Apache Gravitino MCP Gateway $VERSION" "$RC_TAG^{commit}"
  confirm "Push $RELEASE_TAG to $GIT_REPO?"
  publish git -C "$TAG_DIR" push --quiet "$GIT_REPO" "refs/tags/$RELEASE_TAG"
fi

if [[ "$SOURCE_URL" == "$RELEASE_URL" ]]; then
  info "The files are already in $RELEASE_URL"
else
  confirm "Move $STAGE_URL to $RELEASE_URL?"
  publish svn move --quiet --parents "$STAGE_URL" "$RELEASE_URL" \
    --message "Release Apache Gravitino MCP Gateway $VERSION"
fi

info "Uploading the voted wheel and sdist to PyPI"
twine check --strict "${PYTHON_PACKAGES[@]}"
confirm "Upload $PYTHON_NAME $VERSION to PyPI?"
publish twine upload --skip-existing "${PYTHON_PACKAGES[@]}"

# dist/release keeps only the latest release of each maintained branch; the
# archive keeps them all.
for old in $(svn ls "$DIST_RELEASE" 2>/dev/null | tr -d /); do
  [[ "$old" == "$VERSION" ]] && continue
  if ask "Remove $old from dist/release? Keep it if its branch is still maintained."; then
    publish svn delete --quiet "$DIST_RELEASE/$old" --message "Remove Apache Gravitino MCP Gateway $old"
  fi
done

cat <<EOF

Done. Next, as dev/release/README.md describes:
  - publish the Docker image: dev/release/publish-docker.sh -l $VERSION
  - after an hour, update the download page and send the announcement
  - record the release at https://reporter.apache.org/addrelease.html?gravitino
EOF
