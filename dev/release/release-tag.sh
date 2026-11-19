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

# Tags a release candidate on its release branch: sets the version, commits
# and tags it, then moves the branch on to the next patch's development
# version, and pushes both.

source "$(dirname "$0")/common.sh"

USAGE="usage: $0 [-n] <version> <rc>   e.g. $0 0.1.0 1   (-n: don't push)"
parse_args "$USAGE" true "$@"
require git uv

BRANCH=$(release_branch "$VERSION")
NEXT_VERSION="${VERSION%.*}.$((${VERSION##*.} + 1)).dev0"
WORK_DIR="$WORK_ROOT/$VERSION-rc$RC/tag"

git ls-remote --exit-code --heads "$GIT_REPO" "$BRANCH" >/dev/null ||
  die "$BRANCH doesn't exist in $GIT_REPO; cut it from main first"
for tag in "$RC_TAG" "$RELEASE_TAG"; do
  [[ -z "$(git ls-remote --tags "$GIT_REPO" "refs/tags/$tag")" ]] || die "$tag already exists"
done
info "Cloning $BRANCH into $WORK_DIR"
fresh_dir "$WORK_DIR"
git clone --quiet --branch "$BRANCH" "$GIT_REPO" "$WORK_DIR"
use_checkout_identity "$WORK_DIR"
cd "$WORK_DIR"

# Sets the version in pyproject.toml and uv.lock, and nothing else.
set_version() {
  local version=$1
  [[ "$(grep -c '^version = ' pyproject.toml)" == 1 ]] || die "pyproject.toml has no single version line"
  sed -i.bak "s/^version = \".*\"$/version = \"$version\"/" pyproject.toml
  rm pyproject.toml.bak
  uv lock --quiet
  local changes
  changes=$(git diff --numstat)
  [[ -n "$changes" ]] || die "$BRANCH is already at version $version"
  # One line in each file, so a different uv can't rewrite the lock file unseen.
  [[ "$changes" == $'1\t1\tpyproject.toml\n1\t1\tuv.lock' ]] ||
    die "setting the version should change one line in pyproject.toml and one in uv.lock, not: $(git diff --stat)"
  git commit --quiet --all --message "$2"
}

info "Setting the version to $VERSION and tagging $RC_TAG"
set_version "$VERSION" "[MINOR] build: Prepare release $RC_TAG"
git tag --annotate "$RC_TAG" --message "Apache Gravitino MCP Gateway $VERSION-rc$RC"

info "Moving $BRANCH on to $NEXT_VERSION"
set_version "$NEXT_VERSION" "[MINOR] build: Start $NEXT_VERSION"

git log --oneline -3
confirm "Push $BRANCH and $RC_TAG to $GIT_REPO?"
publish git push --quiet --atomic origin "$BRANCH" "refs/tags/$RC_TAG"

if [[ "$DRY_RUN" == true ]]; then
  info "Nothing was pushed. The tagged clone is in $WORK_DIR"
else
  info "Pushed $RC_TAG. Next: dev/release/release-build.sh $VERSION $RC"
fi
