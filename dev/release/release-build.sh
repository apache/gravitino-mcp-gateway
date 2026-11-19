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

# Builds a release candidate from its tag and stages it in dist/dev: the
# source release, and the wheel and sdist built from it, each signed with
# your key (GPG_KEY, or gpg's default) and with a SHA-512 checksum.

source "$(dirname "$0")/common.sh"

USAGE="usage: $0 [-n] <version> <rc>   e.g. $0 0.1.0 1   (-n: don't stage)"
parse_args "$USAGE" true "$@"
require git uv gpg tar unzip
[[ "$DRY_RUN" == true ]] || require svn

BUILD_DIR="$WORK_ROOT/$VERSION-rc$RC/build"
OUT_DIR="$WORK_ROOT/$VERSION-rc$RC/dist"
STAGE_URL="$DIST_DEV/$VERSION-rc$RC"
SOURCE_RELEASE="$SOURCE_NAME-$VERSION-src"

[[ ! -e "$BUILD_DIR" && ! -e "$OUT_DIR" ]] || die "$WORK_ROOT/$VERSION-rc$RC has a build; remove it to start over"
[[ -n "$(git ls-remote --tags "$GIT_REPO" "refs/tags/$RC_TAG")" ]] || die "$RC_TAG doesn't exist; run release-tag.sh"
mkdir -p "$BUILD_DIR" "$OUT_DIR"

info "Checking out $RC_TAG"
git init --quiet "$BUILD_DIR/checkout"
git -C "$BUILD_DIR/checkout" fetch --quiet --depth 1 "$GIT_REPO" "refs/tags/$RC_TAG:refs/tags/$RC_TAG"
git -C "$BUILD_DIR/checkout" -c advice.detachedHead=false checkout --quiet "$RC_TAG"
COMMIT=$(git -C "$BUILD_DIR/checkout" rev-parse HEAD)
grep -q "^version = \"$VERSION\"$" "$BUILD_DIR/checkout/pyproject.toml" ||
  die "$RC_TAG isn't version $VERSION in pyproject.toml"

info "Building the source release"
git -C "$BUILD_DIR/checkout" archive --format=tar.gz --prefix="$SOURCE_RELEASE/" \
  --output="$OUT_DIR/$SOURCE_RELEASE.tar.gz" HEAD

# The Python packages are built from the source release, not from git, so
# that they come from exactly what is voted on.
info "Building the wheel and the sdist from the source release"
tar -xzf "$OUT_DIR/$SOURCE_RELEASE.tar.gz" -C "$BUILD_DIR"
# uv also writes a .gitignore where it builds, so the packages are moved out.
uv build --quiet --sdist --wheel --out-dir "$BUILD_DIR/python" "$BUILD_DIR/$SOURCE_RELEASE"
WHEEL="$OUT_DIR/$PYTHON_NAME-$VERSION-py3-none-any.whl"
mv "$BUILD_DIR/python/$PYTHON_NAME-$VERSION.tar.gz" "$BUILD_DIR/python/$(basename "$WHEEL")" "$OUT_DIR"
WHEEL_FILES=$(unzip -l "$WHEEL")
for file in LICENSE NOTICE; do
  grep -q "licenses/$file$" <<<"$WHEEL_FILES" || die "the wheel has no $file"
done

info "Signing and checksumming"
cd "$OUT_DIR"
for artifact in "$SOURCE_RELEASE.tar.gz" "$PYTHON_NAME-$VERSION.tar.gz" "$(basename "$WHEEL")"; do
  gpg --batch --yes ${GPG_KEY:+--local-user "$GPG_KEY"} --armor --detach-sign --output "$artifact.asc" "$artifact"
  gpg --batch --verify "$artifact.asc" "$artifact" 2>/dev/null || die "the signature of $artifact doesn't verify"
  sha512 "$artifact" >"$artifact.sha512"
done
sha512 --check --status ./*.sha512 || die "a checksum doesn't match"
check_files "$OUT_DIR" "$VERSION"
ls -l

if svn info "$STAGE_URL" >/dev/null 2>&1; then
  die "$STAGE_URL already exists"
fi
confirm "Stage these files in $STAGE_URL?"
publish svn import --quiet --no-ignore "$OUT_DIR" "$STAGE_URL" \
  --message "Stage Apache Gravitino MCP Gateway $VERSION-rc$RC"

cat <<EOF

The release candidate, for the vote email:
  Tag:       $RC_TAG ($COMMIT)
  Files:     $STAGE_URL
  KEYS:      $KEYS_URL
EOF
[[ "$DRY_RUN" == false ]] || info "Nothing was staged. The files are in $OUT_DIR"
