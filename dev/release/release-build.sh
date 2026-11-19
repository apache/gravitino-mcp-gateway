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
require git uv gpg tar unzip curl twine
[[ "$DRY_RUN" == true ]] || require svn

BUILD_DIR="$WORK_ROOT/$VERSION-rc$RC/build"
OUT_DIR="$WORK_ROOT/$VERSION-rc$RC/dist"
STAGE_URL="$DIST_DEV/$VERSION-rc$RC"
SOURCE_RELEASE="$SOURCE_NAME-$VERSION-src"
SDIST="$PYTHON_NAME-$VERSION.tar.gz"
WHEEL="$PYTHON_NAME-$VERSION-py3-none-any.whl"
ARTIFACTS=("$SOURCE_RELEASE.tar.gz" "$SDIST" "$WHEEL")

[[ -n "$(git ls-remote --tags "$GIT_REPO" "refs/tags/$RC_TAG")" ]] || die "$RC_TAG doesn't exist; run release-tag.sh"
fresh_dir "$BUILD_DIR"
fresh_dir "$OUT_DIR"

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
mv "$BUILD_DIR/python/$SDIST" "$BUILD_DIR/python/$WHEEL" "$OUT_DIR"
cd "$OUT_DIR"
WHEEL_FILES=$(unzip -l "$WHEEL")
SDIST_FILES=$(tar -tzf "$SDIST")
for file in LICENSE NOTICE; do
  grep -q "licenses/$file$" <<<"$WHEEL_FILES" || die "the wheel has no $file"
  grep -q "^[^/]*/$file$" <<<"$SDIST_FILES" || die "the sdist has no $file"
done
# What PyPI checks on upload, checked now rather than after the vote.
twine check --strict "$SDIST" "$WHEEL"

info "Signing and checksumming"
# gpg asks for your key's passphrase on this terminal.
if [[ -t 0 ]]; then
  GPG_TTY=$(tty)
  export GPG_TTY
fi
for artifact in "${ARTIFACTS[@]}"; do
  gpg --yes ${GPG_KEY:+--local-user "$GPG_KEY"} --armor --detach-sign --output "$artifact.asc" "$artifact"
  sha512 "$artifact" >"$artifact.sha512"
done
sha512 --check --status ./*.sha512 || die "a checksum doesn't match"
check_files "$OUT_DIR" "$VERSION"

# Voters check the signatures against the published KEYS, so check now that
# your key is in it.
(
  KEYRING_DIR=$(mktemp -d)
  trap 'stop_gpg_agent; rm -rf "$KEYRING_DIR"' EXIT
  use_keys_keyring "$KEYRING_DIR"
  for artifact in "${ARTIFACTS[@]}"; do
    gpg --batch --verify "$artifact.asc" "$artifact" 2>/dev/null ||
      die "$artifact.asc doesn't verify against $KEYS_URL. Is your key in KEYS? A key added to dist/release takes up to 15 minutes to reach downloads.apache.org."
  done
)
ls -l

if command -v svn >/dev/null && svn_exists "$STAGE_URL"; then
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
