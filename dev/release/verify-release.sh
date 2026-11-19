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

# Checks a release candidate as a voter should: downloads it from dist/dev
# (or reads it from a directory with -d), checks the signatures against the
# KEYS file and the checksums, checks the source release's content and
# license headers, then builds it, runs the unit tests and runs the wheel.
#
# It needs curl, gpg, tar, uv and file; Docker for the license header check.

source "$(dirname "$0")/common.sh"

USAGE="usage: $0 [-d <directory>] <version> <rc>   e.g. $0 0.1.0 1"
LOCAL_DIR=""
if [[ "${1:-}" == "-d" ]]; then
  LOCAL_DIR=$(cd "${2:?$USAGE}" && pwd)
  shift 2
fi
parse_args "$USAGE" true "$@"
require curl gpg tar uv file

WORK_DIR=$(mktemp -d)
FILES_DIR="$WORK_DIR/files"
SOURCE_RELEASE="$SOURCE_NAME-$VERSION-src"
ok() { echo "ok: $*"; }

if [[ -n "$LOCAL_DIR" ]]; then
  FILES_DIR="$LOCAL_DIR"
else
  info "Downloading $RC_TAG from $DIST_DEV/$VERSION-rc$RC"
  mkdir "$FILES_DIR"
  for file in $(release_files "$VERSION"); do
    curl --fail --silent --show-error --output "$FILES_DIR/$file" "$DIST_DEV/$VERSION-rc$RC/$file"
  done
fi
for file in $(release_files "$VERSION"); do
  [[ -f "$FILES_DIR/$file" ]] || die "$file is missing"
done
ok "all 9 files are there"

use_keys_keyring "$WORK_DIR"
cd "$FILES_DIR"
for signature in *.asc; do
  gpg --batch --verify "$signature" "${signature%.asc}" 2>/dev/null || die "$signature doesn't verify against $KEYS_URL"
done
ok "the signatures verify against $KEYS_URL"
sha512 --check --status ./*.sha512 || die "a checksum doesn't match"
ok "the SHA-512 checksums match"

tar -xzf "$SOURCE_RELEASE.tar.gz" -C "$WORK_DIR"
SOURCE_DIR="$WORK_DIR/$SOURCE_RELEASE"
[[ -d "$SOURCE_DIR" ]] || die "the source release doesn't unpack to $SOURCE_RELEASE/"
for file in LICENSE NOTICE; do
  [[ -f "$SOURCE_DIR/$file" ]] || die "the source release has no $file"
done
grep -q "^version = \"$VERSION\"$" "$SOURCE_DIR/pyproject.toml" || die "the source release isn't version $VERSION"
ok "the source release unpacks to $SOURCE_RELEASE/ with LICENSE and NOTICE, at version $VERSION"

# file, not grep -I, which tells binary files apart the same way on Linux and macOS.
BINARY_FILES=$(find "$SOURCE_DIR" -type f -size +0 -exec file --no-pad --mime-encoding {} + | grep -E ": +binary$" | cut -d: -f1 | sed "s#^$SOURCE_DIR/##" || true)
[[ -z "$BINARY_FILES" ]] || die "the source release has binary files: $BINARY_FILES"
ok "the source release has no binary files"

# Runs Apache SkyWalking Eyes, the license header checker CI runs, at the
# version CI uses, and names the files it finds without a header.
check_headers() {
  local eyes log="$WORK_DIR/license-headers.log" missing
  eyes=$(grep -o 'skywalking-eyes/header@v[0-9.]*' "$SOURCE_DIR/.github/workflows/ci.yml" | cut -d@ -f2)
  if ! docker run --rm --volume "$SOURCE_DIR:/github/workspace" "apache/skywalking-eyes:${eyes#v}" \
    header check >"$log" 2>&1; then
    missing=$(sed -e $'s/\x1b\\[[0-9;]*m//g' "$log" | sed -n '/valid license header:/,/^ERROR one or more/p' |
      sed '1d;$d' | tr '\n' ' ')
    [[ -n "$missing" ]] || die "the license header check failed: $(tail -3 "$log")"
    die "these files have no license header: $missing"
  fi
  ok "every file has the license header (Apache SkyWalking Eyes ${eyes#v})"
}

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  check_headers
else
  echo "SKIPPED: the license header check needs Docker"
fi

info "Building the source release and running the unit tests"
(cd "$SOURCE_DIR" && uv sync --quiet --locked --all-extras &&
  uv run --quiet pytest -m "not integration" -q -p no:cacheprovider | tail -1) ||
  die "the source release doesn't build, or its unit tests fail"
ok "the source release builds and its unit tests pass"

uv venv --quiet --python "$(cat "$SOURCE_DIR/.python-version")" "$WORK_DIR/wheel-venv"
uv pip install --quiet --python "$WORK_DIR/wheel-venv" "$FILES_DIR/$PYTHON_NAME-$VERSION-py3-none-any.whl"
"$WORK_DIR/wheel-venv/bin/gravitino-mcp" --help >/dev/null
ok "the wheel installs and runs gravitino-mcp"

echo
echo "All checks passed. The unpacked release is in $WORK_DIR"
