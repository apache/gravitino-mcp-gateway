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

# What the release scripts share. The scripts source it; don't run it.
#
# The locations can be overridden, which is how the scripts are tested
# against a local git repository and a local SVN repository.

# The scripts that source this file use its variables.
# shellcheck disable=SC2034

set -euo pipefail

# The checkout the scripts run from.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

GIT_REPO="${RELEASE_GIT_REPO:-https://github.com/apache/gravitino-mcp-gateway.git}"
DIST_DEV="${RELEASE_DIST_DEV:-https://dist.apache.org/repos/dist/dev/gravitino/mcp-gateway}"
DIST_RELEASE="${RELEASE_DIST_RELEASE:-https://dist.apache.org/repos/dist/release/gravitino/mcp-gateway}"
KEYS_URL="${RELEASE_KEYS_URL:-https://downloads.apache.org/gravitino/KEYS}"
WORK_ROOT="${RELEASE_WORK_DIR:-$HOME/gravitino-mcp-gateway-release}"

# The source release, and the Python packages built from it.
SOURCE_NAME="gravitino-mcp-gateway"
PYTHON_NAME="apache_gravitino_mcp_gateway"

DRY_RUN=false

info() { echo "==> $*"; }
die() {
  echo "error: $*" >&2
  exit 1
}

# Runs a command that changes something outside this machine, or only
# prints it in a dry run.
publish() {
  if [[ "$DRY_RUN" == true ]]; then
    echo "[dry run] $*"
  else
    "$@"
  fi
}

# Asks a yes-or-no question; a dry run answers yes.
ask() {
  [[ "$DRY_RUN" == true ]] && return 0
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" == y || "$answer" == Y ]]
}

# Asks before a step that changes something outside this machine, and stops
# unless the answer is yes.
confirm() {
  ask "$1" || die "stopped"
}

require() {
  local command
  for command in "$@"; do
    command -v "$command" >/dev/null || die "$command is required"
  done
}

# Reads "[-n] <version> <rc>", or "[-n] <version>" when the RC isn't needed,
# and sets DRY_RUN, VERSION, RC, RC_TAG and RELEASE_TAG.
parse_args() {
  local usage=$1 needs_rc=$2
  shift 2
  local opt
  OPTIND=1
  while getopts ":nh" opt; do
    case "$opt" in
      n) DRY_RUN=true ;;
      h)
        echo "$usage"
        exit 0
        ;;
      *) die "$usage" ;;
    esac
  done
  shift $((OPTIND - 1))
  VERSION="${1:-}"
  RC="${2:-}"
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$usage"
  RELEASE_TAG="v$VERSION"
  if [[ "$needs_rc" == true ]]; then
    [[ "$RC" =~ ^[1-9][0-9]*$ ]] || die "$usage"
    RC_TAG="v$VERSION-rc$RC"
  fi
  return 0
}

# The release branch of a version: branch-0.1 for 0.1.0 and 0.1.1.
release_branch() {
  local major_minor=${1%.*}
  echo "branch-$major_minor"
}

# Sets a clone's git identity to that of the checkout the scripts run from,
# so that release commits and tags carry your apache.org address.
use_checkout_identity() {
  local clone=$1 key value
  for key in user.name user.email; do
    value=$(git -C "$SCRIPT_DIR" config "$key") || die "set git $key in this checkout"
    git -C "$clone" config "$key" "$value"
  done
  [[ "$value" == *@apache.org ]] || echo "warning: commits and tags will be by $value, not an apache.org address" >&2
}

sha512() {
  if command -v sha512sum >/dev/null; then
    sha512sum "$@"
  else
    shasum -a 512 "$@"
  fi
}

# The names of the files a release candidate stages: the source release and
# the Python packages, each with a signature and a checksum.
release_files() {
  local version=$1 name
  for name in "$SOURCE_NAME-$version-src.tar.gz" "$PYTHON_NAME-$version.tar.gz" \
    "$PYTHON_NAME-$version-py3-none-any.whl"; do
    echo "$name" "$name.asc" "$name.sha512"
  done
}

# Makes a keyring of its own in a directory, holding only the keys in KEYS,
# so that signatures are checked against the published KEYS alone.
use_keys_keyring() {
  local keys
  export GNUPGHOME="$1/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  keys=$(curl --fail --silent --show-error "$KEYS_URL") || die "can't download $KEYS_URL"
  gpg --batch --quiet --import <<<"$keys" 2>/dev/null || die "$KEYS_URL has no keys to import"
}

# Fails unless a directory holds exactly a release candidate's files.
check_files() {
  local dir=$1 version=$2
  [[ "$(find "$dir" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort)" == \
    "$(release_files "$version" | tr ' ' '\n' | sort)" ]] ||
    die "$dir doesn't hold exactly the files of $version: $(find "$dir" -mindepth 1 -maxdepth 1 -exec basename {} \;)"
}
