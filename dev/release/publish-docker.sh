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

# Builds the Docker image of a published release for amd64 and arm64, from
# its source release in dist/release, and pushes it to Docker Hub as
# apache/gravitino-mcp-gateway:<version>, and also :latest with -l.
#
# The Publish Docker image workflow runs it with the Docker Hub account ASF
# Infra provides. To run it yourself, sign in first with `docker login`, as an
# account that may push to apache/gravitino-mcp-gateway.

source "$(dirname "$0")/common.sh"

USAGE="usage: $0 [-n] [-l] <version>   e.g. $0 -l 0.1.0   (-n: don't push, -l: also tag latest)"
TAG_LATEST=false
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "-l" ]]; then TAG_LATEST=true; else ARGS+=("$arg"); fi
done
parse_args "$USAGE" false "${ARGS[@]+"${ARGS[@]}"}"
require docker svn gpg curl tar

IMAGE="${RELEASE_DOCKER_IMAGE:-apache/gravitino-mcp-gateway}"
BUILDER="gravitino-mcp-gateway"
SOURCE_RELEASE="$SOURCE_NAME-$VERSION-src"
WORK_DIR=$(mktemp -d)
trap 'stop_gpg_agent; rm -rf "$WORK_DIR"' EXIT

info "Checking the source release in $DIST_RELEASE/$VERSION"
svn export --quiet "$DIST_RELEASE/$VERSION" "$WORK_DIR/files"
use_keys_keyring "$WORK_DIR"
(
  cd "$WORK_DIR/files"
  gpg --batch --verify "$SOURCE_RELEASE.tar.gz.asc" "$SOURCE_RELEASE.tar.gz" 2>/dev/null ||
    die "the source release doesn't verify against KEYS"
  sha512 --check --status "$SOURCE_RELEASE.tar.gz.sha512" || die "the source release's checksum doesn't match"
)
tar -xzf "$WORK_DIR/files/$SOURCE_RELEASE.tar.gz" -C "$WORK_DIR"

# A builder that can build for both architectures, made once.
docker buildx inspect "$BUILDER" >/dev/null 2>&1 ||
  docker buildx create --name "$BUILDER" --driver docker-container >/dev/null

# latest is only for the newest release, so that it never moves back.
if [[ "$TAG_LATEST" == true ]]; then
  for entry in $(svn ls "$DIST_RELEASE" | tr -d /); do
    if [[ "$entry" =~ $VERSION_PATTERN ]] && version_lower "$VERSION" "$entry"; then
      die "$entry is newer than $VERSION in dist/release, so leave out -l"
    fi
  done
fi

NAMES=("$IMAGE:$VERSION")
[[ "$TAG_LATEST" == true ]] && NAMES+=("$IMAGE:latest")
TAGS=()
for name in "${NAMES[@]}"; do TAGS+=(--tag "$name"); done
if [[ "$DRY_RUN" == true ]]; then
  OUTPUT=(--output type=cacheonly)
else
  OUTPUT=(--push)
fi

confirm "Build and push ${NAMES[*]} for linux/amd64 and linux/arm64?"
info "Building ${NAMES[*]}"
docker buildx build --builder "$BUILDER" --platform linux/amd64,linux/arm64 \
  --file "$WORK_DIR/$SOURCE_RELEASE/docker/Dockerfile" "${TAGS[@]}" "${OUTPUT[@]}" \
  --label org.opencontainers.image.title="Apache Gravitino MCP Gateway" \
  --label org.opencontainers.image.version="$VERSION" \
  --label org.opencontainers.image.source="https://github.com/apache/gravitino-mcp-gateway" \
  --label org.opencontainers.image.licenses="Apache-2.0" \
  "$WORK_DIR/$SOURCE_RELEASE"

if [[ "$DRY_RUN" == true ]]; then
  info "Built for both architectures; nothing was pushed"
else
  info "Pushed ${NAMES[*]}"
fi
