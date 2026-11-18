#!/bin/bash
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
set -ex
mcp_gateway_dir="$(dirname "${BASH_SOURCE-$0}")"
mcp_gateway_dir="$(cd "${mcp_gateway_dir}">/dev/null; pwd)"
gravitino_home="$(cd "${mcp_gateway_dir}/../../..">/dev/null; pwd)"

# Removed old packages
rm -rf "${mcp_gateway_dir}/packages"
mkdir -p "${mcp_gateway_dir}/packages/mcp-gateway"

# Copy only what the image needs, so local state (.secrets.json, *.db, .venv) never ships.
cd "${gravitino_home}/mcp-gateway"
cp -r pyproject.toml uv.lock .python-version README.md \
  mcp_gateway mcp_gateway_cli mcp_gateway_sdk \
  "${mcp_gateway_dir}/packages/mcp-gateway"
# The image bundles third-party packages, so it ships the binary LICENSE and NOTICE.
cp LICENSE.bin "${mcp_gateway_dir}/packages/mcp-gateway/LICENSE"
cp NOTICE.bin "${mcp_gateway_dir}/packages/mcp-gateway/NOTICE"
find "${mcp_gateway_dir}/packages/mcp-gateway" -name "__pycache__" -type d -prune -exec rm -rf {} +
