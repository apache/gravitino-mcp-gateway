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

# As alice, Gravitino's service admin, creates the metalake that Gravitino's MCP
# server serves, with a catalog in it. Existing ones are left as they are.

set -euo pipefail

until curl -s -o /dev/null "${GRAVITINO_URL}/api/version"; do
  echo "Waiting for Gravitino at ${GRAVITINO_URL}"
  sleep 3
done

token=$(curl -sf "${KEYCLOAK_URL}/realms/gravitino/protocol/openid-connect/token" \
  -d client_id=mcp-client -d grant_type=password \
  -d username=alice -d password=alice -d "scope=openid gravitino" |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')

create() {
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${GRAVITINO_URL}/api$1" \
    -H "Authorization: Bearer ${token}" \
    -H "Accept: application/vnd.gravitino.v1+json" \
    -H "Content-Type: application/json" -d "$2")
  # 409: it already exists.
  if [[ "${status}" != 200 && "${status}" != 409 ]]; then
    echo "POST $1 failed with HTTP ${status}"
    exit 1
  fi
}

create /metalakes '{"name": "demo", "comment": "For the MCP gateway", "properties": {}}'
create /metalakes/demo/catalogs \
  '{"name": "models", "type": "MODEL", "comment": "An empty model catalog", "properties": {}}'

echo "Metalake demo is ready"
