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

# Creates the "gravitino" realm for trying the MCP gateway locally. It does
# nothing when the realm already exists. Not for production: the passwords and
# the client secret are fixed.

set -euo pipefail

kcadm=/opt/keycloak/bin/kcadm.sh
realm=gravitino

until "${kcadm}" config credentials --server "${KEYCLOAK_URL}" --realm master \
  --user "${KC_BOOTSTRAP_ADMIN_USERNAME}" \
  --password "${KC_BOOTSTRAP_ADMIN_PASSWORD}" >/dev/null 2>&1; do
  echo "Waiting for Keycloak at ${KEYCLOAK_URL}"
  sleep 3
done

if "${kcadm}" get "realms/${realm}" >/dev/null 2>&1; then
  echo "Realm ${realm} already exists"
  exit 0
fi

"${kcadm}" create realms -s realm="${realm}" -s enabled=true

# A client scope that adds the client $1 to the audience of access tokens. Every
# client may request it, including MCP clients that register themselves.
audience_scope() {
  local scope_id
  scope_id=$("${kcadm}" create client-scopes -r "${realm}" -i \
    -s name="$1" -s protocol=openid-connect \
    -s 'attributes."include.in.token.scope"=true' \
    -s 'attributes."display.on.consent.screen"=false')
  "${kcadm}" create "client-scopes/${scope_id}/protocol-mappers/models" \
    -r "${realm}" -s name="$1 audience" -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s "config.\"included.client.audience\"=$1" \
    -s 'config."access.token.claim"=true' \
    -s 'config."introspection.token.claim"=true' \
    -s 'config."id.token.claim"=false'
  # Clients that register themselves may request nothing else, so the scope
  # also names the user, as the gateway and Gravitino need.
  local claim
  for claim in email:email preferred_username:username; do
    "${kcadm}" create "client-scopes/${scope_id}/protocol-mappers/models" \
      -r "${realm}" -s name="${claim%%:*}" -s protocol=openid-connect \
      -s protocolMapper=oidc-usermodel-attribute-mapper \
      -s "config.\"user.attribute\"=${claim##*:}" \
      -s "config.\"claim.name\"=${claim%%:*}" \
      -s 'config."jsonType.label"=String' \
      -s 'config."access.token.claim"=true' \
      -s 'config."introspection.token.claim"=true' \
      -s 'config."id.token.claim"=true' \
      -s 'config."userinfo.token.claim"=true'
  done
  # The gateway trusts an email only when the token says it is verified.
  "${kcadm}" create "client-scopes/${scope_id}/protocol-mappers/models" \
    -r "${realm}" -s name="email verified" -s protocol=openid-connect \
    -s protocolMapper=oidc-usermodel-property-mapper \
    -s 'config."user.attribute"=emailVerified' \
    -s 'config."claim.name"=email_verified' \
    -s 'config."jsonType.label"=boolean' \
    -s 'config."access.token.claim"=true' \
    -s 'config."introspection.token.claim"=true' \
    -s 'config."id.token.claim"=true' \
    -s 'config."userinfo.token.claim"=true'
  "${kcadm}" update "default-optional-client-scopes/${scope_id}" -r "${realm}"
}

create_client() {
  "${kcadm}" create clients -r "${realm}" -f -
}

audience_scope gravitino
audience_scope mcp-gateway

# Gravitino's audience. Gravitino accepts tokens issued for it.
create_client <<'EOF'
{
  "clientId": "gravitino",
  "name": "Gravitino",
  "publicClient": false,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false
}
EOF

# The gateway signs users in, and exchanges their tokens for Gravitino's audience.
create_client <<'EOF'
{
  "clientId": "mcp-gateway",
  "name": "Gravitino MCP Gateway",
  "secret": "mcp-gateway-secret",
  "publicClient": false,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "redirectUris": ["http://localhost:8000/*"],
  "webOrigins": ["+"],
  "attributes": {
    "standard.token.exchange.enabled": "true",
    "post.logout.redirect.uris": "http://localhost:8000/*"
  },
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "gravitino", "mcp-gateway"
  ],
  "optionalClientScopes": ["offline_access"]
}
EOF

# Stands in for an MCP client such as an IDE. The password grant is for scripts.
create_client <<'EOF'
{
  "clientId": "mcp-client",
  "name": "MCP client",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["http://127.0.0.1:33418/*", "http://localhost:33418/*"],
  "attributes": {"pkce.code.challenge.method": "S256"},
  "defaultClientScopes": ["acr", "basic", "email", "profile", "roles", "web-origins"],
  "optionalClientScopes": ["offline_access", "gravitino", "mcp-gateway"]
}
EOF

# Gravitino's web UI, at :8090 or from `pnpm dev` at :3000. Its tokens are for
# Gravitino and for the gateway, whose pages the UI shows.
create_client <<'EOF'
{
  "clientId": "gravitino-ui",
  "name": "Gravitino web UI",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "redirectUris": ["http://localhost:8090/*", "http://localhost:3000/*"],
  "webOrigins": ["http://localhost:8090", "http://localhost:3000"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "http://localhost:8090/*##http://localhost:3000/*"
  },
  "defaultClientScopes": [
    "acr", "basic", "email", "profile", "roles", "web-origins",
    "gravitino", "mcp-gateway"
  ],
  "optionalClientScopes": ["offline_access"]
}
EOF

for user in alice bob; do
  "${kcadm}" create users -r "${realm}" -s username="${user}" \
    -s email="${user}@example.com" -s emailVerified=true -s enabled=true \
    -s firstName="${user^}" -s lastName=Example
  "${kcadm}" set-password -r "${realm}" --username "${user}" \
    --new-password "${user}"
done

# MCP clients register themselves without an access token (RFC 7591). Allow
# that from any address, for clients whose URLs are on these hosts. VS Code
# sends URLs on vscode.dev, insiders.vscode.dev and code.visualstudio.com.
policy_id=$("${kcadm}" get components -r "${realm}" -q name="Trusted Hosts" \
  --fields id --format csv --noquotes)
"${kcadm}" update "components/${policy_id}" -r "${realm}" \
  -s 'config."host-sending-registration-request-must-match"=["false"]' \
  -s 'config."trusted-hosts"=["localhost","127.0.0.1","vscode.dev","*.vscode.dev","code.visualstudio.com"]'

echo "Realm ${realm} created"
