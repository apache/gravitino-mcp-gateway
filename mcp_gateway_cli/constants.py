# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Where the CLI keeps its files, and the addresses it gives MCP clients.

MCP clients keep a sign-in per endpoint, so every client writer and doctor
use these addresses, and no other.
"""

from pathlib import Path

# Where the CLI keeps the user's login and the proxy's files.
CONFIG_DIR = Path.home() / ".gravitino-mcp"
# The running proxy's ID, which only this user can read.
PROXY_ID_FILE = CONFIG_DIR / "proxy.id"

# The local proxy's port, and how long it waits for the gateway: longer than the
# gateway's MCP_TOOL_CALL_TIMEOUT (1200 s by default), so a long tool call is
# not cut off.
PROXY_PORT = 8001
PROXY_REQUEST_TIMEOUT = 1260

PROXY_BASE_URL = f"http://localhost:{PROXY_PORT}"

# Logical MCP server name -> canonical proxy endpoint.
# Keep names stable: they become the server keys in every client config.
MCP_SERVERS = {
    "gravitino": f"{PROXY_BASE_URL}/mcp/gravitino",
}

# Gateway used when neither MCP_GATEWAY_URL, --gateway-url, nor a saved login
# names one (see auth.get_gateway_url()).
DEFAULT_GATEWAY_URL = "http://localhost:8000"

# launchd / systemd identifiers for the always-on proxy service.
SERVICE_LABEL = "org.apache.gravitino.mcp.proxy"
