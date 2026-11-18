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

"""
MCP Gateway CLI - Command-line interface for the Gravitino MCP Gateway
"""

import functools
import json
import os
import sys
import webbrowser
from typing import Optional
from urllib.parse import quote, urlencode

import click
import requests

from mcp_gateway import VERSION as _VERSION

# Import auth and proxy modules
from . import auth as auth_module
from . import autostart as autostart_module
from . import doctor as doctor_module
from . import mcp_client
from . import proxy as proxy_module
from . import setup_cmd as setup_module
from .constants import DEFAULT_GATEWAY_URL

# Upper bound for gateway API calls that list services, tools or prompts.
_API_TIMEOUT_SECONDS = 60


def get_gateway_url() -> str:
    """Get gateway URL from auth module."""
    return auth_module.get_gateway_url()


def get_access_token() -> Optional[str]:
    """Get OAuth access token from auth module."""
    return auth_module.get_access_token()


def require_auth():
    """Decorator to require OAuth authentication."""

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            token = get_access_token()
            if not token:
                click.echo(
                    "Not authenticated. Run 'gravitino-mcp login' first.", err=True
                )
                sys.exit(1)

            return f(*args, **kwargs)

        return wrapper

    return decorator


@click.group()
@click.version_option(version=_VERSION, prog_name="gravitino-mcp")
def cli():
    """MCP Gateway CLI - Interact with the MCP Gateway"""
    pass


@cli.command()
@click.argument("service")
@require_auth()
def connect(service: str):
    """Manually connect to an MCP service (auto-SSO services connect automatically)"""
    # The browser signs in through the identity provider, which usually
    # remembers the user, and then starts connecting to the service.
    connect_url = _sign_in_url(f"/portal/connect/{quote(service, safe='')}")

    click.echo(f"Connecting {service}...")
    _open_in_browser(connect_url)
    click.echo("\n   Complete the OAuth flow in your browser.")
    click.echo(
        "\n   For auto-SSO enabled services, you can skip this and just call tools directly!"
    )
    click.echo("   After authorization: gravitino-mcp services")


def _sign_in_url(next_path: str) -> str:
    """The gateway's sign-in URL, which continues to ``next_path`` once signed in."""
    return f"{get_gateway_url()}/auth/oauth/login?{urlencode({'next': next_path})}"


def _open_in_browser(url: str) -> None:
    try:
        opened = webbrowser.open(url)
    except Exception:  # pylint: disable=broad-exception-caught
        opened = False
    if opened:
        click.echo("Opened in your browser")
    click.echo("   If the browser didn't open, copy and paste this URL:")
    click.echo(f"   {url}")


@cli.command()
@require_auth()
def services():
    """List the MCP servers you can see, and how to use each one."""
    gateway_url = get_gateway_url()
    try:
        response = requests.get(
            f"{gateway_url}/api/catalog/mcps",
            headers={"Authorization": f"Bearer {get_access_token()}"},
            timeout=_API_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        click.echo(f"Failed to list services: {e}", err=True)
        sys.exit(1)

    servers = response.json()
    if not servers:
        click.echo("\nWarning: No MCP servers available.\n")
        click.echo(
            "   Request access on the MCP > My Servers page of Gravitino's web UI.\n"
        )
        return

    click.echo("\nMCP servers:\n")
    for server in servers:
        service_id = server["service_id"]
        click.echo(f"   {server.get('icon') or ''} {server['name']} ({service_id})")
        if server.get("description"):
            click.echo(f"      {server['description']}")
        own_sign_in = server.get("auth_type") == "oauth" and not server.get(
            "auto_sso_enabled"
        )
        if own_sign_in and not server.get("connected"):
            click.echo(f"      Connect first: gravitino-mcp connect {service_id}")
        else:
            click.echo(f"      Tools: gravitino-mcp tools {service_id}")
        click.echo()


def _mcp_request(service: str, method: str, params: Optional[dict] = None):
    """The result of a JSON-RPC request to ``service``, exiting with a message on failure."""
    try:
        return mcp_client.request(
            get_gateway_url(), get_access_token(), service, method, params
        )
    except mcp_client.McpError as e:
        click.echo(f"{e}", err=True)
    except requests.exceptions.RequestException as e:
        click.echo(f"The request to {service} failed: {e}", err=True)
    sys.exit(1)


@cli.command()
@click.argument("service")
@require_auth()
def tools(service: str):
    """List the tools of an MCP server (e.g., gravitino-mcp tools gravitino)"""
    tools_list = (_mcp_request(service, "tools/list") or {}).get("tools", [])

    click.echo(f"\nTools of {service}:\n")
    if not tools_list:
        click.echo("   No tools found.")
        return

    for tool in tools_list:
        click.echo(f"   {tool['name']}")
        click.echo(f"      {tool.get('description', 'No description')}")
        schema = tool.get("inputSchema") or {}
        params = list(schema.get("properties", {}))
        if params:
            click.echo(f"      Parameters: {', '.join(params)}")
        if schema.get("required"):
            click.echo(f"      Required: {', '.join(schema['required'])}")
        click.echo(
            f"      Call: gravitino-mcp call {service} {tool['name']} --params '{{...}}'"
        )
        click.echo()


@cli.command()
@click.argument("service")
@click.argument("tool_name")
@click.option("--params", help="JSON arguments for the tool", default="{}")
@require_auth()
def call(service: str, tool_name: str, params: str):
    """Call an MCP tool (e.g., gravitino-mcp call gravitino get_list_of_catalogs)"""
    try:
        arguments = json.loads(params)
    except json.JSONDecodeError:
        click.echo(f"Invalid JSON in --params: {params}", err=True)
        sys.exit(1)

    result = _mcp_request(
        service, "tools/call", {"name": tool_name, "arguments": arguments}
    )
    if not isinstance(result, dict) or "content" not in result:
        click.echo(json.dumps(result, indent=2))
        return

    click.echo("\nResult:\n")
    for item in result["content"]:
        if isinstance(item, dict) and "text" in item:
            click.echo(item["text"])
        else:
            click.echo(json.dumps(item, indent=2))
    if result.get("isError"):
        sys.exit(1)


@cli.command()
@require_auth()
def whoami():
    """Show information about the currently authenticated user"""
    gateway_url = get_gateway_url()
    access_token = get_access_token()

    try:
        # Get current user info
        user_response = requests.get(
            f"{gateway_url}/api/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_API_TIMEOUT_SECONDS,
        )
        user_response.raise_for_status()
        user_info = user_response.json()

        click.echo("\nCurrent User:\n")
        click.echo(f"   Username: {user_info.get('username', 'N/A')}")
        if user_info.get("email"):
            click.echo(f"   Email: {user_info['email']}")
        if user_info.get("is_admin"):
            click.echo("   Role: Administrator")
        elif user_info.get("is_service_account"):
            click.echo("   Role: Service Account")
        else:
            click.echo("   Role: User")

        click.echo("\n   Authentication: Valid (OAuth)")
        click.echo(f"   Gateway: {gateway_url}")

        # Show token file location
        tokens = auth_module.load_tokens()
        if tokens:
            click.echo(f"   Token file: {auth_module.TOKEN_FILE}")
            if tokens.get("created_at"):
                click.echo(f"   Logged in: {tokens['created_at']}")

        click.echo()

    except requests.exceptions.RequestException as e:
        click.echo(f"Failed to get user info: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--gateway-url",
    default=lambda: os.getenv("MCP_GATEWAY_URL", DEFAULT_GATEWAY_URL),
    help="Gateway URL to authenticate with",
)
def login(gateway_url: str):
    """Authenticate with MCP Gateway using OAuth.

    This uses OAuth device flow - no password needed!
    Your browser will open for authentication.
    Tokens and gateway URL are saved for all future commands.
    The tokens refresh themselves for as long as your identity provider allows.

    Examples:
        gravitino-mcp login
        gravitino-mcp login --gateway-url https://mcp-gateway.example.com
    """
    click.echo("MCP Gateway Login")
    click.echo("=" * 60)

    success = auth_module.device_flow_login(gateway_url)

    if success:
        click.echo("\nYou can now use MCP Gateway CLI:")
        click.echo("   gravitino-mcp call gravitino get_list_of_catalogs")
        click.echo("\nStart the auth proxy for VSCode:")
        click.echo("   gravitino-mcp proxy start")
    else:
        click.echo("\nLogin failed. Please try again.")
        sys.exit(1)


@cli.command()
def logout():
    """Log out and remove stored OAuth tokens."""
    auth_module.logout()


@cli.command()
@click.option("--gateway-url", default=None, help="Gateway URL to authenticate with")
@click.option("--no-login", is_flag=True, default=False, help="Skip the login step")
@click.option(
    "--no-autostart",
    is_flag=True,
    default=False,
    help="Skip installing the always-on proxy service",
)
def setup(gateway_url, no_login, no_autostart):
    """One-command onboarding: login, configure all AI clients, and start the proxy.

    Idempotent — safe to re-run any time.
    """
    success = setup_module.run_setup(
        gateway_url=gateway_url,
        do_login=not no_login,
        enable_autostart=not no_autostart,
        echo=click.echo,
    )
    if not success:
        sys.exit(1)


@cli.command()
def doctor():
    """Diagnose MCP/proxy/auth problems and print fixes."""
    ok = doctor_module.run_doctor(echo=click.echo)
    if not ok:
        sys.exit(1)


@cli.group()
def proxy():
    """Manage the local auth proxy for IDE integration.

    The proxy runs on localhost:8001 and auto-injects OAuth tokens.
    For VS Code, Cursor and other MCP clients that connect over HTTP.
    """
    pass


@proxy.command()
def start():
    """Start the auth proxy daemon."""
    success = proxy_module.start_proxy()
    if not success:
        sys.exit(1)


@proxy.command()
def stop():
    """Stop the auth proxy daemon."""
    success = proxy_module.stop_proxy()
    if not success:
        sys.exit(1)


@proxy.command()
def status():
    """Show auth proxy status."""
    success = proxy_module.proxy_status()
    if not success:
        sys.exit(1)


@proxy.command()
def restart():
    """Restart the auth proxy daemon."""
    success = proxy_module.restart_proxy()
    if not success:
        sys.exit(1)


@proxy.command(name="run")
def proxy_run():
    """Run the proxy in the foreground (used by the auto-start service)."""
    sys.exit(proxy_module.run_proxy_foreground())


@proxy.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output (like tail -f)")
@click.option("--lines", "-n", default=50, help="Number of lines to show (default: 50)")
def logs(follow, lines):
    """View proxy logs."""
    success = proxy_module.proxy_logs(follow=follow, lines=lines)
    if not success:
        sys.exit(1)


@cli.group()
def autostart():
    """Manage the always-on proxy service (launchd / systemd)."""
    pass


@autostart.command(name="enable")
def autostart_enable():
    """Install and start the auto-start proxy service."""
    result = autostart_module.enable()
    click.echo(f"{result.status}: {result.detail}")
    if result.status == autostart_module.STATUS_ERROR:
        sys.exit(1)


@autostart.command(name="disable")
def autostart_disable():
    """Stop and remove the auto-start proxy service."""
    result = autostart_module.disable()
    click.echo(f"{result.status}: {result.detail}")
    if result.status == autostart_module.STATUS_ERROR:
        sys.exit(1)


@autostart.command(name="status")
def autostart_status():
    """Show whether the auto-start proxy service is installed."""
    result = autostart_module.status()
    click.echo(f"{result.status}" + (f": {result.path}" if result.path else ""))


if __name__ == "__main__":
    cli()
