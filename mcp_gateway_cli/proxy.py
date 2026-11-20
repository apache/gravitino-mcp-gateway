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
Proxy management commands for MCP Gateway CLI
"""

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import psutil
import requests

from .auth import TOKEN_FILE, load_tokens
from .constants import CONFIG_DIR, PROXY_BASE_URL, PROXY_ID_FILE, PROXY_PORT
from .proxy_identity import proof

PROXY_PID_FILE = CONFIG_DIR / "proxy.pid"
PROXY_LOG_FILE = CONFIG_DIR / "proxy.log"


def get_proxy_pid() -> int:
    """Get the PID of the running proxy from the PID file"""
    if not PROXY_PID_FILE.exists():
        return None

    try:
        with open(PROXY_PID_FILE, encoding="utf-8") as f:
            pid = int(f.read().strip())

        # Check if process is actually running
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            # Verify it's actually our proxy. The proxy can be launched two ways:
            #   • detached daemon  -> `python -P -m mcp_gateway_cli.proxy_daemon`
            #   • foreground (run) -> `... gravitino-mcp proxy run` (used by launchd/systemd)
            cmdline = " ".join(proc.cmdline())
            if "proxy_daemon" in cmdline or "proxy run" in cmdline:
                return pid
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # PID file is stale, remove it
    try:
        PROXY_PID_FILE.unlink()
    except OSError:
        pass

    return None


def is_proxy_running() -> bool:
    """Whether this user's proxy is running.

    Another user's program can hold the port, so whatever answers there must
    know the ID that only this user can read.
    """
    return bool(get_proxy_pid()) or _answers_as_this_users_proxy()


def _answers_as_this_users_proxy() -> bool:
    nonce = secrets.token_hex(16)
    try:
        proxy_id = PROXY_ID_FILE.read_text(encoding="utf-8").strip()
        response = requests.get(
            f"{PROXY_BASE_URL}/health", params={"nonce": nonce}, timeout=1
        )
        answered = str(response.json().get("proof", ""))
    except (OSError, ValueError, AttributeError, requests.exceptions.RequestException):
        return False
    expected = proof(proxy_id, nonce)
    return bool(expected) and secrets.compare_digest(expected, answered)


def _port_in_use(port: int) -> bool:
    """Whether a program listens on ``port`` on this machine."""
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def start_proxy():
    """Start the auth proxy daemon"""
    # Check if already running
    if is_proxy_running():
        print(f"Proxy is already running on port {PROXY_PORT}")
        return True

    # Check if tokens exist (user must login first)
    if not TOKEN_FILE.exists():
        print("Not authenticated. Please run 'gravitino-mcp login' first.")
        return False

    if _port_in_use(PROXY_PORT):
        print(
            f"Port {PROXY_PORT} is in use by another program, so the proxy can't "
            "start. Stop that program, then run: gravitino-mcp proxy start"
        )
        return False

    print(f"Starting Auth Proxy on port {PROXY_PORT}...")

    # Start proxy as a background process
    try:
        # Get the path to the Python executable and proxy script
        python_exe = sys.executable

        # Open log file for writing
        PROXY_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PROXY_LOG_FILE, "a", encoding="utf-8") as log_file:
            # The daemon outlives this command, so it is never waited on.
            process = subprocess.Popen(  # pylint: disable=consider-using-with
                # -P and the home directory keep a module in the current
                # directory, such as a cloned repo, from running in its place.
                [python_exe, "-P", "-m", "mcp_gateway_cli.proxy_daemon"],
                cwd=Path.home(),
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,  # Detach from parent
            )

        # Save PID
        PROXY_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PROXY_PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(process.pid))

        # Wait for proxy to actually start listening (up to 8 seconds)
        started = False
        for _ in range(16):
            time.sleep(0.5)
            if _answers_as_this_users_proxy():
                started = True
                break

        if started:
            print(f"Proxy started successfully (PID: {process.pid})")
            print(f"Local proxy: http://localhost:{PROXY_PORT}")
            print("   Forwards to gateway URL from your login")
            print(f"\nConfigure your IDE to use: http://localhost:{PROXY_PORT}")
            print("   The proxy auto-injects your OAuth tokens")
            return True
        print("Proxy failed to start. Check logs:")
        print("   gravitino-mcp proxy logs")
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Failed to start proxy: {e}")
        return False


def stop_proxy():
    """Stop the auth proxy daemon"""
    pid = get_proxy_pid()

    if not pid:
        print("Proxy is not running")
        return True

    print(f"Stopping proxy (PID: {pid})...")

    try:
        # Try graceful shutdown first
        process = psutil.Process(pid)
        process.terminate()

        # Wait up to 5 seconds for graceful shutdown
        for _ in range(10):
            if not psutil.pid_exists(pid):
                break
            time.sleep(0.5)

        # If still running, force kill
        if psutil.pid_exists(pid):
            process.kill()

        # Remove PID file
        if PROXY_PID_FILE.exists():
            PROXY_PID_FILE.unlink()
        PROXY_ID_FILE.unlink(missing_ok=True)

        print("Proxy stopped successfully")
        return True

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Failed to stop proxy: {e}")
        return False


def proxy_status():
    """Show proxy status"""
    pid = get_proxy_pid()

    if not pid:
        print("Proxy is not running")
        print("\nStart the proxy with: gravitino-mcp proxy start")
        return False

    try:
        process = psutil.Process(pid)
        cpu_percent = process.cpu_percent(interval=0.1)
        mem_info = process.memory_info()
        mem_mb = mem_info.rss / 1024 / 1024

        print("Proxy is running")
        print("\nStatus:")
        backend_url = (load_tokens() or {}).get("gateway_url", "(unknown)")

        print(f"   PID:         {pid}")
        print(f"   Port:        {PROXY_PORT}")
        print(f"   Backend:     {backend_url}")
        print(f"   CPU:         {cpu_percent:.1f}%")
        print(f"   Memory:      {mem_mb:.1f} MB")

        if _answers_as_this_users_proxy():
            print("   Health:      Proxy ready")
        else:
            print("   Health:      Not responding")

        return True

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error checking proxy status: {e}")
        return False


def restart_proxy():
    """Restart the auth proxy"""
    print("Restarting proxy...")
    stop_proxy()
    time.sleep(1)
    return start_proxy()


def run_proxy_foreground(
    wait_seconds: float = 300.0, poll_interval: float = 3.0
) -> int:
    """Run the auth proxy in the foreground (blocking).

    This is the entry point used by OS service managers (launchd / systemd),
    which supervise a long-lived foreground process. Humans should use
    ``start``/``stop``/``restart`` instead.

    If not yet authenticated (e.g. the service loaded before the user logged
    in), wait up to ``wait_seconds`` for the token file to appear, then exit
    **cleanly** (code 0) if it still doesn't. Exiting cleanly — rather than
    crashing with a non-zero code — stops the supervisor from respawning us in
    a tight loop (launchd KeepAlive=SuccessfulExit:false / systemd
    Restart=on-failure both treat a clean exit as "do not restart").

    Returns a process exit code; only returns if the server stops or we give up.
    """
    token_file = TOKEN_FILE
    if not token_file.exists():
        print(
            "Not authenticated yet; waiting for login "
            f"(up to {int(wait_seconds)}s). Run 'gravitino-mcp login'.",
            file=sys.stderr,
        )
        waited = 0.0
        while waited < wait_seconds and not token_file.exists():
            time.sleep(poll_interval)
            waited += poll_interval
        if not token_file.exists():
            print(
                "Still not authenticated; exiting cleanly. The service will "
                "start again on next login. Run 'gravitino-mcp login' then "
                "'gravitino-mcp proxy start'.",
                file=sys.stderr,
            )
            return 0

    # Record our PID so `proxy status`/`stop` can find this instance too.
    PROXY_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PROXY_PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    # Import lazily so the rest of the CLI works without the daemon deps loaded.
    # pylint: disable-next=import-outside-toplevel
    from .proxy_daemon import start_proxy as _serve

    exit_code = 0
    try:
        _serve(port=PROXY_PORT, token_file=token_file)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Proxy server crashed: {e}", file=sys.stderr)
        exit_code = 1
    finally:
        # Best-effort cleanup of our own PID file on shutdown.
        try:
            if PROXY_PID_FILE.exists() and PROXY_PID_FILE.read_text().strip() == str(
                os.getpid()
            ):
                PROXY_PID_FILE.unlink()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    return exit_code


def proxy_logs(follow: bool = False, lines: int = 50):
    """View proxy logs"""
    if not PROXY_LOG_FILE.exists():
        print(f"No log file found at {PROXY_LOG_FILE}")
        print("\nLogs will be created when the proxy starts")
        return False

    if follow:
        # Follow mode - tail -f
        print("Following proxy logs (Ctrl+C to stop)...\n")
        try:
            with open(PROXY_LOG_FILE, "r", encoding="utf-8") as f:
                # Go to end of file
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        print(line, end="")
                    else:
                        time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n\nStopped following logs")
            return True
    else:
        # Show last N lines
        print(f"Last {lines} lines of proxy logs:\n")
        try:
            with open(PROXY_LOG_FILE, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
                for line in all_lines[-lines:]:
                    print(line, end="")
            print(
                "\n\nUse 'gravitino-mcp proxy logs --follow' to tail logs in real-time"
            )
            print(f"Log file: {PROXY_LOG_FILE}")
            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"Error reading logs: {e}")
            return False
