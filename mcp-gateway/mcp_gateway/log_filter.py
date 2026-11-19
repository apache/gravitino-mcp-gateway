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
Sensitive data redaction for all log output.

Installs a logging filter that scrubs JWTs, Bearer tokens, passwords,
and other secrets from every log record before it is emitted — including
third-party loggers such as uvicorn.access.
"""

import logging
import re
from typing import Pattern

# Patterns to catch common secret shapes
_PATTERNS: list[tuple[Pattern, str]] = [
    # Bearer / Authorization header values  →  "Bearer [REDACTED]"
    (
        re.compile(
            r"(Bearer\s+)[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    # Raw JWTs (three base64url segments), also inside URL-encoded text such as
    # "Bearer%20eyJ...", where there is no word boundary before them
    (
        re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*"),
        "[JWT_REDACTED]",
    ),
    # Secrets and tokens in query strings or form data
    (
        re.compile(
            r"(client_secret|password|client_secret_encrypted|"
            r"access_token|refresh_token|id_token|token|"
            r"api[_-]?key|key|sig|signature|secret)=(?!\[)([^&\s\"\']+)",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
    # Slack's incoming webhook URLs, whose path is the secret
    (
        re.compile(r"(hooks\.slack\.com/services/)[^\s\"\']+"),
        r"\1[REDACTED]",
    ),
    # Device codes, also as a repr (device_code='...') or a JSON field
    (
        re.compile(r"(device_code[\"']?\s*[=:]\s*[\"']?)([^&\s\"',)]+)"),
        r"\1[REDACTED]",
    ),
    # Authorization codes, only as query or form parameters, since "code=" is
    # also how status codes are logged
    (
        re.compile(r"([?&]code=)([^&\s\"\']+)"),
        r"\1[REDACTED]",
    ),
    # "Authorization": "Bearer ..." in logged dicts/headers
    (
        re.compile(r"(\"Authorization\"\s*:\s*\"Bearer\s+)[^\"]+\"", re.IGNORECASE),
        r'\1[REDACTED]"',
    ),
]


def _redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class SensitiveDataFilter(logging.Filter):
    """Redacts secrets from log record messages and args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if record.name == "uvicorn.access" and isinstance(record.args, tuple):
                # uvicorn's access formatter unpacks record.args, so keep the tuple.
                record.args = tuple(
                    _redact(arg) if isinstance(arg, str) else arg for arg in record.args
                )
            else:
                # Replace the pre-formatted message and clear args so getMessage()
                # won't try to re-format with the original (potentially secret) args.
                record.msg = _redact(record.getMessage())
                record.args = None
        except Exception:  # pylint: disable=broad-exception-caught
            # The message doesn't fit its arguments, and logging prints both as
            # they are: redact each part instead.
            _redact_parts(record)
        return True


def _redact_parts(record: logging.LogRecord) -> None:
    """Redact a record's message and each of its arguments, apart."""
    try:
        record.msg = _redact(str(record.msg))
        if isinstance(record.args, tuple):
            record.args = tuple(_redact(str(arg)) for arg in record.args)
        elif record.args:
            record.args = (_redact(str(record.args)),)
    except Exception:  # pylint: disable=broad-exception-caught
        # Never let the filter crash the application, nor let a secret through.
        record.msg = "[a log record that could not be redacted]"
        record.args = None


def install_sensitive_data_filter() -> None:
    """
    Attach the SensitiveDataFilter wherever log records are emitted, so that
    *all* log output is scrubbed.

    A filter on a logger only sees records logged on that logger, not records
    propagated from its children, so the filter goes on the root logger's
    handlers, which every propagated record passes through. Named third-party
    loggers that may not propagate get it on the logger and its handlers.

    Call once at application startup, after logging is configured.
    """
    filt = SensitiveDataFilter()

    for handler in logging.getLogger().handlers:
        _add_once(handler, filt)

    for name in (
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
        "fastapi",
        "httpx",
        "httpcore",
    ):
        named = logging.getLogger(name)
        _add_once(named, filt)
        for handler in named.handlers:
            _add_once(handler, filt)


def _add_once(target: logging.Filterer, filt: SensitiveDataFilter) -> None:
    if not any(isinstance(f, SensitiveDataFilter) for f in target.filters):
        target.addFilter(filt)
