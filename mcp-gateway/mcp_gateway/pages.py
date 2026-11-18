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

"""The pages the gateway shows a browser itself, while signing in or connecting.

Everything else people do in a browser, they do in Gravitino's web UI.
"""

import re
from typing import Optional

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from . import TEMPLATES_DIR

# Where a sign-in ends when nothing asked to go elsewhere.
HOME = "/portal"

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# OAuth error codes (RFC 6749 section 4.1.2.1) are short ASCII words.
_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def message_page(  # pylint: disable=too-many-arguments
    request: Request,
    title: str,
    message: str,
    *,
    status_code: int = 200,
    link: Optional[tuple[str, str]] = None,
    form: Optional[tuple[str, str]] = None,
) -> HTMLResponse:
    """A page with a title and a message, and optionally a link or a one-button form.

    ``link`` and ``form`` are (URL, text) pairs. Jinja escapes every value.
    """
    link_url, link_text = link or (None, None)
    form_action, form_button = form or (None, None)
    return templates.TemplateResponse(
        request,
        "message.html",
        {
            "title": title,
            "message": message,
            "link_url": link_url,
            "link_text": link_text,
            "form_action": form_action,
            "form_button": form_button,
        },
        status_code=status_code,
    )


def wrong_account_page(request: Request) -> HTMLResponse:
    """Shown when a connection finishes in a browser signed in as someone else."""
    return message_page(
        request,
        "Connection not saved",
        "This connection was started by a different account. Sign in to the "
        "gateway as yourself and connect again.",
        status_code=403,
    )


def expired_sign_in_page(request: Request) -> HTMLResponse:
    """Shown when a connection finishes with a state the gateway no longer holds."""
    return message_page(
        request,
        "Not connected",
        "The sign-in expired or started in another browser. Connect again.",
        status_code=400,
    )


def refused_sign_in_page(
    request: Request, error: Optional[str], service: Optional[str] = None
) -> HTMLResponse:
    """Shown when a sign-in sends the browser back without a code: to the
    gateway, or to connect ``service``.

    The error is shown only if it is an error code: anyone can put text in a link.
    """
    code_name = error if error and _ERROR_CODE.fullmatch(error) else "no code"
    if service is None:
        return message_page(
            request,
            "Not signed in",
            f"The sign-in did not finish ({code_name}).",
            link=("/auth/oauth/login", "Sign in again"),
            status_code=400,
        )
    return message_page(
        request,
        "Not connected",
        f"The sign-in did not connect you to {service} ({code_name}). Connect again.",
        status_code=400,
    )
