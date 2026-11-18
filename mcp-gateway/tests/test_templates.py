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

"""The gateway's pages load from the package, escape what they show, and post
their forms to routes the gateway serves."""

import re

import pytest
from fastapi import Request

from mcp_gateway import TEMPLATES_DIR, pages
from mcp_gateway.main import app
from mcp_gateway.routes import device_flow

_FORM = re.compile(r"""<form\b[^>]*\bmethod="(\w+)"[^>]*\baction="(/[^"{]*)\"""", re.I)


@pytest.mark.parametrize(
    "templates", [pages.templates, device_flow.templates], ids=["pages", "device"]
)
def test_templates_load_from_the_package_in_any_working_directory(
    templates, monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)

    for name in ("device_approval.html", "message.html"):
        assert templates.get_template(name).filename == str(TEMPLATES_DIR / name)


def test_page_text_is_escaped():
    """Messages carry names from identity providers and errors from servers."""
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    page = pages.message_page(request, "<b>t</b>", "<script>alert(1)</script>")

    assert "<script>" not in page.body.decode()
    assert "&lt;script&gt;" in page.body.decode()


def test_every_form_posts_to_a_gateway_route():
    forms = {
        (method.upper(), action)
        for page in TEMPLATES_DIR.glob("*.html")
        for method, action in _FORM.findall(page.read_text(encoding="utf-8"))
    }
    routes = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }

    assert forms == {("POST", "/device/approve"), ("POST", "/device")}
    assert forms <= routes
