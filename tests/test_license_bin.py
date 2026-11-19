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

"""LICENSE.bin lists every package the Docker image installs.

The image runs ``uv sync --locked --no-dev --all-extras`` on Linux, so the
packages are the gateway's runtime dependencies in uv.lock, with every extra.
"""

import re
import tomllib
from pathlib import Path

from packaging.markers import Marker, default_environment

PROJECT_DIR = Path(__file__).resolve().parent.parent
ROOT_PACKAGE = "apache-gravitino-mcp-gateway"
# The image is Linux, on the official CPython 3.11 image.
IMAGE_ENVIRONMENT = {
    **default_environment(),
    "implementation_name": "cpython",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_system": "Linux",
    "python_full_version": "3.11.0",
    "python_version": "3.11",
    "sys_platform": "linux",
}
# Components of the image that are not Python packages from uv.lock.
OTHER_COMPONENTS: set = set()


def _applies(dependency):
    marker = dependency.get("marker")
    return marker is None or Marker(marker).evaluate(IMAGE_ENVIRONMENT)


def _image_packages():
    lock = tomllib.loads((PROJECT_DIR / "uv.lock").read_text(encoding="utf-8"))
    packages = {package["name"]: package for package in lock["package"]}
    root = packages[ROOT_PACKAGE]
    wanted = list(root["dependencies"])
    for group in root.get("optional-dependencies", {}).values():
        wanted.extend(group)

    installed = set()
    while wanted:
        dependency = wanted.pop()
        if not _applies(dependency):
            continue
        package = packages[dependency["name"]]
        for extra in dependency.get("extra", []):
            wanted.extend(package.get("optional-dependencies", {}).get(extra, []))
        if dependency["name"] in installed:
            continue
        installed.add(dependency["name"])
        wanted.extend(package.get("dependencies", []))
    return installed


def _listed_components():
    text = (PROJECT_DIR / "LICENSE.bin").read_text(encoding="utf-8")
    bundled = text[text.index("This product bundles") :]
    # Components are listed one lowercase name to a line, under a license heading.
    return set(
        re.findall(r"^   ([a-z0-9]+(?:[._-][a-z0-9]+)*)$", bundled, re.MULTILINE)
    )


def test_license_bin_lists_every_package_the_image_installs():
    expected = _image_packages()
    listed = _listed_components()

    assert {
        "missing": sorted(expected - listed),
        "not installed": sorted(listed - expected - OTHER_COMPONENTS),
    } == {"missing": [], "not installed": []}


def test_the_image_package_list_follows_extras_and_markers():
    """A resolver that lost extras or markers would make the test above vacuous."""
    packages = _image_packages()

    assert {"boto3", "slack-bolt", "uvloop", "httptools"} <= packages
    assert "colorama" not in packages  # Windows only
    assert "pytest" not in packages  # a dev dependency
