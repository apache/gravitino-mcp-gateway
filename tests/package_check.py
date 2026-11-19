#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Checks an installed wheel, as CI's packaging job does.

Run it with the Python the wheel is installed in, from the repository root.
Python then imports the installed package, not the checkout.
"""

import sys
from importlib.metadata import version
from pathlib import Path

import mcp_gateway
import mcp_gateway_cli
import mcp_gateway_sdk

PACKAGE = "apache-gravitino-mcp-gateway"
TEMPLATES = ("device_approval.html", "message.html")


def main() -> None:
    for module in (mcp_gateway, mcp_gateway_cli, mcp_gateway_sdk):
        if "site-packages" not in Path(module.__file__).parts:
            sys.exit(f"{module.__name__} came from {module.__file__}, not the installed wheel")
    if mcp_gateway.VERSION != version(PACKAGE):
        sys.exit(f"The gateway reports {mcp_gateway.VERSION}, but the package is {version(PACKAGE)}")
    missing = [name for name in TEMPLATES if not (mcp_gateway.TEMPLATES_DIR / name).is_file()]
    if missing:
        sys.exit(f"The wheel lacks the templates {missing}")
    print(f"{PACKAGE} {mcp_gateway.VERSION} is installed correctly")


if __name__ == "__main__":
    main()
