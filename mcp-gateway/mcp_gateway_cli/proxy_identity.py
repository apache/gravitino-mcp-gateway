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

"""How the CLI tells this user's proxy from another program on its port.

The proxy keeps a random ID in a file only this user can read, and proves it
knows the ID by answering a nonce with an HMAC of it; the ID itself is never
sent, so whoever asks can't answer as this proxy once it stops.
"""

import hashlib
import hmac


def proof(proxy_id: str, nonce: str) -> str:
    """What the proxy with ``proxy_id`` answers to ``nonce``."""
    if not proxy_id or not nonce:
        return ""
    return hmac.new(proxy_id.encode(), nonce.encode(), hashlib.sha256).hexdigest()
