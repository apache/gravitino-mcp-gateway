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
# Build from the repository root: docker build -f docker/Dockerfile .
FROM python:3.11-slim

LABEL maintainer="dev@gravitino.apache.org"

WORKDIR /opt/mcp-gateway

COPY --chmod=755 pyproject.toml uv.lock .python-version README.md /opt/mcp-gateway/
COPY --chmod=755 mcp_gateway /opt/mcp-gateway/mcp_gateway
COPY --chmod=755 mcp_gateway_cli /opt/mcp-gateway/mcp_gateway_cli
COPY --chmod=755 mcp_gateway_sdk /opt/mcp-gateway/mcp_gateway_sdk
# The image bundles third-party packages, which LICENSE.bin and NOTICE.bin cover.
COPY --chmod=755 LICENSE.bin /opt/mcp-gateway/LICENSE
COPY --chmod=755 NOTICE.bin /opt/mcp-gateway/NOTICE

COPY --chmod=755 docker/start-mcp-gateway.sh /opt/mcp-gateway/

# uv defaults its cache to $HOME/.cache/uv, which a non-root user cannot create.
ENV UV_CACHE_DIR=/opt/mcp-gateway/.cache/uv
# Use the image's Python rather than downloading one.
ENV UV_PYTHON_DOWNLOADS=never
# The default SQLite database lives in data/, so that a volume mounted there keeps it.
ENV DATABASE_URL=sqlite:////opt/mcp-gateway/data/mcp_gateway.db
# The image is for deployments, so it starts only with production's settings; set
# ENVIRONMENT=development to try it without them.
ENV ENVIRONMENT=production

# --no-dev leaves pylint and the test tools out of the image. Every extra is installed so
# any secret-storage backend or the Slack bot can be enabled through configuration.
# uv, pinned so every build installs the same way, is mounted for this step only and
# stays out of the image.
RUN --mount=from=ghcr.io/astral-sh/uv:0.12.14,source=/uv,target=/bin/uv \
    uv sync --locked --no-dev --all-extras \
    && rm -rf /opt/mcp-gateway/.cache

# The gateway writes only data/, where a mounted volume keeps its owner and mode;
# its group, 0, can write there whatever uid it runs as.
RUN mkdir -p /opt/mcp-gateway/data \
    && chgrp 0 /opt/mcp-gateway/data \
    && chmod 775 /opt/mcp-gateway/data \
    && useradd -u 1000 -g 0 -M -s /sbin/nologin gravitino

USER 1000

EXPOSE 8000

ENTRYPOINT ["/bin/bash", "start-mcp-gateway.sh"]
