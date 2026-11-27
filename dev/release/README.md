<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Releasing the MCP gateway

A release follows the [ASF release policy](https://www.apache.org/legal/release-policy.html). The
Apache Gravitino PMC votes on the source release. The wheel, the sdist and the Docker image are
convenience binaries, built from that source release and published only after the vote.

| Artifact | Staged for the vote in | Published to |
| --- | --- | --- |
| `gravitino-mcp-gateway-<version>-src.tar.gz` | `dist/dev/gravitino/mcp-gateway/<version>-rc<n>/` | `dist/release/gravitino/mcp-gateway/<version>/` |
| `apache_gravitino_mcp_gateway-<version>.tar.gz` and `…-py3-none-any.whl` | the same | the same, and PyPI |
| `apache/gravitino-mcp-gateway:<version>` | — | Docker Hub |

Each file in `dist` has a detached signature (`.asc`) and a SHA-512 checksum (`.sha512`).

## Before the first release

- You are on the Apache Gravitino PMC, since only the PMC can write to `dist/release`.
- Your signing key, RSA of at least 2048 bits and 4096 for a new key, is in
  [Gravitino's KEYS](https://downloads.apache.org/gravitino/KEYS). To add it, append
  `gpg --armor --export <you>@apache.org` to `KEYS` in
  `https://dist.apache.org/repos/dist/release/gravitino/` and commit.
- You have `git`, `uv`, `gpg`, `svn`, `curl`, `tar`, `unzip`, `file`, `twine` and Docker with
  `buildx`, and can push to this repository. The scripts commit and tag as the git user of the
  checkout you run them from, so make its `user.email` your apache.org address. gpg asks for your
  key's passphrase on the terminal.
- You can upload to the `apache-gravitino-mcp-gateway` project on PyPI, with an API token in
  `TWINE_PASSWORD` and `TWINE_USERNAME=__token__`, or in `~/.pypirc`. The first upload creates the
  project; then add the other PMC members as owners.
- ASF Infra has set up `apache/gravitino-mcp-gateway` on Docker Hub, and the `DOCKERHUB_USER` and
  `DOCKERHUB_TOKEN` secrets that let this repository's workflows push to it. The repository's
  description says that its images are convenience binaries, not ASF releases.
- Your GitHub login is in the list of release managers in
  `.github/workflows/publish-docker.yml`, which only they may run.

Every script that changes something outside your machine asks first, and with `-n` does
everything else and changes nothing outside it. They work in `~/gravitino-mcp-gateway-release`, or
`RELEASE_WORK_DIR`, and each run replaces what an earlier run left there.

## Steps

The examples release 0.1.0, from release candidate 1.

1. **Cut the release branch**, for the first release of a minor version, from an up-to-date
   `main`: `git push <this repository's remote> main:branch-0.1`. Then open a pull request that sets
   `main`'s version to `0.2.0.dev0`, with `uv lock`. Later fixes for 0.1 go to `main` first, then
   to `branch-0.1`.

2. **Tag the release candidate.** This sets the version to 0.1.0 on `branch-0.1`, tags
   `v0.1.0-rc1`, moves the branch on to `0.1.1.dev0`, and pushes:

   ```shell
   dev/release/release-tag.sh 0.1.0 1
   ```

3. **Build and stage it.** This builds the source release from the tag, builds the wheel and sdist
   from the source release, signs and checksums them, and stages them in `dist/dev`:

   ```shell
   dev/release/release-build.sh 0.1.0 1
   ```

4. **Check it as a voter would**, then start the vote on dev@gravitino.apache.org:

   ```shell
   dev/release/verify-release.sh 0.1.0 1
   ```

   It downloads the files from `dist/dev`, or checks files you already have with
   `-d <directory>`, and needs Docker for the license header check.

   Model the `[VOTE]`, `[RESULT][VOTE]` and `[ANNOUNCE]` emails on Gravitino's past releases in the
   [dev@ archive](https://lists.apache.org/list.html?dev@gravitino.apache.org). The vote email links
   to the staged files, the tag and its commit, and `KEYS`, and points voters to
   `verify-release.sh`. The vote stays open at least 72 hours, and passes with at least three
   binding +1 votes and more +1 than -1. If it fails, fix what it found on `main` and
   `branch-0.1`, remove `0.1.0-rc1` from `dist/dev` with `svn delete`, and start again from step 2
   with release candidate 2.

5. **Publish it.** This tags `v0.1.0`, moves the files to `dist/release`, uploads the voted wheel
   and sdist to PyPI, and offers to remove older releases from `dist/release`. The move makes the
   release official; if a later step fails, fix it and run the script again, which skips what is
   done:

   ```shell
   dev/release/release-publish.sh 0.1.0 1
   ```

   Then publish the Docker image: run the **Publish Docker image** workflow from this repository's
   Actions tab, with the version, and `latest` for the newest release only. It runs
   `dev/release/publish-docker.sh`, which builds the image for amd64 and arm64 from the source
   release in `dist/release`. Run it first as a dry run, which builds without pushing, then again
   without.

6. **Announce it**, an hour later, once the files are on `downloads.apache.org`:
   - Add the release to Gravitino's download page. Link the source release through
     `https://www.apache.org/dyn/closer.lua/gravitino/mcp-gateway/0.1.0/gravitino-mcp-gateway-0.1.0-src.tar.gz`,
     and its signature, checksum and `KEYS` through `https://downloads.apache.org/gravitino/`.
   - Send the `[ANNOUNCE]` email from your apache.org address, to announce@apache.org too.
   - Record the release at <https://reporter.apache.org/addrelease.html?gravitino>.

