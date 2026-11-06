# SPDX-License-Identifier: MIT
#
# kalkan image: the deterministic engine and the pinned scanners.
# Claude Code is not part of the image. docker/README.md tells how to use it with the image.
#
# Build from the repository root. The build context must hold pyproject.toml:
#   docker build -f docker/Dockerfile -t kalkan:local .
#
# The image installs every tool of src/kalkan/tools/manifest.json. The Dockerfile has no tool
# list of its own: each install layer asks docker/manifest_tools.py for its tools, so a new
# manifest tool arrives without a change here.
#
# Build arguments:
#   WITH_GPL=true|false       The GPL tools (Hadolint, ShellCheck, ...) in their own layer.
#                             Default: true. WITH_HADOLINT=false (the older name) also leaves
#                             them out.
#   WITH_GO=true|false        The pinned Go toolchain and the tools that need Go (gosec,
#                             govulncheck, ...). Default: true.

# python:3.12-slim (Debian trixie, Python 3.12.15). The digest is the multi-platform image index,
# read from the Docker Hub registry on 2026-10-16. Change the tag and the digest together.
ARG PYTHON_IMAGE=python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ARG WITH_GPL=true
ARG WITH_HADOLINT=true
ARG WITH_GO=true

# ---------------------------------------------------------------------------------------------
# base: Python, git, CA certificates and the non-root user. No compilers.
FROM ${PYTHON_IMAGE} AS base
ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore
# The Debian packages come from the release of the pinned base image. The Debian archive keeps
# only the current version of a package, so the versions are not pinned one by one.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 kalkan \
    && useradd --system --uid 10001 --gid kalkan --home-dir /home/kalkan --create-home \
        --shell /usr/sbin/nologin kalkan

# ---------------------------------------------------------------------------------------------
# engine: the repository in /opt/kalkan and the engine venv in /opt/kalkan/.venv, the path that
# the /kalkan skill calls. The install is editable because the engine finds rules/ and
# knowledge/ relative to its source folder (src/kalkan/matchers/spec.py). The first command
# stops the build when docker/manifest_tools.py cannot read the manifest.
FROM base AS engine
COPY . /opt/kalkan
RUN python /opt/kalkan/docker/manifest_tools.py core gpl go go-gpl > /dev/null \
    && python -m venv /opt/kalkan/.venv \
    && /opt/kalkan/.venv/bin/python -m pip install --no-cache-dir -e /opt/kalkan \
    && /opt/kalkan/.venv/bin/python -m compileall -q /opt/kalkan/src

# ---------------------------------------------------------------------------------------------
# go: the pinned Go toolchain, checked against the SHA-256 that go.dev publishes. Only with
# WITH_GO=true; otherwise /opt/go stays empty. GO_VERSION and the two SHA-256 values must equal
# the "go" entry of src/kalkan/tools/manifest.json (linux-amd64, linux-arm64); a unit test
# checks it. kalkan accepts this Go as a system Go (its version is at least the highest
# min_go_version of the Go tools), so the image needs no second copy in .tools/go.
FROM base AS go
ARG WITH_GO
ARG GO_VERSION=1.26.9
ARG GO_SHA256_AMD64=42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d
ARG GO_SHA256_ARM64=4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052
RUN set -eu; \
    mkdir -p /opt/go; \
    if [ "$WITH_GO" = "true" ]; then \
        arch="$(dpkg --print-architecture)"; \
        case "$arch" in \
            amd64) sha256="$GO_SHA256_AMD64" ;; \
            arm64) sha256="$GO_SHA256_ARM64" ;; \
            *) echo "no pinned Go toolchain for $arch" >&2; exit 1 ;; \
        esac; \
        url="https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"; \
        python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" \
            "$url" /tmp/go.tar.gz; \
        printf '%s  %s\n' "$sha256" /tmp/go.tar.gz > /tmp/go.tar.gz.sha256; \
        sha256sum -c /tmp/go.tar.gz.sha256; \
        tar -C /opt -xzf /tmp/go.tar.gz; \
        rm /tmp/go.tar.gz /tmp/go.tar.gz.sha256; \
    elif [ "$WITH_GO" != "false" ]; then \
        echo "WITH_GO must be true or false" >&2; exit 1; \
    fi

# ---------------------------------------------------------------------------------------------
# final: engine, scanners, non-root user. The layers go from the least to the most variable,
# and each build argument is declared just before its first use: a change of WITH_GPL or
# WITH_GO then keeps the cached layer of the core scanners. A change in the repository copy
# rebuilds the tool layers.
FROM base AS final
ENV KALKAN_HOME=/opt/kalkan \
    KALKAN_RUNS_DIR=/work/runs \
    HOME=/home/kalkan \
    GOTOOLCHAIN=local \
    PATH=/opt/kalkan/.venv/bin:/opt/go/bin:${PATH}
COPY --from=engine /opt/kalkan /opt/kalkan

# Core scanners: every manifest tool that needs no Go and has no GPL license
# (docker/manifest_tools.py core). kalkan's own installer downloads each asset, refuses a
# SHA-256 mismatch and writes .tools/installed.json; a tool without a build for the platform is
# skipped. "tools verify" hashes the installed files again. The tool list splits into words on
# purpose. The installer writes installed.json with mode 0600, so every install layer makes it
# readable for the non-root user.
# hadolint ignore=SC2086
RUN set -eu; \
    tools="$(python /opt/kalkan/docker/manifest_tools.py core)"; \
    if [ -n "$tools" ]; then \
        kalkan tools install $tools; \
        kalkan tools verify $tools; \
        chmod 0644 /opt/kalkan/.tools/installed.json; \
    fi

# GPL tools (docker/manifest_tools.py gpl: Hadolint and the other GPL or AGPL scanners). kalkan
# (MIT) runs the unmodified binaries as separate processes only. They stay in their own layer,
# and --build-arg WITH_GPL=false (or WITH_HADOLINT=false) leaves them out of the image.
ARG WITH_GPL
ARG WITH_HADOLINT
# hadolint ignore=SC2086
RUN set -eu; \
    case "$WITH_GPL/$WITH_HADOLINT" in \
        true/true) tools="$(python /opt/kalkan/docker/manifest_tools.py gpl)" ;; \
        true/false | false/true | false/false) tools="" ;; \
        *) echo "WITH_GPL and WITH_HADOLINT must be true or false" >&2; exit 1 ;; \
    esac; \
    if [ -n "$tools" ]; then \
        kalkan tools install $tools; \
        kalkan tools verify $tools; \
        chmod 0644 /opt/kalkan/.tools/installed.json; \
    fi

# The tools that need Go (docker/manifest_tools.py go, plus go-gpl with the GPL tools): gosec,
# govulncheck and the others. They build with "go install" and the Go of /opt/go, or run with
# it; the Go checksum database verifies each module. kalkan builds with GOPATH, GOMODCACHE and
# GOCACHE under .tools/go-build and deletes that folder after the builds ("kalkan tools
# install"); the rm below stays as a second guard. Only with WITH_GO=true.
ARG WITH_GO
COPY --from=go /opt/go /opt/go
# hadolint ignore=SC2086
RUN set -eu; \
    if [ "$WITH_GO" = "true" ]; then \
        groups="go"; \
        if [ "$WITH_GPL" = "true" ] && [ "$WITH_HADOLINT" = "true" ]; then groups="go go-gpl"; fi; \
        tools="$(python /opt/kalkan/docker/manifest_tools.py $groups)"; \
        go version; \
        if [ -n "$tools" ]; then \
            kalkan tools install $tools; \
            kalkan tools verify $tools; \
            chmod 0644 /opt/kalkan/.tools/installed.json; \
        fi; \
        rm -rf /opt/kalkan/.tools/go-build; \
    fi

# The runs folder and the vulnerability database folder belong to the non-root user, so that a
# new named volume at /opt/kalkan/.tools/vulndb takes this owner and "kalkan sca update-db"
# can fill it (docker/README.md).
COPY docker/entrypoint.sh /usr/local/bin/kalkan-entrypoint
RUN chmod 0755 /usr/local/bin/kalkan-entrypoint \
    && mkdir -p /work/runs /opt/kalkan/runs /opt/kalkan/.tools/vulndb \
    && chown kalkan:kalkan /work/runs /opt/kalkan/runs /opt/kalkan/.tools/vulndb

LABEL org.opencontainers.image.title="kalkan" \
      org.opencontainers.image.description="kalkan engine and pinned security scanners (no Claude Code)" \
      org.opencontainers.image.source="https://github.com/dtechcloud/kalkan" \
      kalkan.with-gpl="${WITH_GPL}" \
      kalkan.with-go="${WITH_GO}"

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/kalkan-entrypoint"]
CMD ["--help"]
