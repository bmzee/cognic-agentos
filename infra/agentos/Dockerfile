# syntax=docker/dockerfile:1.7
# Cognic AgentOS — production runtime images.
#
# Two final stages (selected via `--target`):
#
#   1. runtime              — kernel image: server + observability only.
#                             ≤120 MiB. Adapter Python packages NOT installed
#                             (operators run plugin-pack adapters here, or
#                             prefer the slimmer kernel for a custom build).
#                             Uvicorn factory: create_app (no adapter probing).
#
#   2. default-adapters     — kernel + bundled default adapters:
#                             Sprint 1C: Postgres / Qdrant / Vault /
#                             Ollama / Langfuse-OTel.
#                             Sprint 1D: + Oracle (oracledb thin) /
#                             Dynatrace (Metric Ingest API) /
#                             OpenAI-compat embedding (vLLM / SGLang /
#                             OpenAI / Azure-via-shim).
#                             ≤220 MiB. Built via `--extra adapters` so the
#                             [project.optional-dependencies] adapters group
#                             lands in /opt/venv. Uvicorn factory:
#                             create_prod_app (lifespan probes adapters).
#                             Budget raised from BUILD_PLAN's original
#                             180 MiB during Sprint 1C T15 — measured size
#                             198 MiB after dependency pruning; numpy/grpc/
#                             cryptography compiled libs dominate. Sprint
#                             1D added oracledb (~40 MiB unstripped) but
#                             a `strip --strip-unneeded` pass over the
#                             builder venv brought the final image to
#                             ~174 MiB. Sprint 4 T13 added pinned cosign
#                             v3.0.6 + OPA v1.16.1 binaries — neither is
#                             strippable in the alpine builder (their
#                             Go-specific PIE ELF layout is not
#                             recognised by alpine's binutils strip; we
#                             accept upstream-shipped bytes rather than
#                             reach for sstrip / llvm-strip / UPX).
#                             Measured default-adapters reality: 356-
#                             359 MiB, so the workflow budget was
#                             revised in T13-followup from 220 → 370
#                             MiB (measured + small buffer). Kernel
#                             ≤120 MiB budget is unaffected — kernel
#                             image explicitly does NOT carry either
#                             binary.
#                             Sprint 5 T2 added the official `mcp` SDK
#                             v1.27.0 to the adapters extras group
#                             (NOT to base dependencies). Kernel image
#                             does NOT carry the SDK and `create_app`
#                             deliberately does not wire MCPHost into
#                             app.state. Operators using the kernel
#                             image get governance + audit + /system/*
#                             read surfaces; the Sprint-5 MCP admission
#                             modules (mcp_manifest, mcp_capabilities,
#                             mcp_authz) import + construct on the
#                             kernel image without the SDK installed.
#                             End-to-end signed-pack admission still
#                             depends on the Sprint-4 cosign + OPA
#                             binaries which ship in this default-
#                             adapters image only — the kernel image
#                             cannot complete `register_with_full_
#                             attestation_check` without those
#                             binaries on PATH. MCP-host serving
#                             (call_tool / list_tools) is default-
#                             adapters-only via `create_prod_app`.
#                             This is the same precedent Sprint 4 set
#                             for cosign + OPA binaries.
#
# Build args wire git SHA + build timestamp into the image so /version is
# truthful in deployed environments.

ARG PYTHON_VERSION=3.12.8

# ---------- builder --------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Alpine ships musl; uv installer needs ca-certs + curl. binutils provides
# `strip` — mirrors the Sprint 1D pattern on default-adapters-builder. The
# kernel image gained sqlalchemy + alembic + greenlet in Sprint 2; greenlet
# ships compiled .so files that benefit from strip.
RUN apk add --no-cache ca-certificates curl binutils

# Pinned uv version; the SHA is verified by upstream's installer.
ADD https://astral.sh/uv/0.5.29/install.sh /uv-install.sh
RUN sh /uv-install.sh && rm /uv-install.sh
ENV PATH="/root/.local/bin:${PATH}"

# Copy lockfile + project metadata first so dep changes alone bust the cache.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable \
 && find /opt/venv -depth \( -type d -name __pycache__ -o -type d -name tests -o -type d -name test \) -exec rm -rf {} + \
 && find /opt/venv -name "*.dist-info" -exec sh -c 'rm -rf "$1"/RECORD "$1"/WHEEL "$1"/METADATA.bak' _ {} \; \
 && find /opt/venv -name "*.so" -exec strip --strip-unneeded {} + 2>/dev/null || true

# ---------- runtime --------------------------------------------------
FROM python:${PYTHON_VERSION}-alpine AS runtime

ARG BUILD_SHA=dev
ARG BUILD_TIME=unknown
ARG PACKAGE_VERSION=0.0.1

LABEL org.opencontainers.image.title="cognic-agentos" \
      org.opencontainers.image.description="Cognic AgentOS — bank-grade governance kernel + runtime + protocol layer" \
      org.opencontainers.image.vendor="Cognic" \
      org.opencontainers.image.source="https://github.com/bmzee/cognic-agentos" \
      org.opencontainers.image.version="${PACKAGE_VERSION}" \
      org.opencontainers.image.revision="${BUILD_SHA}" \
      org.opencontainers.image.created="${BUILD_TIME}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    COGNIC_HOST=0.0.0.0 \
    COGNIC_PORT=8000 \
    COGNIC_API_PREFIX=/api/v1 \
    COGNIC_RUNTIME_PROFILE=prod \
    COGNIC_BUILD_SHA="${BUILD_SHA}" \
    COGNIC_BUILD_TIME="${BUILD_TIME}"

# Non-root runtime user (Alpine BusyBox addgroup/adduser).
RUN addgroup -S -g 10001 cognic \
 && adduser -S -u 10001 -G cognic -h /home/cognic -s /sbin/nologin cognic

# Resolved venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Application source — read-only, owned by root, readable by cognic.
WORKDIR /app
COPY --chown=root:cognic src ./src
COPY --chown=root:cognic pyproject.toml README.md ./

# ADR-024: ship the OPA policy bundles (build_runtime's OPAEngine reads
# /app/policies/_default/*.rego) + alembic.ini (the migration script_location config) in-image.
# chmod -R a+rX guarantees the non-root cognic user reads /app/policies, /app/alembic.ini AND
# /app/src regardless of the build-context umask (a+rX = read for all + traverse for dirs; never
# adds execute to a plain file). /app/src is included because `alembic upgrade head` reads the
# migrations from src/cognic_agentos/db/migrations (alembic script_location) as the non-root user
# — a 600 migration file from a restrictive build-context umask would otherwise be unreadable and
# the migration Job fails with PermissionError (Proof 1b-2 attempt-3 finding).
COPY --chown=root:cognic policies ./policies
COPY --chown=root:cognic alembic.ini ./
RUN chmod -R a+rX /app/policies /app/alembic.ini /app/src

USER cognic

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
url='http://127.0.0.1:'+os.environ.get('COGNIC_PORT','8000')+os.environ.get('COGNIC_API_PREFIX','/api/v1')+'/healthz'; \
sys.exit(0 if urllib.request.urlopen(url, timeout=3).status==200 else 1)"

# Shell-form CMD so $COGNIC_HOST / $COGNIC_PORT are interpolated at container
# start. `exec` makes uvicorn PID 1 so SIGTERM/SIGKILL flow correctly.
# Kernel image: create_app (NO adapter probing — adapter Python packages
# are not installed here; using create_prod_app would AdapterNotInstalled).
CMD ["sh", "-c", "exec uvicorn cognic_agentos.portal.api.app:create_app --factory --host \"$COGNIC_HOST\" --port \"$COGNIC_PORT\""]

# ---------- default-adapters builder ---------------------------------
# Same uv-driven dep resolution as the kernel builder, but adds
# `--extra adapters` so the [project.optional-dependencies] adapters
# group (sqlalchemy/asyncpg/qdrant-client/hvac/langfuse + their
# transitives) lands in /opt/venv.
FROM python:${PYTHON_VERSION}-alpine AS default-adapters-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build
# ca-certificates + curl: uv installer prerequisites.
# gcc + musl-dev + linux-headers: oracledb (Sprint 1D) does NOT ship a
# musllinux wheel as of v3.4.2, so uv builds from source. Without these
# the build fails with `error: command 'gcc' failed: No such file or
# directory`. Build tools live in this builder stage only — the runtime
# `default-adapters` image copies /opt/venv and never sees gcc.
# binutils: provides `strip`. Source-built .so files retain debug
# symbols by default; stripping oracledb's four compiled extensions
# alone reclaims ~22 MiB and is what brings the image under the
# 220 MiB ceiling.
RUN apk add --no-cache ca-certificates curl gcc musl-dev linux-headers binutils
ADD https://astral.sh/uv/0.5.29/install.sh /uv-install.sh
RUN sh /uv-install.sh && rm /uv-install.sh
ENV PATH="/root/.local/bin:${PATH}"

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# --no-dev keeps test deps out; --extra adapters opts INTO the
# optional-deps group so asyncpg/qdrant-client/hvac/langfuse/oracledb
# etc. land in the venv. Without --extra adapters the default-adapters
# image would be byte-identical to the kernel image and break the
# runtime contract for default drivers.
RUN uv sync --frozen --no-dev --no-editable --extra adapters \
 && find /opt/venv -depth \( \
        -type d -name __pycache__ \
     -o -type d -name tests \
     -o -type d -name test \
     -o -type d -name examples \
     -o -type d -name docs \
   \) -exec rm -rf {} + \
 && find /opt/venv -name "*.dist-info" -exec sh -c 'rm -rf "$1"/RECORD "$1"/WHEEL "$1"/METADATA.bak' _ {} \; \
 && find /opt/venv -name "*.pyc" -delete \
 && find /opt/venv -name "*.pyi" -delete \
 && find /opt/venv -name "*.so" -exec strip --strip-unneeded {} + 2>/dev/null || true

# Sprint 4 T13: cosign + OPA Go binaries for the trust gate + policy
# engine. Both are statically-linked Go binaries (musl-compatible);
# fetched in the BUILDER stage with SHA-256 verification, COPY'd into
# the runtime stage below. Kernel image deliberately does NOT carry
# these — the trust gate (T6) and policy engine (T2) only run in the
# default-adapters runtime profile.
#
# Pinning policy: ARG-driven so CI can override for security-driven
# point-bumps without a Dockerfile edit, but the defaults below ARE
# the verified-good values — `docker build` with no overrides MUST
# produce the same bytes as CI. SHA-256 mismatch fails the build.
ARG COSIGN_VERSION=3.0.6
ARG COSIGN_SHA256=c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74
ARG OPA_VERSION=1.16.1
ARG OPA_SHA256=dc00b1c32c52f1557f7f127940bc3f1de6c507fdfbe0446f19d3b19ca5786494

# Note on stripping: neither cosign v3.0.6 nor OPA v1.16.1 can be stripped
# in this build path. Both ship as Go binaries whose ELF layout (PIE +
# Go-specific sections) alpine's binutils does not recognise; `strip
# --strip-unneeded` fails with "Unable to recognise the format of the
# input file" on each. Reaching for sstrip / llvm-strip / UPX to force
# stripping would add a build-time toolchain dependency for a marginal
# win and risk supply-chain weirdness on the verifier binaries. Both
# binaries therefore land in the runtime image at upstream-shipped size,
# and the default-adapters image budget (in .github/workflows/python.yml)
# absorbs the cost. Kernel image budget unaffected.
RUN curl -sSL --fail --retry 5 --retry-delay 3 --retry-all-errors \
      -o /tmp/cosign \
      "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
 && echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c - \
 && install -m 0755 /tmp/cosign /usr/local/bin/cosign \
 && rm /tmp/cosign \
 && /usr/local/bin/cosign version >/dev/null

RUN curl -sSL --fail --retry 5 --retry-delay 3 --retry-all-errors \
      -o /tmp/opa \
      "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" \
 && echo "${OPA_SHA256}  /tmp/opa" | sha256sum -c - \
 && install -m 0755 /tmp/opa /usr/local/bin/opa \
 && rm /tmp/opa \
 && /usr/local/bin/opa version >/dev/null

# ---------- default-adapters runtime ---------------------------------
FROM python:${PYTHON_VERSION}-alpine AS default-adapters

ARG BUILD_SHA=dev
ARG BUILD_TIME=unknown
ARG PACKAGE_VERSION=0.0.1

LABEL org.opencontainers.image.title="cognic-agentos-default-adapters" \
      org.opencontainers.image.description="Cognic AgentOS kernel + bundled default adapters (Postgres/Qdrant/Vault/Ollama/Langfuse-OTel + Oracle/Dynatrace/OpenAI-compat-embedding)" \
      org.opencontainers.image.vendor="Cognic" \
      org.opencontainers.image.source="https://github.com/bmzee/cognic-agentos" \
      org.opencontainers.image.version="${PACKAGE_VERSION}" \
      org.opencontainers.image.revision="${BUILD_SHA}" \
      org.opencontainers.image.created="${BUILD_TIME}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    COGNIC_HOST=0.0.0.0 \
    COGNIC_PORT=8000 \
    COGNIC_API_PREFIX=/api/v1 \
    COGNIC_RUNTIME_PROFILE=prod \
    COGNIC_BUILD_SHA="${BUILD_SHA}" \
    COGNIC_BUILD_TIME="${BUILD_TIME}"

RUN addgroup -S -g 10001 cognic \
 && adduser -S -u 10001 -G cognic -h /home/cognic -s /sbin/nologin cognic

COPY --from=default-adapters-builder /opt/venv /opt/venv

# Sprint 4 T13: cosign + OPA binaries fetched + sha256-verified in the
# builder stage. Trust gate (T6) calls cosign via subprocess; policy
# engine (T2) calls opa via subprocess. Both pinned via builder-stage
# ARGs (see COSIGN_VERSION / OPA_VERSION there for the in-tree pins).
COPY --from=default-adapters-builder /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=default-adapters-builder /usr/local/bin/opa /usr/local/bin/opa

WORKDIR /app
COPY --chown=root:cognic src ./src
COPY --chown=root:cognic pyproject.toml README.md ./

# ADR-024: ship the OPA policy bundles (build_runtime's OPAEngine reads
# /app/policies/_default/*.rego) + alembic.ini (the migration script_location config) in-image.
# chmod -R a+rX guarantees the non-root cognic user reads /app/policies, /app/alembic.ini AND
# /app/src regardless of the build-context umask (a+rX = read for all + traverse for dirs; never
# adds execute to a plain file). /app/src is included because `alembic upgrade head` reads the
# migrations from src/cognic_agentos/db/migrations (alembic script_location) as the non-root user
# — a 600 migration file from a restrictive build-context umask would otherwise be unreadable and
# the migration Job fails with PermissionError (Proof 1b-2 attempt-3 finding).
COPY --chown=root:cognic policies ./policies
COPY --chown=root:cognic alembic.ini ./
RUN chmod -R a+rX /app/policies /app/alembic.ini /app/src

USER cognic
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
url='http://127.0.0.1:'+os.environ.get('COGNIC_PORT','8000')+os.environ.get('COGNIC_API_PREFIX','/api/v1')+'/healthz'; \
sys.exit(0 if urllib.request.urlopen(url, timeout=3).status==200 else 1)"

# default-adapters image: create_prod_app wires bundled_registry so the
# lifespan probes the bundled adapters — Sprint 1C: Postgres / Qdrant /
# Vault / Ollama / Langfuse-OTel; Sprint 1D: + Oracle / Dynatrace /
# OpenAI-compat embedding (vLLM/SGLang/OpenAI/Azure-via-shim).
CMD ["sh", "-c", "exec uvicorn cognic_agentos.portal.api.app:create_prod_app --factory --host \"$COGNIC_HOST\" --port \"$COGNIC_PORT\""]
