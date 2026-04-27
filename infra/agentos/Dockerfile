# syntax=docker/dockerfile:1.7
# Cognic AgentOS — production runtime image.
#
# Stages:
#   1. builder — installs uv, resolves the locked dep set into /opt/venv
#   2. runtime — slim image, non-root user, HEALTHCHECK on /healthz
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

# Alpine ships musl; uv installer needs ca-certs + curl. Build tools only
# in case a future dep lacks a musllinux wheel — Sprint 1A deps all do.
RUN apk add --no-cache ca-certificates curl

# Pinned uv version; the SHA is verified by upstream's installer.
ADD https://astral.sh/uv/0.5.29/install.sh /uv-install.sh
RUN sh /uv-install.sh && rm /uv-install.sh
ENV PATH="/root/.local/bin:${PATH}"

# Copy lockfile + project metadata first so dep changes alone bust the cache.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable \
 && find /opt/venv -depth \( -type d -name __pycache__ -o -type d -name tests -o -type d -name test \) -exec rm -rf {} + \
 && find /opt/venv -name "*.dist-info" -exec sh -c 'rm -rf "$1"/RECORD "$1"/WHEEL "$1"/METADATA.bak' _ {} \;

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

USER cognic

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
url='http://127.0.0.1:'+os.environ.get('COGNIC_PORT','8000')+os.environ.get('COGNIC_API_PREFIX','/api/v1')+'/healthz'; \
sys.exit(0 if urllib.request.urlopen(url, timeout=3).status==200 else 1)"

CMD ["uvicorn", "cognic_agentos.portal.api.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
