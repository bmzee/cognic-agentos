# syntax=docker/dockerfile:1.7
# Cognic AgentOS — canonical sandbox egress-proxy image (T30, ADR-004).
#
# This image is the SINGLE egress enforcement point for a sandbox session: the
# runtime container has NO external network route and reaches the outside world
# ONLY through this proxy sidecar. The isolation is realised per backend:
#   * Docker — the runtime container is attached solely to a sandbox-internal
#     bridge (`HostConfig.NetworkMode = <internal net>`, docker_sibling.py:638);
#     that bridge has no external route, and the runtime reaches the proxy via
#     the `egress-proxy:3128` Docker-DNS alias on it. (NOT `--network none`,
#     which would preclude a same-bridge sidecar.)
#   * Kubernetes — the runtime + proxy share a Pod netns (workload points at
#     `http://localhost:3128`) behind a deny-all egress NetworkPolicy.
# In both cases the proxy sidecar is the sole egress path. tinyproxy enforces a
# per-session destination allow-list (`FilterDefaultDeny Yes` + an anchored-regex
# Filter); the Python PID1 entrypoint renders that config from the session's
# `ALLOW_LIST`, tails tinyproxy's native log, and writes the `ProxyAccessRecord`
# audit JSONL the AgentOS backend reads.
#
# Two pieces of IMAGE CONTENT (stdlib-only Python; NOT the cognic_agentos
# package — it is not present here):
#   * entrypoint.py            — PID1 orchestrator (launch + tail + audit + signals)
#   * cognic_egress_shim.py    — pure render/parse helpers (entrypoint imports it)
#
# Immutability: tinyproxy is version-PINNED because the entrypoint's log-string
# mapping is wording-coupled to tinyproxy 1.11.1 (T1 spike, residual risk #2).
# Nothing is installed at container-create time — banks reject runtime-install
# patterns at security audit ([[feedback_immutable_runtime_images_no_dynamic_install]]).
#
# This Dockerfile produces the DEV build (tag `:dev`). The CANONICAL signed +
# SBOM'd + scanned artifact (`cognic/sandbox-egress-proxy:v1@sha256:<real>`) is
# produced by the T9 build/sign/push runbook from these same bytes.

# Base pinned to the multi-arch index digest of debian:bookworm-slim (captured
# 2026-05-29). A deliberate base bump updates this line AND the pin asserted by
# tests/unit/sandbox/egress_proxy/test_dockerfile.py in the same edit.
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

LABEL org.opencontainers.image.title="cognic-sandbox-egress-proxy" \
      org.opencontainers.image.description="Cognic AgentOS canonical sandbox egress proxy — tinyproxy allow-list enforcement + audit shim (PID1)" \
      org.opencontainers.image.vendor="Cognic" \
      org.opencontainers.image.source="https://github.com/bmzee/cognic-agentos"

# Single pinned package step (the only build-time network fetch). tinyproxy is
# version-pinned (security/version-coupling); python3 is intentionally NOT
# hard-pinned — its bookworm version carries an arch-specific binNMU suffix
# (`+b1`) that would break the cross-arch canonical amd64 build, and the
# stdlib-only shim is interpreter-version-tolerant. The digest-pinned base + the
# T9 SBOM capture the resolved python3 version for the canonical artifact.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tinyproxy=1.11.1-2.1+deb12u1 \
        python3 \
 && rm -rf /var/lib/apt/lists/*

# Dedicated non-root account (fixed numeric uid/gid; distinct from the 10001
# used by the agentos kernel image). The proxy runs as this user; tinyproxy
# binds 3128 (unprivileged) and writes its log under the chowned dir below.
RUN groupadd -g 10002 cognicproxy \
 && useradd -u 10002 -g 10002 -M -d /nonexistent -s /usr/sbin/nologin cognicproxy

# Pre-create + chown the runtime dirs the entrypoint writes (it cannot mkdir
# under /etc or /var/log as a non-root user). This MUST precede the VOLUME
# instruction below — Docker discards filesystem changes made to a VOLUME path
# AFTER the VOLUME directive, which would silently revert /var/log/cognic-proxy
# to root-owned and break access.jsonl creation at runtime.
RUN mkdir -p /etc/cognic-proxy /var/log/cognic-proxy \
 && chown -R 10002:10002 /etc/cognic-proxy /var/log/cognic-proxy

# Image-content modules → /opt/cognic. The entrypoint does a same-dir
# `from cognic_egress_shim import ...`, so both files MUST live together here
# (Python puts the script's own dir on sys.path[0]).
COPY cognic_egress_shim.py /opt/cognic/cognic_egress_shim.py
COPY entrypoint.py /opt/cognic/entrypoint.py

# Explicit PATH so the entrypoint's bare `tinyproxy` argv resolves to /usr/bin;
# unbuffered + no-bytecode so logs flush promptly and no __pycache__ write is
# attempted under a read-only/non-writable /opt.
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Declared AFTER the chown above so the volume baseline carries 10002 ownership.
VOLUME ["/var/log/cognic-proxy"]

EXPOSE 3128

# Liveness: a stdlib-only TCP connect to the proxy port (no curl/nc installed —
# minimal surface). Complements the entrypoint's own child-death exit
# propagation (T6) so orchestration can detect a wedged-but-alive proxy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('127.0.0.1',3128))==0 else 1)"

USER 10002:10002

# Exec-form (JSON array) is REQUIRED: it makes the Python entrypoint PID1 so its
# SIGTERM/SIGINT handlers (T6) actually receive container-stop signals. Shell-
# form would interpose /bin/sh as PID1 and swallow them.
ENTRYPOINT ["python3", "/opt/cognic/entrypoint.py"]
