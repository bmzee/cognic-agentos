# syntax=docker/dockerfile:1.7
# Cognic AgentOS — canonical sandbox runtime-python image (T30, ADR-004).
#
# This is the WORKLOAD container the sandbox launches per session. The backend
# does NOT override the container command (no `Cmd` in the runtime HostConfig at
# docker_sibling.py), so the image's keep-alive CMD holds the container open and
# AgentOS drives the workload via `session.exec([...])`. Production sandboxes use
# this immutable, digest-pinned, signed image — no dynamic install at create
# time ([[feedback_immutable_runtime_images_no_dynamic_install]]).
#
# Two load-bearing contracts this image satisfies (proven by the
# tests/fixtures/sandbox/runtime-fixture.Dockerfile approach this mirrors):
#
#   1. /workspace writable under a read-only rootfs. The Docker backend sets
#      HostConfig.ReadonlyRootfs from policy.read_only_root (default True) and
#      mounts nothing writable at /workspace. The VOLUME declaration is the
#      mechanism: Docker auto-creates a fresh anonymous volume at /workspace at
#      container start, and a volume mount is writable even under
#      ReadonlyRootfs=True. (Under K8s the backend's emptyDir at /workspace
#      supersedes the VOLUME — harmless.) chmod 0777 mirrors the fixture: it
#      sidesteps UID-matching across the Docker forced user (65534:65534) and
#      OpenShift restricted-v2 arbitrary UIDs, on a per-session ephemeral volume
#      that nothing else mounts.
#
#   2. The workload-GID contract. Credential projection chgrp's projected files
#      (mode 0440, group-readable) to the workload GID, which the Docker
#      preflight parses from THIS image's USER directive
#      (_inspect_image_user_directive → verify_docker_credential_projection_
#      preflight, docker_sibling.py). The backend forces the container to run as
#      _NON_ROOT_USER = 65534:65534, so the image USER GID MUST be 65534 for the
#      running workload to read its projected credentials. Pinned by the USER-GID
#      drift detector in tests/unit/sandbox/test_runtime_python_dockerfile.py.
#
# DEV build (tag `:dev`); the CANONICAL signed + SBOM'd + scanned artifact
# (`cognic/sandbox-runtime-python:v1@sha256:<real>`) is produced by the T9
# build/sign/push runbook from these same bytes.

# Same pinned debian:bookworm-slim multi-arch index digest as the egress-proxy
# image (captured 2026-05-29).
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

LABEL org.opencontainers.image.title="cognic-sandbox-runtime-python" \
      org.opencontainers.image.description="Cognic AgentOS canonical sandbox runtime — Python 3 workload base (exec-driven, non-root, read-only-root-compatible)" \
      org.opencontainers.image.vendor="Cognic" \
      org.opencontainers.image.source="https://github.com/bmzee/cognic-agentos"

# Single pinned package step (the only build-time network fetch). python3 is the
# workload interpreter; coreutils + /bin/sh ship in the base (the exec model +
# credential-read probes use cat/ls). python3 is intentionally NOT hard-pinned
# (its bookworm version carries an arch-specific binNMU suffix that would break
# the cross-arch canonical amd64 build); the digest-pinned base + the T9 SBOM
# capture the resolved version for the canonical artifact.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
 && rm -rf /var/lib/apt/lists/*

# /workspace — see contract #1 above. World-writable on the per-session
# ephemeral anonymous volume so the forced non-root user (or an OpenShift
# arbitrary UID) can write regardless of UID.
RUN mkdir -p /workspace && chmod 0777 /workspace

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Declared after the chmod above so the anonymous-volume baseline carries the
# writable mode.
VOLUME ["/workspace"]

WORKDIR /workspace

# Contract #2 above: GID 65534 MUST equal the backend-forced _NON_ROOT_USER GID.
USER 65534:65534

# Keep-alive: the sandbox is exec-driven (the backend execs workloads in); the
# image command only needs to hold the container open. `sleep infinity` (GNU
# coreutils) is the proven idiom — exec'd processes are reaped by the container
# runtime, not this PID1.
CMD ["sleep", "infinity"]
