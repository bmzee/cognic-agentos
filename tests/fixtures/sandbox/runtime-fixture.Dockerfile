# TEST FIXTURE — not a canonical/production sandbox image.
# See docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md
#
# Minimal sandbox runtime fixture (#477 §4.1): bash + GNU coreutils +
# GNU tar (all in the debian-slim base — busybox tar has symlink/xattr
# edge cases that would muddy the AC4 symlink + exec-bit proof).
#
# /workspace writability under read-only rootfs: DockerSibling sets
# HostConfig.ReadonlyRootfs from policy.read_only_root (default True,
# policy.py:169) and mounts NOTHING writable at /workspace
# (docker_sibling.py HostConfig has no Tmpfs/Binds/Mounts for it). The
# VOLUME declaration is what keeps /workspace writable — Docker
# auto-creates a fresh anonymous volume there at container start, and
# a volume mount is writable even under ReadonlyRootfs=True. chmod
# 0777 (world-writable) is acceptable for a throwaway test fixture and
# sidesteps UID-matching across Docker's non-root user
# (65534:65534 per docker_sibling.py:147) and OpenShift
# restricted-v2 arbitrary UIDs. The image still declares USER
# 65534:65534 so Kubernetes runAsNonRoot can prove the image default
# is non-root before the container starts; OpenShift restricted-v2 may
# still assign a namespace-range UID at admission. Under K8s the
# backend's own emptyDir mount at /workspace supersedes the VOLUME —
# harmless.
FROM debian:bookworm-slim
RUN mkdir -p /workspace && chmod 0777 /workspace
VOLUME ["/workspace"]
WORKDIR /workspace
USER 65534:65534
CMD ["sleep", "infinity"]
