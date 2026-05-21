# TEST FIXTURE — not a canonical/production sandbox image.
# See docs/superpowers/specs/2026-05-20-477-fixture-live-proof-design.md
#
# Minimal egress-proxy fixture (#477 §4.2). It does NOT filter or
# forward traffic. It only: (a) creates a present + readable
# /var/log/cognic-proxy/access.jsonl, and (b) stays alive for the
# sidecar's lifetime so the backend's proxy-log read succeeds (a dead
# sidecar / absent file is the egress_audit_unreadable failure mode).
# An EMPTY access.jsonl is valid — the backend parser
# _parse_proxy_log_jsonl returns () on empty input.
#
# access.jsonl MUST be created at RUNTIME, not build time: both
# DockerSibling (the VOLUME anonymous volume) and KubernetesPod (its
# emptyDir mount) mount a fresh empty dir over /var/log/cognic-proxy,
# which HIDES any file baked into the image layer — a build-time
# `touch` would be shadowed and the sidecar would present an absent
# log -> egress_audit_unreadable. So the CMD touches the file after
# the mount is in place, then stays alive. chmod 0777 + VOLUME keeps
# the dir writable under ReadonlyRootfs=True for the Docker leg;
# under K8s the backend's emptyDir mount supersedes the VOLUME.
FROM debian:bookworm-slim
RUN mkdir -p /var/log/cognic-proxy && chmod 0777 /var/log/cognic-proxy
VOLUME ["/var/log/cognic-proxy"]
CMD ["sh", "-c", "touch /var/log/cognic-proxy/access.jsonl && exec sleep infinity"]
