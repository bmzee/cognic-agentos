"""Sprint 10.6 T20 Phase 2 — K8s projection executor (pure helpers)
per ADR-004 §25 + Sprint 10.6 spec §5.4 K8s executor section +
§5.5 + §5.7 + plan §932 (patched 2026-05-27).

The K8s-backend half of the credential-projection per-backend split.
Mirrors T19's ``_docker_executor.py`` doctrinal shape:

  * A new per-concern module (NOT inlined into ``kubernetes_pod.py``).
  * Pure-functional helpers: opaque Secret-name derivation, V1Secret
    body builder, volume + volumeMount pair builder, audit-metadata
    result dataclass.
  * NO K8s API calls. NO ``create_namespaced_secret`` /
    ``delete_namespaced_secret``. The T21 lifecycle integration
    (``kubernetes_pod.create()`` mint-then-project loop +
    ``kubernetes_pod.destroy()`` LIFO Secret cleanup) wires the K8s
    API calls around these pure helpers.

T20 scope (user-locked at session start):
  1. ``derive_secret_opaque()`` — 16-hex random body
  2. ``compute_k8s_secret_name(secret_opaque)`` — DNS-1123 prefix
  3. ``compute_k8s_secret_spec(...)`` — V1Secret body dict
  4. ``compute_k8s_credential_volume_and_mount(...)`` — (volume, mount) pair
  5. ``CredentialSecretMount`` — pair-carrier for the T20 pod-spec
     extension on ``kubernetes_pod._build_pod_spec``
  6. ``K8sExecutorResult`` — spec §5.7 audit-metadata projection

Out-of-scope (T21):
  - Async ``create_namespaced_secret`` call site + retry policy
  - Async ``delete_namespaced_secret`` LIFO cleanup
  - kubernetes_pod.create() mint-then-project loop integration

User-locked K8s object-shape decisions (correcting the T20-entry-review
draft):
  * Volume name is the OPAQUE Secret name (DNS-1123 safe), NOT raw
    ``logical_name``. A logical_name like ``db_main`` has ``_`` which
    violates DNS-1123 label rules; the SEMANTIC logical_name appears
    ONLY in the mount path ``/run/credentials/<logical_name>``
    (no-slash canonical form, matches T19 Docker).
  * ``owner_references`` is OPTIONAL + defaults to empty — Pod UID
    does not exist at Secret-creation time (Secrets must exist BEFORE
    Pod create so the kubelet can project them). T21 can patch the
    reference post-Pod-create as defense-in-depth; AgentOS-driven
    ``delete_namespaced_secret`` remains authoritative for cleanup.
  * ``cognic/logical-name`` as a LABEL is fine — the T14 credentials
    validator caps logical_name at 32 chars (cli/validators/credentials.py:95),
    under the K8s 63-char label-value cap.

Critical-controls from birth — owns the wire-public K8s Secret shape +
the opaque Secret-name + label/annotation split + DNS-1123 volume-name
contract; promotes to the durable per-file CC coverage gate at Z1c
alongside ``_preflight.py`` + ``_docker_executor.py``.
"""

from __future__ import annotations

import base64
import dataclasses
import re
import secrets
from collections.abc import Sequence
from typing import Any

from cognic_agentos.sandbox.projection import ProjectionPlan

# ---------------------------------------------------------------------------
# Boundary-input grammar guards (Sprint 10.6 T20 round-4 reviewer P1)
# ---------------------------------------------------------------------------

#: 16-hex grammar for the body after ``cognic-cred-``. Mirrors the
#: T19 Docker ``_OPAQUE_TOKEN_PATTERN``. A direct call to
#: ``compute_k8s_secret_name(secret_opaque="db_main")`` pre-fix
#: returned ``"cognic-cred-db_main"`` which both leaked the
#: logical_name AND violated DNS-1123 (underscore). Reviewer-locked
#: round-4 P1 fix: validate at the callable boundary.
_OPAQUE_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{16}$")

#: Canonical full-Secret-name shape: ``cognic-cred-`` prefix + 16-hex.
#: Used at ``compute_k8s_secret_spec`` + ``compute_k8s_credential_volume_and_mount``
#: where callers can pass ``secret_name`` directly (bypassing
#: ``compute_k8s_secret_name``). Defence-in-depth — the secret_opaque
#: regex above closes one path; this one closes the other.
_SECRET_NAME_PATTERN: re.Pattern[str] = re.compile(r"^cognic-cred-[0-9a-f]{16}$")

#: Single-segment safe ``logical_name`` grammar. Mirrors the T14
#: manifest validator's ``credentials.<logical_name>`` block-key
#: pattern at ``cli/validators/credentials.py``. Even though a
#: well-formed T18 ``ProjectionPlan`` carries a manifest-validated
#: ``logical_name``, the executor is a callable boundary so we guard
#: at this seam too (parallel to T19's relative_path defence-in-depth).
_LOGICAL_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

#: Single-segment safe field-name grammar (the ``relative_path`` on
#: each ``ProjectionPlanEntry``; becomes a key in the K8s Secret
#: ``data`` map). Identical shape to the logical_name pattern + the
#: T14 ``credentials.*.fields[].name`` pattern + T19 Docker's
#: ``_FIELD_NAME_PATTERN``. Declared as its own alias so the semantic
#: difference (logical_name = block key; field_name = entry within
#: the credential) is explicit at the call sites that consume it.
#: Round-6 reviewer P1 boundary guard.
_FIELD_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


# ---------------------------------------------------------------------------
# Opaque Secret-name derivation
# ---------------------------------------------------------------------------


def derive_secret_opaque() -> str:
    """Return a fresh 16-hex random token (the body after
    ``cognic-cred-``).

    Per spec §5.4 K8s row: ``cognic-cred-<16-hex>``. Mirrors T19's
    Docker session/credential opaque derivation; same crypto-random
    source (``secrets.token_hex(8)``) so a collision is practically
    impossible.
    """
    return secrets.token_hex(8)


def compute_k8s_secret_name(*, secret_opaque: str) -> str:
    """Return the K8s Secret name ``cognic-cred-<secret_opaque>``.

    Pure-functional formatter; the opaque-name drift detector
    (test-only) pins that the name NEVER carries semantic
    identifiers (logical_name / vault_path / lease_id / tenant_id).

    Defence-in-depth boundary guard (T20 round-4 P1): ``secret_opaque``
    MUST match ``^[0-9a-f]{16}$``. A direct call with
    ``secret_opaque="db_main"`` would otherwise produce
    ``"cognic-cred-db_main"`` — leaking the logical_name AND
    violating DNS-1123 (underscore). Reaching this boundary with
    a non-conforming opaque is a programmer-error contract
    violation, NOT a wire-public credential refusal; raises
    ``ValueError`` per the T19 pattern.
    """
    if not _OPAQUE_TOKEN_PATTERN.fullmatch(secret_opaque):
        raise ValueError(
            f"secret_opaque must match {_OPAQUE_TOKEN_PATTERN.pattern!r} "
            f"(16-hex lowercase); got {secret_opaque!r}"
        )
    return f"cognic-cred-{secret_opaque}"


# ---------------------------------------------------------------------------
# V1Secret body builder
# ---------------------------------------------------------------------------


def compute_k8s_secret_spec(
    *,
    plan: ProjectionPlan,
    secret_name: str,
    session_id: str,
    owner_references: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Return the V1Secret body dict per spec §5.4 K8s executor.

    Wire-public V1Secret body shape:

      - ``apiVersion: v1`` + ``kind: Secret`` + ``type: Opaque``
      - ``data`` field (base64-encoded bytes) — NEVER ``stringData``
        (byte-exact preservation of binary credential values; the T18
        planner produces ``content_bytes`` so the data MUST round-trip
        unchanged through base64).
      - 3 required labels (visible via ``kubectl get secrets -l``):
        ``cognic/component=credential-projection`` /
        ``cognic/session-id=<session_id>`` /
        ``cognic/logical-name=<plan.logical_name>``. The
        logical-name label is consciously kept despite list-leak
        tradeoff for cleanup label-selector queries (spec §5.4).
      - 2 annotations (less visible than labels):
        ``cognic/lease-id=<plan.lease_id>`` (Vault lease IDs contain
        ``/`` chars; label-hostile) +
        ``cognic/tenant-id=<plan.tenant_id>`` (moved out of labels
        per spec §5.4 to reduce list-leak surface).
      - ``ownerReferences`` defaults to ``[]`` — Pod UID does not
        exist at Secret-creation time. T21 can patch post-Pod-create.

    Pure-functional — no I/O. The T21 lifecycle integration will pass
    this dict to ``client.CoreV1Api(...).create_namespaced_secret(...)``.

    Defence-in-depth boundary guards (T20 rounds 4 + 6 P1):
      * ``secret_name`` MUST match ``^cognic-cred-[0-9a-f]{16}$``.
        A direct call bypassing ``compute_k8s_secret_name`` could
        otherwise smuggle a non-opaque or DNS-1123-invalid name
        through to the K8s API (which would silently reject OR
        leak the logical_name via metadata.name).
      * ``plan.logical_name`` MUST match the T14 manifest grammar
        ``^[a-z][a-z0-9_]{0,31}$``. The logical_name flows into the
        wire-public ``metadata.labels["cognic/logical-name"]`` field;
        a hand-rolled ``ProjectionPlan(logical_name="../db")`` would
        otherwise leak through to the K8s API + label-listing
        surface (T20 round-6 reviewer P1).
      * Each ``entry.relative_path`` MUST match the T14 field-name
        grammar ``^[a-z][a-z0-9_]{0,31}$``. Relative paths become
        keys in the wire-public ``data`` map; a hand-rolled
        ``ProjectionPlanEntry(relative_path="../token")`` would
        otherwise produce a Secret with ``data["../token"] = ...``
        (T20 round-6 reviewer P1, mirrors T19 Docker's
        ``relative_path`` guard).
    Raises ``ValueError`` on any grammar violation. Programmer-error
    contract violations, NOT wire-public credential refusals.
    """
    if not _SECRET_NAME_PATTERN.fullmatch(secret_name):
        raise ValueError(
            f"secret_name must match {_SECRET_NAME_PATTERN.pattern!r} "
            f"(cognic-cred- prefix + 16-hex); got {secret_name!r}"
        )
    if not _LOGICAL_NAME_PATTERN.fullmatch(plan.logical_name):
        raise ValueError(
            f"plan.logical_name must match {_LOGICAL_NAME_PATTERN.pattern!r} "
            f"(T14 manifest grammar); got {plan.logical_name!r}"
        )
    for entry in plan.entries:
        if not _FIELD_NAME_PATTERN.fullmatch(entry.relative_path):
            raise ValueError(
                f"entry.relative_path must match {_FIELD_NAME_PATTERN.pattern!r} "
                f"(T14 field-name grammar); got {entry.relative_path!r}"
            )
    data: dict[str, str] = {}
    for entry in plan.entries:
        # Base64 round-trip is byte-exact per RFC 4648. The encoded
        # form is ASCII-safe so JSON serialization of the Secret body
        # has no UTF-8 considerations.
        data[entry.relative_path] = base64.b64encode(entry.content_bytes).decode("ascii")

    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": secret_name,
            "labels": {
                "cognic/component": "credential-projection",
                "cognic/session-id": session_id,
                "cognic/logical-name": plan.logical_name,
            },
            "annotations": {
                "cognic/lease-id": plan.lease_id,
                "cognic/tenant-id": plan.tenant_id,
            },
            "ownerReferences": list(owner_references),
        },
        "data": data,
    }


# ---------------------------------------------------------------------------
# Volume + volumeMount pair builder
# ---------------------------------------------------------------------------


def compute_k8s_credential_volume_and_mount(
    *,
    logical_name: str,
    secret_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the ``(volume, volumeMount)`` pair the pod-spec extension
    merges into the Pod body.

    User-locked DNS-1123 contract:
      * ``volume.name = secret_name`` (the opaque ``cognic-cred-<16-hex>``;
        DNS-1123 safe by construction). NEVER raw ``logical_name`` —
        a logical_name with ``_`` violates DNS-1123 label rules.
      * ``volume.secret.secretName = secret_name``
      * ``volume.secret.defaultMode = 0o440`` (kubelet sets file mode
        at projection time; no chmod required from AgentOS).
      * ``volumeMount.mountPath = /run/credentials/<logical_name>``
        (semantic identifier visible ONLY in the workload-facing
        path; file paths have no DNS-label constraint).
      * ``volumeMount.readOnly = True`` (workload reads but cannot
        modify — bind-mount equivalent).
      * ``volumeMount.name = secret_name`` (K8s requires the mount
        name to match a volume name).

    Defence-in-depth boundary guards (T20 round-4 P1):
      * ``secret_name`` MUST match ``^cognic-cred-[0-9a-f]{16}$``.
        Smuggling a non-opaque secret_name through this helper
        would otherwise produce a DNS-1123-invalid volume name
        and leak the logical_name via the volume entry.
      * ``logical_name`` MUST match the T14 manifest grammar
        ``^[a-z][a-z0-9_]{0,31}$``. The logical_name flows into
        the mount path ``/run/credentials/<logical_name>``; a
        ``../escaped`` value would otherwise produce a
        path-injection mount target inside the workload container.
        Parallel to T19's relative_path defence-in-depth guard.
    """
    if not _SECRET_NAME_PATTERN.fullmatch(secret_name):
        raise ValueError(
            f"secret_name must match {_SECRET_NAME_PATTERN.pattern!r} "
            f"(cognic-cred- prefix + 16-hex); got {secret_name!r}"
        )
    if not _LOGICAL_NAME_PATTERN.fullmatch(logical_name):
        raise ValueError(
            f"logical_name must match {_LOGICAL_NAME_PATTERN.pattern!r} "
            f"(T14 manifest grammar); got {logical_name!r}"
        )
    volume = {
        "name": secret_name,
        "secret": {
            "secretName": secret_name,
            "defaultMode": 0o440,
        },
    }
    mount = {
        "name": secret_name,
        "mountPath": f"/run/credentials/{logical_name}",
        "readOnly": True,
    }
    return volume, mount


# ---------------------------------------------------------------------------
# Pair-carrier — passed through ``kubernetes_pod._build_pod_spec``
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class CredentialSecretMount:
    """The ``(logical_name, secret_name)`` pair-carrier T21 threads
    through ``kubernetes_pod._build_pod_spec`` to emit credential
    volumes + mounts.

    Frozen + slots — same idiom as T18's ``ProjectionPlanEntry``.
    The pod-spec extension iterates ``Sequence[CredentialSecretMount]``
    and calls ``compute_k8s_credential_volume_and_mount`` per entry.
    """

    logical_name: str
    secret_name: str


# ---------------------------------------------------------------------------
# Audit-metadata result — parallel to T19's ProjectionExecutorResult
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class K8sExecutorResult:
    """K8s-side audit-metadata projection per spec §5.7
    ``credentials_projected`` payload (K8s row).

    Parallel to T19's ``ProjectionExecutorResult`` but with K8s-specific
    backend resource name (Secret name) instead of ``host_staging_dir``.
    T21 will populate this from the post-create response (or from the
    inputs at create time for fields the API doesn't echo back) and
    emit the ``sandbox.lifecycle.credentials_projected`` chain row.

    Spec §5.7 K8s row fields (all wire-public):
      * ``logical_name`` — semantic credential identifier
      * ``vault_path`` — Vault secret-engine path
      * ``tenant_id`` — owning tenant
      * ``lease_id`` — Vault lease ID
      * ``projected_field_count`` — count of fields written
      * ``purpose_category`` — closed-enum Wave-1 category
      * ``purpose_description`` — free-text purpose declaration
      * ``secret_name`` — backend resource name (K8s row)
      * ``container_mount_target`` — semantic workload-facing path
      * ``session_id`` — sandbox session correlator
    """

    logical_name: str
    vault_path: str
    tenant_id: str
    lease_id: str
    projected_field_count: int
    purpose_category: str
    purpose_description: str
    secret_name: str
    container_mount_target: str
    session_id: str


__all__ = [
    "CredentialSecretMount",
    "K8sExecutorResult",
    "compute_k8s_credential_volume_and_mount",
    "compute_k8s_secret_name",
    "compute_k8s_secret_spec",
    "derive_secret_opaque",
]
