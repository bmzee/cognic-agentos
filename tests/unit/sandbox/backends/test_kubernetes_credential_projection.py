"""Sprint 10.6 T20 Phase 2 — K8s projection executor regressions
per ADR-004 §25 + Sprint 10.6 spec §5.4 K8s executor section +
§5.5 + §5.7 + plan §932 (patched 2026-05-27).

The K8s-backend half of the credential-projection per-backend split.
Mirrors the T19 Phase 2 ``_docker_executor.py`` doctrinal shape: a
new module (``_k8s_executor.py``) carrying ONLY the pure-functional
helpers + the audit metadata projection. The substantive lifecycle
integration (``create()`` / ``destroy()`` wiring on
``kubernetes_pod.py``) is OWNED BY T21.

T20 scope (user-locked at session start):
  1. Pure-functional Secret-spec builder: ``compute_k8s_secret_spec(...)``
  2. Pure-functional volume + volumeMount pair builder
  3. Pure-functional opaque Secret-name derivation
  4. Audit-metadata result dataclass (parallel to Docker's
     ``ProjectionExecutorResult`` but with K8s resource name +
     no host_staging_dir)

Out-of-scope (T21):
  - K8s API calls (``create_namespaced_secret``, ``delete_namespaced_secret``)
  - ``kubernetes_pod.create()`` mint-then-project loop integration
  - LIFO Secret cleanup in ``kubernetes_pod.destroy()``

User-locked K8s object-shape corrections rejecting the T20-entry-review
draft:
  - Volume name is the OPAQUE Secret name (DNS-1123 safe), NEVER the
    raw ``logical_name`` (e.g., ``db_main`` has ``_`` which violates
    DNS-1123 label rules); semantic ``logical_name`` appears ONLY in
    the mount path ``/run/credentials/<logical_name>``
  - ``owner_references`` is OPTIONAL + defaults to empty — Pod UID does
    not exist at Secret-creation time (Secrets must exist BEFORE Pod
    create); T21 can post-Pod-create patch the reference as
    defense-in-depth. AgentOS-driven ``delete_namespaced_secret``
    remains authoritative.
  - Raw ``cognic/logical-name`` as a LABEL is fine — the T14 validator
    caps logical_name at 32 chars, under the K8s 63-char label-value cap.

Critical-controls from birth — owns the wire-public K8s Secret shape +
the opaque Secret-name + label/annotation split + DNS-1123 volume-name
contract; promotes to the durable per-file CC coverage gate at Z1c
alongside ``_preflight.py`` + ``_docker_executor.py``.
"""

from __future__ import annotations

import base64
import dataclasses
import re

import pytest

from cognic_agentos.sandbox.backends._k8s_executor import (
    CredentialSecretMount,
    K8sExecutorResult,
    compute_k8s_credential_volume_and_mount,
    compute_k8s_secret_name,
    compute_k8s_secret_spec,
    derive_secret_opaque,
)
from cognic_agentos.sandbox.projection import (
    ProjectionPlan,
    ProjectionPlanEntry,
)

# ---------------------------------------------------------------------------
# Test helpers — pure construction of fixtures (no I/O).
# ---------------------------------------------------------------------------


def _make_plan(
    *,
    logical_name: str = "db_main",
    vault_path: str = "database/creds/db-main",
    lease_id: str | None = None,
    fields: dict[str, bytes] | None = None,
    tenant_id: str = "tenant-k8s-test",
    purpose_category: str = "application_database_read",
    purpose_description: str = "Read-only application database access.",
) -> ProjectionPlan:
    if fields is None:
        fields = {"username": b"v-tok-uname", "password": b"p@ss"}
    if lease_id is None:
        lease_id = f"{vault_path}/lease-test-abc123"
    entries = tuple(
        ProjectionPlanEntry(relative_path=name, content_bytes=content, mode=0o440)
        for name, content in fields.items()
    )
    return ProjectionPlan(
        entries=entries,
        logical_name=logical_name,
        lease_id=lease_id,
        projected_field_count=len(entries),
        vault_path=vault_path,
        purpose_category=purpose_category,
        purpose_description=purpose_description,
        tenant_id=tenant_id,
    )


# ---------------------------------------------------------------------------
# Opaque Secret-name derivation
# ---------------------------------------------------------------------------


class TestDeriveSecretOpaque:
    """The body after ``cognic-cred-`` MUST be 16-hex random per spec
    §5.4 K8s row + the parallel doctrine to T19 Docker's session/
    credential opaques. ``secrets.token_hex(8)`` source.
    """

    def test_returns_16_hex_string(self) -> None:
        token = derive_secret_opaque()
        assert len(token) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", token), f"non-hex: {token!r}"

    def test_two_calls_return_different_values(self) -> None:
        assert derive_secret_opaque() != derive_secret_opaque()


class TestComputeK8sSecretName:
    """Per spec §5.4 K8s: ``cognic-cred-<16-hex>``. Pure-functional
    formatter + opaque-name drift detector lives here.
    """

    def test_returns_cognic_cred_prefix_plus_token(self) -> None:
        assert (
            compute_k8s_secret_name(secret_opaque="0123456789abcdef")
            == "cognic-cred-0123456789abcdef"
        )

    def test_name_is_dns_1123_label_safe(self) -> None:
        # K8s DNS-1123 label rules (also the constraint on Secret
        # names + volume names): lowercase alphanumeric + hyphen;
        # MUST start with alphanumeric; MUST end with alphanumeric;
        # max 63 chars.
        name = compute_k8s_secret_name(secret_opaque="0123456789abcdef")
        assert re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", name), (
            f"Secret name {name!r} violates DNS-1123 label rules"
        )
        assert len(name) <= 63
        assert "_" not in name  # underscore is NOT DNS-1123 safe


class TestOpaqueSecretNameDriftDetector:
    """Wire-public-artifact contract: the K8s Secret name MUST NEVER
    leak semantic identifiers via ``kubectl get secrets``. Parallel
    to T19 Docker's opaque-path drift detector at the Secret-name
    boundary.
    """

    def test_secret_name_never_contains_logical_name(self) -> None:
        name = compute_k8s_secret_name(secret_opaque="0123456789abcdef")
        # Test with a distinctive logical_name that would be obvious
        # if it leaked through.
        distinctive = "db_main_with_distinctive_token"
        assert distinctive not in name
        # Generic semantic-leak tokens that should never appear in
        # the opaque Secret name.
        assert "logical_name" not in name
        assert "db_main" not in name

    def test_secret_name_never_contains_vault_path_components(self) -> None:
        name = compute_k8s_secret_name(secret_opaque="0123456789abcdef")
        assert "database" not in name
        assert "creds" not in name
        assert "vault" not in name

    def test_secret_name_never_contains_tenant_id_or_lease_id(self) -> None:
        name = compute_k8s_secret_name(secret_opaque="0123456789abcdef")
        assert "tenant" not in name
        assert "lease" not in name


# ---------------------------------------------------------------------------
# K8s Secret spec — wire-public V1Secret body shape
# ---------------------------------------------------------------------------


class TestComputeK8sSecretSpec:
    """Per spec §5.4 K8s + the user-locked T20 entry corrections.

    Wire-public V1Secret body constraints:
      - ``apiVersion: v1`` + ``kind: Secret`` + ``type: Opaque``
      - ``data`` field (base64-encoded bytes) — NEVER ``stringData``
      - 3 required labels: ``cognic/component=credential-projection``,
        ``cognic/session-id``, ``cognic/logical-name``
      - 2 annotations (less visible than labels): ``cognic/lease-id``,
        ``cognic/tenant-id``
      - ``owner_references`` defaults to empty (Pod UID not yet
        available at Secret-creation time)
    """

    def test_apiversion_and_kind_are_v1_secret(self) -> None:
        plan = _make_plan(fields={"username": b"u"})
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        assert spec["apiVersion"] == "v1"
        assert spec["kind"] == "Secret"

    def test_secret_type_is_opaque(self) -> None:
        plan = _make_plan(fields={"username": b"u"})
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        assert spec["type"] == "Opaque"

    def test_data_field_is_base64_not_stringdata(self) -> None:
        plan = _make_plan(
            fields={"username": b"alice", "password": b"hunter2"},
        )
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        # MUST use data (base64-encoded) for byte-exact preservation of
        # binary credential values — stringData would force a
        # UTF-8-encode round-trip.
        assert "data" in spec
        assert "stringData" not in spec, "spec MUST NOT use stringData (byte-exact contract)"
        assert spec["data"]["username"] == base64.b64encode(b"alice").decode("ascii")
        assert spec["data"]["password"] == base64.b64encode(b"hunter2").decode("ascii")

    def test_data_preserves_byte_exact_content(self) -> None:
        # Multi-byte UTF-8 + raw bytes round-trip through base64.
        plan = _make_plan(fields={"password": "señorita-naïveté".encode()})
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        decoded = base64.b64decode(spec["data"]["password"])
        assert decoded == "señorita-naïveté".encode()

    def test_required_labels_present(self) -> None:
        plan = _make_plan(logical_name="db_main")
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        labels = spec["metadata"]["labels"]
        assert labels["cognic/component"] == "credential-projection"
        assert labels["cognic/session-id"] == "session-abc-123"
        assert labels["cognic/logical-name"] == "db_main"

    def test_lease_id_is_annotation_not_label(self) -> None:
        # Vault lease IDs contain `/` chars which violate K8s label
        # syntax — must be carried as an annotation.
        plan = _make_plan(lease_id="database/creds/db-main/lease-xyz789")
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        labels = spec["metadata"].get("labels", {})
        annotations = spec["metadata"].get("annotations", {})
        assert annotations["cognic/lease-id"] == "database/creds/db-main/lease-xyz789"
        # Negative: lease-id MUST NOT appear in labels
        assert "cognic/lease-id" not in labels

    def test_tenant_id_is_annotation_not_label(self) -> None:
        # tenant_id moved from labels to annotations per spec §5.4 to
        # reduce list-leak via ``kubectl get secrets -l``.
        plan = _make_plan(tenant_id="tenant-acme-prod")
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        labels = spec["metadata"].get("labels", {})
        annotations = spec["metadata"].get("annotations", {})
        assert annotations["cognic/tenant-id"] == "tenant-acme-prod"
        assert "cognic/tenant-id" not in labels

    def test_owner_references_defaults_to_empty(self) -> None:
        # User-locked: Pod UID does not exist at Secret-creation time
        # (Secrets must exist BEFORE Pod create); T21 can optionally
        # patch ownerReferences post-Pod-create.
        plan = _make_plan(fields={"x": b"y"})
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
        )
        # Either omitted OR explicit empty list — both communicate
        # "no owner". Accept both.
        owner_refs = spec["metadata"].get("ownerReferences", [])
        assert owner_refs == [], f"ownerReferences must default to empty, got {owner_refs!r}"

    def test_owner_references_when_provided_carries_through(self) -> None:
        # When T21 patches post-Pod-create, it'll call this same
        # builder with ownerReferences. The pure helper accepts it.
        plan = _make_plan(fields={"x": b"y"})
        owner_refs = [
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "name": "sb-abc123",
                "uid": "pod-uid-deadbeef",
                "controller": True,
                "blockOwnerDeletion": True,
            }
        ]
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name="cognic-cred-0123456789abcdef",
            session_id="session-abc-123",
            owner_references=owner_refs,
        )
        assert spec["metadata"]["ownerReferences"] == owner_refs

    def test_metadata_name_matches_secret_name(self) -> None:
        plan = _make_plan(fields={"x": b"y"})
        secret_name = "cognic-cred-0123456789abcdef"
        spec = compute_k8s_secret_spec(
            plan=plan,
            secret_name=secret_name,
            session_id="session-abc-123",
        )
        assert spec["metadata"]["name"] == secret_name


# ---------------------------------------------------------------------------
# Volume + volumeMount pair — DNS-1123 safety
# ---------------------------------------------------------------------------


class TestComputeK8sCredentialVolumeAndMount:
    """Per spec §5.4 K8s + the user-locked DNS-1123 correction.

    Returns the (volume, volumeMount) pair the T21 pod-spec extension
    will merge into the Pod body.
      - volume.name = OPAQUE Secret name (DNS-1123 safe)
      - volume.secret.secretName = OPAQUE Secret name
      - volume.secret.defaultMode = 0o440
      - volumeMount.mountPath = ``/run/credentials/<logical_name>``
        (semantic visible only inside the workload's namespace)
      - volumeMount.readOnly = True
    """

    def test_returns_volume_and_mount_pair(self) -> None:
        volume, mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert isinstance(volume, dict)
        assert isinstance(mount, dict)

    def test_volume_name_is_opaque_secret_name(self) -> None:
        # User-locked: volume name MUST be the opaque Secret name,
        # NOT raw logical_name (underscore would break DNS-1123).
        volume, _mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",  # contains underscore
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert volume["name"] == "cognic-cred-0123456789abcdef"
        # Negative: raw logical_name MUST NOT appear as volume name
        assert volume["name"] != "db_main"
        assert volume["name"] != "cognic-cred-db_main"

    def test_volume_name_is_dns_1123_safe(self) -> None:
        # Even with a logical_name that has underscore, the volume
        # name (= secret name) is DNS-1123 safe.
        volume, _mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main_with_underscore",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", volume["name"]), (
            f"volume name {volume['name']!r} violates DNS-1123"
        )
        assert "_" not in volume["name"]

    def test_volume_secret_secretname_is_opaque(self) -> None:
        volume, _mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert volume["secret"]["secretName"] == "cognic-cred-0123456789abcdef"

    def test_volume_secret_defaultmode_is_0440(self) -> None:
        # Per spec §5.4: defaultMode 0440. K8s API uses DECIMAL 288
        # for the 0o440 mode bits — the kubelet interprets the
        # integer as octal at projection time.
        volume, _mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert volume["secret"]["defaultMode"] == 0o440  # = 288 decimal

    def test_mount_path_contains_semantic_logical_name(self) -> None:
        # User-locked: semantic logical_name appears ONLY in the mount
        # path (workload-facing), never on the host-visible volume name.
        _volume, mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert mount["mountPath"] == "/run/credentials/db_main"

    def test_mount_path_preserves_underscores_in_logical_name(self) -> None:
        # File paths inside the container have NO DNS-label constraint
        # — the underscore stays intact in the mount path.
        _volume, mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main_with_underscore",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert mount["mountPath"] == "/run/credentials/db_main_with_underscore"

    def test_mount_name_matches_volume_name(self) -> None:
        # K8s spec requires volumeMounts[i].name to match a volumes[j].name.
        volume, mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert mount["name"] == volume["name"]

    def test_mount_is_read_only(self) -> None:
        # Bind-mount equivalent: the workload reads but cannot modify.
        _volume, mount = compute_k8s_credential_volume_and_mount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert mount["readOnly"] is True


# ---------------------------------------------------------------------------
# CredentialSecretMount dataclass — the pair-carrier used by T21
# ---------------------------------------------------------------------------


class TestCredentialSecretMount:
    """The (logical_name, secret_name) pair-carrier T21 will thread
    through ``_build_pod_spec`` to emit credential volumes/mounts.
    Frozen + slots — parallel to T18's ``ProjectionPlanEntry``.
    """

    def test_carries_logical_name_and_secret_name(self) -> None:
        mount = CredentialSecretMount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        assert mount.logical_name == "db_main"
        assert mount.secret_name == "cognic-cred-0123456789abcdef"

    def test_is_frozen(self) -> None:
        mount = CredentialSecretMount(
            logical_name="db_main",
            secret_name="cognic-cred-0123456789abcdef",
        )
        # dataclass(frozen=True) raises FrozenInstanceError on assignment.
        with pytest.raises(dataclasses.FrozenInstanceError):
            mount.logical_name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# K8sExecutorResult — parallel to Docker's ProjectionExecutorResult
# ---------------------------------------------------------------------------


class TestK8sExecutorResultShape:
    """The audit-metadata projection T21 will receive after Secret
    creation. Parallel to T19's ``ProjectionExecutorResult`` but with
    K8s-specific resource name (Secret name) instead of host_staging_dir.
    """

    def test_carries_all_spec_57_credentials_projected_payload_fields(self) -> None:
        result = K8sExecutorResult(
            logical_name="db_main",
            vault_path="database/creds/db-main",
            tenant_id="tenant-k8s-test",
            lease_id="database/creds/db-main/lease-abc123",
            projected_field_count=2,
            purpose_category="application_database_read",
            purpose_description="Read-only application database access.",
            secret_name="cognic-cred-0123456789abcdef",
            container_mount_target="/run/credentials/db_main",
            session_id="session-abc-123",
        )
        # Spec §5.7 credentials_projected payload (K8s row):
        assert result.logical_name == "db_main"
        assert result.vault_path == "database/creds/db-main"
        assert result.tenant_id == "tenant-k8s-test"
        assert result.lease_id == "database/creds/db-main/lease-abc123"
        assert result.projected_field_count == 2
        assert result.purpose_category == "application_database_read"
        assert result.purpose_description == "Read-only application database access."
        # backend resource name (K8s = Secret name)
        assert result.secret_name == "cognic-cred-0123456789abcdef"
        # container_mount_target = semantic workload-facing path
        assert result.container_mount_target == "/run/credentials/db_main"
        # session_id passes through for the audit row
        assert result.session_id == "session-abc-123"


# ---------------------------------------------------------------------------
# Boundary-input grammar guards (T20 round-4 reviewer P1)
# ---------------------------------------------------------------------------


class TestComputeK8sSecretNameGuards:
    """Reviewer-reproduced bug: ``compute_k8s_secret_name(secret_opaque="db_main")``
    returns ``"cognic-cred-db_main"`` which leaks the logical_name AND
    violates DNS-1123 (underscore). Defence-in-depth boundary guard
    at the callable level — opaque MUST be 16-hex lowercase.
    """

    def test_non_hex_opaque_raises(self) -> None:
        # Reviewer's exact repro: passing raw logical_name.
        with pytest.raises(ValueError, match="secret_opaque must match"):
            compute_k8s_secret_name(secret_opaque="db_main")

    def test_uppercase_hex_opaque_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_opaque must match"):
            compute_k8s_secret_name(secret_opaque="ABCDEFABCDEFABCD")

    def test_wrong_length_short_opaque_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_opaque must match"):
            compute_k8s_secret_name(secret_opaque="0123456789abcde")

    def test_wrong_length_long_opaque_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_opaque must match"):
            compute_k8s_secret_name(secret_opaque="0123456789abcdef0")

    def test_empty_opaque_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_opaque must match"):
            compute_k8s_secret_name(secret_opaque="")

    def test_opaque_with_path_traversal_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_opaque must match"):
            compute_k8s_secret_name(secret_opaque="../escaped/12345")


class TestComputeK8sSecretSpecGuards:
    """Even if a caller bypasses ``compute_k8s_secret_name`` and passes
    ``secret_name`` directly, the spec builder MUST refuse names that
    don't match ``^cognic-cred-[0-9a-f]{16}$``.
    """

    def test_non_canonical_secret_name_raises(self) -> None:
        plan = _make_plan(fields={"x": b"y"})
        with pytest.raises(ValueError, match="secret_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-db_main",
                session_id="session-abc-123",
            )

    def test_wrong_prefix_secret_name_raises(self) -> None:
        plan = _make_plan(fields={"x": b"y"})
        with pytest.raises(ValueError, match="secret_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="not-cognic-prefix-0123456789abcdef",
                session_id="session-abc-123",
            )

    def test_uppercase_hex_in_secret_name_raises(self) -> None:
        plan = _make_plan(fields={"x": b"y"})
        with pytest.raises(ValueError, match="secret_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-ABCDEFABCDEFABCD",
                session_id="session-abc-123",
            )

    def test_short_secret_name_raises(self) -> None:
        plan = _make_plan(fields={"x": b"y"})
        with pytest.raises(ValueError, match="secret_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-short",
                session_id="session-abc-123",
            )

    def test_plan_logical_name_with_path_traversal_raises(self) -> None:
        # T20 round-6 reviewer P1: pre-fix a hand-rolled ProjectionPlan
        # with logical_name="../db" leaked through to the wire-public
        # ``metadata.labels["cognic/logical-name"]`` field. Defence-in-depth
        # guard at the executor seam mirrors T19 Docker's relative_path
        # guard.
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="username", content_bytes=b"x", mode=0o440),
            ),
            logical_name="../db",  # malformed
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"plan\.logical_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-0123456789abcdef",
                session_id="session-abc-123",
            )

    def test_plan_logical_name_with_slash_raises(self) -> None:
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="username", content_bytes=b"x", mode=0o440),
            ),
            logical_name="sub/dir",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"plan\.logical_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-0123456789abcdef",
                session_id="session-abc-123",
            )

    def test_plan_logical_name_uppercase_raises(self) -> None:
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="username", content_bytes=b"x", mode=0o440),
            ),
            logical_name="DBMain",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"plan\.logical_name must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-0123456789abcdef",
                session_id="session-abc-123",
            )

    def test_entry_relative_path_with_path_traversal_raises(self) -> None:
        # T20 round-6 reviewer P1: pre-fix a hand-rolled
        # ProjectionPlanEntry with relative_path="../token" leaked
        # through to ``Secret.data["../token"] = ...`` — wire-public
        # leak into the K8s API.
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="../token", content_bytes=b"x", mode=0o440),
            ),
            logical_name="db_main",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"entry\.relative_path must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-0123456789abcdef",
                session_id="session-abc-123",
            )

    def test_entry_relative_path_absolute_raises(self) -> None:
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="/etc/passwd", content_bytes=b"x", mode=0o440),
            ),
            logical_name="db_main",
            lease_id="lease-test",
            projected_field_count=1,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"entry\.relative_path must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-0123456789abcdef",
                session_id="session-abc-123",
            )

    def test_second_entry_with_bad_relative_path_raises(self) -> None:
        # Multi-entry plan where only the SECOND entry is malformed.
        # Pins that the guard iterates the whole list, not just the
        # first entry.
        plan = ProjectionPlan(
            entries=(
                ProjectionPlanEntry(relative_path="username", content_bytes=b"x", mode=0o440),
                ProjectionPlanEntry(relative_path="../escaped", content_bytes=b"y", mode=0o440),
            ),
            logical_name="db_main",
            lease_id="lease-test",
            projected_field_count=2,
            vault_path="database/creds/db-main",
            purpose_category="application_database_read",
            purpose_description="test",
            tenant_id="tenant-test",
        )
        with pytest.raises(ValueError, match=r"entry\.relative_path must match"):
            compute_k8s_secret_spec(
                plan=plan,
                secret_name="cognic-cred-0123456789abcdef",
                session_id="session-abc-123",
            )


class TestComputeK8sCredentialVolumeAndMountGuards:
    """Volume+mount builder MUST refuse bad ``secret_name`` AND bad
    ``logical_name`` (the latter flows into the mount path).
    """

    def test_non_canonical_secret_name_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="db_main",
                secret_name="cognic-cred-db_main",
            )

    def test_logical_name_with_path_traversal_raises(self) -> None:
        with pytest.raises(ValueError, match="logical_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="../escaped",
                secret_name="cognic-cred-0123456789abcdef",
            )

    def test_logical_name_with_slash_raises(self) -> None:
        with pytest.raises(ValueError, match="logical_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="sub/dir",
                secret_name="cognic-cred-0123456789abcdef",
            )

    def test_logical_name_absolute_raises(self) -> None:
        with pytest.raises(ValueError, match="logical_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="/etc/passwd",
                secret_name="cognic-cred-0123456789abcdef",
            )

    def test_logical_name_uppercase_raises(self) -> None:
        with pytest.raises(ValueError, match="logical_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="DBMain",
                secret_name="cognic-cred-0123456789abcdef",
            )

    def test_logical_name_starting_with_digit_raises(self) -> None:
        with pytest.raises(ValueError, match="logical_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="9db",
                secret_name="cognic-cred-0123456789abcdef",
            )

    def test_logical_name_over_32_chars_raises(self) -> None:
        with pytest.raises(ValueError, match="logical_name must match"):
            compute_k8s_credential_volume_and_mount(
                logical_name="a" * 33,
                secret_name="cognic-cred-0123456789abcdef",
            )


class TestGidRangeConstantsLockstepWithValidator:
    """The K8s preflight + the T14 manifest validator MUST enforce
    the same GID range. Drift between them creates the bug class
    where the validator accepts a value the preflight refuses at
    runtime — OR vice versa. Test-only cross-module check per
    ``[[feedback_drift_detector_test_only_no_runtime_import]]``;
    each module declares its own local copy.
    """

    def test_preflight_and_validator_share_gid_range(self) -> None:
        from cognic_agentos.cli.validators.credentials import (
            _GID_MAX as VALIDATOR_GID_MAX,
        )
        from cognic_agentos.cli.validators.credentials import (
            _GID_MIN as VALIDATOR_GID_MIN,
        )
        from cognic_agentos.sandbox._preflight import (
            _GID_MAX as PREFLIGHT_GID_MAX,
        )
        from cognic_agentos.sandbox._preflight import (
            _GID_MIN as PREFLIGHT_GID_MIN,
        )

        assert PREFLIGHT_GID_MIN == VALIDATOR_GID_MIN
        assert PREFLIGHT_GID_MAX == VALIDATOR_GID_MAX

    def test_canonical_gid_max_is_linux_32bit(self) -> None:
        # 2^32 - 1 = 4_294_967_295. Catches a future drift back to
        # 65535 (pre-T20 cap) OR up to int64.
        from cognic_agentos.sandbox._preflight import _GID_MAX

        assert _GID_MAX == 4_294_967_295
