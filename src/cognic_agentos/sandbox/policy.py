"""Sprint 8A T3 — SandboxPolicy + PackAdmissionContext + Stage-1 pure shape validation.

NO I/O. Critical-controls module per AGENTS.md. Stage-2 async admission
(catalog + cosign + SBOM + Rego + credential-adapter + high-risk-tier)
lives in T5 ``sandbox/admission.py`` per spec §6.1.

RiskTier is declared LOCALLY here, NOT imported from
``cognic_agentos.cli._governance_vocab`` — runtime sandbox code must
NOT import build-time CLI vocab per AGENTS.md "Plugin discipline" + the
plan's invariant (no runtime cross-module imports for shared constants
per feedback_drift_detector_test_only_no_runtime_import). A test-only
drift detector at ``tests/unit/sandbox/test_policy_shape.py`` pins this
local Literal against ``cli/_governance_vocab.RiskTier`` — if either
side drifts, the test fails at CI time without coupling runtime modules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

#: Local 8-value RiskTier Literal — matches ADR-014 canonical set verbatim.
#: Drift against ``cli/_governance_vocab.RiskTier`` pinned at TEST layer
#: only (``test_policy_shape.py::TestRiskTierDriftDetectorTestOnly``).
RiskTier = Literal[
    "read_only",
    "internal_write",
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
]

#: ``sha256:<64-hex>`` digest format. Lowercase hex only per OCI convention.
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: OCI image reference shape (repository + optional tag), pure regex —
#: no docker-py / oci-spec dependency. Accepts the realistic shapes
#: from the Sprint 8A canonical catalog (e.g.
#: ``cognic/sandbox-runtime-python:v1``,
#: ``registry.example.com:5000/cognic/sandbox-runtime:v1``) while
#: rejecting empty / leading-hyphen / empty-component / trailing-slash
#: forms.
#:
#: Grammar per the OCI Docker reference spec
#: (opencontainers/distribution-spec):
#:     [registry[:port]/]component[/component]*[:tag]
#: where:
#:     registry: ``[a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*(:[0-9]+)?``
#:     component: ``[a-z0-9]+(separator [a-z0-9]+)*``
#:     separator: ``[._] | __ | -+`` (single dot OR single underscore
#:                OR double underscore OR one-or-more dashes)
#:     tag: ``[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}``
#:
#: Round-9 R9 P2 reviewer fix: the separator alternation now matches
#: Docker-style double-underscore (``sandbox__runtime``) + multi-dash
#: (``sandbox--runtime``) component forms. Prior R1 regex used a flat
#: ``[._-]`` separator which rejected these valid OCI forms — would
#: have refused legitimate bank per-pack images at admission before
#: catalog/cosign got a say.
#:
#: Component grammar still rejects: empty components, leading
#: separator, trailing separator, mixed-class separators (e.g. ``_.``
#: between alphanumeric runs is invalid because it doesn't match any
#: single separator-alternative).
#:
#: Full strict OCI validation (hostname canonicalization, normalization
#: rules) is deferred to the registry at pull time (T10 cold-create
#: step). Stage-1 enforces per-component well-formedness.
_OCI_SEPARATOR = r"(?:__|-+|[._])"  # order matters: __ + -+ tried before [._]
_OCI_REPO_COMPONENT = rf"[a-z0-9]+(?:{_OCI_SEPARATOR}[a-z0-9]+)*"
_OCI_REGISTRY = r"[a-zA-Z0-9]+(?:[.-][a-zA-Z0-9]+)*(?::[0-9]+)?"
_OCI_TAG = r":[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}"
_OCI_REPO_TAG_RE = re.compile(
    rf"^"
    rf"(?:{_OCI_REGISTRY}/)?"
    rf"{_OCI_REPO_COMPONENT}"
    rf"(?:/{_OCI_REPO_COMPONENT})*"
    rf"(?:{_OCI_TAG})?"
    rf"$"
)

#: RFC 1123 hostname per spec §6.1 Step 2:
#: total length 1-253; per-label length 1-63; LDH-only labels.
_RFC1123_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


@dataclass(frozen=True)
class PackAdmissionContext:
    """Pack-level context for sandbox admission. Built by the harness
    from the pack manifest when a tool call requires a sandbox; threaded
    through to ``admit_policy()`` so admission has manifest-level fields
    it needs to make decisions that aren't on per-call
    ``SandboxPolicy``.

    7 fields: the original 6 per spec §6.1 (round-3-third-follow-on
    amendment) — ``pack_id`` + ``pack_version`` + ``pack_artifact_digest``
    + ``risk_tier`` + ``declares_dynamic_install`` + ``profile`` — plus
    the defaulted ``data_classes`` added at Sprint 13.5c1 (ADR-014).
    The warm-pool key derivation still reads ONLY the original
    admission fields (the immutable identity set); the defaulted 7th
    field does not perturb pool keys.

    ``pack_artifact_digest`` is the cosign-verified pack artifact
    sha256 per ADR-016 trust-gate pinning — the immutable identity.
    Pool key uses it (not ``pack_version`` which is human-mutable in
    some workflows); ``pack_version`` stays in audit logs + UI for
    human readability but is NOT load-bearing for admission integrity.

    ``data_classes`` — manifest ``[data_governance].data_classes``
    carried at admission time (Sprint 13.5c1, ADR-014); feeds the
    value-free ApprovalEnvelope on the engine-wired approval path.
    Empty default keeps pre-13.5c1 constructors green.
    """

    pack_id: str
    pack_version: str
    pack_artifact_digest: str
    risk_tier: RiskTier
    declares_dynamic_install: bool
    profile: Literal["production", "development"]
    data_classes: tuple[str, ...] = ()


@dataclass(frozen=True)
class WritableMount:
    """Per spec §6 ``SandboxPolicy.writable_mounts``."""

    host_path: str
    container_path: str
    read_only: bool = False


@dataclass(frozen=True)
class SandboxPolicy:
    """Per-call sandbox policy declared at sandbox-create time.

    Resource caps are validated against per-tenant max from
    ``policy.yaml`` + ``sandbox.rego`` at Stage-2 admission (T5);
    Stage-1 shape validation here only checks per-field shape.

    Notes:
    * ``cpu_cores`` sets the Docker ``--cpus`` throttle. Throttling
      under cap is NOT a runtime violation by itself.
    * ``cpu_time_budget_s`` is OPTIONAL. When set, the backend's
      runtime monitor reads cgroup ``cpuacct.usage_us`` and kills
      the container when accumulated CPU-seconds exceed the budget
      (``cpu_time_budget_exceeded``).
    * ``walltime_s`` is the AgentOS-side wall-clock timer.
    * ``runtime_image`` is the full OCI image reference including
      ``@sha256:<64-hex>`` digest suffix.
    * ``egress_allow_list`` carries RFC 1123 hostnames; HTTP/HTTPS
      scheme implicit (Wave 1). Non-HTTP/HTTPS schemes are refused
      at Stage-1.
    * ``vault_path`` is None at Sprint 8A baseline; setting it
      triggers ``sandbox_credential_adapter_not_configured`` at
      Stage-2 admission (because Sprint-10 ships the real Vault
      adapter; Sprint 8A's stub fails closed).
    * ``warm_pool_key`` is the human-readable name attached to the
      auto-derived pool key for audit purposes (per spec §11).
    """

    cpu_cores: float
    cpu_time_budget_s: float | None
    memory_mb: int
    walltime_s: float
    runtime_image: str
    egress_allow_list: tuple[str, ...]
    vault_path: str | None
    read_only_root: bool = True
    writable_mounts: tuple[WritableMount, ...] = ()
    warm_pool_key: str | None = None


def validate_policy_shape(policy: SandboxPolicy) -> None:
    """PURE Stage-1 shape validation per spec §6.1 step 1+2.

    Raises ``SandboxLifecycleRefused`` on the first failure. NO I/O.

    Validation order:
        1. ``cpu_cores`` > 0
        2. ``memory_mb`` > 0
        3. ``walltime_s`` > 0
        4. ``cpu_time_budget_s`` is None OR > 0
        5. ``runtime_image`` OCI ref shape + ``@sha256:<64-hex>`` suffix
        6. Per-entry ``egress_allow_list`` validation: HTTP/HTTPS-only
           scheme (Wave-1 doctrine) + RFC 1123 hostname per entry.
    """
    if policy.cpu_cores <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_cpu",
            detail=f"cpu_cores must be > 0; got {policy.cpu_cores}",
        )
    if policy.memory_mb <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_memory",
            detail=f"memory_mb must be > 0; got {policy.memory_mb}",
        )
    if policy.walltime_s <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_walltime",
            detail=f"walltime_s must be > 0; got {policy.walltime_s}",
        )
    if policy.cpu_time_budget_s is not None and policy.cpu_time_budget_s <= 0:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_cpu",
            detail=f"cpu_time_budget_s must be > 0 when set; got {policy.cpu_time_budget_s}",
        )
    _validate_image_ref(policy.runtime_image)
    for entry in policy.egress_allow_list:
        _validate_egress_host(entry)


def _validate_image_ref(ref: str) -> None:
    """Validate OCI image ref + ``@sha256:<64-hex>`` digest suffix
    per spec §6.1 step 1.

    Validation steps (all Stage-1 pure — NO subprocess; NO network;
    NO dependency on docker-py at this layer):
        (a) ref contains the ``@sha256:`` separator → refuse if missing
        (b) digest portion matches ``^sha256:[0-9a-f]{64}$``
        (c) repository+tag portion matches the inline OCI shape regex

    The full OCI-grammar validation happens at registry-pull time
    (T10 cold-create step); this layer only catches obvious shape
    errors. Refusal: ``sandbox_image_digest_format_invalid``.
    """
    if "@" not in ref:
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_format_invalid",
            detail=f"image ref missing @sha256: suffix: {ref}",
        )
    repo_tag, digest = ref.rsplit("@", 1)
    if not _SHA256_DIGEST_RE.fullmatch(digest):
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_format_invalid",
            detail=f"digest must be sha256:<64-hex>; got {digest}",
        )
    if not repo_tag or not _OCI_REPO_TAG_RE.fullmatch(repo_tag):
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_format_invalid",
            detail=f"image ref does not match OCI shape: {repo_tag!r}",
        )


def _validate_egress_host(entry: str) -> None:
    """Validate egress allow-list entry per spec §6.1 step 2.

    Stage-1 pure validation. Two checks:
        (a) If the entry carries a scheme, it MUST be ``http`` or
            ``https``. Wave-1 only allows HTTP/HTTPS outbound per
            the §2.1 doctrinal lock.
        (b) The hostname portion MUST match RFC 1123 (1-253 chars
            total; 1-63 chars per label; LDH characters only; no
            leading/trailing hyphen on any label).

    Examples that pass: ``api.example.com``,
    ``https://api.example.com``, ``localhost``, ``a.b.c``.

    Examples that refuse: ``ftp://files.example.com`` (scheme),
    ``-bad.example.com`` (leading hyphen), ``""`` (empty),
    ``a..b.c`` (empty label).
    """
    if "://" in entry:
        scheme, host = entry.split("://", 1)
        if scheme not in ("http", "https"):
            raise SandboxLifecycleRefused(
                "sandbox_policy_egress_protocol_not_http",
                detail=f"Wave-1 allows http/https only; got {scheme}://",
            )
    else:
        host = entry

    # Strip path/query if present (the allow-list is hostname-only)
    host = host.split("/", 1)[0]
    if not host:
        raise SandboxLifecycleRefused(
            "sandbox_policy_egress_host_invalid",
            detail=f"empty hostname in egress entry: {entry!r}",
        )
    if not _RFC1123_HOST_RE.fullmatch(host):
        raise SandboxLifecycleRefused(
            "sandbox_policy_egress_host_invalid",
            detail=f"hostname does not match RFC 1123: {host!r}",
        )
