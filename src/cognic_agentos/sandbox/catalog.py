"""Sprint 8A T6 — canonical image catalog + cosign + SBOM verification.

Critical-controls module per AGENTS.md + spec §17. Substantive
enforcement point — a bug here lets untrusted images run OR runs
code with unverified licenses through the bank's runtime. NOT
thin wiring.

Per spec §9 (catalog table) + ADR-016 amendment ("AgentOS-published
runtime artifacts" subsection) + Sprint-4 trust-gate cosign pattern
at ``protocol/trust_gate.py``. The cosign subprocess invocation
mirrors the Sprint-4 trust-gate doctrine (per-tenant trust root +
``cosign verify --key`` + fail-closed on any non-zero exit).

The 4-image canonical catalog is the AgentOS-published runtime
artifact set; bank deployments may EXTEND with per-tenant pack
images via ``tenant_allow_lists`` (per spec §9 + §10 escape hatch)
but CANNOT shrink the canonical set (that would refuse legitimate
pack runtimes).

Structural conformance: this module ships ``CanonicalImageCatalog``
as the concrete implementation of T5's ``CatalogProtocol`` (declared
in ``sandbox/admission.py`` per the consumer-owned-Protocol rule;
see post-T5 implementation notes at top of the T2 plan-of-record
at commit ``225f509``). T6 does NOT re-declare the Protocol — the
Protocol's canonical home stays in ``admission.py`` until a shared
``sandbox/protocols.py`` module is needed.

Subprocess seams (``_run_cosign_verify`` + ``_run_syft_inspect``):
both shell out to external binaries (``cosign``, ``syft``) via
``asyncio.create_subprocess_exec``. Unit tests patch the seam at
the ``asyncio.create_subprocess_exec`` boundary so the real parsing
+ default-deny license policy code executes; real cosign + syft
integration runs in T10's env-gated DockerSibling backend tests.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

#: Minimal subprocess env — mirrors the Sprint-4 trust-gate doctrine
#: at ``protocol/trust_gate.py:97``. PATH + HOME ONLY; ``os.environ``
#: is NOT passed through. Loss case if absent: cosign/syft inherit
#: every secret + creds env var the AgentOS process holds (AWS_*,
#: VAULT_TOKEN, OIDC bearer, etc.). T6 R3 P2 #4 fix.
_SUBPROCESS_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}


#: Bounded char cap for decoded subprocess stdout/stderr surfaced in
#: result-detail strings. Default 1024 chars caps the chain-payload
#: bloat from an attacker-controlled multi-MB stderr stream. T6 R4
#: P1 #2 fix.
_SUBPROCESS_DETAIL_MAX_CHARS = 1024

#: Per-field caps on SBOM-derived display values surfaced in
#: violation detail strings. T6 R7 P2 fix — without these, an
#: attacker-controlled SBOM with a 20k-char artifact name or license
#: value inflates the chain payload via the violation list. Caps
#: chosen to comfortably exceed real-world max lengths (package
#: names < 100, license IDs < 50, semver < 32) with headroom for
#: long-tail exotic ecosystems.
_MAX_ARTIFACT_NAME_LEN = 256
_MAX_ARTIFACT_VERSION_LEN = 64
_MAX_LICENSE_VALUE_LEN = 256
#: Final SBOM-detail-string cap (defense-in-depth — if a future
#: violation type bypasses per-field bounds, this caps the
#: chain-row impact anyway).
_MAX_SBOM_DETAIL_CHARS = 4096


def _bounded_field(value: str, *, max_chars: int) -> str:
    """Truncate a SBOM-derived display string with an ellipsis
    marker if it exceeds the bound. Used for artifact name +
    version in violation messages where the value is informational
    only (NOT participating in policy membership checks). T6 R7 P2
    fix."""

    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "..."


def _safe_decode_bounded(b: bytes, *, max_chars: int = _SUBPROCESS_DETAIL_MAX_CHARS) -> str:
    """Decode subprocess output (stdout/stderr) without raising on
    non-UTF-8 bytes + bounded length cap. T6 R4 P1 #2 fix.

    ``errors="replace"`` substitutes the Unicode REPLACEMENT CHARACTER
    (U+FFFD) for invalid byte sequences instead of raising
    ``UnicodeDecodeError``. Loss case if absent: a binary that emits
    non-UTF-8 bytes on stderr (a locale-mismatched cosign, a hostile
    registry response surfaced through syft) raises raw
    ``UnicodeDecodeError`` from ``.decode()`` and escapes the
    ``SandboxRefusalReason`` taxonomy.

    Bounded length cap prevents an attacker-controlled multi-MB
    stderr stream from bloating the chain payload. Trust-gate
    doctrine at ``protocol/trust_gate.py:609-624`` uses sha256+length
    for stderr ("privacy + log-injection"); catalog keeps actionability
    via ``errors="replace"`` + truncation because catalog stderr
    surfaces operator-actionable signal (signer mismatch, GPL-3.0
    detected) that pure-hash would lose.
    """

    return b.decode("utf-8", errors="replace")[:max_chars]


@dataclass(frozen=True)
class CosignVerifyResult:
    """Pure-result return type for ``_run_cosign_verify`` /
    ``verify_cosign``. Frozen so callers can pass it through audit
    chain rows without defensive copies."""

    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class SBOMVerifyResult:
    """Pure-result return type for ``_run_syft_inspect`` /
    ``verify_sbom_policy``. Same frozen contract as
    ``CosignVerifyResult``."""

    passed: bool
    detail: str = ""


#: Default Wave-1 license policy applied when a tenant has no entry
#: in ``tenant_license_policies``. The 5-license denied set covers
#: all common AGPL + GPL copyleft variants that strict bank legal
#: review would refuse; the 6-license allowed set covers the
#: permissive licenses the bank legal team has pre-approved. Any
#: other license (LGPL, MPL, BUSL, custom, etc.) is DEFAULT-DENY —
#: tenants override per-deployment.
#:
#: Drift in either set is a per-tenant compliance signal — bank
#: overlays SHOULD pass ``tenant_license_policies`` rather than
#: edit this kernel default.
_DEFAULT_LICENSE_POLICY: dict[str, frozenset[str]] = {
    "denied": frozenset({"GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-1.0", "AGPL-3.0"}),
    "allowed": frozenset(
        {
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Python-2.0",
        }
    ),
}


def _compose_policy(
    kernel: dict[str, frozenset[str]],
    tenant: dict[str, frozenset[str]] | None,
) -> dict[str, frozenset[str]]:
    """Compose tenant license policy on top of the kernel policy per
    ADR-016: bank overlays may TIGHTEN (add denied licenses, narrow
    allowed) but NEVER LOOSEN (cannot remove from kernel denied;
    cannot allow a license outside kernel allowed).

    Without this compose helper, a tenant overlay that fully
    REPLACES ``_DEFAULT_LICENSE_POLICY`` could silently re-allow
    GPL-3.0 or AGPL-3.0 into a bank deployment — a kernel-level
    posture violation that ADR-016 forbids without an ADR amendment.
    T6 R3 P1 #1 fix.

    Compose rules (both sets-as-mathematical-sets):

        effective_denied  = kernel_denied  UNION tenant_denied
        effective_allowed = kernel_allowed INTERSECT tenant_allowed_or_kernel

    where ``tenant_allowed_or_kernel = tenant["allowed"]`` if the
    tenant supplies the ``allowed`` key (even as an empty frozenset
    — that's an explicit "narrow to nothing"), else ``kernel_allowed``
    (no narrowing).

    Returns a fresh dict each call; callers MUST NOT mutate the
    returned frozensets (they're frozen anyway).
    """

    if tenant is None:
        return kernel
    kernel_denied = kernel.get("denied", frozenset())
    kernel_allowed = kernel.get("allowed", frozenset())
    tenant_denied = tenant.get("denied", frozenset())
    # Sentinel: missing ``allowed`` key = "no narrowing"; explicitly
    # supplied (even empty frozenset) = "narrow via intersection".
    if "allowed" in tenant:
        effective_allowed = kernel_allowed & tenant["allowed"]
    else:
        effective_allowed = kernel_allowed
    return {
        "denied": kernel_denied | tenant_denied,
        "allowed": effective_allowed,
    }


class CanonicalImageCatalog:
    """4-image AgentOS canonical catalog + per-tenant allow-list +
    cosign + SBOM verification per spec §9 + ADR-016 amendment.

    Round-3 R4 P1 #3 fix: catalog stores FULL OCI image refs (incl
    tag + digest, e.g. ``cognic/sandbox-runtime-python:v1@sha256:
    aaa...``), NOT bare digests. cosign + syft need the full ref to
    look up the image in the registry; ``docker.io/sha256:...`` is
    NOT a valid OCI ref. The ``_digest_to_ref`` reverse-map lets
    fast O(1) admission-time digest-lookup AND full-ref resolution
    at cosign/syft subprocess time coexist.

    Round-5 R5 P1 #2 fix: ``is_tenant_allow_listed`` queries the
    DERIVED ``_tenant_allow_listed_digests`` (digest-axis), NOT the
    raw ``_tenant_allow_lists`` (full-ref-axis). Admission's
    ``policy.runtime_image.rsplit('@', 1)[1]`` yields the bare digest;
    lookup must compare on the digest axis.

    Per-tenant license policy override via ``tenant_license_policies``
    constructor kwarg — Wave-1 default is ``_DEFAULT_LICENSE_POLICY``
    (5 denied + 6 allowed; default-deny otherwise).
    """

    def __init__(
        self,
        *,
        canonical_refs: frozenset[str],
        tenant_trust_roots: dict[str, Path],
        tenant_allow_lists: dict[str, frozenset[str]],
        tenant_license_policies: dict[str, dict[str, frozenset[str]]] | None = None,
        cosign_verify_timeout_s: float = 60.0,
        syft_inspect_timeout_s: float = 120.0,
    ) -> None:
        # T6 R3 P2 #4 fix: cosign + syft subprocesses are CC; bounded
        # via asyncio.wait_for + kill/reap on timeout (mirrors the
        # Sprint-4 trust-gate doctrine at protocol/trust_gate.py:588-607).
        # syft default is 2x cosign because SBOM scans on large images
        # take longer than signature verification.
        self._cosign_verify_timeout_s = cosign_verify_timeout_s
        self._syft_inspect_timeout_s = syft_inspect_timeout_s
        self._canonical_refs = canonical_refs
        # Derived digest set for fast O(1) admission-time lookup.
        # Built from the full refs at construction so production
        # never has to re-parse on every admission.
        self._canonical_digests: frozenset[str] = frozenset(
            ref.rsplit("@", 1)[1] for ref in canonical_refs if "@" in ref
        )
        self._tenant_trust_roots = tenant_trust_roots
        self._tenant_allow_lists = tenant_allow_lists
        # Derived per-tenant digest sets — same fast-lookup pattern.
        self._tenant_allow_listed_digests: dict[str, frozenset[str]] = {
            tid: frozenset(ref.rsplit("@", 1)[1] for ref in refs if "@" in ref)
            for tid, refs in tenant_allow_lists.items()
        }
        # Reverse-map digest → full OCI ref so cosign + syft can
        # resolve the full ref from just the digest at
        # admission-time subprocess invocation. Loss case if absent:
        # cosign + syft get ``sha256:...`` (not a valid OCI ref) and
        # the subprocess fails with an unhelpful registry-lookup
        # error instead of a clean ``not in catalog reverse-map``
        # message.
        self._digest_to_ref: dict[str, str] = {}
        for ref in canonical_refs:
            if "@" in ref:
                self._digest_to_ref[ref.rsplit("@", 1)[1]] = ref
        for refs in tenant_allow_lists.values():
            for ref in refs:
                if "@" in ref:
                    self._digest_to_ref[ref.rsplit("@", 1)[1]] = ref
        self._tenant_license_policies = tenant_license_policies or {}

    # ---- Membership (sync; matches CatalogProtocol contract) ----

    def is_canonical(self, image_digest: str) -> bool:
        """True iff ``image_digest`` is in the 4-image canonical set.
        Queries the DERIVED ``_canonical_digests`` (built at
        construction)."""

        return image_digest in self._canonical_digests

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        """True iff ``image_digest`` is on the per-tenant allow-list
        for the per-pack image escape hatch (spec §8.2). Queries the
        DERIVED ``_tenant_allow_listed_digests`` per round-5 R5 P1 #2.
        Returns False for tenants with no entry (NOT KeyError;
        NOT silent True)."""

        return image_digest in self._tenant_allow_listed_digests.get(tenant_id, frozenset())

    # ---- Pure-result verification API (caller decides refuse) ----

    async def verify_cosign(self, image_digest: str, *, tenant_id: str) -> CosignVerifyResult:
        """Pure-result variant — caller inspects ``.passed`` and
        decides refuse vs continue. Use when audit-emission needs the
        detail string before deciding the closed-enum refusal
        reason."""

        return await self._run_cosign_verify(image_digest, tenant_id=tenant_id)

    async def verify_sbom_policy(self, image_digest: str, *, tenant_id: str) -> SBOMVerifyResult:
        """Pure-result variant for SBOM check. Same caller-decides
        contract as ``verify_cosign``."""

        return await self._run_syft_inspect(image_digest, tenant_id=tenant_id)

    # ---- Refuse-on-fail API (matches CatalogProtocol contract) ----

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        """Convenience: raises ``SandboxLifecycleRefused`` with
        closed-enum reason ``sandbox_image_cosign_verification_failed``
        on any failure (subprocess non-zero, binary missing, signature
        mismatch). admit_policy step 7 calls this directly per spec
        §6.1."""

        try:
            result = await self._run_cosign_verify(image_digest, tenant_id=tenant_id)
        except FileNotFoundError as exc:
            # cosign binary missing — fail-closed, NOT silent-skip.
            # Loss case if not translated: admission silently passes a
            # supposedly-cosign-verified image because the verification
            # step never ran.
            raise SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail=f"cosign binary missing: {exc}",
            ) from exc
        if not result.passed:
            raise SandboxLifecycleRefused(
                "sandbox_image_cosign_verification_failed",
                detail=result.detail,
            )

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        """Convenience: raises ``SandboxLifecycleRefused`` with
        closed-enum reason ``sandbox_image_sbom_check_failed`` on
        any failure (license policy violation, subprocess non-zero,
        unparseable SBOM JSON). admit_policy step 8 calls this."""

        result = await self._run_syft_inspect(image_digest, tenant_id=tenant_id)
        if not result.passed:
            raise SandboxLifecycleRefused(
                "sandbox_image_sbom_check_failed",
                detail=result.detail,
            )

    # ---- Subprocess seams (mocked at unit-test layer) ----

    async def _run_cosign_verify(self, image_digest: str, *, tenant_id: str) -> CosignVerifyResult:
        """Subprocess seam — shells out to ``cosign verify``.

        Round-3 R4 P1 #3 fix: resolves the full OCI ref via the
        reverse-map BEFORE invoking cosign. Defence-in-depth:
        admission step 6 (catalog membership) should have caught a
        digest-not-in-catalog scenario first, but this seam refuses
        rather than passing a bad ref to cosign.

        Returns:
            ``CosignVerifyResult(passed=True)`` on subprocess exit 0
            with stdout in detail; ``CosignVerifyResult(passed=False)``
            on missing trust root / missing reverse-map entry /
            subprocess non-zero exit (stderr in detail).
        """

        trust_root = self._tenant_trust_roots.get(tenant_id)
        if trust_root is None:
            return CosignVerifyResult(
                passed=False,
                detail=f"no trust root configured for tenant {tenant_id!r}",
            )
        full_ref = self._digest_to_ref.get(image_digest)
        if full_ref is None:
            # Bug-class guard: cosign was asked about a digest that
            # isn't in the catalog's reverse-map. Should be
            # unreachable if admission step 6 (catalog-membership)
            # passed first, but defence-in-depth fails closed.
            return CosignVerifyResult(
                passed=False,
                detail=(
                    f"digest {image_digest} not in catalog reverse-map "
                    f"(admission step 6 should have caught this)"
                ),
            )
        # T6 R3 P2 #4 fix: minimal env (no os.environ pass-through)
        # + bounded timeout via wait_for + SIGKILL + reap on
        # timeout. Mirrors trust_gate.py:574-607 doctrine.
        try:
            proc = await asyncio.create_subprocess_exec(
                "cosign",
                "verify",
                "--key",
                str(trust_root),
                "--certificate-identity-regexp",
                ".*",
                full_ref,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_SUBPROCESS_ENV,
            )
        except OSError as exc:
            # T6 R3 P1 #3 fix: cosign binary missing / exec-format /
            # permission denied — fail-closed via the pure-result API
            # so verify_cosign_or_refuse can translate to the
            # closed-enum SandboxLifecycleRefused. Loss case if not
            # caught: raw OSError escapes admission's
            # SandboxRefusalReason taxonomy.
            return CosignVerifyResult(
                passed=False,
                detail=(f"failed to launch cosign: errno={exc.errno} class={type(exc).__name__}"),
            )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._cosign_verify_timeout_s
            )
        except TimeoutError:
            # SIGKILL + reap; loss case if not killed: hung cosign
            # leaves a zombie process indefinitely.
            proc.kill()
            await proc.wait()
            return CosignVerifyResult(
                passed=False,
                detail=(f"cosign verify timed out after {self._cosign_verify_timeout_s}s"),
            )
        # T6 R4 P1 #2 fix: bounded + replace-on-invalid decode so
        # non-UTF-8 cosign output never raises UnicodeDecodeError
        # past the closed-enum refusal taxonomy.
        if proc.returncode == 0:
            return CosignVerifyResult(passed=True, detail=_safe_decode_bounded(stdout))
        return CosignVerifyResult(passed=False, detail=_safe_decode_bounded(stderr))

    async def _run_syft_inspect(self, image_digest: str, *, tenant_id: str) -> SBOMVerifyResult:
        """Subprocess seam — shells out to ``syft <full-ref> -o json``
        + applies tenant license policy.

        Per-tenant license policy (Wave-1 default at
        ``_DEFAULT_LICENSE_POLICY``):

        * Every license in the SBOM's artifacts MUST be in the
          tenant's ``allowed`` set.
        * No license in the SBOM MAY be in the tenant's ``denied`` set.
        * Licenses neither in allowed nor denied → DEFAULT-DENY
          (refuse with explicit ``not in allow-list`` detail).

        Loss case if not default-deny: a previously-unknown license
        (BUSL-1.1, custom-bank, etc.) silently runs in production
        without legal review.

        Returns:
            ``SBOMVerifyResult(passed=True)`` on syft exit 0 + zero
            license violations; ``SBOMVerifyResult(passed=False)``
            with policy-violation detail otherwise.
        """

        full_ref = self._digest_to_ref.get(image_digest)
        if full_ref is None:
            # Defence-in-depth guard mirroring the cosign variant.
            return SBOMVerifyResult(
                passed=False,
                detail=(
                    f"digest {image_digest} not in catalog reverse-map "
                    f"(admission step 6 should have caught this)"
                ),
            )
        # T6 R3 P2 #4 fix: minimal env + bounded timeout (mirrors
        # cosign discipline + trust_gate.py:574-607 doctrine).
        try:
            proc = await asyncio.create_subprocess_exec(
                "syft",
                full_ref,
                "-o",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_SUBPROCESS_ENV,
            )
        except OSError as exc:
            # T6 R3 P1 #3 fix (symmetric with cosign per
            # feedback_symmetric_exception_ordering): syft binary
            # missing → fail-closed via pure-result API.
            return SBOMVerifyResult(
                passed=False,
                detail=(f"failed to launch syft: errno={exc.errno} class={type(exc).__name__}"),
            )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._syft_inspect_timeout_s
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return SBOMVerifyResult(
                passed=False,
                detail=(f"syft inspect timed out after {self._syft_inspect_timeout_s}s"),
            )
        if proc.returncode != 0:
            # T6 R4 P1 #2 fix: bounded + replace-on-invalid decode
            # (matches cosign path discipline).
            return SBOMVerifyResult(
                passed=False,
                detail=f"syft exited {proc.returncode}: {_safe_decode_bounded(stderr)}",
            )
        # T6 R3 P1 #3 fix: catch JSONDecodeError on malformed syft
        # output. T6 R4 P1 #1 fix: also catch UnicodeDecodeError
        # because ``json.loads(bytes)`` uses internal UTF-8 detection
        # that can raise UnicodeDecodeError for non-UTF8 input. Both
        # routes return SBOMVerifyResult(passed=False) so
        # verify_sbom_policy_or_refuse translates to closed-enum
        # sandbox_image_sbom_check_failed. Loss case if not caught:
        # hostile registry returning non-JSON or non-UTF-8 output
        # (or a syft version change) leaks raw Python exception
        # through admission.
        try:
            sbom = json.loads(stdout)
        except UnicodeDecodeError as exc:
            return SBOMVerifyResult(
                passed=False,
                detail=(f"syft output is not valid UTF-8 (at byte {exc.start}): {exc.reason}"),
            )
        except json.JSONDecodeError as exc:
            return SBOMVerifyResult(
                passed=False,
                detail=(f"syft output is not valid JSON (at offset {exc.pos}): {exc.msg}"),
            )
        # T6 R4 P1 #1 fix: validate the parsed JSON's SHAPE before
        # iterating. Valid JSON that isn't the expected
        # ``{"artifacts": [{"name": ..., "licenses": [{"value": ...}]}]}``
        # shape (e.g. ``[]``, ``null``, a string, ``{"artifacts":
        # ["bad"]}``, ``{"artifacts": [{"licenses": ["MIT"]}]}``)
        # raises AttributeError on ``.get()`` calls otherwise. Each
        # type-mismatch shape-arm returns fail-closed at the layer
        # where the shape contract first breaks.
        if not isinstance(sbom, dict):
            return SBOMVerifyResult(
                passed=False,
                detail=(f"syft output JSON is {type(sbom).__name__}, expected object"),
            )
        # T6 R5 P1 #1 fix: distinguish missing ``artifacts`` key from
        # explicit empty list. Syft always emits the key (even on a
        # static binary with no deps, the value is ``[]`` not absent);
        # missing key is a schema violation that MUST fail-closed,
        # NOT collapse to ``[]`` and pass as ``sbom passed; 0
        # artifacts``. Loss case avoided: malformed syft output
        # ``{}`` bypasses the license inventory entirely. Explicit
        # ``"artifacts": []`` remains the valid-empty case
        # (zero-dep image / static binary).
        if "artifacts" not in sbom:
            return SBOMVerifyResult(
                passed=False,
                detail="syft output missing `artifacts` key",
            )
        artifacts = sbom["artifacts"]
        if not isinstance(artifacts, list):
            return SBOMVerifyResult(
                passed=False,
                detail=(f"syft output `artifacts` is {type(artifacts).__name__}, expected list"),
            )
        # T6 R3 P1 #1 fix: COMPOSE tenant policy onto the kernel
        # default-deny posture instead of replacing it. Tenants may
        # tighten (add denied, narrow allowed) but never loosen
        # (cannot re-allow a kernel-denied license like GPL-3.0
        # without a kernel + ADR amendment per ADR-016).
        policy = _compose_policy(
            _DEFAULT_LICENSE_POLICY,
            self._tenant_license_policies.get(tenant_id),
        )
        violations: list[str] = []
        for idx, artifact in enumerate(artifacts):
            # T6 R4 P1 #1 fix: per-artifact dict-shape guard.
            # Non-dict artifact entries surface as structured
            # violations + continue to the next entry — one bad
            # artifact does not take down the whole inspect, but the
            # SBOM still fails (the violation joins the list).
            if not isinstance(artifact, dict):
                violations.append(
                    f"<non-dict artifact at index {idx}>: "
                    f"{type(artifact).__name__} "
                    f"(syft schema violation; default-deny)"
                )
                continue
            raw_name = artifact.get("name", "?")
            raw_version = artifact.get("version", "?")
            # T6 R7 P2 fix: bound SBOM-derived display fields to
            # prevent attacker-controlled pathological-length fields
            # (20k+ char artifact names) from inflating the chain
            # payload via violation entries. Non-string types coerce
            # via ``str()`` (f-string formatting was already safe;
            # bounding makes the safety explicit).
            artifact_name = _bounded_field(str(raw_name), max_chars=_MAX_ARTIFACT_NAME_LEN)
            artifact_version = _bounded_field(str(raw_version), max_chars=_MAX_ARTIFACT_VERSION_LEN)
            # T6 R3 P1 #2 fix: artifact with NO license info refuses
            # under default-deny doctrine. ``artifact.get("licenses")``
            # may be missing, None, or empty list — all three are
            # "no license info" → ONE refusal entry per artifact.
            # Loss case if not refused: an unlabeled dep (could be
            # GPL-3.0 or anything) silently runs in the sandbox.
            license_entries = artifact.get("licenses") or []
            # T6 R4 P1 #1 fix: per-artifact licenses-is-list guard.
            # A non-list ``licenses`` value (dict, int, etc.) raises
            # TypeError on iteration otherwise.
            if not isinstance(license_entries, list):
                violations.append(
                    f"{artifact_name}@{artifact_version}: "
                    f"`licenses` is {type(license_entries).__name__}, "
                    f"expected list (syft schema violation; default-deny)"
                )
                continue
            if not license_entries:
                violations.append(
                    f"{artifact_name}@{artifact_version}: <no license info> "
                    f"(default-deny per missing-license policy)"
                )
                continue
            for lic in license_entries:
                # T6 R4 P1 #1 fix: per-license dict-shape guard.
                # A string license entry (e.g. ``["MIT"]``) raises
                # AttributeError on ``.get()`` otherwise.
                if not isinstance(lic, dict):
                    violations.append(
                        f"{artifact_name}@{artifact_version}: "
                        f"license entry is {type(lic).__name__}, "
                        f"expected object (syft schema violation; default-deny)"
                    )
                    continue
                lic_id = lic.get("value", "")
                # T6 R6 P1 #1 fix: license value MUST be a string
                # before membership checks. Non-string values (list,
                # dict, int, bool, None) escape the closed-enum
                # taxonomy in different ways:
                #   * Unhashable (list, dict): raise TypeError on
                #     ``lic_id in policy["denied"]`` membership.
                #   * Hashable non-string (int, bool, None): silently
                #     fall through to the default-deny path with a
                #     misleading detail (e.g. ``42 (not in allow-list)``).
                # Both surface as structured schema violations now.
                if not isinstance(lic_id, str):
                    violations.append(
                        f"{artifact_name}@{artifact_version}: "
                        f"license value is {type(lic_id).__name__}, "
                        f"expected string "
                        f"(syft schema violation; default-deny)"
                    )
                    continue
                # T6 R7 P2 fix: bound license value before policy
                # membership check. An attacker-controlled SBOM
                # value of 20k+ chars would otherwise inflate the
                # chain payload via the violation list. Refuse-on-
                # too-long surfaces as a structured schema violation;
                # the cap is well above any realistic SPDX license
                # ID (typically < 50 chars).
                if len(lic_id) > _MAX_LICENSE_VALUE_LEN:
                    violations.append(
                        f"{artifact_name}@{artifact_version}: "
                        f"license value too long "
                        f"({len(lic_id)} chars, max {_MAX_LICENSE_VALUE_LEN}) "
                        f"(syft schema violation; default-deny)"
                    )
                    continue
                if not lic_id:
                    # Empty license-value string is same default-deny
                    # case as missing entry.
                    violations.append(
                        f"{artifact_name}@{artifact_version}: "
                        f"<empty license value> "
                        f"(default-deny per missing-license policy)"
                    )
                elif lic_id in policy["denied"]:
                    violations.append(f"{artifact_name}@{artifact_version}: {lic_id} (denied)")
                elif lic_id not in policy["allowed"]:
                    violations.append(
                        f"{artifact_name}@{artifact_version}: "
                        f"{lic_id} (not in allow-list; default-deny)"
                    )
        if violations:
            head = "; ".join(violations[:5])
            tail = f"; +{len(violations) - 5} more" if len(violations) > 5 else ""
            detail = f"license policy violations ({len(violations)} entries): {head}{tail}"
            # T6 R7 P2 fix: defense-in-depth final cap on the
            # composite detail string. Per-field bounds keep
            # individual violations short; this cap catches any
            # future violation type that bypasses per-field bounds.
            # Test-only load-bearingness verified at R8 P3 via
            # temporary fix-revert (test fails with 407 > 103 when
            # cap branch removed) per feedback_security_regression_
            # hardening.
            if len(detail) > _MAX_SBOM_DETAIL_CHARS:
                detail = detail[:_MAX_SBOM_DETAIL_CHARS] + "..."
            return SBOMVerifyResult(passed=False, detail=detail)
        return SBOMVerifyResult(
            passed=True,
            # T6 R4 P1 #1 fix: use the validated ``artifacts`` local
            # (already shape-checked above) instead of re-deriving
            # via ``sbom.get`` — which would re-introduce the
            # missing-shape-guard bug if a future refactor moves the
            # detail-builder.
            detail=f"sbom passed; {len(artifacts)} artifacts",
        )
