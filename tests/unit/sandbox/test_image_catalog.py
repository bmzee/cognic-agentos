"""Sprint 8A T6 — CanonicalImageCatalog membership + cosign + SBOM.

Critical-controls module per AGENTS.md + spec §17. cosign + syft
subprocesses are mocked at the subprocess boundary
(``monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)``)
so the real ``_run_cosign_verify`` / ``_run_syft_inspect`` parsing
code (JSON parsing, default-deny license policy, reverse-map lookup,
subprocess failure handling) executes under test. Real cosign
integration runs in env-gated DockerSibling backend tests at T10.

CC watchpoints pinned in this file:

* 4-image canonical catalog membership uses the DERIVED digest set
  (not the raw full-ref set); per-tenant allow-list does the same.
* cosign + syft subprocess seams reverse-map the digest to a full
  OCI ref BEFORE shelling out (``docker.io/sha256:...`` is not a
  valid OCI ref).
* cosign-binary-missing + subprocess-non-zero-exit are fail-closed
  refusals (NOT skipped checks).
* License policy is DEFAULT-DENY: a license neither in allowed nor
  in denied refuses with closed-enum
  ``sandbox_image_sbom_check_failed``.
* GPL-3.0 (and the other 4 denied licenses) refuse explicitly.
* MIT + Apache-2.0 (and the other 4 allowed licenses) pass.
* Subprocess failures (non-zero exit, missing binary) translate to
  fail-closed ``SandboxLifecycleRefused`` via the ``_or_refuse``
  variants — never silent skip.
* Structural conformance to T5's ``CatalogProtocol`` (4 methods:
  ``is_canonical`` / ``is_tenant_allow_listed`` (sync) +
  ``verify_cosign_or_refuse`` / ``verify_sbom_policy_or_refuse``
  (async)) is pinned by ``TestCatalogProtocolStructuralConformance``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cognic_agentos.sandbox import SandboxLifecycleRefused
from cognic_agentos.sandbox.admission import CatalogProtocol
from cognic_agentos.sandbox.catalog import (
    CanonicalImageCatalog,
    CosignVerifyResult,
    SBOMVerifyResult,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_CANONICAL_PYTHON = "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
_CANONICAL_SHELL = "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64
_CANONICAL_DATA = "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64
_CANONICAL_PROXY = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64
_TENANT_PACK_IMAGE = "bank/custom-pack-sandbox:v1@sha256:" + "e" * 64

_DIGEST_PYTHON = "sha256:" + "a" * 64
_DIGEST_PACK = "sha256:" + "e" * 64
_DIGEST_UNKNOWN = "sha256:" + "z" * 64


@pytest.fixture
def trust_root(tmp_path: Path) -> Path:
    """Test fixture cosign trust root (mocked subprocess never reads
    its contents; the file just has to exist so the path resolves)."""

    p = tmp_path / "cognic-cosign.pub"
    p.write_text("# fixture cosign pubkey (mocked subprocess does not read)\n")
    return p


@pytest.fixture
def catalog(trust_root: Path) -> CanonicalImageCatalog:
    return CanonicalImageCatalog(
        canonical_refs=frozenset(
            {
                _CANONICAL_PYTHON,
                _CANONICAL_SHELL,
                _CANONICAL_DATA,
                _CANONICAL_PROXY,
            }
        ),
        tenant_trust_roots={"t-1": trust_root},
        tenant_allow_lists={"t-1": frozenset({_TENANT_PACK_IMAGE})},
    )


def _make_fake_subprocess(
    *, returncode: int, stdout: bytes = b"", stderr: bytes = b""
) -> AsyncMock:
    """Returns an AsyncMock suitable for patching
    ``asyncio.create_subprocess_exec``. The returned mock's
    ``.communicate()`` coroutine yields the configured
    ``(stdout, stderr)``; ``.returncode`` reads as the configured
    int."""

    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.returncode = returncode
    return AsyncMock(return_value=proc)


# ---------------------------------------------------------------------------
# Membership tests
# ---------------------------------------------------------------------------


class TestCatalogMembership:
    def test_canonical_image_passes_membership(self, catalog: CanonicalImageCatalog) -> None:
        assert catalog.is_canonical(_DIGEST_PYTHON)

    def test_non_canonical_image_fails_membership(self, catalog: CanonicalImageCatalog) -> None:
        assert not catalog.is_canonical(_DIGEST_UNKNOWN)

    def test_tenant_allow_listed_image_passes(self, catalog: CanonicalImageCatalog) -> None:
        assert catalog.is_tenant_allow_listed(_DIGEST_PACK, "t-1")

    def test_cross_tenant_allow_list_lookup_fails(self, catalog: CanonicalImageCatalog) -> None:
        """A pack image allow-listed for t-1 MUST NOT appear in
        t-other's allow-list (per-tenant isolation)."""

        assert not catalog.is_tenant_allow_listed(_DIGEST_PACK, "t-other")

    def test_unknown_image_fails_both(self, catalog: CanonicalImageCatalog) -> None:
        assert not catalog.is_canonical(_DIGEST_UNKNOWN)
        assert not catalog.is_tenant_allow_listed(_DIGEST_UNKNOWN, "t-1")

    def test_unknown_tenant_returns_empty_allow_list(self, catalog: CanonicalImageCatalog) -> None:
        """A tenant with no entry in ``tenant_allow_lists`` returns
        an empty frozenset; ``is_tenant_allow_listed`` returns False
        for ANY digest (NOT KeyError + NOT silent True)."""

        assert not catalog.is_tenant_allow_listed(_DIGEST_PACK, "tenant-with-no-entry")


# ---------------------------------------------------------------------------
# cosign verification (whole-method mock layer)
# ---------------------------------------------------------------------------


class TestCosignVerification:
    async def test_cosign_verify_passes_for_signed_canonical_image(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        with patch.object(
            catalog,
            "_run_cosign_verify",
            new=AsyncMock(return_value=CosignVerifyResult(passed=True, detail="ok")),
        ):
            result = await catalog.verify_cosign(_DIGEST_PYTHON, tenant_id="t-1")
            assert result.passed is True

    async def test_cosign_verify_fail_raises_refusal(self, catalog: CanonicalImageCatalog) -> None:
        with patch.object(
            catalog,
            "_run_cosign_verify",
            new=AsyncMock(
                return_value=CosignVerifyResult(
                    passed=False, detail="signature does not match trust root"
                )
            ),
        ):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                await catalog.verify_cosign_or_refuse(_DIGEST_PYTHON, tenant_id="t-1")
            assert exc.value.reason == "sandbox_image_cosign_verification_failed"
            assert "signature does not match trust root" in exc.value.detail

    async def test_cosign_binary_missing_is_fail_closed_refusal(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        """No cosign on PATH → refuse fail-closed; do NOT skip the
        check. ``FileNotFoundError`` translates to closed-enum
        ``sandbox_image_cosign_verification_failed``."""

        with patch.object(
            catalog,
            "_run_cosign_verify",
            new=AsyncMock(side_effect=FileNotFoundError("cosign not on PATH")),
        ):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                await catalog.verify_cosign_or_refuse(_DIGEST_PYTHON, tenant_id="t-1")
            assert exc.value.reason == "sandbox_image_cosign_verification_failed"
            assert "cosign" in exc.value.detail


# ---------------------------------------------------------------------------
# SBOM verification (whole-method mock layer)
# ---------------------------------------------------------------------------


class TestSBOMVerification:
    async def test_sbom_blocked_license_raises_refusal(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        with patch.object(
            catalog,
            "_run_syft_inspect",
            new=AsyncMock(
                return_value=SBOMVerifyResult(
                    passed=False, detail="GPL-3.0 detected in transitive deps"
                )
            ),
        ):
            with pytest.raises(SandboxLifecycleRefused) as exc:
                await catalog.verify_sbom_policy_or_refuse(_DIGEST_PYTHON, tenant_id="t-1")
            assert exc.value.reason == "sandbox_image_sbom_check_failed"
            assert "GPL-3.0" in exc.value.detail


# ---------------------------------------------------------------------------
# Subprocess-boundary tests — exercises real parsing code
# ---------------------------------------------------------------------------


class TestRealSubprocessVerification:
    """Round-6 R6 P1 #2 fix: patch ``asyncio.create_subprocess_exec``
    at the subprocess boundary so the real ``_run_cosign_verify`` +
    ``_run_syft_inspect`` code runs (JSON parsing, default-deny
    license policy, reverse-map lookup, subprocess failure handling).
    Without these tests, the whole-method monkeypatch above leaves
    the actual subprocess + parsing logic uncovered."""

    async def test_run_cosign_verify_returns_passed_on_subprocess_exit_zero(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_subprocess(returncode=0, stdout=b"Verified OK")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is True
        assert "Verified OK" in result.detail

    async def test_run_cosign_verify_returns_fail_on_subprocess_exit_nonzero(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_subprocess(returncode=1, stderr=b"signature mismatch")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "signature mismatch" in result.detail

    async def test_run_cosign_verify_returns_fail_when_digest_not_in_reverse_map(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        """Bug-class guard per spec §10 — admission step 6 should
        catch this first, but the catalog's ``_run_cosign_verify``
        MUST also refuse if the digest isn't in
        ``_digest_to_ref``. Defence-in-depth."""

        result = await catalog._run_cosign_verify(_DIGEST_UNKNOWN, tenant_id="t-1")
        assert result.passed is False
        assert "not in catalog reverse-map" in result.detail

    async def test_run_cosign_verify_returns_fail_when_no_trust_root_for_tenant(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        """A tenant with no ``tenant_trust_roots`` entry triggers
        a fail-loud refusal — cosign cannot run without a trust
        root and MUST NOT silently fall through to the default."""

        result = await catalog._run_cosign_verify(
            _DIGEST_PYTHON, tenant_id="tenant-with-no-trust-root"
        )
        assert result.passed is False
        assert "no trust root" in result.detail

    async def test_run_syft_inspect_passes_on_clean_sbom(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A canonical image's SBOM with only MIT + Apache-2.0
        artifacts passes the default-deny policy."""

        clean_sbom = {
            "artifacts": [
                {
                    "name": "requests",
                    "version": "2.31",
                    "licenses": [{"value": "Apache-2.0"}],
                },
                {
                    "name": "click",
                    "version": "8.1",
                    "licenses": [{"value": "MIT"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(clean_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is True
        assert "2 artifacts" in result.detail

    async def test_run_syft_inspect_fails_on_gpl3_detected(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad_sbom = {
            "artifacts": [
                {
                    "name": "readline",
                    "version": "8.0",
                    "licenses": [{"value": "GPL-3.0"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(bad_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "GPL-3.0" in result.detail
        assert "denied" in result.detail

    async def test_run_syft_inspect_default_deny_for_unknown_license(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """License neither in allowed nor in denied → refuse
        (default-deny per the policy doctrine in spec §9 + ADR-016
        amendment). Loss case: silent-allow of BUSL-1.1 (Business
        Source License) into a regulated bank deployment."""

        unknown_sbom = {
            "artifacts": [
                {
                    "name": "exotic-lib",
                    "version": "1.0",
                    "licenses": [{"value": "BUSL-1.1"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(unknown_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "BUSL-1.1" in result.detail
        assert "not in allow-list" in result.detail

    async def test_run_syft_inspect_returns_fail_on_subprocess_nonzero(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_subprocess(returncode=2, stderr=b"syft: unable to inspect image")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "syft exited 2" in result.detail

    async def test_run_syft_inspect_returns_fail_when_digest_not_in_reverse_map(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        """Defence-in-depth guard mirroring the cosign variant."""

        result = await catalog._run_syft_inspect(_DIGEST_UNKNOWN, tenant_id="t-1")
        assert result.passed is False
        assert "not in catalog reverse-map" in result.detail


# ---------------------------------------------------------------------------
# SBOM tenant-specific policy override
# ---------------------------------------------------------------------------


class TestTenantPolicyComposeSemantics:
    """T6 R3 P1 #1 fix: ADR-016 doctrine — tenants may TIGHTEN the
    kernel license policy (add denied, narrow allowed) but NEVER
    LOOSEN (cannot remove from kernel denied; cannot allow a license
    outside kernel allowed). Without these pins, a tenant overlay
    could silently re-allow GPL-3.0 / AGPL-3.0 into a bank deployment
    — a kernel-level posture violation that ADR-016 forbids without
    a kernel + ADR amendment."""

    async def test_tenant_cannot_loosen_kernel_denied_license(
        self, trust_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tenant that tries to allow-list GPL-3.0 (which the kernel
        denies) MUST still see GPL-3.0 refused — the kernel denied set
        is unioned with the tenant denied set; the tenant cannot
        remove an entry from the kernel set."""

        loosening_catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({_CANONICAL_PYTHON}),
            tenant_trust_roots={"open-source-tenant": trust_root},
            tenant_allow_lists={"open-source-tenant": frozenset()},
            tenant_license_policies={
                "open-source-tenant": {
                    "denied": frozenset(),
                    "allowed": frozenset({"GPL-3.0", "MIT"}),
                },
            },
        )
        gpl_sbom = {
            "artifacts": [
                {
                    "name": "readline",
                    "version": "8.0",
                    "licenses": [{"value": "GPL-3.0"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(gpl_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await loosening_catalog._run_syft_inspect(
            _DIGEST_PYTHON, tenant_id="open-source-tenant"
        )
        # Tenant tried to allow GPL-3.0; kernel still denies it.
        assert result.passed is False
        assert "GPL-3.0" in result.detail
        assert "denied" in result.detail

    async def test_tenant_can_add_denied_license(
        self, trust_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tenant that adds Apache-2.0 to denied refuses an
        Apache-2.0 SBOM (effective denied = kernel UNION tenant).
        Apache-2.0 is in the kernel allowed set, but the tenant's
        denied entry takes precedence."""

        strict_catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({_CANONICAL_PYTHON}),
            tenant_trust_roots={"strict-tenant": trust_root},
            tenant_allow_lists={"strict-tenant": frozenset()},
            tenant_license_policies={
                "strict-tenant": {
                    "denied": frozenset({"Apache-2.0"}),
                },
            },
        )
        apache_sbom = {
            "artifacts": [
                {
                    "name": "requests",
                    "version": "2.31",
                    "licenses": [{"value": "Apache-2.0"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(apache_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await strict_catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="strict-tenant")
        assert result.passed is False
        assert "Apache-2.0" in result.detail
        assert "denied" in result.detail

    async def test_tenant_can_narrow_allowed_set(
        self, trust_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tenant that allows only MIT refuses an Apache-2.0 SBOM
        even though Apache-2.0 is in the kernel allowed set
        (effective allowed = kernel ∩ tenant)."""

        narrow_catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({_CANONICAL_PYTHON}),
            tenant_trust_roots={"mit-only-tenant": trust_root},
            tenant_allow_lists={"mit-only-tenant": frozenset()},
            tenant_license_policies={
                "mit-only-tenant": {
                    "allowed": frozenset({"MIT"}),
                },
            },
        )
        apache_sbom = {
            "artifacts": [
                {
                    "name": "requests",
                    "version": "2.31",
                    "licenses": [{"value": "Apache-2.0"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(apache_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await narrow_catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="mit-only-tenant")
        assert result.passed is False
        assert "Apache-2.0" in result.detail
        assert "not in allow-list" in result.detail

    async def test_tenant_cannot_allow_license_outside_kernel_allowed(
        self, trust_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tenant that tries to allow LGPL-3.0 (NOT in kernel
        allowed; NOT in kernel denied) MUST still see LGPL-3.0
        refused under default-deny because the intersection of
        kernel allowed and tenant allowed does NOT include LGPL-3.0."""

        catalog_with_lgpl_allow = CanonicalImageCatalog(
            canonical_refs=frozenset({_CANONICAL_PYTHON}),
            tenant_trust_roots={"tenant-wanting-lgpl": trust_root},
            tenant_allow_lists={"tenant-wanting-lgpl": frozenset()},
            tenant_license_policies={
                "tenant-wanting-lgpl": {
                    "allowed": frozenset({"LGPL-3.0", "MIT"}),
                },
            },
        )
        lgpl_sbom = {
            "artifacts": [
                {
                    "name": "some-lib",
                    "version": "1.0",
                    "licenses": [{"value": "LGPL-3.0"}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(lgpl_sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog_with_lgpl_allow._run_syft_inspect(
            _DIGEST_PYTHON, tenant_id="tenant-wanting-lgpl"
        )
        assert result.passed is False
        assert "LGPL-3.0" in result.detail
        assert "not in allow-list" in result.detail


# ---------------------------------------------------------------------------
# T6 R3 P1 #2 fix: missing-license-info → default-deny
# ---------------------------------------------------------------------------


class TestMissingLicenseInfoDefaultDeny:
    """T6 R3 P1 #2 fix: SBOM policy MUST refuse artifacts with no
    license info (empty ``licenses`` list, missing ``licenses`` key,
    or empty ``value`` string). Loss case: unlabeled dep silently
    runs in the sandbox — could be GPL-3.0 or anything."""

    async def test_run_syft_inspect_fails_when_artifact_has_empty_licenses_list(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sbom = {
            "artifacts": [
                {"name": "unlabeled-dep", "version": "1.0", "licenses": []},
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "<no license info>" in result.detail
        assert "default-deny per missing-license policy" in result.detail

    async def test_run_syft_inspect_fails_when_artifact_has_no_licenses_key(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sbom = {
            "artifacts": [
                {"name": "missing-licenses-key", "version": "2.0"},
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "<no license info>" in result.detail

    async def test_run_syft_inspect_fails_when_licenses_key_is_null(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """syft has been observed to emit ``"licenses": null`` for
        artifacts where the license-detector returned no result. The
        ``or []`` fallback collapses None into the empty-list case."""

        sbom = {
            "artifacts": [
                {
                    "name": "null-licenses-dep",
                    "version": "3.0",
                    "licenses": None,
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "<no license info>" in result.detail

    async def test_run_syft_inspect_fails_when_license_value_is_empty_string(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An entry of ``{"value": ""}`` is the same default-deny case
        as a missing entry — surfaces under the per-entry
        ``<empty license value>`` violation."""

        sbom = {
            "artifacts": [
                {
                    "name": "empty-license-value-dep",
                    "version": "4.0",
                    "licenses": [{"value": ""}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "<empty license value>" in result.detail


# ---------------------------------------------------------------------------
# T6 R3 P1 #3 fix: syft binary missing + malformed JSON
# ---------------------------------------------------------------------------


class TestSyftLaunchAndParseFailures:
    """T6 R3 P1 #3 fix: syft launch failures + malformed JSON output
    MUST translate to closed-enum ``sandbox_image_sbom_check_failed``
    via ``verify_sbom_policy_or_refuse`` — not leak raw Python
    exceptions through admission. Symmetric with cosign per
    ``feedback_symmetric_exception_ordering``."""

    async def test_syft_binary_missing_via_pure_result_returns_fail(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pure-result ``_run_syft_inspect`` catches OSError on
        launch + returns ``SBOMVerifyResult(passed=False)`` with a
        ``failed to launch syft`` detail."""

        def _raise_oserror(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError(2, "No such file or directory", "syft")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _raise_oserror)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "failed to launch syft" in result.detail

    async def test_syft_binary_missing_via_or_refuse_raises_refusal(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end through ``verify_sbom_policy_or_refuse``: syft
        missing → closed-enum ``sandbox_image_sbom_check_failed``."""

        def _raise_oserror(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError(2, "No such file or directory", "syft")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _raise_oserror)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await catalog.verify_sbom_policy_or_refuse(_DIGEST_PYTHON, tenant_id="t-1")
        assert exc.value.reason == "sandbox_image_sbom_check_failed"
        assert "failed to launch syft" in exc.value.detail

    async def test_run_syft_inspect_fails_on_malformed_json_output(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """syft exits 0 but stdout is not valid JSON — fail-closed
        via pure-result API. Loss case: hostile registry returning
        non-JSON output (or a syft version change) silently passes
        admission because ``json.JSONDecodeError`` escapes the
        SandboxRefusalReason taxonomy."""

        fake = _make_fake_subprocess(returncode=0, stdout=b"this is not json {{{")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "not valid JSON" in result.detail

    async def test_malformed_json_via_or_refuse_raises_refusal(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end: malformed JSON → closed-enum
        ``sandbox_image_sbom_check_failed`` via the wrapper."""

        fake = _make_fake_subprocess(returncode=0, stdout=b"<html><body>error</body></html>")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await catalog.verify_sbom_policy_or_refuse(_DIGEST_PYTHON, tenant_id="t-1")
        assert exc.value.reason == "sandbox_image_sbom_check_failed"
        assert "not valid JSON" in exc.value.detail


# ---------------------------------------------------------------------------
# T6 R3 P2 #4 fix: subprocess timeout + minimal env
# ---------------------------------------------------------------------------


class TestSubprocessTimeoutAndMinimalEnv:
    """T6 R3 P2 #4 fix: cosign + syft subprocesses are bounded via
    ``asyncio.wait_for`` with kill+reap on timeout, and run with a
    minimal explicit env (PATH + HOME only) — never inheriting
    ``os.environ``. Mirrors the Sprint-4 trust-gate discipline at
    ``protocol/trust_gate.py:97`` (_SUBPROCESS_ENV) + ``:588-607``
    (wait_for + kill + reap)."""

    async def test_run_cosign_verify_timeout_kills_process_and_returns_fail(
        self,
        trust_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A hung cosign subprocess MUST be killed + reaped + the
        admission MUST refuse with a timeout-detail
        ``CosignVerifyResult(passed=False)``."""

        # Tight 0.05s timeout so the test runs fast.
        tight_catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({_CANONICAL_PYTHON}),
            tenant_trust_roots={"t-1": trust_root},
            tenant_allow_lists={"t-1": frozenset()},
            cosign_verify_timeout_s=0.05,
        )

        kill_called = []
        wait_called = []

        # Fake proc whose communicate() hangs (sleeps longer than the
        # tight timeout) so wait_for fires TimeoutError + the kill +
        # reap path runs.
        async def _hanging_communicate() -> tuple[bytes, bytes]:
            await asyncio.sleep(10.0)
            return (b"", b"")

        proc = AsyncMock()
        proc.communicate = _hanging_communicate
        proc.kill = lambda: kill_called.append(True)
        proc.wait = AsyncMock(side_effect=lambda: wait_called.append(True))
        monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))

        result = await tight_catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "timed out after 0.05s" in result.detail
        # SIGKILL + reap both fired — no zombie process leak.
        assert kill_called == [True]
        assert wait_called == [True]

    async def test_run_syft_inspect_timeout_kills_process_and_returns_fail(
        self,
        trust_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Symmetric with cosign — hung syft MUST be killed + reaped."""

        tight_catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({_CANONICAL_PYTHON}),
            tenant_trust_roots={"t-1": trust_root},
            tenant_allow_lists={"t-1": frozenset()},
            syft_inspect_timeout_s=0.05,
        )

        kill_called = []
        wait_called = []

        async def _hanging_communicate() -> tuple[bytes, bytes]:
            await asyncio.sleep(10.0)
            return (b"", b"")

        proc = AsyncMock()
        proc.communicate = _hanging_communicate
        proc.kill = lambda: kill_called.append(True)
        proc.wait = AsyncMock(side_effect=lambda: wait_called.append(True))
        monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))

        result = await tight_catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "timed out after 0.05s" in result.detail
        assert kill_called == [True]
        assert wait_called == [True]

    async def test_cosign_subprocess_invoked_with_minimal_env(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cosign subprocess MUST be launched with env={PATH, HOME}
        ONLY — never inheriting ``os.environ``. Loss case: cosign
        inherits AWS_*, VAULT_TOKEN, OIDC bearer tokens, etc."""

        captured_env: dict[str, object] = {}

        async def _capturing_exec(*args: object, **kwargs: object) -> AsyncMock:
            captured_env["env"] = kwargs.get("env")
            proc = AsyncMock()
            proc.communicate = AsyncMock(return_value=(b"Verified OK", b""))
            proc.returncode = 0
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _capturing_exec)
        await catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        env = captured_env["env"]
        assert env is not None
        assert isinstance(env, dict)
        assert set(env.keys()) == {"PATH", "HOME"}

    async def test_syft_subprocess_invoked_with_minimal_env(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """syft subprocess MUST be launched with the same minimal env
        as cosign — symmetric subprocess discipline."""

        captured_env: dict[str, object] = {}
        clean_sbom: dict[str, list[object]] = {"artifacts": []}

        async def _capturing_exec(*args: object, **kwargs: object) -> AsyncMock:
            captured_env["env"] = kwargs.get("env")
            proc = AsyncMock()
            proc.communicate = AsyncMock(return_value=(json.dumps(clean_sbom).encode(), b""))
            proc.returncode = 0
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _capturing_exec)
        await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        env = captured_env["env"]
        assert env is not None
        assert isinstance(env, dict)
        assert set(env.keys()) == {"PATH", "HOME"}


# ---------------------------------------------------------------------------
# CC pin: T6 catalog structurally conforms to T5's CatalogProtocol
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# T6 R4 P1 #1 fix: Syft JSON shape validation (parses, but wrong shape)
# ---------------------------------------------------------------------------


class TestSyftJSONShapeValidation:
    """T6 R4 P1 #1 fix: ``_run_syft_inspect`` MUST fail-closed on
    valid JSON that doesn't match the expected SBOM shape
    (``{"artifacts": [{"name": ..., "licenses": [{"value": ...}]}]}``).
    Without these guards, schema drift in syft output OR a hostile
    registry returning wrong-shape valid JSON raises raw
    AttributeError/TypeError and escapes the
    ``sandbox_image_sbom_check_failed`` closed-enum taxonomy."""

    async def test_run_syft_inspect_fails_when_sbom_is_json_list(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Top-level JSON is a list `[]` — refuse with shape error."""

        fake = _make_fake_subprocess(returncode=0, stdout=b"[]")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "list" in result.detail
        assert "expected object" in result.detail

    async def test_run_syft_inspect_fails_when_sbom_is_json_null(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Top-level JSON is `null` — refuse with shape error."""

        fake = _make_fake_subprocess(returncode=0, stdout=b"null")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "NoneType" in result.detail
        assert "expected object" in result.detail

    async def test_run_syft_inspect_fails_when_sbom_is_json_string(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Top-level JSON is a string — refuse with shape error."""

        fake = _make_fake_subprocess(returncode=0, stdout=b'"not an object"')
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "str" in result.detail
        assert "expected object" in result.detail

    async def test_run_syft_inspect_fails_when_artifacts_is_not_a_list(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`artifacts` value is a dict instead of a list — refuse
        with shape error before iteration."""

        sbom = {"artifacts": {"unexpected": "dict-not-list"}}
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "`artifacts` is dict" in result.detail
        assert "expected list" in result.detail

    async def test_run_syft_inspect_fails_when_artifacts_key_missing(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R5 P1 #1 fix: a dict with NO ``artifacts`` key MUST
        fail-closed — NOT silently pass as ``sbom passed; 0
        artifacts``. Loss case avoided: syft schema drift or hostile
        registry emitting ``{}`` bypasses the license inventory
        entirely. Distinguishes from the valid-empty case (explicit
        ``"artifacts": []``)."""

        fake = _make_fake_subprocess(returncode=0, stdout=b"{}")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "missing `artifacts` key" in result.detail

    async def test_run_syft_inspect_passes_when_artifacts_is_explicit_empty_list(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R5 P1 #1 contract: an explicit ``"artifacts": []``
        remains the valid-empty case (a static binary with no
        runtime deps; zero-dep image). Distinguishes from the
        missing-key schema violation above."""

        sbom: dict[str, list[object]] = {"artifacts": []}
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is True
        assert "0 artifacts" in result.detail

    async def test_run_syft_inspect_fails_when_artifacts_is_explicit_null(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R5 P1 #1 follow-on: an explicit ``"artifacts": null``
        is NOT a missing key (the key IS present) but the value is
        not a list — refuses via the isinstance check as
        ``NoneType, expected list`` (a separate failure path from
        the missing-key error)."""

        fake = _make_fake_subprocess(returncode=0, stdout=b'{"artifacts": null}')
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "`artifacts` is NoneType" in result.detail
        assert "expected list" in result.detail

    async def test_run_syft_inspect_fails_when_license_value_is_list(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R6 P1 #1 fix: license value is a list (unhashable) —
        MUST refuse via structured schema violation instead of
        raising raw TypeError on the ``in policy["denied"]``
        membership check. Loss case avoided: hostile registry or
        syft version-drift emitting ``{"value": ["MIT", "BSD"]}``
        bypasses the closed-enum refusal taxonomy."""

        sbom = {
            "artifacts": [
                {
                    "name": "list-license-value",
                    "version": "1.0",
                    "licenses": [{"value": ["MIT", "BSD-3-Clause"]}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "license value is list" in result.detail
        assert "syft schema violation" in result.detail

    async def test_run_syft_inspect_fails_when_license_value_is_dict(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R6 P1 #1 fix: license value is a dict (unhashable) —
        same TypeError class as the list case."""

        sbom = {
            "artifacts": [
                {
                    "name": "dict-license-value",
                    "version": "1.0",
                    "licenses": [{"value": {"id": "MIT", "url": "..."}}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "license value is dict" in result.detail
        assert "syft schema violation" in result.detail

    async def test_run_syft_inspect_fails_when_license_value_is_int(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R6 P1 #1 fix: license value is an int (hashable but
        not str) — would silently fall through to the default-deny
        path with a misleading ``42 (not in allow-list)`` detail
        otherwise. New isinstance check produces a clean schema-
        violation message."""

        sbom = {
            "artifacts": [
                {
                    "name": "int-license-value",
                    "version": "1.0",
                    "licenses": [{"value": 42}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "license value is int" in result.detail
        assert "syft schema violation" in result.detail

    async def test_run_syft_inspect_fails_when_license_value_is_null(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """T6 R6 P1 #1 fix: explicit ``"value": null`` is a
        non-string value (NoneType) — distinct failure path from
        missing-value-key (which falls back to ``""`` and surfaces
        as the ``<empty license value>`` default-deny case)."""

        fake = _make_fake_subprocess(
            returncode=0,
            stdout=(
                b'{"artifacts": [{"name": "null-license-value", '
                b'"version": "1.0", "licenses": [{"value": null}]}]}'
            ),
        )
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "license value is NoneType" in result.detail
        assert "syft schema violation" in result.detail


# ---------------------------------------------------------------------------
# T6 R7 P2 fix: SBOM-derived display fields are bounded
# ---------------------------------------------------------------------------


class TestSBOMDerivedFieldsBounded:
    """T6 R7 P2 fix: SBOM-derived display fields (artifact name,
    version, license value) MUST be bounded so an attacker-
    controlled SBOM with pathological-length fields cannot inflate
    the chain-row payload via the violation detail string. R4
    bounded subprocess stdout/stderr; R7 closes the gap for SBOM
    field contents that flow through the violation list."""

    async def test_run_syft_inspect_truncates_huge_artifact_name(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 20k-char artifact name MUST surface in the violation
        detail truncated with an ellipsis marker. Without the bound,
        every violation entry for this artifact carries the full
        20k chars."""

        huge_name = "x" * 20000
        sbom = {
            "artifacts": [
                {
                    "name": huge_name,
                    "version": "1.0",
                    "licenses": [],  # triggers <no license info> default-deny
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        # Detail length must be bounded — well under 1k for one
        # violation with one bounded name.
        assert len(result.detail) < 1024
        # The huge name doesn't appear verbatim — truncated.
        assert huge_name not in result.detail
        # Ellipsis marker present per the _bounded_field contract.
        assert "..." in result.detail

    async def test_run_syft_inspect_truncates_huge_artifact_version(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same bound applies to artifact version (tighter cap =
        64 chars)."""

        huge_version = "v" * 5000
        sbom = {
            "artifacts": [
                {
                    "name": "test-pkg",
                    "version": huge_version,
                    "licenses": [],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert len(result.detail) < 1024
        assert huge_version not in result.detail
        assert "..." in result.detail

    async def test_run_syft_inspect_fails_when_license_value_too_long(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An over-length license value (e.g. 1000 chars) surfaces
        as a structured ``license value too long`` schema violation
        instead of flowing into the membership check with its full
        length. Loss case avoided: a 20k-char license value
        inflates the chain payload via the policy-violation entry."""

        huge_license = "L" * 1000
        sbom = {
            "artifacts": [
                {
                    "name": "huge-license-pkg",
                    "version": "1.0",
                    "licenses": [{"value": huge_license}],
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "license value too long" in result.detail
        # Exact char count surfaces in the message for operator
        # debugging without including the value itself.
        assert "1000 chars" in result.detail
        assert "max 256" in result.detail
        # The huge license value does NOT appear in the detail.
        assert huge_license not in result.detail
        assert len(result.detail) < 1024

    async def test_run_syft_inspect_caps_final_detail_string(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defense-in-depth: the composite detail string (head +
        tail across many violations) MUST be capped even if per-
        field bounds were somehow bypassed.

        R8 P3 fix per feedback_security_regression_hardening:
        the prior version of this test was vacuous — the natural
        detail was only ~410 chars (far under the 4096 default cap),
        so removing the ``if len(detail) > _MAX_SBOM_DETAIL_CHARS``
        branch left the test still passing (TM-revert would have
        produced identical output). This rewrite monkeypatches the
        cap to a small value (100 chars) so the cap branch actually
        fires on natural violations, and asserts both the bounded
        length AND the ellipsis marker — both would fail under
        TM-revert."""

        # Monkeypatch the cap constant to a tiny value so even a
        # handful of bounded-field violations overflow it. Read site
        # is at function-call time, so the patched value takes
        # effect; auto-reverted at teardown.
        small_cap = 100
        monkeypatch.setattr(
            "cognic_agentos.sandbox.catalog._MAX_SBOM_DETAIL_CHARS",
            small_cap,
        )

        # 10 missing-license artifacts. Each violation is ~75 chars
        # so the head (first 5 joined with "; ") + tail (+5 more)
        # easily exceeds the patched 100-char cap.
        sbom = {
            "artifacts": [
                {
                    "name": f"pkg-{i}",
                    "version": "1.0",
                    "licenses": [],
                }
                for i in range(10)
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        # Length-bound assertion: with the patched cap, detail must
        # be ≤ small_cap + len("...") — load-bearing iff the cap
        # branch actually executed.
        assert len(result.detail) <= small_cap + len("...")
        # Ellipsis-marker assertion: the cap branch appends "..." to
        # the truncated detail; absence proves the branch did NOT
        # execute (TM-revert proof: removing the cap branch fails
        # this assertion).
        assert result.detail.endswith("...")

    async def test_run_syft_inspect_fails_when_artifact_entry_is_string(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An artifact entry that's a string (not a dict) — surface
        per-entry shape violation; SBOM fails overall."""

        sbom = {"artifacts": ["bad"]}
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "<non-dict artifact at index 0>" in result.detail
        assert "str" in result.detail
        assert "syft schema violation" in result.detail

    async def test_run_syft_inspect_fails_when_license_entry_is_string(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A license entry that's a string (not a dict like
        ``{"value": "MIT"}``) — surface per-license shape violation."""

        sbom = {
            "artifacts": [
                {
                    "name": "bad-license-shape",
                    "version": "1.0",
                    "licenses": ["MIT"],  # should be [{"value": "MIT"}]
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "license entry is str" in result.detail
        assert "syft schema violation" in result.detail

    async def test_run_syft_inspect_fails_when_artifact_licenses_is_dict(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``licenses`` field is a dict (not a list) — surface
        per-artifact shape violation before iteration raises TypeError."""

        sbom = {
            "artifacts": [
                {
                    "name": "dict-licenses",
                    "version": "1.0",
                    "licenses": {"unexpected": "dict"},
                },
            ]
        }
        fake = _make_fake_subprocess(returncode=0, stdout=json.dumps(sbom).encode())
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "`licenses` is dict" in result.detail
        assert "syft schema violation" in result.detail

    async def test_run_syft_inspect_fails_on_non_utf8_stdout(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """syft stdout is non-UTF-8 bytes (e.g. UTF-16 BOM followed
        by non-decodable sequence) — UnicodeDecodeError catch
        translates to fail-closed via the pure-result API."""

        # \xff\xfe is the UTF-16 LE BOM; json.loads(bytes) tries to
        # auto-detect encoding from the first 4 bytes and may raise
        # UnicodeDecodeError on subsequent non-decodable bytes.
        fake = _make_fake_subprocess(returncode=0, stdout=b"\xff\xfe\xff\xfe\xff")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        # Either path is acceptable — UnicodeDecodeError OR
        # JSONDecodeError. The contract is: never raises; always
        # returns SBOMVerifyResult(passed=False).
        assert "not valid" in result.detail


# ---------------------------------------------------------------------------
# T6 R4 P1 #2 fix: subprocess output decode is bounded + replace-on-invalid
# ---------------------------------------------------------------------------


class TestSubprocessOutputDecodeBoundedAndSafe:
    """T6 R4 P1 #2 fix: cosign + syft stdout/stderr decoding uses
    ``errors='replace'`` + bounded length cap so non-UTF-8 bytes
    never raise UnicodeDecodeError out of the refusal path. Without
    these guards, a binary emitting non-UTF-8 bytes on stderr
    (locale-mismatched cosign, hostile registry surfaced through
    syft) escapes the closed-enum taxonomy via the raw
    ``stderr.decode()`` call."""

    async def test_run_cosign_verify_succeeds_with_replacement_chars_on_non_utf8_stdout(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cosign exit 0 with non-UTF-8 stdout: returns passed=True
        with replacement chars in detail (NOT raw UnicodeDecodeError)."""

        # b'\xff\xfe' is an invalid UTF-8 byte sequence; preceded by
        # "OK" prefix to verify the replacement char appears mid-string.
        fake = _make_fake_subprocess(returncode=0, stdout=b"OK\xff\xfe!")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is True
        # Unicode REPLACEMENT CHARACTER (U+FFFD) appears in the detail
        # in place of the invalid bytes.
        assert "OK" in result.detail
        assert "�" in result.detail

    async def test_run_cosign_verify_fails_with_replacement_chars_on_non_utf8_stderr(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cosign non-zero exit with non-UTF-8 stderr: returns
        passed=False with replacement chars in detail."""

        fake = _make_fake_subprocess(returncode=1, stderr=b"signature mismatch \xff\xfe \xc3\x28")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "signature mismatch" in result.detail
        assert "�" in result.detail

    async def test_run_syft_inspect_fails_with_replacement_chars_on_non_utf8_stderr(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """syft non-zero exit with non-UTF-8 stderr: returns
        passed=False with replacement chars in detail."""

        fake = _make_fake_subprocess(returncode=2, stderr=b"syft error \xff\xfe \xc3\x28")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_syft_inspect(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert "syft exited 2" in result.detail
        assert "syft error" in result.detail
        assert "�" in result.detail

    async def test_subprocess_output_decode_truncates_at_1024_chars(
        self, catalog: CanonicalImageCatalog, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A multi-MB stderr stream MUST be truncated at the bounded
        cap so the chain payload doesn't bloat unboundedly. Loss
        case if absent: attacker-controlled stderr inflates audit
        chain rows by megabytes."""

        # 4 KB of stderr; we expect truncation to <= 1024 chars.
        huge_stderr = b"error " * 1000  # 6000 bytes
        fake = _make_fake_subprocess(returncode=1, stderr=huge_stderr)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        result = await catalog._run_cosign_verify(_DIGEST_PYTHON, tenant_id="t-1")
        assert result.passed is False
        assert len(result.detail) <= 1024


# ---------------------------------------------------------------------------
# CC pin: T6 catalog structurally conforms to T5's CatalogProtocol
# ---------------------------------------------------------------------------


class TestCatalogProtocolStructuralConformance:
    """T6 ships CanonicalImageCatalog as the concrete impl that T5's
    admit_policy consumes via CatalogProtocol. This pin catches a
    future refactor that renames a Protocol-required method
    (which would only fail at admit_policy's first call otherwise).

    Per ``feedback_consumer_owned_protocol_for_unlanded_dep``: the
    Protocol is owned by sandbox/admission.py (consumer); T6
    structurally conforms. ``runtime_checkable`` + ``isinstance``
    are the structural-conformance gate."""

    def test_canonical_image_catalog_satisfies_catalog_protocol(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        assert isinstance(catalog, CatalogProtocol)

    def test_canonical_image_catalog_has_all_4_protocol_methods(
        self, catalog: CanonicalImageCatalog
    ) -> None:
        # Direct method-presence pin so a future test failure points at
        # the missing method by name, not just "not a CatalogProtocol".
        for name in (
            "is_canonical",
            "is_tenant_allow_listed",
            "verify_cosign_or_refuse",
            "verify_sbom_policy_or_refuse",
        ):
            assert hasattr(catalog, name), (
                f"CanonicalImageCatalog missing CatalogProtocol method {name!r}; "
                f"admit_policy will fail at first call"
            )
