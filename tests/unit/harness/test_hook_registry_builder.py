"""M5 (ADR-008 + ADR-017) — harness hook-registry boot loader.

``build_dlp_guard`` walks the ALREADY-TRUSTED registry candidates (trust is
upstream), admits each verified hook pack's ``[hooks]`` declarations into a
``HookRegistry`` (digest-pinned via ``register_pack``), and assembles the
``DLPGuard`` the MCP host consumes. Per-pack fail-closed: a malformed hook
pack is skipped + logged (mirrors the MCP mapper's warn-skip doctrine); the
guard still builds — and the skipped pack's hook ids then fail CLOSED at
scan time (``dlp_hook_id_unresolved``), never silently pass.

The admit test fabricates a REAL ``importlib.metadata.EntryPoint`` whose
value points at a hook class in THIS module, so ``EntryPoint.load()`` (the
deferred-load contract — pack code is NOT imported at manifest walk) is
genuinely exercised. ``importlib.metadata`` access is patched at the
module-under-test's ``md`` attribute so the stdlib stays untouched.
"""

from __future__ import annotations

import importlib.metadata as md
import logging
import types
from collections.abc import Iterator
from typing import Any, ClassVar

import pytest

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.harness.hook_registry import build_dlp_guard
from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult

_DIST = "cognic-hook-schema-guard"
_PKG = "cognic_hook_schema_guard"


class _RefuseForbiddenHook(Hook):
    """Real hook the fabricated entry-point loads FROM THIS MODULE — the
    admit test proves a genuine deferred ``EntryPoint.load()`` resolves it
    AND that its code actually runs (pass + refuse arms)."""

    hook_id: ClassVar[str] = "refuse_forbidden_schema_arg"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        if b"__FORBIDDEN__" in payload:
            return HookResult(
                decision="refuse",
                redacted_payload=None,
                policy_reason="forbidden_schema_arg",
            )
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _StubRegistry:
    def __init__(self, candidates: list[RegisteredPackCandidate]) -> None:
        self._c = candidates

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        return iter(self._c)


def _cand(digest: str | None = "sha256:" + "c" * 64) -> RegisteredPackCandidate:
    return RegisteredPackCandidate(
        distribution_name=_DIST, package_name=_PKG, signature_digest=digest
    )


_DECLARATION: dict[str, Any] = {
    "hook_id": "refuse_forbidden_schema_arg",
    "phase": "dlp_pre",
    "ordering_class": "input_validation",
    "timeout_seconds": 1.0,
    "fail_policy": "fail_closed",
}

_REAL_EP = md.EntryPoint(
    name="refuse_forbidden_schema_arg",
    value="tests.unit.harness.test_hook_registry_builder:_RefuseForbiddenHook",
    group="cognic.hooks",
)


def _fake_md(*eps: md.EntryPoint, version: str = "0.1.0", missing: bool = False) -> Any:
    """A namespace standing in for ``hook_registry.md`` — ``distribution``
    returns a dist-like carrying the given entry-points (or raises
    PackageNotFoundError when ``missing``)."""

    def _distribution(name: str) -> Any:
        if missing:
            raise md.PackageNotFoundError(name)
        return types.SimpleNamespace(entry_points=list(eps), version=version)

    return types.SimpleNamespace(
        distribution=_distribution, PackageNotFoundError=md.PackageNotFoundError
    )


def _patch(monkeypatch: pytest.MonkeyPatch, *, manifest: Any, md_ns: Any) -> None:
    monkeypatch.setattr(
        "cognic_agentos.harness.hook_registry.extract_pack_manifest",
        lambda **kw: manifest,
    )
    monkeypatch.setattr("cognic_agentos.harness.hook_registry.md", md_ns)


@pytest.fixture
def settings() -> Settings:
    return build_settings_without_env_file()


def _ctx_template(pack_id: str = "cognic-tool-oracle-schema") -> HookContext:
    return HookContext(
        hook_id="",
        phase="dlp_pre",
        pack_id=pack_id,
        tenant_id="tenant-1",
        request_id="req-1",
        trace_id=None,
        parent_trace_id=None,
        manifest_data_classes=("internal",),
        manifest_purpose="operational_telemetry",
    )


# ---------------------------------------------------------------------------
# Admission — verified pack resolves + its real hook code runs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest",
    [
        {"hooks": {"declarations": [_DECLARATION]}},
        {"tool": {"cognic": {"hooks": {"declarations": [_DECLARATION]}}}},
    ],
    ids=["canonical-hooks-block", "legacy-tool-cognic-hooks-block"],
)
async def test_build_dlp_guard_admits_verified_hook_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, manifest: dict[str, Any]
) -> None:
    _patch(monkeypatch, manifest=manifest, md_ns=_fake_md(_REAL_EP))
    guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    # the declared hook resolves (NOT dlp_hook_id_unresolved) and its REAL
    # loaded code runs: a permitted payload passes...
    outcome = await guard.scan_pre(
        payload=canonical_bytes({"table": "EMPLOYEES"}),
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "passed"
    # ...and the forbidden sentinel refuses through the SAME loaded hook.
    refused = await guard.scan_pre(
        payload=canonical_bytes({"table": "__FORBIDDEN__"}),
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert refused.outcome == "refused"
    assert refused.refusal_reason == "dlp_dispatcher_refused"
    assert refused.underlying_policy_reason == "forbidden_schema_arg"


# ---------------------------------------------------------------------------
# Per-pack fail-closed skips — the guard still builds; skipped hook ids
# fail CLOSED at scan time
# ---------------------------------------------------------------------------


async def test_declared_hook_without_entry_point_skips_pack_not_fatal(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # [hooks] declares a hook_id the distribution ships NO cognic.hooks
    # entry-point for → the whole pack is skipped (logged); guard builds.
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(),  # no entry-points
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert "hook.declaration_no_entry_point" in caplog.text
    outcome = await guard.scan_pre(
        payload=b"{}",
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "refused"
    assert outcome.refusal_reason == "dlp_hook_id_unresolved"


def test_pack_without_hooks_block_is_ignored(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # non-hook packs (no [hooks]) contribute nothing — silent, guard builds.
    _patch(
        monkeypatch,
        manifest={"tool": {"cognic": {"mcp": {"transport": "streamable-http"}}}},
        md_ns=_fake_md(_REAL_EP),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert len(caplog.records) == 0


@pytest.mark.parametrize(
    "manifest",
    [
        {"hooks": {"declarations": []}},
        {"hooks": {"declarations": "not-a-list"}},
        {"hooks": {"declarations": [_DECLARATION, "not-a-table"]}},
        {"tool": {"cognic": {"hooks": {"declarations": ["not-a-table"]}}}},
    ],
    ids=[
        "empty-declarations",
        "declarations-not-list",
        "canonical-non-table-entry",
        "legacy-non-table-entry",
    ],
)
async def test_malformed_hooks_block_skips_pack_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    caplog: pytest.LogCaptureFixture,
    manifest: dict[str, Any],
) -> None:
    # Present-but-malformed hook blocks are NOT silently treated as absent and
    # are NOT partially admitted. The whole pack is skipped fail-closed.
    _patch(monkeypatch, manifest=manifest, md_ns=_fake_md(_REAL_EP))
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert "hook.block_malformed" in caplog.text
    outcome = await guard.scan_pre(
        payload=b"{}",
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "refused"
    assert outcome.refusal_reason == "dlp_hook_id_unresolved"


async def test_missing_signature_digest_refuses_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # register_pack fail-closed (pack_not_verified) on an empty digest — the
    # pack is skipped (logged); its hook id then fails closed at scan time.
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(_REAL_EP),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand(digest=None)]), settings=settings)
    assert "hook.registry_refused" in caplog.text
    outcome = await guard.scan_pre(
        payload=b"{}",
        declared_hook_ids=("refuse_forbidden_schema_arg",),
        context_template=_ctx_template(),
    )
    assert outcome.outcome == "refused"
    assert outcome.refusal_reason == "dlp_hook_id_unresolved"


def test_malformed_declaration_field_skips_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # a declaration HookDeclaration refuses at construction (ValueError —
    # non-numeric timeout) → warn-skip, guard builds.
    bad = dict(_DECLARATION, timeout_seconds="not-a-number")
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [bad]}},
        md_ns=_fake_md(_REAL_EP),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert "hook.declaration_malformed" in caplog.text


def test_distribution_not_found_skips_pack(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    # the candidate's distribution is not importable-metadata-visible →
    # warn-skip (the trust registry saw it, the venv lost it — fail closed).
    _patch(
        monkeypatch,
        manifest={"hooks": {"declarations": [_DECLARATION]}},
        md_ns=_fake_md(missing=True),
    )
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert "hook.distribution_not_found" in caplog.text


def test_manifest_not_found_silent_skip(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

    def _raise(**kw: Any) -> Any:
        raise PackManifestNotFoundError("no manifest")

    monkeypatch.setattr("cognic_agentos.harness.hook_registry.extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert len(caplog.records) == 0  # no hook intent → silent (mapper doctrine)


def test_manifest_malformed_warns_and_skips(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    from cognic_agentos.protocol.mcp_manifest import PackManifestMalformedError

    def _raise(**kw: Any) -> Any:
        raise PackManifestMalformedError("bad toml")

    monkeypatch.setattr("cognic_agentos.harness.hook_registry.extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        guard = build_dlp_guard(registry=_StubRegistry([_cand()]), settings=settings)
    assert guard is not None
    assert "hook.pack_manifest_malformed" in caplog.text
