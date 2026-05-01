"""Sprint 4 T5 — plugin registry discovery + register API tests.

Critical-controls coverage per AGENTS.md (≥95% line / ≥90% branch on
``protocol/plugin_registry.py``). Test classes:

  * ``TestDiscovery`` — ``discover()`` walks the three entry-point
    groups and returns metadata records only. Includes the P2-K
    reviewer-fix regression (no eager ``EntryPoint.load()``).
  * ``TestRegisterSuccess`` — register a discovered pack with
    ``attestation_grade={full, partial}``; verify the
    ``RegistrationOutcome`` shape + the chained ``audit_event``
    (``plugin.registration_succeeded``).
  * ``TestRegisterRefusal`` — register with ``refusal_reason`` from
    the closed enum; verify the refused outcome + the
    ``plugin.registration_refused`` audit emission.
  * ``TestRegisterValidation`` — boundary checks for the
    success-XOR-refusal contract, closed-enum vocabulary, and pack-kind
    validation.
  * ``TestLoadAndKnownPacks`` — sync ``load`` returns the pack on
    success, raises ``RegistrationRefused`` after a refused register,
    raises ``PluginNotRegistered`` when never registered.
  * ``TestConcurrency`` — concurrent ``register`` calls serialise via
    the chain-head primitive (audit emissions are append-only and
    monotonic).
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import importlib.metadata as _im
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    PluginIdentityConflict,
    PluginKind,
    PluginNotRegistered,
    PluginRecord,
    PluginRegistry,
    RegistrationOutcome,
    RegistrationRefused,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite-aiosqlite engine with audit_event + chain_heads created
    and the audit chain head seeded — mirrors the gateway-test pattern
    in tests/unit/llm/conftest.py."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'plugin_registry_test.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=_dt.datetime.now(_dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def registry(audit_store: AuditStore) -> PluginRegistry:
    return PluginRegistry(audit_store=audit_store)


#: Test-fixture cosign signature digest. Real digests are sha256 hex
#: strings emitted by the trust gate (T6); the registry only requires
#: a non-empty string per ADR-002 + R3 reviewer-P2 fix. Tests that
#: exercise the success path supply this constant.
_TEST_SIGNATURE_DIGEST = "sha256:" + "a" * 64


def _make_record(
    *,
    kind: PluginKind = "tools",
    name: str = "demo_pack",
    distribution_name: str = "cognic-tool-demo",
    distribution_version: str = "1.0.0",
    entry_point_value: str = "cognic_tool_demo:Plugin",
) -> PluginRecord:
    return PluginRecord(
        kind=kind,
        name=name,
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        entry_point_value=entry_point_value,
    )


def _make_pack(
    *,
    kind: PluginKind = "tools",
    name: str = "demo_pack",
    distribution_name: str = "cognic-tool-demo",
    distribution_version: str = "1.0.0",
    entry_point_value: str = "cognic_tool_demo:Plugin",
    load_returns: Any = None,
) -> DiscoveredPack:
    """Build a ``DiscoveredPack`` paired with a fake EntryPoint.

    Used everywhere ``register()`` is called from a test so the
    discover→register→load flow stays exercised end-to-end. The fake
    EntryPoint supports ``load()`` returning a sentinel for tests
    that exercise the load path.
    """
    record = _make_record(
        kind=kind,
        name=name,
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        entry_point_value=entry_point_value,
    )
    ep = _FakeEntryPoint(
        name=name,
        value=entry_point_value,
        dist=_FakeDistribution(name=distribution_name, version=distribution_version),
        load_returns=load_returns,
    )
    return DiscoveredPack(record=record, entry_point=ep)  # type: ignore[arg-type]


async def _read_audit_events(engine: AsyncEngine) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        rows = (await conn.execute(select(_audit_event).order_by(_audit_event.c.sequence))).all()
    return [dict(r._mapping) for r in rows]


# ---------------------------------------------------------------------------
# TestDiscovery
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """Stand-in for ``importlib.metadata.EntryPoint``.

    Exposes the same surface ``discover()`` reads (``name`` / ``value``
    / ``dist`` / ``load``) so the real metadata-walk path is exercised
    without installing a real distribution. ``load`` is wired so the
    P2-K reviewer-fix regression can monitor whether discover()
    accidentally calls it.
    """

    def __init__(
        self,
        *,
        name: str,
        value: str,
        dist: Any,
        load_sentinel: dict[str, Any] | None = None,
        load_returns: Any = None,
    ) -> None:
        self.name = name
        self.value = value
        self.dist = dist
        self._load_sentinel = load_sentinel
        self._load_returns = load_returns

    def load(self) -> Any:
        if self._load_sentinel is not None:
            self._load_sentinel["loaded"] = True
        return self._load_returns


class _FakeDistribution:
    """``importlib.metadata.Distribution``-shaped stub."""

    def __init__(self, *, name: str, version: str) -> None:
        self._name = name
        self.version = version

    @property
    def metadata(self) -> dict[str, str]:
        # importlib's Distribution.metadata is a Message-like; for our
        # purposes a dict-like with ``Name`` is sufficient.
        return {"Name": self._name}


@pytest.fixture
def fake_entry_points(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, list[Any]]]:
    """Inject fake entry points keyed by group. Tests populate the
    ``groups`` dict and the monkeypatch routes
    ``importlib.metadata.entry_points(group=...)`` to the fake list."""
    groups: dict[str, list[Any]] = {}

    def _fake(*, group: str) -> list[Any]:
        return groups.get(group, [])

    monkeypatch.setattr(_im, "entry_points", _fake)
    yield groups


class TestDiscovery:
    def test_discover_walks_all_three_entry_point_groups(
        self, registry: PluginRegistry, fake_entry_points: dict[str, list[Any]]
    ) -> None:
        fake_entry_points["cognic.tools"] = [
            _FakeEntryPoint(
                name="t1",
                value="m1:T",
                dist=_FakeDistribution(name="cognic-tool-t1", version="1.0.0"),
            )
        ]
        fake_entry_points["cognic.skills"] = [
            _FakeEntryPoint(
                name="s1",
                value="m2:S",
                dist=_FakeDistribution(name="cognic-skill-s1", version="0.2.0"),
            )
        ]
        fake_entry_points["cognic.agents"] = [
            _FakeEntryPoint(
                name="a1",
                value="m3:A",
                dist=_FakeDistribution(name="cognic-agent-a1", version="2.5.1"),
            )
        ]
        packs = registry.discover()
        assert all(isinstance(p, DiscoveredPack) for p in packs)
        kinds = sorted(p.record.kind for p in packs)
        assert kinds == ["agents", "skills", "tools"]
        # Distribution name + version flow into the record (for cosign-
        # signature pinning in T6 + T10).
        names = sorted(p.record.distribution_name for p in packs)
        assert names == ["cognic-agent-a1", "cognic-skill-s1", "cognic-tool-t1"]
        # Each pack carries the captured EntryPoint reference — the
        # caller never has to re-walk importlib metadata to load.
        assert all(p.entry_point is not None for p in packs)

    def test_discover_returns_empty_when_no_packs_installed(
        self, registry: PluginRegistry, fake_entry_points: dict[str, list[Any]]
    ) -> None:
        # All three groups empty.
        assert registry.discover() == []

    def test_discover_handles_missing_dist_metadata_gracefully(
        self, registry: PluginRegistry, fake_entry_points: dict[str, list[Any]]
    ) -> None:
        """``ep.dist`` is None for in-memory / synthetic entry points
        (test harnesses, editable-install corner cases). Discovery
        records placeholders rather than crashing — the trust gate at
        T6 will refuse anything without a real signed distribution."""
        fake_entry_points["cognic.tools"] = [_FakeEntryPoint(name="orphan", value="m:T", dist=None)]
        packs = registry.discover()
        assert len(packs) == 1
        assert packs[0].record.distribution_name == "<unknown>"
        assert packs[0].record.distribution_version == "<unknown>"

    def test_discover_does_not_eager_import_pack_modules(
        self, registry: PluginRegistry, fake_entry_points: dict[str, list[Any]]
    ) -> None:
        """P2-K reviewer-fix — pin the §1 deferred-load invariant.

        A pack's ``__init__.py`` executing during ``discover()`` would
        defeat the trust gate's pre-import verification. The sentinel
        only flips when ``load()`` is called — discover() must walk
        metadata only.
        """
        sentinel: dict[str, Any] = {"loaded": False}

        class _Tool:
            pass

        fake_entry_points["cognic.tools"] = [
            _FakeEntryPoint(
                name="test_tool",
                value="cognic_tool_demo:Plugin",
                dist=_FakeDistribution(name="cognic-tool-demo", version="1.0.0"),
                load_sentinel=sentinel,
                load_returns=_Tool,
            )
        ]
        packs = registry.discover()
        assert len(packs) == 1
        assert sentinel["loaded"] is False, (
            "discover() eager-imported a pack — §1 deferred-load invariant "
            "violated. The trust gate's pre-import verification depends on "
            "discover() walking metadata only."
        )

    async def test_full_discover_register_load_flow_without_manual_entry_point(
        self,
        registry: PluginRegistry,
        fake_entry_points: dict[str, list[Any]],
    ) -> None:
        """R2 reviewer-P2 fix integration test: a caller using only the
        public API can discover, register, and load WITHOUT manually
        forwarding an ``EntryPoint``. ``DiscoveredPack`` carries the
        non-loaded EntryPoint from discover() into register() so the
        sync ``load()`` resolves to the same module/attr the installed
        distribution declares — no second ``importlib`` walk required.
        """

        class _Tool:
            pass

        fake_entry_points["cognic.tools"] = [
            _FakeEntryPoint(
                name="public_demo",
                value="cognic_tool_public_demo:Plugin",
                dist=_FakeDistribution(name="cognic-tool-public-demo", version="3.0.0"),
                load_returns=_Tool,
            )
        ]
        # Discover via the public API.
        packs = registry.discover()
        assert len(packs) == 1
        # Register the discovered pack — no manual entry_point=...
        outcome = await registry.register(
            packs[0],
            attestation_grade="full",
            signature_digest=_TEST_SIGNATURE_DIGEST,
        )
        assert outcome.status == "registered"
        assert outcome.name == "public_demo"
        assert outcome.pack_id == "cognic-tool-public-demo"
        # Load resolves through the EntryPoint discover() captured.
        assert registry.load("tools", "public_demo") is _Tool


# ---------------------------------------------------------------------------
# TestRegisterSuccess
# ---------------------------------------------------------------------------


class TestRegisterSuccess:
    async def test_register_full_grade_emits_succeeded_audit(
        self,
        registry: PluginRegistry,
        engine: AsyncEngine,
    ) -> None:
        outcome = await registry.register(
            _make_pack(),
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
            tenant_id="tenant-1",
            request_id="req-1",
        )
        # Outcome shape pinned per the field-name contract (T10 + T11
        # consume these names — entry-point ``name`` is reported
        # separately from ``pack_id`` so a single distribution
        # exposing several entry points renders correctly).
        assert isinstance(outcome, RegistrationOutcome)
        assert outcome.status == "registered"
        assert outcome.name == "demo_pack"
        assert outcome.attestation_grade == "full"
        assert outcome.refusal_reason is None
        assert outcome.signature_digest == "sha256:" + "a" * 64
        assert outcome.kind == "tools"
        assert outcome.pack_id == "cognic-tool-demo"
        assert outcome.version == "1.0.0"
        assert outcome.registered_at is not None
        # Audit chain has exactly one row tied to plugin.registration_succeeded.
        rows = await _read_audit_events(engine)
        assert len(rows) == 1
        assert rows[0]["event_type"] == "plugin.registration_succeeded"
        payload = rows[0]["payload"]
        assert payload["status"] == "registered"
        assert payload["name"] == "demo_pack"
        assert payload["attestation_grade"] == "full"
        assert payload["pack_id"] == "cognic-tool-demo"
        assert payload["kind"] == "tools"
        assert payload["refusal_reason"] is None

    async def test_register_partial_grade_emits_succeeded(
        self,
        registry: PluginRegistry,
        engine: AsyncEngine,
    ) -> None:
        pack = _make_pack(name="grace_pack")
        outcome = await registry.register(
            pack, attestation_grade="partial", signature_digest=_TEST_SIGNATURE_DIGEST
        )
        assert outcome.attestation_grade == "partial"
        assert outcome.name == "grace_pack"
        rows = await _read_audit_events(engine)
        assert rows[0]["event_type"] == "plugin.registration_succeeded"
        assert rows[0]["payload"]["attestation_grade"] == "partial"
        assert rows[0]["payload"]["name"] == "grace_pack"

    async def test_register_persists_to_known_packs(self, registry: PluginRegistry) -> None:
        await registry.register(
            _make_pack(), attestation_grade="full", signature_digest=_TEST_SIGNATURE_DIGEST
        )
        outcomes = registry.known_packs()
        assert len(outcomes) == 1
        assert outcomes[0].name == "demo_pack"
        assert outcomes[0].pack_id == "cognic-tool-demo"
        assert outcomes[0].kind == "tools"
        assert outcomes[0].status == "registered"

    async def test_register_iso_controls_includes_a74(
        self, registry: PluginRegistry, engine: AsyncEngine
    ) -> None:
        """ISO 42001 A.7.4 — admission decisions on plugin packs are
        impact: high. The audit row must carry the control tag for
        the evidence-pack export."""
        await registry.register(
            _make_pack(), attestation_grade="full", signature_digest=_TEST_SIGNATURE_DIGEST
        )
        rows = await _read_audit_events(engine)
        assert "A.7.4" in (rows[0]["iso_controls"] or [])


# ---------------------------------------------------------------------------
# TestRegisterRefusal
# ---------------------------------------------------------------------------


REFUSAL_REASONS_TO_TEST = [
    "not_in_tenant_allowlist",
    "cosign_verification_failed",
    "sbom_missing",
    "sigstore_bundle_persistence_failed",
    "slsa_tampered",
    "intoto_tampered",
    "sbom_tampered",
    "policy_denied_partial_grade",
]


class TestRegisterRefusal:
    @pytest.mark.parametrize("reason", REFUSAL_REASONS_TO_TEST)
    async def test_register_refusal_emits_refused_audit(
        self,
        registry: PluginRegistry,
        engine: AsyncEngine,
        reason: str,
    ) -> None:
        pack = _make_pack(name=f"reject_{reason}")
        outcome = await registry.register(pack, refusal_reason=reason)  # type: ignore[arg-type]
        assert outcome.status == "refused_at_registration"
        assert outcome.name == f"reject_{reason}"
        assert outcome.refusal_reason == reason
        assert outcome.attestation_grade is None
        assert outcome.registered_at is None
        rows = await _read_audit_events(engine)
        assert rows[0]["event_type"] == "plugin.registration_refused"
        assert rows[0]["payload"]["refusal_reason"] == reason
        assert rows[0]["payload"]["name"] == f"reject_{reason}"

    async def test_refusal_outcome_appears_in_known_packs(self, registry: PluginRegistry) -> None:
        await registry.register(_make_pack(), refusal_reason="cosign_verification_failed")
        outcomes = registry.known_packs()
        assert len(outcomes) == 1
        assert outcomes[0].name == "demo_pack"
        assert outcomes[0].status == "refused_at_registration"


# ---------------------------------------------------------------------------
# TestRegisterValidation — boundary checks (negative paths).
# ---------------------------------------------------------------------------


class TestRegisterValidation:
    async def test_neither_grade_nor_reason_rejected(self, registry: PluginRegistry) -> None:
        with pytest.raises(ValueError, match="requires either attestation_grade"):
            await registry.register(_make_pack())

    async def test_both_grade_and_reason_rejected(self, registry: PluginRegistry) -> None:
        with pytest.raises(ValueError, match="rejects both attestation_grade"):
            await registry.register(
                _make_pack(),
                attestation_grade="full",
                refusal_reason="cosign_verification_failed",
            )

    async def test_unknown_refusal_reason_rejected(self, registry: PluginRegistry) -> None:
        with pytest.raises(ValueError, match="not in the closed"):
            # Pass a string outside the closed enum.
            await registry.register(_make_pack(), refusal_reason="made_up_reason")  # type: ignore[arg-type]

    async def test_unknown_attestation_grade_rejected(self, registry: PluginRegistry) -> None:
        with pytest.raises(ValueError, match="attestation_grade"):
            await registry.register(_make_pack(), attestation_grade="bronze")  # type: ignore[arg-type]

    async def test_unknown_kind_rejected(self, registry: PluginRegistry) -> None:
        with pytest.raises(ValueError, match="not a valid pack kind"):
            await registry.register(
                _make_pack(kind="prompts"),  # type: ignore[arg-type]
                attestation_grade="full",
            )

    async def test_success_path_requires_signature_digest(
        self, registry: PluginRegistry, engine: AsyncEngine
    ) -> None:
        """R3 reviewer-P2 fix: a successful registration MUST carry the
        cosign verification digest per ADR-002. Calling register() with
        ``attestation_grade`` but no ``signature_digest`` would let
        T10/T11 advertise a registered/full pack with no signature
        evidence — the registry refuses at its boundary instead of
        relying on T10 caller discipline."""
        with pytest.raises(ValueError, match="non-empty signature_digest"):
            await registry.register(_make_pack(), attestation_grade="full")
        # Nothing reached the chain.
        assert registry.known_packs() == []
        assert await _read_audit_events(engine) == []

    @pytest.mark.parametrize("empty_digest", ["", "   ", "\t\n"])
    async def test_success_path_rejects_empty_signature_digest(
        self, registry: PluginRegistry, empty_digest: str
    ) -> None:
        """Whitespace-only digests are not signature evidence either —
        the boundary check uses ``.strip()`` so quote-stripped empties
        are rejected the same as ``None``."""
        with pytest.raises(ValueError, match="non-empty signature_digest"):
            await registry.register(
                _make_pack(),
                attestation_grade="full",
                signature_digest=empty_digest,
            )

    async def test_partial_grade_also_requires_signature_digest(
        self, registry: PluginRegistry
    ) -> None:
        """The grace-period ``partial`` grade still requires the
        signature — only the full attestation set may degrade, not the
        cosign verification floor. ADR-002 + ADR-016 §"Mandatory floor"."""
        with pytest.raises(ValueError, match="non-empty signature_digest"):
            await registry.register(_make_pack(), attestation_grade="partial")

    async def test_refusal_path_does_not_require_signature_digest(
        self, registry: PluginRegistry
    ) -> None:
        """Refusal flows stay flexible — verification may not have
        run (e.g. ``not_in_tenant_allowlist`` short-circuits before
        cosign), or its absence may itself be the refusal cause."""
        outcome = await registry.register(_make_pack(), refusal_reason="not_in_tenant_allowlist")
        assert outcome.status == "refused_at_registration"
        assert outcome.signature_digest is None

    async def test_chain_emission_failure_aborts_registration(
        self,
        registry: PluginRegistry,
        engine: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If ``AuditStore.append`` raises, the register call must
        propagate the error AND the in-memory ``_records`` dict must
        NOT contain the half-registered pack — the audit chain is the
        source of truth."""

        async def _boom(self: AuditStore, event: Any) -> tuple[Any, Any]:
            raise RuntimeError("audit chain unavailable")

        monkeypatch.setattr(AuditStore, "append", _boom)
        with pytest.raises(RuntimeError, match="audit chain unavailable"):
            await registry.register(
                _make_pack(),
                attestation_grade="full",
                signature_digest=_TEST_SIGNATURE_DIGEST,
            )
        # State is clean.
        assert registry.known_packs() == []

    async def test_duplicate_kind_name_different_distribution_rejected(
        self, registry: PluginRegistry, engine: AsyncEngine
    ) -> None:
        """R2 reviewer-P2 fix: two distributions claiming the same
        ``(kind, name)`` slot must NOT silently overwrite each other.
        That is the plugin-trust attack surface — a malicious second
        pack could shadow a legitimate first by timing its registration.
        The registry refuses; operators resolve by uninstalling one of
        the conflicting distributions."""
        first = _make_pack(
            name="search",
            distribution_name="cognic-tool-search",
            distribution_version="1.0.0",
        )
        await registry.register(
            first, attestation_grade="full", signature_digest=_TEST_SIGNATURE_DIGEST
        )
        impostor = _make_pack(
            name="search",
            distribution_name="cognic-tool-search-impostor",
            distribution_version="0.0.1",
            entry_point_value="malicious_pack:Plugin",
        )
        with pytest.raises(PluginIdentityConflict, match="identity conflict"):
            await registry.register(
                impostor,
                attestation_grade="full",
                signature_digest=_TEST_SIGNATURE_DIGEST,
            )
        # The original survives; impostor never reached the chain.
        outcomes = registry.known_packs()
        assert len(outcomes) == 1
        assert outcomes[0].pack_id == "cognic-tool-search"
        rows = await _read_audit_events(engine)
        assert len(rows) == 1  # only the original registration emitted

    async def test_re_register_same_identity_replaces_outcome(
        self, registry: PluginRegistry, engine: AsyncEngine
    ) -> None:
        """Re-registering the SAME PluginRecord (e.g. after addressing
        a refusal cause) is allowed and replaces the previous outcome.
        The audit chain captures both events for the evidence trail."""
        pack = _make_pack(name="retry_pack")
        # First attempt refused.
        first = await registry.register(pack, refusal_reason="cosign_verification_failed")
        assert first.status == "refused_at_registration"
        # Operator addresses the cause; same identity re-registers.
        second = await registry.register(
            pack, attestation_grade="full", signature_digest=_TEST_SIGNATURE_DIGEST
        )
        assert second.status == "registered"
        # known_packs reflects the latest outcome only.
        outcomes = registry.known_packs()
        assert len(outcomes) == 1
        assert outcomes[0].status == "registered"
        # Both audit events captured.
        rows = await _read_audit_events(engine)
        assert [r["event_type"] for r in rows] == [
            "plugin.registration_refused",
            "plugin.registration_succeeded",
        ]


# ---------------------------------------------------------------------------
# TestLoadAndKnownPacks
# ---------------------------------------------------------------------------


class TestLoadAndKnownPacks:
    async def test_load_returns_entry_point_target(self, registry: PluginRegistry) -> None:
        class _Tool:
            pass

        pack = _make_pack(load_returns=_Tool)
        await registry.register(
            pack, attestation_grade="full", signature_digest=_TEST_SIGNATURE_DIGEST
        )
        loaded = registry.load("tools", "demo_pack")
        assert loaded is _Tool

    async def test_load_raises_registration_refused_after_refusal(
        self, registry: PluginRegistry
    ) -> None:
        await registry.register(_make_pack(), refusal_reason="cosign_verification_failed")
        with pytest.raises(RegistrationRefused) as exc:
            registry.load("tools", "demo_pack")
        assert exc.value.kind == "tools"
        assert exc.value.name == "demo_pack"
        assert exc.value.refusal_reason == "cosign_verification_failed"

    def test_load_raises_plugin_not_registered_when_unknown(self, registry: PluginRegistry) -> None:
        with pytest.raises(PluginNotRegistered):
            registry.load("tools", "never_registered")

    async def test_known_packs_returns_insertion_order(self, registry: PluginRegistry) -> None:
        """T11 ``/api/v1/system/plugins`` requires deterministic order
        across repeat reads — Python dict insertion-order is the
        guarantee."""
        await registry.register(
            _make_pack(name="alpha"),
            attestation_grade="full",
            signature_digest=_TEST_SIGNATURE_DIGEST,
        )
        await registry.register(
            _make_pack(name="bravo", kind="skills"),
            refusal_reason="sbom_missing",
        )
        await registry.register(
            _make_pack(name="charlie", kind="agents"),
            attestation_grade="partial",
            signature_digest=_TEST_SIGNATURE_DIGEST,
        )
        outcomes = registry.known_packs()
        assert [o.kind for o in outcomes] == ["tools", "skills", "agents"]
        assert [o.name for o in outcomes] == ["alpha", "bravo", "charlie"]


# ---------------------------------------------------------------------------
# TestConcurrency — chain-head + mutation-lock serialise concurrent registers.
# ---------------------------------------------------------------------------


class TestConcurrency:
    async def test_concurrent_registers_serialise_via_chain_head(
        self, registry: PluginRegistry, engine: AsyncEngine
    ) -> None:
        """Concurrent ``register`` calls must each get a unique chain
        sequence number; nothing is dropped or duplicated. SQLite has
        no row-level locking, but the in-process mutation_lock + the
        chain-head compare-and-set together give us the same
        invariant: monotonic sequences with no gaps."""
        packs = [_make_pack(name=f"pack_{i}") for i in range(8)]
        await asyncio.gather(
            *(
                registry.register(
                    p, attestation_grade="full", signature_digest=_TEST_SIGNATURE_DIGEST
                )
                for p in packs
            )
        )
        rows = await _read_audit_events(engine)
        assert len(rows) == 8
        sequences = [r["sequence"] for r in rows]
        assert sequences == list(range(1, 9))  # 1..8 monotonic
        # All eight packs landed in known_packs (one per concurrent call).
        assert len(registry.known_packs()) == 8

    async def test_concurrent_duplicate_name_impostor_rejected(
        self,
        registry: PluginRegistry,
        engine: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """R2 reviewer-P2 fix regression: with the conflict check INSIDE
        the mutation_lock, two concurrent registrations for the same
        ``(kind, name)`` but different distributions cannot both reach
        the audit chain. The second one observes the first under the
        lock and raises ``PluginIdentityConflict`` BEFORE its own audit
        emission, so only one chain row is written.

        Forces a deterministic interleave by stalling the first
        ``audit_store.append`` until the second register call has
        contended on the lock. Without the in-lock guard, the second
        call would sneak past the (still-empty) ``_records`` check
        before the first append landed and silently overwrite.
        """
        first_append_started = asyncio.Event()
        first_append_resume = asyncio.Event()
        original_append = AuditStore.append

        async def _stall_first_append(self: AuditStore, event: Any) -> tuple[Any, Any]:
            # Only stall the FIRST call (the legitimate registration).
            # Subsequent calls (the impostor's, if it ever reaches the
            # audit step — it shouldn't) run unmodified.
            if not first_append_started.is_set():
                first_append_started.set()
                await first_append_resume.wait()
            return await original_append(self, event)

        monkeypatch.setattr(AuditStore, "append", _stall_first_append)

        legitimate = _make_pack(
            name="search",
            distribution_name="cognic-tool-search",
            distribution_version="1.0.0",
        )
        impostor = _make_pack(
            name="search",
            distribution_name="cognic-tool-search-impostor",
            distribution_version="0.0.1",
            entry_point_value="malicious_pack:Plugin",
        )

        # Kick off legitimate first; let it stall inside the lock at append().
        first_task = asyncio.create_task(
            registry.register(
                legitimate,
                attestation_grade="full",
                signature_digest=_TEST_SIGNATURE_DIGEST,
            )
        )
        await first_append_started.wait()
        # Now the impostor races — it must wait on the mutation_lock
        # and, when it eventually acquires the lock (after first
        # finishes), see the legitimate registration and refuse.
        second_task = asyncio.create_task(
            registry.register(
                impostor,
                attestation_grade="full",
                signature_digest=_TEST_SIGNATURE_DIGEST,
            )
        )
        # Release the legitimate append.
        first_append_resume.set()

        legit_outcome = await first_task
        assert legit_outcome.status == "registered"
        assert legit_outcome.pack_id == "cognic-tool-search"

        # Impostor must surface PluginIdentityConflict, not race past
        # to a successful registration.
        with pytest.raises(PluginIdentityConflict, match="identity conflict"):
            await second_task

        # Only ONE audit row exists — impostor never emitted.
        rows = await _read_audit_events(engine)
        assert len(rows) == 1
        assert rows[0]["payload"]["pack_id"] == "cognic-tool-search"
        # known_packs reflects only the legitimate registration.
        outcomes = registry.known_packs()
        assert len(outcomes) == 1
        assert outcomes[0].pack_id == "cognic-tool-search"
