"""Sprint 13.8 (ADR-002) — read-only iter_registered_pack_candidates() accessor.

CC stop-rule coverage for the MCP-host builder's trusted-set source: registered
candidates only, package_name derived from record.entry_point_value WITHOUT
loading pack code, refused outcomes excluded, known_packs() unchanged.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    PluginRecord,
    PluginRegistry,
    RegisteredPackCandidate,
)

_SIG = "sha256:" + "a" * 64


@pytest.fixture
def audit_store() -> MagicMock:
    # mirrors tests/unit/protocol/test_a2a_cancellation.py::audit_store — register()
    # ignores the append return and stores in _records, so a mock suffices.
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


class _FakeDistribution:
    def __init__(self, name: str, version: str) -> None:
        self.metadata = {"Name": name, "Version": version}


class _FakeEntryPoint:
    def __init__(self, *, name: str, value: str, dist: _FakeDistribution) -> None:
        self.name, self.value, self.dist = name, value, dist

    def load(self):  # pragma: no cover — the accessor MUST NOT call this
        raise AssertionError("EntryPoint.load() must not be called by the accessor")


def _pack(*, ep_value: str, dist: str = "cognic-tool-foo", name: str = "foo") -> DiscoveredPack:
    record = PluginRecord(
        kind="tools",
        name=name,
        distribution_name=dist,
        distribution_version="1.0.0",
        entry_point_value=ep_value,
    )
    ep = _FakeEntryPoint(name=name, value=ep_value, dist=_FakeDistribution(dist, "1.0.0"))
    return DiscoveredPack(record=record, entry_point=ep)  # type: ignore[arg-type]


async def _reg_registered(
    audit_store: MagicMock, *, ep_value: str, dist: str = "cognic-tool-foo"
) -> PluginRegistry:
    reg = PluginRegistry(audit_store=audit_store)
    await reg.register(
        _pack(ep_value=ep_value, dist=dist), attestation_grade="full", signature_digest=_SIG
    )
    return reg


async def test_iter_yields_registered_candidate_with_derived_package_name(
    audit_store: MagicMock,
) -> None:
    # entry-point value "deep_pkg.server:app" → package_name "deep_pkg", even
    # though distribution_name is "cognic-tool-foo" (package≠distribution layout).
    reg = await _reg_registered(audit_store, ep_value="deep_pkg.server:app")
    cands = list(reg.iter_registered_pack_candidates())
    assert len(cands) == 1
    assert isinstance(cands[0], RegisteredPackCandidate)
    assert cands[0].package_name == "deep_pkg"  # from record.entry_point_value
    assert cands[0].distribution_name == "cognic-tool-foo"
    assert cands[0].signature_digest == _SIG


async def test_iter_never_calls_entry_point_load(audit_store: MagicMock) -> None:
    # no-load proof: _FakeEntryPoint.load() raises; the accessor reads only
    # record.entry_point_value (a string), so iterating MUST NOT raise.
    reg = await _reg_registered(audit_store, ep_value="deep_pkg.server:app")
    cands = list(reg.iter_registered_pack_candidates())  # would raise if load() were called
    assert cands[0].package_name == "deep_pkg"


async def test_iter_excludes_refused_at_registration(audit_store: MagicMock) -> None:
    # a refused_at_registration outcome MUST NOT appear.
    reg = PluginRegistry(audit_store=audit_store)
    await reg.register(_pack(ep_value="x:Y"), refusal_reason="cosign_verification_failed")
    assert list(reg.iter_registered_pack_candidates()) == []


async def test_known_packs_unchanged_regression(audit_store: MagicMock) -> None:
    # adding the accessor must not alter known_packs() output.
    reg = await _reg_registered(audit_store, ep_value="deep_pkg:app")
    outcomes = reg.known_packs()
    assert [o.pack_id for o in outcomes] == ["cognic-tool-foo"]
    assert all(o.status in ("registered", "refused_at_registration") for o in outcomes)
